#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use ed25519_dalek::Signer as _;
use fcp_crypto::{CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError};
use fcp_telnyx::{client::decode_client_state_token, connector::TelnyxConnector};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const API_KEY: &str = "telnyx_local_non_mock_key";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Option<Value>,
}

struct LoopbackServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).expect("Telnyx loopback listener should bind");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its address")
        );
        let (request_tx, received) = mpsc::channel();

        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener
                    .accept()
                    .expect("loopback listener should accept expected request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("loopback stream should set read timeout");

                let request = read_complete_request(&mut stream);
                request_tx
                    .send(request)
                    .expect("captured request should be delivered");

                let raw_response = format!(
                    "HTTP/1.1 {}\r\n\
                     content-type: application/json\r\n\
                     content-length: {}\r\n\
                     connection: close\r\n\
                     \r\n\
                     {}",
                    response.status,
                    response.body.len(),
                    response.body
                );
                stream
                    .write_all(raw_response.as_bytes())
                    .expect("loopback response should be writable");
            }
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn take(&self) -> CapturedRequest {
        self.received
            .recv_timeout(Duration::from_secs(5))
            .expect("loopback request should arrive")
    }

    fn join(self) {
        self.join
            .join()
            .expect("loopback server thread should finish");
    }
}

struct HttpResponse {
    status: &'static str,
    body: &'static str,
}

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let read = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);

        if header_end.is_none() {
            header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n");
            if let Some(end) = header_end {
                let head = String::from_utf8_lossy(&bytes[..end]);
                content_length = parse_content_length(&head);
            }
        }

        if let Some(end) = header_end {
            let body_start = end + 4;
            if bytes.len() >= body_start + content_length {
                let head = String::from_utf8(bytes[..end].to_vec())
                    .expect("request headers should be valid UTF-8");
                let body_slice = &bytes[body_start..body_start + content_length];
                let body = if body_slice.is_empty() {
                    None
                } else {
                    Some(
                        serde_json::from_slice(body_slice)
                            .expect("request body should be JSON when present"),
                    )
                };
                return CapturedRequest { head, body };
            }
        }
    }

    panic!("loopback request ended before complete headers/body were read");
}

fn parse_content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn assert_request(captured: &CapturedRequest, method: &str, target: &str) {
    let request_line = captured
        .head
        .lines()
        .next()
        .expect("captured request should include a request line");
    assert_eq!(request_line, format!("{method} {target} HTTP/1.1"));

    let lower_head = captured.head.to_ascii_lowercase();
    assert!(
        lower_head.contains(&format!("authorization: bearer {API_KEY}")),
        "request should carry redaction-safe bearer auth; head={}",
        captured.head
    );
}

async fn configured_connector(
    base_url: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> (TelnyxConnector, Ed25519SigningKey) {
    let mut connector = TelnyxConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "public_key": telnyx_public_key_config(signing_key),
            "base_url": format!("{base_url}/v2"),
            "timestamp_tolerance_seconds": 300
        }))
        .await
        .expect("connector should configure against loopback base URL");
    let host_key = setup_handshake(&mut connector).await;
    (connector, host_key)
}

async fn setup_handshake(connector: &mut TelnyxConnector) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["telnyx.read", "telnyx.voice", "telnyx.webhook"]
        }))
        .await
        .expect("Telnyx handshake should complete");
    signing_key
}

fn telnyx_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32])
}

fn telnyx_public_key_config(signing_key: &ed25519_dalek::SigningKey) -> String {
    STANDARD.encode(signing_key.verifying_key().to_bytes())
}

fn sign_telnyx_webhook(
    signing_key: &ed25519_dalek::SigningKey,
    timestamp: &str,
    raw_body: &str,
) -> String {
    let mut signed = Vec::new();
    signed.extend_from_slice(timestamp.as_bytes());
    signed.push(b'|');
    signed.extend_from_slice(raw_body.as_bytes());
    STANDARD.encode(signing_key.sign(&signed).to_bytes())
}

fn capability_for(operation: &str) -> &'static str {
    match operation {
        "telnyx.call.status" => "telnyx.read",
        "telnyx.webhook.validate_signature"
        | "telnyx.webhook.evaluate_inbound_policy"
        | "telnyx.webhook.parse_event"
        | "telnyx.webhook.ingest_request" => "telnyx.webhook",
        _ => "telnyx.voice",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for(operation))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + chrono::Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &mut TelnyxConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    input: Value,
) -> Value {
    let capability_proof = generate_valid_token(signing_key, connector.instance_id(), operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_proof
        }))
        .await
        .expect("operation should succeed")
}

fn telnyx_event_raw(call_control_id: &str, client_state: &str) -> String {
    json!({
        "data": {
            "id": format!("evt-{call_control_id}"),
            "event_type": "call.initiated",
            "occurred_at": "2026-05-14T00:00:00Z",
            "record_type": "event",
            "payload": {
                "call_control_id": call_control_id,
                "call_session_id": "call-session-e2e",
                "client_state": client_state,
                "from": "+15551230000",
                "to": "+15559870000",
                "media": { "bytes": 320, "frames": 2 }
            }
        }
    })
    .to_string()
}

fn webhook_input(raw_body: &str, timestamp: &str, signature: &str) -> Value {
    json!({
        "method": "POST",
        "headers": {
            "Telnyx-Timestamp": timestamp,
            "Telnyx-Signature-Ed25519": signature
        },
        "raw_body": raw_body,
        "body": serde_json::from_str::<Value>(raw_body).expect("webhook body should be JSON"),
        "inbound_policy": "open",
        "request_region": { "source": "telnyx_local_non_mock_loopback" }
    })
}

fn success_responses() -> Vec<HttpResponse> {
    vec![
        HttpResponse {
            status: "201 Created",
            body: r#"{"data":{"call_control_id":"call-control-e2e","call_leg_id":"call-leg-e2e","call_session_id":"call-session-e2e","status":"queued"}}"#,
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{"data":{"result":"answered","call_control_id":"call-control-e2e"}}"#,
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{"data":{"result":"speaking","call_control_id":"call-control-e2e"}}"#,
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{"data":{"result":"transferred","call_control_id":"call-control-e2e"}}"#,
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{"data":{"result":"gathering","call_control_id":"call-control-e2e"}}"#,
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{"data":{"result":"hangup","call_control_id":"call-control-e2e"}}"#,
        },
        HttpResponse {
            status: "503 Service Unavailable",
            body: "temporary",
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{"data":{"call_control_id":"transient","status":"bridged"}}"#,
        },
        HttpResponse {
            status: "422 Unprocessable Entity",
            body: r#"{"errors":[{"detail":"provider rejected call"}]}"#,
        },
    ]
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_call_control_and_webhook_flow_uses_loopback_http() {
    let server = LoopbackServer::start(success_responses());
    let telnyx_key = telnyx_signing_key();
    let (mut connector, host_key) = configured_connector(&server.base_url, &telnyx_key).await;

    let create = invoke(
        &mut connector,
        &host_key,
        "telnyx.call.initiate",
        json!({
            "to": "+15551230000",
            "from": "+15559870000",
            "connection_id": "conn-e2e",
            "webhook_url": "https://voice.example.com/telnyx",
            "stream_url": "wss://voice.example.com/media"
        }),
    )
    .await;
    assert_eq!(create["call"]["call_control_id"], "call-control-e2e");

    let create_request = server.take();
    assert_request(&create_request, "POST", "/v2/calls");
    let create_body = create_request
        .body
        .expect("call creation should include JSON");
    assert_eq!(create_body["connection_id"], "conn-e2e");
    assert_eq!(create_body["stream_url"], "wss://voice.example.com/media");
    let client_state = create_body["client_state"]
        .as_str()
        .expect("call creation should embed client_state")
        .to_string();
    let callback_binding =
        decode_client_state_token(&client_state).expect("client_state should decode");
    assert_eq!(callback_binding.len(), 22);
    assert_eq!(
        create_body["stream_auth_token"].as_str(),
        Some(callback_binding.as_str())
    );

    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.continue",
            json!({"call_control_id": "call-control-e2e"}),
        )
        .await["result"],
        "answered"
    );
    assert_request(
        &server.take(),
        "POST",
        "/v2/calls/call-control-e2e/actions/answer",
    );

    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.speak",
            json!({"call_control_id": "call-control-e2e", "payload": "hello"}),
        )
        .await["result"],
        "speaking"
    );
    let speak_request = server.take();
    assert_request(
        &speak_request,
        "POST",
        "/v2/calls/call-control-e2e/actions/speak",
    );
    assert_eq!(
        speak_request
            .body
            .expect("speak request should include JSON")["payload"],
        "hello"
    );

    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.transfer",
            json!({"call_control_id": "call-control-e2e", "to": "+15557654321"}),
        )
        .await["result"],
        "transferred"
    );
    assert_request(
        &server.take(),
        "POST",
        "/v2/calls/call-control-e2e/actions/transfer",
    );

    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.gather",
            json!({"call_control_id": "call-control-e2e", "payload": "press one"}),
        )
        .await["result"],
        "gathering"
    );
    assert_request(
        &server.take(),
        "POST",
        "/v2/calls/call-control-e2e/actions/gather_using_speak",
    );

    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.end",
            json!({"call_control_id": "call-control-e2e"}),
        )
        .await["result"],
        "hangup"
    );
    assert_request(
        &server.take(),
        "POST",
        "/v2/calls/call-control-e2e/actions/hangup",
    );

    let timestamp = Utc::now().timestamp().to_string();
    let raw_body = telnyx_event_raw("call-control-e2e", &client_state);
    let signature = sign_telnyx_webhook(&telnyx_key, &timestamp, &raw_body);
    let ingest = invoke(
        &mut connector,
        &host_key,
        "telnyx.webhook.ingest_request",
        webhook_input(&raw_body, &timestamp, &signature),
    )
    .await;
    assert_eq!(ingest["accepted"], true);
    assert_eq!(ingest["signature"]["reason_code"], "signature_validated");
    assert_eq!(ingest["policy"]["reason_code"], "inbound_open");

    let transient = invoke(
        &mut connector,
        &host_key,
        "telnyx.call.status",
        json!({ "call_control_id": "transient" }),
    )
    .await;
    assert_eq!(transient["status"], "bridged");
    assert_request(&server.take(), "GET", "/v2/calls/transient");
    assert_request(&server.take(), "GET", "/v2/calls/transient");

    let provider_error_capability =
        generate_valid_token(&host_key, connector.instance_id(), "telnyx.call.status");
    let provider_error = connector
        .handle_invoke(json!({
            "operation": "telnyx.call.status",
            "input": { "call_control_id": "provider-error" },
            "capability_token": provider_error_capability
        }))
        .await
        .expect_err("provider 422 should map to an FCP external error");
    assert_eq!(provider_error.error_code(), "FCP-7003");
    assert_request(&server.take(), "GET", "/v2/calls/provider-error");

    server.join();

    let evidence = json!({
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": "telnyx",
        "fixture_transport": "hand_rolled_loopback_tcp_http",
        "operations": [
            "telnyx.call.initiate",
            "telnyx.call.continue",
            "telnyx.call.speak",
            "telnyx.call.transfer",
            "telnyx.call.gather",
            "telnyx.call.end",
            "telnyx.call.status",
            "telnyx.webhook.ingest_request"
        ],
        "streaming_boundary": "call_control_webhook_client_state_binding",
        "event_transcript": {
            "event_type": "call.initiated",
            "signature": "validated",
            "retry": "503_then_200"
        },
        "cleanup": "loopback_server_joined"
    });
    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    println!("TELNYX_LOCAL_NON_MOCK_EVIDENCE {evidence}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_auth_denial_maps_to_unauthorized() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "401 Unauthorized",
        body: r#"{"errors":[{"detail":"invalid api key"}]}"#,
    }]);
    let telnyx_key = telnyx_signing_key();
    let (mut connector, host_key) = configured_connector(&server.base_url, &telnyx_key).await;
    let capability_proof =
        generate_valid_token(&host_key, connector.instance_id(), "telnyx.call.status");

    let error = connector
        .handle_invoke(json!({
            "operation": "telnyx.call.status",
            "input": { "call_control_id": "auth-denied" },
            "capability_token": capability_proof
        }))
        .await
        .expect_err("provider auth failure should map to Unauthorized");
    assert!(
        matches!(error, FcpError::Unauthorized { .. }),
        "expected Unauthorized, got {error:?}"
    );

    assert_request(&server.take(), "GET", "/v2/calls/auth-denied");
    server.join();
}
