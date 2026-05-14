//! Local loopback acceptance coverage for the FCP `Outlook` connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_outlook::OutlookConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.50";
const CONNECTOR_ID: &str = "fcp.outlook";
const ACCESS_SECRET: &str = "local_outlook_acceptance_secret";
const USER_TEXT_SECRET: &str = "secret outlook body";
const PROVIDER_TEXT_SECRET: &str = "provider secret";
const CAP_READ: &str = "outlook.read";
const CAP_SEND: &str = "outlook.send";
const OP_LIST_MESSAGES: &str = "outlook.list_messages";
const OP_SEND_MESSAGE: &str = "outlook.send_message";
const LIST_MESSAGES_BODY: &str = r#"{
  "value": [
    {
      "id": "message-local-1",
      "subject": "provider secret",
      "bodyPreview": "secret outlook body",
      "isRead": false
    }
  ]
}"#;
const RATE_LIMIT_BODY: &str = r#"{
  "error": { "message": "provider secret" }
}"#;

#[derive(Debug, Clone, Copy)]
struct ResponseSpec {
    status: u16,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
}

impl ResponseSpec {
    const fn json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            headers: &[],
            body,
        }
    }

    const fn with_headers(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: &'static str,
    ) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
struct RequestObservation {
    request_line: String,
    headers: Vec<String>,
    body: String,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackFixture {
    fn start(responses: Vec<ResponseSpec>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, response)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> Vec<RequestObservation> {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: ResponseSpec) -> RequestObservation {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set read timeout");

    let raw = read_http_message(&mut stream);
    let header_end = find_header_end(&raw).expect("request contains header terminator");
    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();
    let body_start = header_end + 4;
    let body = String::from_utf8_lossy(&raw[body_start..]).to_string();

    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        status_reason(response.status),
        response.body.len()
    )
    .expect("write response headers");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write response header");
    }
    write!(stream, "\r\n{}", response.body).expect("write response body");

    RequestObservation {
        request_line,
        headers,
        body,
    }
}

fn read_http_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let total_len = header_end + 4 + content_length(&headers);
            while request.len() < total_len {
                let bytes_read = stream
                    .read(&mut buffer)
                    .expect("read connector request body");
                assert!(bytes_read > 0, "connector body should not close early");
                request.extend_from_slice(&buffer[..bytes_read]);
                assert!(request.len() < 16384, "request body should stay bounded");
            }
            request.truncate(total_len);
            return request;
        }

        assert!(request.len() < 16384, "request headers should stay bounded");
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("content-length is usize")
            })
        })
        .unwrap_or(0)
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        429 => "Too Many Requests",
        _ => "Status",
    }
}

fn has_header(headers: &[String], name: &str, expected_value: &str) -> bool {
    headers.iter().any(|line| {
        let Some((actual_name, actual_value)) = line.split_once(':') else {
            return false;
        };
        actual_name.eq_ignore_ascii_case(name) && actual_value.trim() == expected_value
    })
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    connector: &OutlookConnector,
    capability: &str,
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
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:local-acceptance")
        .operations(&[operation])
        .issuer("node:local-acceptance")
        .target_instance(connector.instance_id().as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

fn handshake_request(capabilities: &[&'static str], public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: public_key,
        nonce: [47_u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|capability| CapabilityId::from_static(capability))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

async fn setup_connector(
    fixture: &LoopbackFixture,
    capabilities: &[&'static str],
) -> (OutlookConnector, Ed25519SigningKey) {
    let mut connector = OutlookConnector::new();
    connector
        .configure(json!({
            "access_token": ACCESS_SECRET,
            "graph_host": fixture.base_url(),
            "request_timeout_ms": 5000
        }))
        .await
        .expect("configure connector");
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handshake(handshake_request(capabilities, verifying_key.to_bytes()))
        .await
        .expect("handshake connector");
    (connector, signing_key)
}

async fn invoke(
    connector: &OutlookConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new(format!("req-{operation}")),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: valid_token(signing_key, connector, capability, operation),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await?;
    assert_eq!(response.status, InvokeStatus::Ok);
    Ok(response.result.expect("successful response has result"))
}

fn emit_acceptance(event: &str, connector: &OutlookConnector, payload: &Value) {
    let mut object = serde_json::Map::new();
    object.insert("event".into(), json!(event));
    object.insert(
        "command_line".into(),
        json!("cargo test -p fcp-outlook --test local_non_mock -- --nocapture"),
    );
    object.insert("git_revision".into(), json!(git_revision()));
    object.insert("bead_id".into(), json!(BEAD_ID));
    object.insert("suite_class".into(), json!(ACCEPTANCE_SUITE_CLASS));
    object.insert(
        "acceptance_suite_class".into(),
        json!(ACCEPTANCE_SUITE_CLASS),
    );
    object.insert("connector_id".into(), json!(CONNECTOR_ID));
    object.insert("fixture_mode".into(), json!("loopback"));
    object.insert("provider_class".into(), json!("raw_tcp_http_fixture"));
    object.insert("zone".into(), json!("z:work"));
    object.insert(
        "instance_id_hash".into(),
        json!(fcp_outlook_hash(connector.instance_id().as_str())),
    );
    object.insert("cleanup_result".into(), json!("fixture_server_closed"));
    object.insert("skip_reason".into(), Value::Null);
    if let Some(payload) = payload.as_object() {
        object.extend(payload.clone());
    }

    let line = Value::Object(object).to_string();
    assert_redacted(&line);
    eprintln!("OUTLOOK_ACCEPTANCE_JSONL {line}");
}

fn git_revision() -> &'static str {
    option_env!("GIT_REVISION").unwrap_or("unknown")
}

fn fcp_outlook_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize()).chars().take(16).collect()
}

fn assert_redacted(serialized: &str) {
    assert!(!serialized.contains(ACCESS_SECRET));
    assert!(!serialized.contains(USER_TEXT_SECRET));
    assert!(!serialized.contains(PROVIDER_TEXT_SECRET));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_and_send_cross_graph_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, LIST_MESSAGES_BODY),
        ResponseSpec::json(202, ""),
    ]);
    let (connector, signing_key) = setup_connector(&fixture, &[CAP_READ, CAP_SEND]).await;
    let health = connector.health().await;
    assert!(matches!(health.status, fcp_core::HealthState::Ready));

    let list_result = invoke(
        &connector,
        &signing_key,
        OP_LIST_MESSAGES,
        CAP_READ,
        json!({ "folder_id": "inbox", "top": 2 }),
    )
    .await
    .expect("list messages should succeed");
    assert_eq!(list_result["value"].as_array().map_or(0, Vec::len), 1);

    let send_result = invoke(
        &connector,
        &signing_key,
        OP_SEND_MESSAGE,
        CAP_SEND,
        json!({
            "to": ["recipient@example.invalid"],
            "cc": ["copy@example.invalid"],
            "subject": "Local acceptance",
            "body": USER_TEXT_SECRET
        }),
    )
    .await
    .expect("send message should succeed");
    assert_eq!(send_result["status"], "ok");
    assert_redacted(&send_result.to_string());

    let observations = fixture.join();
    assert_eq!(observations.len(), 2);
    let list_request = observations.first().expect("list request present");
    assert!(
        list_request
            .request_line
            .starts_with("GET /v1.0/me/mailFolders/inbox/messages?$top=2&")
    );
    assert!(
        list_request
            .request_line
            .contains("$select=id,subject,from,receivedDateTime,isRead,bodyPreview")
    );
    assert!(has_header(
        &list_request.headers,
        "authorization",
        &format!("Bearer {ACCESS_SECRET}")
    ));

    let send_request = observations.get(1).expect("send request present");
    assert_eq!(send_request.request_line, "POST /v1.0/me/sendMail HTTP/1.1");
    assert!(has_header(
        &send_request.headers,
        "authorization",
        &format!("Bearer {ACCESS_SECRET}")
    ));
    let body: Value = serde_json::from_str(&send_request.body).expect("send body JSON");
    assert_eq!(body["message"]["subject"], "Local acceptance");
    assert_eq!(body["message"]["body"]["contentType"], "Text");
    assert_eq!(body["message"]["body"]["content"], USER_TEXT_SECRET);
    assert_eq!(
        body["message"]["toRecipients"][0]["emailAddress"]["address"],
        "recipient@example.invalid"
    );
    assert_eq!(
        body["message"]["ccRecipients"][0]["emailAddress"]["address"],
        "copy@example.invalid"
    );

    emit_acceptance(
        "list_and_send",
        &connector,
        &json!({
            "operations": [OP_LIST_MESSAGES, OP_SEND_MESSAGE],
            "capabilities": [CAP_READ, CAP_SEND],
            "request_response_boundary": "GET /v1.0/me/mailFolders/{id}/messages + POST /v1.0/me/sendMail",
            "auth_gate": "bearer_header_forwarded",
            "health_local_no_egress": true,
            "list_count": list_result["value"].as_array().map_or(0, Vec::len),
            "send_status": send_result["status"],
            "result": "ok",
            "error_code": Value::Null,
            "retry_backoff_decision": "none"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_without_provider_body() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::with_headers(
        429,
        &[("Retry-After", "3")],
        RATE_LIMIT_BODY,
    )]);
    let (connector, signing_key) = setup_connector(&fixture, &[CAP_READ]).await;

    let error = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req-rate-limit"),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::from_static(OP_LIST_MESSAGES),
            zone_id: ZoneId::work(),
            input: json!({ "top": 1 }),
            capability_token: valid_token(&signing_key, &connector, CAP_READ, OP_LIST_MESSAGES),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await
        .expect_err("rate limit should fail the invocation");
    let debug = format!("{error:?}");
    assert_redacted(&debug);
    match error {
        FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 3000),
        other => panic!("unexpected rate-limit mapping: {other:?}"),
    }

    let observations = fixture.join();
    assert_eq!(observations.len(), 1);
    assert!(
        observations[0]
            .request_line
            .starts_with("GET /v1.0/me/mailFolders/inbox/messages?$top=1&")
    );
    assert!(has_header(
        &observations[0].headers,
        "authorization",
        &format!("Bearer {ACCESS_SECRET}")
    ));

    emit_acceptance(
        "rate_limit_mapping",
        &connector,
        &json!({
            "operation": OP_LIST_MESSAGES,
            "capability": CAP_READ,
            "request_response_boundary": "GET /v1.0/me/mailFolders/inbox/messages",
            "auth_gate": "bearer_header_forwarded",
            "http_status": 429,
            "retry_after_ms": 3000,
            "result": "ok",
            "error_code": "rate_limited",
            "retry_backoff_decision": "retry_after_header_seconds"
        }),
    );
}
