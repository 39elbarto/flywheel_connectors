//! Local loopback acceptance coverage for the FCP `Inworld` connector.

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
use fcp_inworld::InworldConnector;
use fcp_inworld::connector::{
    CAP_HEALTH, CAP_ROUTER, OP_HEALTH, OP_ROUTER_CHAT, test_handshake_request,
};
use fcp_inworld::types::stable_hash;
use fcp_prelude::{CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.47";
const AUTH_SECRET: &str = "local_inworld_acceptance_secret";
const USER_TEXT_SECRET: &str = "secret user text";
const PROVIDER_TEXT_SECRET: &str = "provider secret";
const PROVIDER_ID_SECRET: &str = "router-provider-id-secret";
const ROUTER_OK_BODY: &str = r#"{
  "id": "router-provider-id-secret",
  "model": "auto",
  "choices": [
    { "message": { "role": "assistant", "content": "provider secret" } }
  ],
  "usage": { "prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6 },
  "metadata": { "attempts": [{ "model": "inworld" }] }
}"#;
const PROVIDER_ERROR_BODY: &str = r#"{
  "error": { "message": "provider secret" }
}"#;

#[derive(Debug, Clone, Copy)]
struct ResponseSpec {
    status: u16,
    body: &'static str,
}

impl ResponseSpec {
    const fn json(status: u16, body: &'static str) -> Self {
        Self { status, body }
    }
}

#[derive(Debug)]
struct RequestObservation {
    request_line: String,
    headers: Vec<String>,
    body: String,
}

struct LoopbackFixture {
    address: String,
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
            address: address.to_string(),
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn realtime_ws_url(&self) -> String {
        format!("ws://{}/api/v1/realtime/session", self.address)
    }

    fn tts_ws_url(&self) -> String {
        format!("ws://{}/tts/v1/voice:streamBidirectional", self.address)
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
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        status_reason(response.status),
        response.body.len(),
        response.body
    )
    .expect("write response");

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
        401 => "Unauthorized",
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
    instance_id: &str,
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
        .target_instance(instance_id)
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

async fn setup_connector(
    fixture: &LoopbackFixture,
    capabilities: &[&'static str],
) -> (InworldConnector, Ed25519SigningKey) {
    let mut connector = InworldConnector::new();
    connector
        .handle_configure(json!({
            "api_key": AUTH_SECRET,
            "realtime_ws_url": fixture.realtime_ws_url(),
            "tts_ws_url": fixture.tts_ws_url(),
            "router_base_url": fixture.base_url(),
            "request_timeout_ms": 5000
        }))
        .await
        .expect("configure connector");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let requested = capabilities
        .iter()
        .map(|capability| CapabilityId::from_static(capability))
        .collect();
    connector
        .handshake(test_handshake_request(requested, verifying_key.to_bytes()))
        .await
        .expect("handshake connector");

    (connector, signing_key)
}

async fn invoke(
    connector: &InworldConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let grant = valid_token(
        signing_key,
        connector.instance_id().as_str(),
        capability,
        operation,
    );
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": grant,
        }))
        .await
}

fn emit_acceptance(event: &str, connector: &InworldConnector, payload: &Value) {
    let mut object = serde_json::Map::new();
    object.insert("event".into(), json!(event));
    object.insert(
        "command_line".into(),
        json!("cargo test -p fcp-inworld --test local_non_mock -- --nocapture"),
    );
    object.insert("git_revision".into(), json!(git_revision()));
    object.insert("bead_id".into(), json!(BEAD_ID));
    object.insert("suite_class".into(), json!(ACCEPTANCE_SUITE_CLASS));
    object.insert(
        "acceptance_suite_class".into(),
        json!(ACCEPTANCE_SUITE_CLASS),
    );
    object.insert("connector_id".into(), json!("fcp.inworld"));
    object.insert("fixture_mode".into(), json!("loopback"));
    object.insert("provider_class".into(), json!("raw_tcp_http_fixture"));
    object.insert("zone".into(), json!("z:work"));
    object.insert(
        "instance_id_hash".into(),
        json!(stable_hash(connector.instance_id().as_str())),
    );
    object.insert("cleanup_result".into(), json!("fixture_server_closed"));
    object.insert("skip_reason".into(), Value::Null);
    if let Some(payload) = payload.as_object() {
        object.extend(payload.clone());
    }

    let line = Value::Object(object).to_string();
    assert_redacted(&line);
    eprintln!("INWORLD_ACCEPTANCE_JSONL {line}");
}

fn git_revision() -> &'static str {
    option_env!("GIT_REVISION").unwrap_or("unknown")
}

fn assert_redacted(serialized: &str) {
    assert!(!serialized.contains(AUTH_SECRET));
    assert!(!serialized.contains(USER_TEXT_SECRET));
    assert!(!serialized.contains(PROVIDER_TEXT_SECRET));
    assert!(!serialized.contains(PROVIDER_ID_SECRET));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_router_chat_and_health_cross_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::json(200, ROUTER_OK_BODY)]);
    let (connector, signing_key) = setup_connector(&fixture, &[CAP_ROUTER, CAP_HEALTH]).await;

    let health = invoke(&connector, &signing_key, OP_HEALTH, CAP_HEALTH, json!({}))
        .await
        .expect("health invoke should succeed");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["auth_mode"], "basic_api_key");
    assert_eq!(
        health["docs_decision"],
        "realtime_primary_tts_router_same_connector"
    );

    let result = invoke(
        &connector,
        &signing_key,
        OP_ROUTER_CHAT,
        CAP_ROUTER,
        json!({
            "model": "auto",
            "messages": [{ "role": "user", "content": USER_TEXT_SECRET }],
            "stream": false,
            "temperature": 0.1,
            "extra_body": { "trace_id": "local-non-mock" }
        }),
    )
    .await
    .expect("router invoke should succeed");

    assert_eq!(result["mode"], "router_chat_completion");
    assert_eq!(result["operation_result"], "ok");
    assert_eq!(result["model_id"], "auto");
    assert_eq!(result["choice_count"], 1);
    assert_eq!(result["metadata_attempt_count"], 1);
    assert_eq!(result["cleanup_result"], "http_response_consumed");
    assert_redacted(&result.to_string());

    let observations = fixture.join();
    assert_eq!(observations.len(), 1);
    let observation = observations.first().expect("one router request");
    assert_eq!(
        observation.request_line,
        "POST /v1/chat/completions HTTP/1.1"
    );
    assert!(has_header(
        &observation.headers,
        "authorization",
        &format!("Basic {AUTH_SECRET}")
    ));
    assert!(has_header(
        &observation.headers,
        "content-type",
        "application/json"
    ));
    let body: Value = serde_json::from_str(&observation.body).expect("request body JSON");
    assert_eq!(body["model"], "auto");
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], USER_TEXT_SECRET);
    let temperature = body["temperature"]
        .as_f64()
        .expect("temperature is numeric");
    assert!(
        (temperature - 0.1).abs() < 0.000_001,
        "temperature should preserve configured value"
    );
    assert_eq!(body["extra_body"]["trace_id"], "local-non-mock");

    emit_acceptance(
        "router_chat_and_health",
        &connector,
        &json!({
            "operation_id": OP_ROUTER_CHAT,
            "capability": CAP_ROUTER,
            "request_response_boundary": "POST /v1/chat/completions",
            "auth_gate": "basic_header_forwarded",
            "health_local_no_egress": true,
            "operation_result": result["operation_result"],
            "id_hash": result["id_hash"],
            "prompt_bytes": result["prompt_bytes"],
            "output_text_bytes": result["output_text_bytes"],
            "choice_count": result["choice_count"],
            "metadata_attempt_count": result["metadata_attempt_count"],
            "result": "ok",
            "error_code": Value::Null,
            "retry_backoff_decision": "none"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_router_errors_are_redacted_and_classified() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(401, PROVIDER_ERROR_BODY),
        ResponseSpec::json(429, PROVIDER_ERROR_BODY),
    ]);
    let (connector, signing_key) = setup_connector(&fixture, &[CAP_ROUTER]).await;

    for (model, expected_status, expected_retryable) in [
        ("unauthorized", Some(401_u16), false),
        ("rate-limited", Some(429_u16), true),
    ] {
        let error = invoke(
            &connector,
            &signing_key,
            OP_ROUTER_CHAT,
            CAP_ROUTER,
            json!({
                "model": model,
                "messages": [{ "role": "user", "content": USER_TEXT_SECRET }],
                "stream": false
            }),
        )
        .await
        .expect_err("provider error should fail the invocation");
        let debug = format!("{error:?}");
        assert_redacted(&debug);
        match error {
            FcpError::External {
                service,
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(service, "inworld");
                assert_eq!(status_code, expected_status);
                assert_eq!(retryable, expected_retryable);
                assert_redacted(&message);
            }
            other => panic!("unexpected error mapping: {other:?}"),
        }
    }

    let observations = fixture.join();
    assert_eq!(observations.len(), 2);
    for observation in &observations {
        assert_eq!(
            observation.request_line,
            "POST /v1/chat/completions HTTP/1.1"
        );
        assert!(has_header(
            &observation.headers,
            "authorization",
            &format!("Basic {AUTH_SECRET}")
        ));
    }

    emit_acceptance(
        "router_error_mapping",
        &connector,
        &json!({
            "operation_id": OP_ROUTER_CHAT,
            "capability": CAP_ROUTER,
            "request_response_boundary": "POST /v1/chat/completions",
            "auth_gate": "basic_header_forwarded",
            "http_statuses": [401, 429],
            "result": "ok",
            "error_code": "external_error_redacted",
            "retry_backoff_decision": "429_retryable_401_non_retryable"
        }),
    );
}
