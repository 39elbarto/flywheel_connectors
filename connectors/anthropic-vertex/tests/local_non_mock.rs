//! Local loopback acceptance coverage for the FCP Anthropic Vertex connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_anthropic_vertex::connector::{
    AnthropicVertexConnector, OP_MESSAGES_CREATE, OP_MESSAGES_STREAM, OP_MODELS_NORMALIZE,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde::Serialize;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.54";
const CONNECTOR_ID: &str = "fcp.anthropic-vertex";
const PROJECT_ID: &str = "fcp-local-project";
const LOCATION: &str = "us-east5";
const ACCESS_TOKEN: &str = "vertex-local-access-token";
const QUOTA_PROJECT: &str = "billing-local-project";
const CAP_MESSAGES: &str = "anthropic_vertex.messages";
const CAP_MODELS_READ: &str = "anthropic_vertex.models.read";

const CREATE_RESPONSE_BODY: &str = r#"{
  "id": "msg_vertex_local",
  "type": "message",
  "role": "assistant",
  "content": [{"type": "text", "text": "local response text"}],
  "model": "claude-sonnet-4-6",
  "stop_reason": "end_turn",
  "usage": {"input_tokens": 4, "output_tokens": 5}
}"#;

const STREAM_RESPONSE_BODY: &str = "event: message_start\n\
data: {\"type\":\"message_start\"}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"local stream text\"}}\n\n\
data: [DONE]\n\n";

const RATE_LIMIT_BODY: &str = r#"{
  "error": {
    "code": 429,
    "status": "RESOURCE_EXHAUSTED",
    "message": "provider local body secret"
  }
}"#;

#[derive(Debug, Clone, Copy)]
struct ResponseSpec {
    status: u16,
    content_type: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
}

impl ResponseSpec {
    const fn json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            content_type: "application/json",
            headers: &[],
            body,
        }
    }

    const fn event_stream(body: &'static str) -> Self {
        Self {
            status: 200,
            content_type: "text/event-stream",
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
            content_type: "application/json",
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
    response_status: u16,
    response_body_bytes: usize,
    retry_after_ms: Option<u64>,
}

impl RequestObservation {
    fn method(&self) -> &str {
        self.request_line.split_whitespace().next().unwrap_or("")
    }

    fn target(&self) -> &str {
        self.request_line.split_whitespace().nth(1).unwrap_or("")
    }

    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

struct LoopbackServer {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackServer {
    fn start(responses: Vec<ResponseSpec>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Anthropic Vertex listener");
        let address = listener.local_addr().expect("read loopback address");
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
            .expect("loopback handle present")
            .join()
            .expect("loopback thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: ResponseSpec) -> RequestObservation {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set request read timeout");
    let raw = read_http_message(&mut stream);
    let header_end = find_header_end(&raw).expect("request has headers");
    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();
    let body = String::from_utf8_lossy(&raw[header_end + 4..]).to_string();

    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        status_reason(response.status),
        response.content_type,
        response.body.len()
    )
    .expect("write response headers");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write extra response header");
    }
    write!(stream, "\r\n{}", response.body).expect("write response body");

    RequestObservation {
        request_line,
        headers,
        body,
        response_status: response.status,
        response_body_bytes: response.body.len(),
        retry_after_ms: response.headers.iter().find_map(|(name, value)| {
            name.eq_ignore_ascii_case("retry-after")
                .then(|| value.parse::<u64>().expect("retry-after seconds") * 1_000)
        }),
    }
}

fn read_http_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream
            .read(&mut buffer)
            .expect("read Anthropic Vertex request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let total_len = header_end + 4 + content_length(&headers);
            while request.len() < total_len {
                let bytes_read = stream
                    .read(&mut buffer)
                    .expect("read Anthropic Vertex request body");
                assert!(bytes_read > 0, "connector body should not close early");
                request.extend_from_slice(&buffer[..bytes_read]);
            }
            return request;
        }
    }
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("content-length"))
        })
        .unwrap_or(0)
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        429 => "Too Many Requests",
        _ => "Stubbed",
    }
}

async fn setup_connector(
    connector: &mut AnthropicVertexConnector,
    signing_key: &Ed25519SigningKey,
    base_url: &str,
    max_retries: u32,
) {
    connector
        .configure(json!({
            "project_id": PROJECT_ID,
            "location": LOCATION,
            "access_token": ACCESS_TOKEN,
            "quota_project_id": QUOTA_PROJECT,
            "base_url": base_url,
            "retry": {
                "max_retries": max_retries,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure Anthropic Vertex connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [23_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_MESSAGES),
                CapabilityId::from_static(CAP_MODELS_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake Anthropic Vertex connector");
}

fn capability_for(
    connector: &AnthropicVertexConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
) -> CapabilityToken {
    let capability = match operation {
        OP_MESSAGES_CREATE | OP_MESSAGES_STREAM => CAP_MESSAGES,
        OP_MODELS_NORMALIZE => CAP_MODELS_READ,
        _ => panic!("unsupported operation {operation}"),
    };
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:anthropic-vertex-local")
        .operations(&[operation])
        .issuer("node:local-acceptance")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &AnthropicVertexConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("anthropic-vertex-local-{operation}")),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: capability_for(connector, signing_key, operation),
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

#[derive(Debug, Serialize)]
struct EvidenceLog {
    suite_class: &'static str,
    bead_id: &'static str,
    connector_id: &'static str,
    operation: &'static str,
    capability: &'static str,
    zone: &'static str,
    route: &'static str,
    method: String,
    outcome: &'static str,
    response_status: Option<u16>,
    response_body_bytes: Option<usize>,
    retry_after_ms: Option<u64>,
    redaction: &'static str,
}

fn evidence_log(
    operation: &'static str,
    request: Option<&RequestObservation>,
    outcome: &'static str,
) -> EvidenceLog {
    EvidenceLog {
        suite_class: ACCEPTANCE_SUITE_CLASS,
        bead_id: BEAD_ID,
        connector_id: CONNECTOR_ID,
        operation,
        capability: match operation {
            OP_MESSAGES_CREATE | OP_MESSAGES_STREAM => CAP_MESSAGES,
            OP_MODELS_NORMALIZE => CAP_MODELS_READ,
            _ => "unknown",
        },
        zone: "z:work",
        route: request.map_or("no_egress", route_label),
        method: request.map_or_else(
            || "IN_PROCESS".to_string(),
            |request| request.method().to_string(),
        ),
        outcome,
        response_status: request.map(|request| request.response_status),
        response_body_bytes: request.map(|request| request.response_body_bytes),
        retry_after_ms: request.and_then(|request| request.retry_after_ms),
        redaction: "google_bearer_prompt_completion_and_provider_body_not_logged",
    }
}

fn route_label(request: &RequestObservation) -> &'static str {
    if request.target().contains(":streamRawPredict") {
        "messages.stream_raw_predict"
    } else if request.target().contains(":rawPredict") {
        "messages.raw_predict"
    } else {
        "unrecognized"
    }
}

fn assert_auth_headers(request: &RequestObservation) {
    let expected = format!("Bearer {ACCESS_TOKEN}");
    assert_eq!(
        request.header_value("authorization"),
        Some(expected.as_str())
    );
    assert_eq!(
        request.header_value("x-goog-user-project"),
        Some(QUOTA_PROJECT)
    );
}

fn assert_redacted(logs: &[EvidenceLog]) {
    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [
        ACCESS_TOKEN,
        QUOTA_PROJECT,
        "local prompt text",
        "local response text",
        "local stream text",
        "provider local body secret",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "evidence logs should not contain sensitive sentinel `{forbidden}`"
        );
    }
    for entry in logs {
        eprintln!(
            "{}",
            serde_json::to_string(entry).expect("emit JSONL evidence")
        );
    }
}

#[fcp_async_core::test]
async fn connector_messages_create_and_stream_use_raw_loopback_boundary() {
    let server = LoopbackServer::start(vec![
        ResponseSpec::json(200, CREATE_RESPONSE_BODY),
        ResponseSpec::event_stream(STREAM_RESPONSE_BODY),
    ]);
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = AnthropicVertexConnector::new();
    setup_connector(&mut connector, &signing_key, server.base_url(), 0).await;

    let created = invoke(
        &connector,
        &signing_key,
        OP_MESSAGES_CREATE,
        json!({
            "model": "sonnet-4.6",
            "messages": [{"role": "user", "content": "local prompt text"}],
            "max_tokens": 8
        }),
    )
    .await
    .expect("messages.create should succeed");
    assert_eq!(created["id"], "msg_vertex_local");

    let stream = invoke(
        &connector,
        &signing_key,
        OP_MESSAGES_STREAM,
        json!({
            "model": "claude-sonnet-4-5-20250929",
            "messages": [{"role": "user", "content": "local prompt text"}],
            "max_tokens": 8
        }),
    )
    .await
    .expect("messages.stream should succeed");
    assert_eq!(stream["event_count"], 2);
    assert_eq!(
        stream["events"][1]["payload_json"]["delta"]["text"],
        "local stream text"
    );

    let normalized = invoke(
        &connector,
        &signing_key,
        OP_MODELS_NORMALIZE,
        json!({ "model": "claude-opus-4-5-20251101" }),
    )
    .await
    .expect("models.normalize should succeed");
    assert_eq!(normalized["vertex_model"], "claude-opus-4-5@20251101");

    let requests = server.join();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method(), "POST");
    assert!(requests[0].target().contains(":rawPredict"));
    assert_auth_headers(&requests[0]);
    let create_body: Value = serde_json::from_str(&requests[0].body).expect("create request JSON");
    assert_eq!(create_body["anthropic_version"], "vertex-2023-10-16");
    assert_eq!(create_body["stream"], false);
    assert!(create_body.get("model").is_none());
    assert!(create_body.get("model_id").is_none());

    assert_eq!(requests[1].method(), "POST");
    assert!(requests[1].target().contains(":streamRawPredict"));
    assert_eq!(
        requests[1].header_value("accept"),
        Some("text/event-stream")
    );
    assert_auth_headers(&requests[1]);
    let stream_body: Value = serde_json::from_str(&requests[1].body).expect("stream request JSON");
    assert_eq!(stream_body["stream"], true);

    let logs = vec![
        evidence_log(OP_MESSAGES_CREATE, Some(&requests[0]), "pass"),
        evidence_log(OP_MESSAGES_STREAM, Some(&requests[1]), "pass"),
        evidence_log(OP_MODELS_NORMALIZE, None, "pass"),
    ];
    assert_redacted(&logs);
}

#[fcp_async_core::test]
async fn connector_rate_limit_preserves_retry_after_without_secret_logging() {
    let server = LoopbackServer::start(vec![ResponseSpec::with_headers(
        429,
        &[("retry-after", "2")],
        RATE_LIMIT_BODY,
    )]);
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = AnthropicVertexConnector::new();
    setup_connector(&mut connector, &signing_key, server.base_url(), 0).await;

    let err = invoke(
        &connector,
        &signing_key,
        OP_MESSAGES_CREATE,
        json!({
            "model": "sonnet-4.6",
            "messages": [{"role": "user", "content": "local prompt text"}],
            "max_tokens": 8
        }),
    )
    .await
    .expect_err("rate-limited response should map to FCP rate limit");
    assert!(matches!(
        err,
        FcpError::RateLimited {
            retry_after_ms: 2_000,
            ..
        }
    ));

    let requests = server.join();
    assert_eq!(requests.len(), 1);
    assert_auth_headers(&requests[0]);
    assert_eq!(requests[0].response_status, 429);
    assert_eq!(requests[0].retry_after_ms, Some(2_000));

    let logs = vec![evidence_log(
        OP_MESSAGES_CREATE,
        Some(&requests[0]),
        "rate_limited",
    )];
    assert_redacted(&logs);
}

#[test]
fn evidence_schema_carries_connector_and_tracker_identity() {
    let log = evidence_log(OP_MODELS_NORMALIZE, None, "pass");
    let value = serde_json::to_value(log).expect("evidence JSON");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(
        ConnectorId::from_static(CONNECTOR_ID).as_str(),
        CONNECTOR_ID
    );
    assert_eq!(
        OperationId::from_static(OP_MODELS_NORMALIZE).as_str(),
        OP_MODELS_NORMALIZE
    );
    assert_eq!(
        RequestId::new("anthropic-vertex-local").to_string(),
        "anthropic-vertex-local"
    );
    assert_eq!(ZoneId::work().as_str(), "z:work");
}
