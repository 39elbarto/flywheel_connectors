//! Local loopback acceptance coverage for the FCP `Zoom` connector.

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
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_zoom::ZoomConnector;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.53";
const CONNECTOR_ID: &str = "fcp.zoom";
const ACCOUNT_ID: &str = "zoom_account_local";
const CLIENT_ID: &str = "zoom_local_client";
const CLIENT_SECRET: &str = "zoom_local_secret";
const ACCESS_SECRET: &str = "zoom_local_access_secret";
const PROVIDER_TEXT_SECRET: &str = "provider zoom secret";
const BASIC_AUTH_VALUE: &str = "Basic em9vbV9sb2NhbF9jbGllbnQ6em9vbV9sb2NhbF9zZWNyZXQ=";
const CAP_MEETINGS_READ: &str = "zoom.meetings.read";
const CAP_MEETINGS_WRITE: &str = "zoom.meetings.write";
const OP_MEETINGS_LIST: &str = "zoom.meetings.list";
const OP_MEETINGS_CREATE: &str = "zoom.meetings.create";
const LIST_BODY: &str = r#"{
  "meetings": [
    {
      "id": 123456789,
      "topic": "Local acceptance sync",
      "type": 2,
      "duration": 30,
      "status": "waiting"
    }
  ],
  "page_count": 1,
  "page_number": 1,
  "page_size": 2,
  "total_records": 1,
  "next_page_token": "next-local"
}"#;
const CREATE_BODY: &str = r#"{
  "id": 987654321,
  "uuid": "zoom-local-meeting",
  "topic": "Created local acceptance",
  "type": 2,
  "duration": 45,
  "timezone": "UTC",
  "status": "waiting",
  "join_url": "https://zoom.example.invalid/j/987654321"
}"#;
const RATE_LIMIT_BODY: &str = r#"{
  "code": 429,
  "message": "provider zoom secret"
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
        201 => "Created",
        429 => "Too Many Requests",
        _ => "Status",
    }
}

fn header_value<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|line| {
        let (actual_name, actual_value) = line.split_once(':')?;
        actual_name
            .eq_ignore_ascii_case(name)
            .then(|| actual_value.trim())
    })
}

fn has_header(headers: &[String], name: &str, expected_value: &str) -> bool {
    header_value(headers, name).is_some_and(|actual| actual == expected_value)
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    connector: &ZoomConnector,
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
        .target_instance(connector.instance_id())
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
        nonce: [53_u8; 32],
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
) -> (ZoomConnector, Ed25519SigningKey) {
    let mut connector = ZoomConnector::new();
    connector
        .configure(json!({
            "base_url": format!("{}/v2", fixture.base_url()),
            "oauth_base_url": fixture.base_url(),
            "account_id": ACCOUNT_ID,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "request_timeout_ms": 5000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
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
    connector: &ZoomConnector,
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

fn token_response() -> ResponseSpec {
    ResponseSpec::json(
        200,
        r#"{"access_token":"zoom_local_access_secret","token_type":"bearer","expires_in":3600}"#,
    )
}

fn assert_oauth_request(request: &RequestObservation) {
    assert_eq!(request.request_line, "POST /oauth/token HTTP/1.1");
    assert!(has_header(
        &request.headers,
        "content-type",
        "application/x-www-form-urlencoded"
    ));
    assert!(has_header(
        &request.headers,
        "authorization",
        BASIC_AUTH_VALUE
    ));
    assert!(request.body.contains("grant_type=account_credentials"));
    assert!(request.body.contains(&format!("account_id={ACCOUNT_ID}")));
}

fn emit_acceptance(event: &str, connector: &ZoomConnector, payload: &Value) {
    let mut object = serde_json::Map::new();
    object.insert("event".into(), json!(event));
    object.insert(
        "command_line".into(),
        json!("cargo test -p fcp-zoom --test local_non_mock -- --nocapture"),
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
        json!(fcp_zoom_hash(connector.instance_id())),
    );
    object.insert("cleanup_result".into(), json!("fixture_server_closed"));
    object.insert("skip_reason".into(), Value::Null);
    if let Some(payload) = payload.as_object() {
        object.extend(payload.clone());
    }

    let line = Value::Object(object).to_string();
    assert_redacted(&line);
    eprintln!("ZOOM_ACCEPTANCE_JSONL {line}");
}

fn git_revision() -> &'static str {
    option_env!("GIT_REVISION").unwrap_or("unknown")
}

fn fcp_zoom_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize()).chars().take(16).collect()
}

fn assert_redacted(serialized: &str) {
    assert!(!serialized.contains(ACCESS_SECRET));
    assert!(!serialized.contains(CLIENT_SECRET));
    assert!(!serialized.contains(PROVIDER_TEXT_SECRET));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_and_create_cross_zoom_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        token_response(),
        ResponseSpec::json(200, LIST_BODY),
        token_response(),
        ResponseSpec::json(201, CREATE_BODY),
    ]);
    let (connector, signing_key) =
        setup_connector(&fixture, &[CAP_MEETINGS_READ, CAP_MEETINGS_WRITE]).await;
    let health = connector.health().await;
    assert!(matches!(health.status, fcp_core::HealthState::Ready));

    let list_result = invoke(
        &connector,
        &signing_key,
        OP_MEETINGS_LIST,
        CAP_MEETINGS_READ,
        json!({
            "user_id": "me",
            "page_size": 2,
            "next_page_token": "cursor-local"
        }),
    )
    .await
    .expect("list meetings should succeed");
    assert_eq!(list_result["meetings"].as_array().map_or(0, Vec::len), 1);
    assert_eq!(list_result["next_page_token"], "next-local");

    let create_result = invoke(
        &connector,
        &signing_key,
        OP_MEETINGS_CREATE,
        CAP_MEETINGS_WRITE,
        json!({
            "user_id": "me",
            "topic": "Created local acceptance",
            "type": 2,
            "duration": 45,
            "timezone": "UTC"
        }),
    )
    .await
    .expect("create meeting should succeed");
    assert_eq!(create_result["id"], 987654321_u64);
    assert_redacted(&create_result.to_string());

    let observations = fixture.join();
    assert_eq!(observations.len(), 4);
    assert_oauth_request(&observations[0]);

    let list_request = &observations[1];
    assert!(
        list_request
            .request_line
            .starts_with("GET /v2/users/me/meetings?")
    );
    assert!(list_request.request_line.contains("page_size=2"));
    assert!(
        list_request
            .request_line
            .contains("next_page_token=cursor-local")
    );
    assert!(has_header(
        &list_request.headers,
        "authorization",
        &format!("Bearer {ACCESS_SECRET}")
    ));

    assert_oauth_request(&observations[2]);

    let create_request = &observations[3];
    assert_eq!(
        create_request.request_line,
        "POST /v2/users/me/meetings HTTP/1.1"
    );
    assert!(has_header(
        &create_request.headers,
        "authorization",
        &format!("Bearer {ACCESS_SECRET}")
    ));
    let body: Value = serde_json::from_str(&create_request.body).expect("create body JSON");
    assert_eq!(body["topic"], "Created local acceptance");
    assert_eq!(body["type"], 2);
    assert_eq!(body["duration"], 45);
    assert_eq!(body["timezone"], "UTC");

    emit_acceptance(
        "list_and_create",
        &connector,
        &json!({
            "operations": [OP_MEETINGS_LIST, OP_MEETINGS_CREATE],
            "capabilities": [CAP_MEETINGS_READ, CAP_MEETINGS_WRITE],
            "request_response_boundary": "POST /oauth/token + GET/POST /v2/users/{id}/meetings",
            "auth_gate": "basic_oauth_then_bearer_header_forwarded",
            "health_local_no_egress": true,
            "list_count": list_result["meetings"].as_array().map_or(0, Vec::len),
            "created_meeting_id_hash": fcp_zoom_hash(create_result["id"].to_string().as_str()),
            "result": "ok",
            "error_code": Value::Null,
            "retry_backoff_decision": "none"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_without_provider_body() {
    let fixture = LoopbackFixture::start(vec![
        token_response(),
        ResponseSpec::with_headers(429, &[("Retry-After", "4")], RATE_LIMIT_BODY),
    ]);
    let (connector, signing_key) = setup_connector(&fixture, &[CAP_MEETINGS_READ]).await;

    let error = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req-rate-limit"),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::from_static(OP_MEETINGS_LIST),
            zone_id: ZoneId::work(),
            input: json!({ "user_id": "me", "page_size": 1 }),
            capability_token: valid_token(
                &signing_key,
                &connector,
                CAP_MEETINGS_READ,
                OP_MEETINGS_LIST,
            ),
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
        FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 4000),
        other => panic!("unexpected rate-limit mapping: {other:?}"),
    }

    let observations = fixture.join();
    assert_eq!(observations.len(), 2);
    assert_oauth_request(&observations[0]);
    assert!(
        observations[1]
            .request_line
            .starts_with("GET /v2/users/me/meetings?")
    );
    assert!(observations[1].request_line.contains("page_size=1"));
    assert!(has_header(
        &observations[1].headers,
        "authorization",
        &format!("Bearer {ACCESS_SECRET}")
    ));

    emit_acceptance(
        "rate_limit_mapping",
        &connector,
        &json!({
            "operation": OP_MEETINGS_LIST,
            "capability": CAP_MEETINGS_READ,
            "request_response_boundary": "POST /oauth/token + GET /v2/users/{id}/meetings",
            "auth_gate": "basic_oauth_then_bearer_header_forwarded",
            "http_status": 429,
            "retry_after_ms": 4000,
            "result": "ok",
            "error_code": "rate_limited",
            "retry_backoff_decision": "retry_after_header_seconds"
        }),
    );
}
