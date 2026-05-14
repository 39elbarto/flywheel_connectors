//! Local loopback acceptance coverage for the FCP `Plivo` connector.

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

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_plivo::connector::PlivoConnector;
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError};
use serde_json::json;

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.44";
const AUTH_ID: &str = "MA123456789LOCAL";
const AUTH_SECRET: &str = "local_plivo_acceptance_secret";
const OP_CALL_STATUS: &str = "plivo.call.status";
const OP_CALL_INITIATE: &str = "plivo.call.initiate";
const CALL_UUID: &str = "call-local-0001";
const STATUS_RESPONSE_BODY: &str = r#"{
  "call_uuid": "call-local-0001",
  "from_number": "+15551230000",
  "to_number": "+15559870000",
  "call_direction": "outbound",
  "call_status": "in-progress",
  "api_id": "api-local-status"
}"#;
const INITIATE_RESPONSE_BODY: &str = r#"{
  "call_uuid": "call-local-0002",
  "request_uuid": "request-local-0002",
  "message": "call fired",
  "api_id": "api-local-initiate"
}"#;
const RATE_LIMIT_BODY: &str = r#"{
  "error": "rate limit exceeded"
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
            base_url: format!("http://{address}/v1/Account/{AUTH_ID}"),
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
        write!(stream, "{name}: {value}\r\n").expect("write extra response header");
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
    operation: &str,
) -> CapabilityToken {
    let capability = match operation {
        OP_CALL_STATUS => "plivo.read",
        _ => "plivo.voice",
    };
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

async fn setup_connector(base_url: &str) -> (PlivoConnector, Ed25519SigningKey) {
    let mut connector = PlivoConnector::new();
    connector
        .handle_configure(json!({
            "auth_id": AUTH_ID,
            "auth_token": AUTH_SECRET,
            "base_url": base_url
        }))
        .await
        .expect("configure connector");

    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["plivo.read", "plivo.voice", "plivo.webhook"]
        }))
        .await
        .expect("handshake connector");

    (connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_call_status_and_initiate_cross_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, STATUS_RESPONSE_BODY),
        ResponseSpec::json(201, INITIATE_RESPONSE_BODY),
    ]);
    let (mut connector, signing_key) = setup_connector(fixture.base_url()).await;

    let self_check = connector
        .handle_self_check()
        .await
        .expect("self check uses local endpoint policy");
    assert_eq!(self_check["status"], "healthy");

    let status_result = connector
        .handle_invoke(json!({
            "operation": OP_CALL_STATUS,
            "input": { "call_uuid": CALL_UUID },
            "capability_token": valid_token(&signing_key, connector.instance_id(), OP_CALL_STATUS)
        }))
        .await
        .expect("get call status through loopback");
    assert_eq!(status_result["call_uuid"], CALL_UUID);
    assert_eq!(status_result["call_status"], "in-progress");

    let initiate_result = connector
        .handle_invoke(json!({
            "operation": OP_CALL_INITIATE,
            "input": {
                "to": "+15559870000",
                "from": "+15551230000",
                "answer_url": "https://agent.example/plivo/answer",
                "answer_method": "POST",
                "time_limit": 30
            },
            "capability_token": valid_token(&signing_key, connector.instance_id(), OP_CALL_INITIATE)
        }))
        .await
        .expect("initiate call through loopback");
    assert_eq!(initiate_result["call"]["call_uuid"], "call-local-0002");
    assert_eq!(initiate_result["session"]["answer_url_auth_embedded"], true);
    assert_eq!(
        initiate_result["session"]["call_auth_token_preview"],
        "redacted"
    );

    let health = connector.handle_health().await.expect("health response");
    assert_eq!(health["configured"], true);
    assert_eq!(health["handshaken"], true);
    assert_eq!(health["sessions"], 1);
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");

    let observations = fixture.join();
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].request_line,
        format!("GET /v1/Account/{AUTH_ID}/Call/{CALL_UUID}/ HTTP/1.1")
    );
    assert_eq!(
        observations[1].request_line,
        format!("POST /v1/Account/{AUTH_ID}/Call/ HTTP/1.1")
    );

    let expected_auth = format!(
        "Basic {}",
        STANDARD.encode(format!("{AUTH_ID}:{AUTH_SECRET}"))
    );
    for observation in &observations {
        assert!(has_header(
            &observation.headers,
            "authorization",
            &expected_auth
        ));
        assert!(has_header(
            &observation.headers,
            "accept",
            "application/json"
        ));
        assert!(has_header(
            &observation.headers,
            "user-agent",
            "fcp-plivo/0.1.0"
        ));
    }
    assert!(has_header(
        &observations[1].headers,
        "content-type",
        "application/x-www-form-urlencoded"
    ));
    assert!(observations[1].body.contains("to=%2B15559870000"));
    assert!(observations[1].body.contains("from=%2B15551230000"));
    assert!(observations[1].body.contains(
        "answer_url=https%3A%2F%2Fagent.example%2Fplivo%2Fanswer%3Ffcp_call_auth_token%3D"
    ));
    assert!(observations[1].body.contains("answer_method=POST"));
    assert!(observations[1].body.contains("time_limit=30"));
    assert!(!format!("{initiate_result:?}").contains(AUTH_SECRET));

    let artifact = json!({
        "connector": "plivo",
        "connector_id": "fcp.plivo",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-plivo --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operations": [OP_CALL_STATUS, OP_CALL_INITIATE],
        "request_response_boundary": {
            "methods": ["GET", "POST"],
            "paths": [
                format!("/v1/Account/{AUTH_ID}/Call/{CALL_UUID}/"),
                format!("/v1/Account/{AUTH_ID}/Call/")
            ],
            "form_body_verified": true,
            "callback_auth_embedded_and_redacted": true
        },
        "auth_gate": {
            "mode": "basic_header",
            "authorization_header_verified": true,
            "upstream_credentials_used": false
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_provider_error() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::with_headers(429, &[("retry-after", "0")], RATE_LIMIT_BODY),
        ResponseSpec::with_headers(429, &[("retry-after", "0")], RATE_LIMIT_BODY),
        ResponseSpec::with_headers(429, &[("retry-after", "0")], RATE_LIMIT_BODY),
        ResponseSpec::with_headers(429, &[("retry-after", "0")], RATE_LIMIT_BODY),
    ]);
    let (mut connector, signing_key) = setup_connector(fixture.base_url()).await;

    let error = connector
        .handle_invoke(json!({
            "operation": OP_CALL_STATUS,
            "input": { "call_uuid": CALL_UUID },
            "capability_token": valid_token(&signing_key, connector.instance_id(), OP_CALL_STATUS)
        }))
        .await
        .expect_err("rate limit response should map to FCP rate limit error");
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let observations = fixture.join();

    match error {
        FcpError::RateLimited {
            retry_after_ms,
            violation,
        } => {
            assert_eq!(retry_after_ms, 0);
            assert!(violation.is_none());
        }
        other => panic!("unexpected provider error mapping: {other:?}"),
    }

    assert_eq!(observations.len(), 4);
    let expected_auth = format!(
        "Basic {}",
        STANDARD.encode(format!("{AUTH_ID}:{AUTH_SECRET}"))
    );
    for observation in &observations {
        assert_eq!(
            observation.request_line,
            format!("GET /v1/Account/{AUTH_ID}/Call/{CALL_UUID}/ HTTP/1.1")
        );
        assert!(has_header(
            &observation.headers,
            "authorization",
            &expected_auth
        ));
    }

    let artifact = json!({
        "connector": "plivo",
        "connector_id": "fcp.plivo",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-plivo --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http_rate_limit",
        "provider_class": "local_sufficient",
        "operation": OP_CALL_STATUS,
        "request_response_boundary": {
            "method": "GET",
            "path": format!("/v1/Account/{AUTH_ID}/Call/{CALL_UUID}/"),
            "status": 429,
            "retry_after_ms": 0,
            "attempts": observations.len()
        },
        "auth_gate": {
            "mode": "basic_header",
            "authorization_header_verified": true,
            "upstream_credentials_used": false
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
