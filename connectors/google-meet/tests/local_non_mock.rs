//! Local loopback acceptance coverage for the FCP Google Meet connector.

#![allow(
    clippy::expect_used,
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
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_meet::connector::GoogleMeetConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityToken, ConnectorId, FcpError, OperationId, RequestId, ZoneId,
};
use serde::Serialize;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.51";
const CONNECTOR_ID: &str = "fcp.google-meet";
const CONNECTOR_RUNTIME_ID: &str = "google-meet";
const ACCESS_TOKEN: &str = "local-google-meet-access-token";
const READ_CAP: &str = "meet.space.read";
const CREATE_CAP: &str = "meet.space.create";
const END_CAP: &str = "meet.space.end";
const READONLY_SCOPE: &str = "https://www.googleapis.com/auth/meetings.space.readonly";
const CREATED_SCOPE: &str = "https://www.googleapis.com/auth/meetings.space.created";
const SPACE_GET_OP: &str = "gmeet.space.get";
const SPACE_CREATE_OP: &str = "gmeet.space.create";
const SPACE_END_OP: &str = "gmeet.space.end_active_conference";

const SPACE_GET_BODY: &str = r#"{
  "name": "spaces/abc-defg-hij",
  "meetingUri": "https://meet.google.com/abc-defg-hij",
  "meetingCode": "abc-defg-hij"
}"#;

const SPACE_CREATE_BODY: &str = r#"{
  "name": "spaces/created-fixture",
  "meetingUri": "https://meet.google.com/created-fixture",
  "meetingCode": "created-fixture"
}"#;

const SPACE_WITH_ACTIVE_CONFERENCE_BODY: &str = r#"{
  "name": "spaces/abc-defg-hij",
  "meetingUri": "https://meet.google.com/abc-defg-hij",
  "meetingCode": "abc-defg-hij",
  "activeConference": {
    "conferenceRecord": "conferenceRecords/rec-active"
  }
}"#;

const RATE_LIMIT_BODY: &str = r#"{
  "error": {
    "message": "quota exceeded"
  }
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
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
            base_url: format!("http://{address}/v2"),
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

    let reason = status_reason(response.status);
    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        reason,
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

fn auth_config(base_url: &str) -> Value {
    json!({
        "access_token": ACCESS_TOKEN,
        "required_scopes": [READONLY_SCOPE, CREATED_SCOPE],
        "base_url": base_url,
        "drive_base_url": base_url,
    })
}

async fn configure_and_handshake(
    connector: &mut GoogleMeetConnector,
    signing_key: &Ed25519SigningKey,
    base_url: &str,
    capabilities: &[&str],
) {
    connector
        .handle_configure(auth_config(base_url))
        .await
        .expect("configure Google Meet connector");
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": capabilities,
        }))
        .await
        .expect("handshake Google Meet connector");
}

fn capability_token(
    connector: &GoogleMeetConnector,
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
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
        .principal("user:google-meet-local")
        .operations(&[operation])
        .issuer("node:local-acceptance")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &GoogleMeetConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    capability: &str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_token(connector, signing_key, capability, operation),
        }))
        .await
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
    response_status: u16,
    response_body_bytes: usize,
    retry_after_ms: Option<u64>,
    redaction: &'static str,
}

fn evidence_log(
    operation: &'static str,
    capability: &'static str,
    request: &RequestObservation,
    outcome: &'static str,
) -> EvidenceLog {
    EvidenceLog {
        suite_class: ACCEPTANCE_SUITE_CLASS,
        bead_id: BEAD_ID,
        connector_id: CONNECTOR_ID,
        operation,
        capability,
        zone: "z:work",
        route: route_label(request),
        method: request.method().to_string(),
        outcome,
        response_status: request.response_status,
        response_body_bytes: request.response_body_bytes,
        retry_after_ms: request.retry_after_ms,
        redaction: "oauth_token_and_meeting_code_not_logged",
    }
}

fn route_label(request: &RequestObservation) -> &'static str {
    let target = request.target();
    if target == "/v2/spaces" {
        "spaces.create"
    } else if target.contains(":endActiveConference") {
        "spaces.end_active_conference"
    } else if target.starts_with("/v2/spaces/") {
        "spaces.get"
    } else {
        "unrecognized"
    }
}

fn assert_authorization(requests: &[RequestObservation]) {
    let expected = format!("Bearer {ACCESS_TOKEN}");
    for request in requests {
        assert_eq!(
            request.header_value("authorization"),
            Some(expected.as_str()),
            "request should carry bearer auth: {}",
            request.request_line
        );
    }
}

fn assert_redacted(logs: &[EvidenceLog]) {
    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [ACCESS_TOKEN, "abc-defg-hij", "created-fixture"] {
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

#[fcp_async_core::runtime::test]
async fn connector_space_lifecycle_uses_raw_loopback_boundary() {
    let server = LoopbackServer::start(vec![
        ResponseSpec::json(200, SPACE_GET_BODY),
        ResponseSpec::json(200, SPACE_CREATE_BODY),
        ResponseSpec::json(200, SPACE_WITH_ACTIVE_CONFERENCE_BODY),
        ResponseSpec::json(200, "{}"),
    ]);
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = GoogleMeetConnector::new();
    configure_and_handshake(
        &mut connector,
        &signing_key,
        server.base_url(),
        &[READ_CAP, CREATE_CAP, END_CAP],
    )
    .await;

    let fetched = invoke(
        &connector,
        &signing_key,
        SPACE_GET_OP,
        READ_CAP,
        json!({ "space": "https://meet.google.com/abc-defg-hij" }),
    )
    .await
    .expect("space get should succeed");
    assert_eq!(fetched["space"]["name"], "spaces/abc-defg-hij");

    let created = invoke(
        &connector,
        &signing_key,
        SPACE_CREATE_OP,
        CREATE_CAP,
        json!({}),
    )
    .await
    .expect("space create should succeed");
    assert_eq!(created["space"]["name"], "spaces/created-fixture");
    assert_eq!(created["required_scopes"][0], CREATED_SCOPE);

    let ended = invoke(
        &connector,
        &signing_key,
        SPACE_END_OP,
        END_CAP,
        json!({ "space": "spaces/abc-defg-hij" }),
    )
    .await
    .expect("active conference end should succeed");
    assert_eq!(ended["ended"], true);
    assert_eq!(
        ended["resolved_space"]["activeConference"]["conferenceRecord"],
        "conferenceRecords/rec-active"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 4);
    assert_authorization(&requests);
    assert_eq!(requests[0].method(), "GET");
    assert!(
        requests[0]
            .target()
            .starts_with("/v2/spaces/abc%2Ddefg%2Dhij"),
        "unexpected get target: {}",
        requests[0].target()
    );
    assert_eq!(requests[1].method(), "POST");
    assert_eq!(requests[1].target(), "/v2/spaces");
    assert_eq!(requests[1].body, "{}");
    assert_eq!(requests[2].method(), "GET");
    assert!(
        requests[2]
            .target()
            .starts_with("/v2/spaces/abc%2Ddefg%2Dhij"),
        "unexpected end preflight target: {}",
        requests[2].target()
    );
    assert_eq!(requests[3].method(), "POST");
    assert!(
        requests[3].target().contains(":endActiveConference"),
        "unexpected end target: {}",
        requests[3].target()
    );

    let logs = vec![
        evidence_log(SPACE_GET_OP, READ_CAP, &requests[0], "pass"),
        evidence_log(SPACE_CREATE_OP, CREATE_CAP, &requests[1], "pass"),
        evidence_log(SPACE_END_OP, END_CAP, &requests[3], "pass"),
    ];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn connector_rate_limit_preserves_retry_after_without_secret_logging() {
    let server = LoopbackServer::start(vec![ResponseSpec::with_headers(
        429,
        &[("retry-after", "2")],
        RATE_LIMIT_BODY,
    )]);
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = GoogleMeetConnector::new();
    configure_and_handshake(&mut connector, &signing_key, server.base_url(), &[READ_CAP]).await;

    let err = invoke(
        &connector,
        &signing_key,
        SPACE_GET_OP,
        READ_CAP,
        json!({ "space": "spaces/rate-limited" }),
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
    assert_authorization(&requests);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].response_status, 429);
    assert_eq!(requests[0].retry_after_ms, Some(2_000));

    let logs = vec![evidence_log(
        SPACE_GET_OP,
        READ_CAP,
        &requests[0],
        "rate_limited",
    )];
    assert_redacted(&logs);
}

#[test]
fn evidence_schema_carries_connector_and_tracker_identity() {
    let request = RequestObservation {
        request_line: "GET /v2/spaces/redacted HTTP/1.1".to_string(),
        headers: Vec::new(),
        body: String::new(),
        response_status: 200,
        response_body_bytes: 2,
        retry_after_ms: None,
    };
    let log = evidence_log(SPACE_GET_OP, READ_CAP, &request, "pass");
    let value = serde_json::to_value(log).expect("evidence JSON");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(
        ConnectorId::from_static(CONNECTOR_RUNTIME_ID).as_str(),
        CONNECTOR_RUNTIME_ID
    );
    assert_eq!(
        OperationId::new(SPACE_GET_OP)
            .expect("valid operation")
            .as_str(),
        SPACE_GET_OP
    );
    assert_eq!(
        RequestId::new("google-meet-local-non-mock").to_string(),
        "google-meet-local-non-mock"
    );
    assert_eq!(ZoneId::work().as_str(), "z:work");
}
