//! Local loopback acceptance coverage for the `Zendesk` connector.

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

use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{CapabilityConstraints, ConnectorId, FcpError, OperationId, RequestId, ZoneId};
use fcp_zendesk::connector::ZendeskConnector;
use serde::Serialize;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.4.6.4.5";
const CONNECTOR_ID: &str = "fcp.zendesk";
const SUBDOMAIN: &str = "local-zendesk";
const EMAIL: &str = "agent@example.com";
const API_TOKEN: &str = "local-zendesk-api-token";
const TICKET_ID: i64 = 123;
const OP_GET_TICKET: &str = "zendesk.get_ticket";
const OP_CREATE_TICKET: &str = "zendesk.create_ticket";
const SENSITIVE_SUBJECT: &str = "Local acceptance ticket";
const SENSITIVE_DESCRIPTION: &str = "Customer cannot access workspace";

const GET_TICKET_RESPONSE_BODY: &str = r#"{
  "ticket": {
    "id": 123,
    "subject": "Provider subject",
    "status": "open",
    "priority": "normal"
  }
}"#;

const CREATE_TICKET_RESPONSE_BODY: &str = r#"{
  "ticket": {
    "id": 123,
    "subject": "Local acceptance ticket",
    "status": "new",
    "priority": "high"
  }
}"#;

const UNAUTHORIZED_BODY: &str = r#"{"error":"provider body"}"#;
const JSON_HEADERS: &[(&str, &str)] = &[("content-type", "application/json")];

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
            headers: JSON_HEADERS,
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

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackFixture {
    fn start(responses: Vec<ResponseSpec>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Zendesk listener");
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
            base_url: format!("http://{address}/api/v2"),
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
    let raw = read_http_request(&mut stream);
    let (head, body) = split_request(&raw);
    let request = String::from_utf8_lossy(head);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();

    write_response(&mut stream, response);

    RequestObservation {
        request_line,
        headers,
        body: String::from_utf8_lossy(body).to_string(),
        response_status: response.status,
        response_body_bytes: response.body.len(),
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 2048];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(header_end) = find_header_end(&request) {
            let expected_body_len = content_length(&request[..header_end]);
            let body_bytes = request.len().saturating_sub(header_end + 4);
            if body_bytes >= expected_body_len {
                return request;
            }
        }
        assert!(request.len() < 16 * 1024, "request should stay bounded");
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn split_request(request: &[u8]) -> (&[u8], &[u8]) {
    let header_end = find_header_end(request).expect("request contains header terminator");
    (&request[..header_end], &request[header_end + 4..])
}

fn content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn write_response(stream: &mut TcpStream, response: ResponseSpec) {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nconnection: close\r\ncontent-length: {}\r\n",
        response.status,
        status_reason(response.status),
        response.body.len()
    )
    .expect("write response status");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write response header");
    }
    write!(stream, "\r\n{}", response.body).expect("write response body");
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        401 => "Unauthorized",
        _ => "Status",
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_tickets_get_and_create_use_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, GET_TICKET_RESPONSE_BODY),
        ResponseSpec::json(201, CREATE_TICKET_RESPONSE_BODY),
    ]);
    let (connector, signing_key) = configured_connector(fixture.base_url()).await;
    let instance_id = connector.instance_id().to_string();

    let ticket = invoke(
        &connector,
        OP_GET_TICKET,
        json!({ "ticket_id": TICKET_ID }),
        capability_token(&signing_key, &instance_id, OP_GET_TICKET),
    )
    .await
    .expect("get_ticket should succeed");
    let created = invoke(
        &connector,
        OP_CREATE_TICKET,
        json!({
            "subject": SENSITIVE_SUBJECT,
            "description": SENSITIVE_DESCRIPTION,
            "priority": "high"
        }),
        capability_token(&signing_key, &instance_id, OP_CREATE_TICKET),
    )
    .await
    .expect("create_ticket should succeed");
    let observations = fixture.join();

    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].method(), "GET");
    assert_eq!(observations[0].target(), "/api/v2/tickets/123.json");
    assert_eq!(observations[1].method(), "POST");
    assert_eq!(observations[1].target(), "/api/v2/tickets.json");
    assert_auth_headers(&observations);
    assert!(
        observations[1]
            .header_value("content-type")
            .is_some_and(|value| value.starts_with("application/json"))
    );

    let body: Value = serde_json::from_str(&observations[1].body).expect("request body JSON");
    assert_eq!(body["ticket"]["subject"], SENSITIVE_SUBJECT);
    assert_eq!(body["ticket"]["description"], SENSITIVE_DESCRIPTION);
    assert_eq!(body["ticket"]["priority"], "high");
    assert_eq!(ticket["ticket"]["id"], TICKET_ID);
    assert_eq!(created["ticket"]["id"], TICKET_ID);

    let logs = vec![
        evidence_log(OP_GET_TICKET, Some(&observations[0]), "passed"),
        evidence_log(OP_CREATE_TICKET, Some(&observations[1]), "passed"),
    ];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_maps_without_secret_logging() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::json(401, UNAUTHORIZED_BODY)]);
    let (connector, signing_key) = configured_connector(fixture.base_url()).await;
    let instance_id = connector.instance_id().to_string();

    let err = invoke(
        &connector,
        OP_GET_TICKET,
        json!({ "ticket_id": TICKET_ID }),
        capability_token(&signing_key, &instance_id, OP_GET_TICKET),
    )
    .await
    .expect_err("unauthorized get_ticket should map to FCP error");
    let observations = fixture.join();

    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].method(), "GET");
    assert_eq!(observations[0].target(), "/api/v2/tickets/123.json");
    assert_auth_headers(&observations);
    match err {
        FcpError::Unauthorized { code: 2001, .. } => {}
        other => panic!("expected unauthorized FCP error, got {other:?}"),
    }

    let logs = vec![evidence_log(
        OP_GET_TICKET,
        Some(&observations[0]),
        "unauthorized",
    )];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn evidence_schema_carries_connector_and_tracker_identity() {
    let log = evidence_log(OP_GET_TICKET, None, "passed");
    let value = serde_json::to_value(log).expect("evidence JSON");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(
        ConnectorId::from_static(CONNECTOR_ID).as_str(),
        CONNECTOR_ID
    );
    assert_eq!(
        OperationId::from_static(OP_GET_TICKET).as_str(),
        OP_GET_TICKET
    );
    assert_eq!(RequestId::new("zendesk-local").to_string(), "zendesk-local");
    assert_eq!(ZoneId::work().as_str(), "z:work");

    let introspection = ZendeskConnector::new()
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    assert_eq!(
        introspection["operations"].as_array().map_or(0, Vec::len),
        14
    );
}

async fn configured_connector(base_url: &str) -> (ZendeskConnector, Ed25519SigningKey) {
    let mut connector = ZendeskConnector::new();
    connector
        .handle_configure(json!({
            "subdomain": SUBDOMAIN,
            "email": EMAIL,
            "api_token": API_TOKEN,
            "base_url": base_url
        }))
        .await
        .expect("configure Zendesk connector");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["zendesk.read", "zendesk.write"]
        }))
        .await
        .expect("handshake Zendesk connector");
    (connector, signing_key)
}

async fn invoke(
    connector: &ZendeskConnector,
    operation: &'static str,
    input: Value,
    capability_token: fcp_core::CapabilityToken,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_token
        }))
        .await
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    operation: &'static str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign capability token");
    fcp_core::CapabilityToken::from_raw(cose)
}

fn assert_auth_headers(observations: &[RequestObservation]) {
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{EMAIL}/token:{API_TOKEN}").as_bytes())
    );
    for observation in observations {
        assert_eq!(
            observation.header_value("authorization"),
            Some(expected.as_str())
        );
    }
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
        capability: capability_for_operation(operation),
        zone: "z:work",
        route: request.map_or("in_process_no_egress", route_label),
        method: request.map_or_else(
            || "IN_PROCESS".to_string(),
            |request| request.method().to_string(),
        ),
        outcome,
        response_status: request.map(|request| request.response_status),
        response_body_bytes: request.map(|request| request.response_body_bytes),
        redaction: "api_token_email_ticket_ids_subjects_provider_body_not_logged",
    }
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_GET_TICKET => "zendesk.read",
        OP_CREATE_TICKET => "zendesk.write",
        _ => panic!("unsupported operation {operation}"),
    }
}

fn route_label(request: &RequestObservation) -> &'static str {
    match (request.method(), request.target()) {
        ("GET", target) if target.starts_with("/api/v2/tickets/") => "tickets_get",
        ("POST", "/api/v2/tickets.json") => "tickets_create",
        _ => "unrecognized",
    }
}

fn assert_redacted(logs: &[EvidenceLog]) {
    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [
        SUBDOMAIN,
        EMAIL,
        API_TOKEN,
        &TICKET_ID.to_string(),
        SENSITIVE_SUBJECT,
        SENSITIVE_DESCRIPTION,
        "Provider subject",
        "provider body",
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
