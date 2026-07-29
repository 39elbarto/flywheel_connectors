//! Local loopback acceptance coverage for the `HubSpot` connector.

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
use std::time::{Duration, Duration as StdDuration};

use fcp_hubspot::connector::HubSpotConnector;
use fcp_prelude::{ConnectorId, FcpError, OperationId, RequestId, ZoneId};
use serde::Serialize;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.4.6.4.2";
const CONNECTOR_ID: &str = "fcp.hubspot";
const ACCESS_TOKEN: &str = "local-hubspot-access-token";
const CONTACT_ID: &str = "contact-local";
const OP_CONTACTS_LIST: &str = "hubspot.contacts.list";
const OP_CONTACTS_CREATE: &str = "hubspot.contacts.create";
const SENSITIVE_EMAIL: &str = "local.acceptance@example.com";
const SENSITIVE_FIRSTNAME: &str = "Acceptance";
const SENSITIVE_LASTNAME: &str = "Contact";

const LIST_RESPONSE_BODY: &str = r#"{
  "results": [
    {
      "id": "contact-local",
      "properties": {
        "email": "provider@example.com",
        "firstname": "Provider"
      }
    }
  ],
  "paging": {"next": {"after": "cursor2"}}
}"#;

const CREATE_RESPONSE_BODY: &str = r#"{
  "id": "contact-local",
  "properties": {
    "email": "local.acceptance@example.com",
    "firstname": "Acceptance",
    "lastname": "Contact"
  }
}"#;

const RATE_LIMIT_BODY: &str = r#"{"message":"provider body","status":"error"}"#;
const JSON_HEADERS: &[(&str, &str)] = &[("content-type", "application/json")];
const RATE_LIMIT_HEADERS: &[(&str, &str)] =
    &[("content-type", "application/json"), ("retry-after", "10")];

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

    const fn json_with_headers(
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

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackFixture {
    fn start(responses: Vec<ResponseSpec>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HubSpot listener");
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
        retry_after_ms: response.headers.iter().find_map(|(name, value)| {
            name.eq_ignore_ascii_case("retry-after").then(|| {
                value
                    .parse::<u64>()
                    .expect("retry-after seconds")
                    .checked_mul(1_000)
                    .expect("retry-after milliseconds fit")
            })
        }),
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
        429 => "Too Many Requests",
        _ => "Status",
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_contacts_list_and_create_use_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, LIST_RESPONSE_BODY),
        ResponseSpec::json(201, CREATE_RESPONSE_BODY),
    ]);
    let connector = configured_connector(fixture.base_url()).await;

    let contacts = invoke(
        &connector,
        OP_CONTACTS_LIST,
        json!({
            "limit": 2,
            "properties": ["email", "firstname"]
        }),
    )
    .await
    .expect("contacts.list should succeed");
    let created = invoke(
        &connector,
        OP_CONTACTS_CREATE,
        json!({
            "properties": {
                "email": SENSITIVE_EMAIL,
                "firstname": SENSITIVE_FIRSTNAME,
                "lastname": SENSITIVE_LASTNAME
            }
        }),
    )
    .await
    .expect("contacts.create should succeed");
    let observations = fixture.join();

    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].method(), "GET");
    assert_eq!(
        observations[0].target(),
        "/crm/v3/objects/contacts?limit=2&properties=email&properties=firstname"
    );
    assert_eq!(observations[1].method(), "POST");
    assert_eq!(observations[1].target(), "/crm/v3/objects/contacts");
    assert_auth_headers(&observations);
    assert!(
        observations[1]
            .header_value("content-type")
            .is_some_and(|value| value.starts_with("application/json"))
    );

    let body: Value = serde_json::from_str(&observations[1].body).expect("request body JSON");
    assert_eq!(body["properties"]["email"], SENSITIVE_EMAIL);
    assert_eq!(body["properties"]["firstname"], SENSITIVE_FIRSTNAME);
    assert_eq!(contacts["results"].as_array().map_or(0, Vec::len), 1);
    assert_eq!(created["contact"]["id"], CONTACT_ID);

    let logs = vec![
        evidence_log(OP_CONTACTS_LIST, Some(&observations[0]), "passed"),
        evidence_log(OP_CONTACTS_CREATE, Some(&observations[1]), "passed"),
    ];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_without_secret_logging() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::json_with_headers(
        429,
        RATE_LIMIT_HEADERS,
        RATE_LIMIT_BODY,
    )]);
    let connector = configured_connector(fixture.base_url()).await;

    let err = invoke(&connector, OP_CONTACTS_LIST, json!({}))
        .await
        .expect_err("rate-limited contacts.list should map to FCP error");
    let observations = fixture.join();

    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].method(), "GET");
    assert_eq!(observations[0].target(), "/crm/v3/objects/contacts");
    assert_auth_headers(&observations);
    match err {
        FcpError::External {
            service,
            status_code: Some(429),
            retryable: true,
            retry_after: Some(delay),
            ..
        } => {
            assert_eq!(service, "hubspot");
            assert_eq!(delay, Duration::from_secs(10));
        }
        other => panic!("expected retryable external 429 error, got {other:?}"),
    }

    let logs = vec![evidence_log(
        OP_CONTACTS_LIST,
        Some(&observations[0]),
        "rate_limited",
    )];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn evidence_schema_carries_connector_and_tracker_identity() {
    let log = evidence_log(OP_CONTACTS_LIST, None, "passed");
    let value = serde_json::to_value(log).expect("evidence JSON");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(
        ConnectorId::from_static(CONNECTOR_ID).as_str(),
        CONNECTOR_ID
    );
    assert_eq!(
        OperationId::from_static(OP_CONTACTS_LIST).as_str(),
        OP_CONTACTS_LIST
    );
    assert_eq!(RequestId::new("hubspot-local").to_string(), "hubspot-local");
    assert_eq!(ZoneId::work().as_str(), "z:work");

    let introspection = HubSpotConnector::new()
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    assert_eq!(
        introspection["operations"].as_array().map_or(0, Vec::len),
        24
    );
}

async fn configured_connector(base_url: &str) -> HubSpotConnector {
    let mut connector = HubSpotConnector::new();
    connector
        .handle_configure(json!({
            "access_token": ACCESS_TOKEN,
            "base_url": base_url
        }))
        .await
        .expect("configure HubSpot connector");
    connector
        .handle_handshake(json!({"session_id": "hubspot-local"}))
        .await
        .expect("handshake HubSpot connector");
    connector
}

async fn invoke(
    connector: &HubSpotConnector,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation_id": operation,
            "input": input
        }))
        .await
}

fn assert_auth_headers(observations: &[RequestObservation]) {
    for observation in observations {
        assert_eq!(
            observation.header_value("authorization"),
            Some("Bearer local-hubspot-access-token")
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
        retry_after_ms: request.and_then(|request| request.retry_after_ms),
        redaction: "token_contact_ids_contact_properties_and_provider_body_not_logged",
    }
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_CONTACTS_LIST => "hubspot.contacts.read",
        OP_CONTACTS_CREATE => "hubspot.contacts.write",
        _ => panic!("unsupported operation {operation}"),
    }
}

fn route_label(request: &RequestObservation) -> &'static str {
    match (request.method(), request.target()) {
        ("GET", target) if target.starts_with("/crm/v3/objects/contacts") => "contacts_list",
        ("POST", "/crm/v3/objects/contacts") => "contacts_create",
        _ => "unrecognized",
    }
}

fn assert_redacted(logs: &[EvidenceLog]) {
    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [
        ACCESS_TOKEN,
        CONTACT_ID,
        SENSITIVE_EMAIL,
        SENSITIVE_FIRSTNAME,
        SENSITIVE_LASTNAME,
        "provider body",
        "provider@example.com",
        "Provider",
        "cursor2",
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
