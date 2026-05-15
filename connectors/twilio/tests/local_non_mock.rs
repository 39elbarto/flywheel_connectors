//! Local loopback acceptance coverage for the `Twilio` connector.

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
use fcp_twilio::connector::TwilioConnector;
use serde::Serialize;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.4.6.4.4";
const CONNECTOR_ID: &str = "fcp.twilio";
const ACCOUNT_SID: &str = "AClocal1234567890123456789012345678";
const AUTH_TOKEN: &str = "local-twilio-auth-token";
const MESSAGE_SID: &str = "SMlocal1234567890123456789012345678";
const OP_LIST_MESSAGES: &str = "twilio.list_messages";
const OP_SEND_MESSAGE: &str = "twilio.send_message";
const SENSITIVE_TO: &str = "+15551234567";
const SENSITIVE_FROM: &str = "+15559876543";
const SENSITIVE_BODY: &str = "Local acceptance message";

const LIST_RESPONSE_BODY: &str = r#"{
  "messages": [
    {
      "sid": "SMlocal1234567890123456789012345678",
      "status": "delivered",
      "to": "+15551234567",
      "from": "+15559876543",
      "body": "provider body"
    }
  ],
  "next_page_uri": null
}"#;

const SEND_RESPONSE_BODY: &str = r#"{
  "sid": "SMlocal1234567890123456789012345678",
  "status": "queued",
  "to": "+15551234567",
  "from": "+15559876543",
  "body": "Local acceptance message"
}"#;

const UNAUTHORIZED_BODY: &str = r#"{"message":"provider body","code":20003}"#;
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Twilio listener");
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
            base_url: format!("http://{address}/2010-04-01/Accounts/{ACCOUNT_SID}"),
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
async fn local_non_mock_messages_list_and_send_use_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, LIST_RESPONSE_BODY),
        ResponseSpec::json(201, SEND_RESPONSE_BODY),
    ]);
    let (mut connector, signing_key) = configured_connector(fixture.base_url()).await;
    let instance_id = connector.instance_id().to_string();

    let messages = invoke(
        &mut connector,
        OP_LIST_MESSAGES,
        json!({
            "to": SENSITIVE_TO,
            "from": SENSITIVE_FROM,
            "page_size": 2
        }),
        capability_token(&signing_key, &instance_id, OP_LIST_MESSAGES),
    )
    .await
    .expect("list_messages should succeed");
    let sent = invoke(
        &mut connector,
        OP_SEND_MESSAGE,
        json!({
            "to": SENSITIVE_TO,
            "from": SENSITIVE_FROM,
            "body": SENSITIVE_BODY
        }),
        capability_token(&signing_key, &instance_id, OP_SEND_MESSAGE),
    )
    .await
    .expect("send_message should succeed");
    let observations = fixture.join();

    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].method(), "GET");
    assert_eq!(
        observations[0].target(),
        "/2010-04-01/Accounts/AClocal1234567890123456789012345678/Messages.json?To=%2B15551234567&From=%2B15559876543&PageSize=2"
    );
    assert_eq!(observations[1].method(), "POST");
    assert_eq!(
        observations[1].target(),
        "/2010-04-01/Accounts/AClocal1234567890123456789012345678/Messages.json"
    );
    assert_auth_headers(&observations);
    assert!(
        observations[1]
            .header_value("content-type")
            .is_some_and(|value| value.starts_with("application/json"))
    );

    let body: Value = serde_json::from_str(&observations[1].body).expect("request body JSON");
    assert_eq!(body["To"], SENSITIVE_TO);
    assert_eq!(body["From"], SENSITIVE_FROM);
    assert_eq!(body["Body"], SENSITIVE_BODY);
    assert_eq!(messages["messages"].as_array().map_or(0, Vec::len), 1);
    assert_eq!(sent["sid"], MESSAGE_SID);

    let logs = vec![
        evidence_log(OP_LIST_MESSAGES, Some(&observations[0]), "passed"),
        evidence_log(OP_SEND_MESSAGE, Some(&observations[1]), "passed"),
    ];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_maps_without_secret_logging() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::json(401, UNAUTHORIZED_BODY)]);
    let (mut connector, signing_key) = configured_connector(fixture.base_url()).await;
    let instance_id = connector.instance_id().to_string();

    let err = invoke(
        &mut connector,
        OP_LIST_MESSAGES,
        json!({}),
        capability_token(&signing_key, &instance_id, OP_LIST_MESSAGES),
    )
    .await
    .expect_err("unauthorized list_messages should map to FCP error");
    let observations = fixture.join();

    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].method(), "GET");
    assert_eq!(
        observations[0].target(),
        "/2010-04-01/Accounts/AClocal1234567890123456789012345678/Messages.json"
    );
    assert_auth_headers(&observations);
    match err {
        FcpError::Unauthorized { code: 2001, .. } => {}
        other => panic!("expected unauthorized FCP error, got {other:?}"),
    }

    let logs = vec![evidence_log(
        OP_LIST_MESSAGES,
        Some(&observations[0]),
        "unauthorized",
    )];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn evidence_schema_carries_connector_and_tracker_identity() {
    let log = evidence_log(OP_LIST_MESSAGES, None, "passed");
    let value = serde_json::to_value(log).expect("evidence JSON");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(
        ConnectorId::from_static(CONNECTOR_ID).as_str(),
        CONNECTOR_ID
    );
    assert_eq!(
        OperationId::from_static(OP_LIST_MESSAGES).as_str(),
        OP_LIST_MESSAGES
    );
    assert_eq!(RequestId::new("twilio-local").to_string(), "twilio-local");
    assert_eq!(ZoneId::work().as_str(), "z:work");

    let introspection = TwilioConnector::new()
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    assert_eq!(
        introspection["operations"].as_array().map_or(0, Vec::len),
        42
    );
}

async fn configured_connector(base_url: &str) -> (TwilioConnector, Ed25519SigningKey) {
    let mut connector = TwilioConnector::new();
    connector
        .handle_configure(json!({
            "account_sid": ACCOUNT_SID,
            "auth_token": AUTH_TOKEN,
            "base_url": base_url
        }))
        .await
        .expect("configure Twilio connector");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["twilio.read", "twilio.message"]
        }))
        .await
        .expect("handshake Twilio connector");
    (connector, signing_key)
}

async fn invoke(
    connector: &mut TwilioConnector,
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
        base64::engine::general_purpose::STANDARD.encode(format!("{ACCOUNT_SID}:{AUTH_TOKEN}"))
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
        redaction: "auth_token_account_sid_phone_numbers_message_body_provider_body_not_logged",
    }
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_LIST_MESSAGES => "twilio.read",
        OP_SEND_MESSAGE => "twilio.message",
        _ => panic!("unsupported operation {operation}"),
    }
}

fn route_label(request: &RequestObservation) -> &'static str {
    match (request.method(), request.target()) {
        ("GET", target) if target.contains("/Messages.json") => "messages_list",
        ("POST", target) if target.ends_with("/Messages.json") => "messages_send",
        _ => "unrecognized",
    }
}

fn assert_redacted(logs: &[EvidenceLog]) {
    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [
        ACCOUNT_SID,
        AUTH_TOKEN,
        MESSAGE_SID,
        SENSITIVE_TO,
        SENSITIVE_FROM,
        SENSITIVE_BODY,
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
