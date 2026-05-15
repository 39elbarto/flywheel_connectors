//! Local loopback acceptance coverage for the `Discord` connector.

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
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_discord::DiscordConnector;
use fcp_prelude::{CapabilityConstraints, ConnectorId, FcpError, OperationId, RequestId, ZoneId};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.62";
const CONNECTOR_ID: &str = "fcp.discord";
const BOT_TOKEN: &str = "local-discord-bot-token";
const CONTENT_SENTINEL: &str = "DISCORD_CONTENT_SHOULD_NOT_APPEAR_IN_EVIDENCE";
const CAP_READ: &str = "discord.read";
const CAP_SEND: &str = "discord.send";
const OP_GET_CHANNEL: &str = "discord.get_channel";
const OP_LIST_CHANNELS: &str = "discord.list_channels";
const OP_TRIGGER_TYPING: &str = "discord.trigger_typing";
const CHANNEL_ID: &str = "111111111";
const GUILD_ID: &str = "222222222";
const ALL_REQUIRED_INTENTS: u64 = (1 << 0) | (1 << 9) | (1 << 12) | (1 << 15);

const USER_RESPONSE_BODY: &str = r#"{
  "id": "999999999",
  "username": "AcceptanceBot",
  "bot": true
}"#;

const CHANNEL_RESPONSE_BODY: &str = r#"{
  "id": "111111111",
  "type": 0,
  "guild_id": "222222222",
  "name": "ops",
  "topic": "provider topic should stay out of evidence"
}"#;

const CHANNELS_RESPONSE_BODY: &str = r#"[
  {
    "id": "111111111",
    "type": 0,
    "guild_id": "222222222",
    "name": "ops"
  }
]"#;

const EMPTY_RESPONSE_BODY: &str = "{}";
const RATE_LIMIT_BODY: &str =
    r#"{"message":"provider body should stay out of evidence","retry_after":2.5}"#;
const JSON_HEADERS: &[(&str, &str)] = &[("content-type", "application/json")];
const RATE_LIMIT_HEADERS: &[(&str, &str)] =
    &[("content-type", "application/json"), ("retry-after", "2.5")];

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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Discord listener");
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
                let seconds = value.parse::<f64>().expect("retry-after seconds");
                let millis = StdDuration::try_from_secs_f64(seconds)
                    .expect("retry-after duration")
                    .as_millis();
                u64::try_from(millis).expect("retry-after milliseconds fit")
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
        429 => "Too Many Requests",
        _ => "Status",
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_read_and_typing_paths_use_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, USER_RESPONSE_BODY),
        ResponseSpec::json(200, CHANNEL_RESPONSE_BODY),
        ResponseSpec::json(200, CHANNELS_RESPONSE_BODY),
        ResponseSpec::json(200, EMPTY_RESPONSE_BODY),
    ]);
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = configured_connector(fixture.base_url()).await;
    handshake_connector(&mut connector, &signing_key).await;

    let channel = invoke(
        &connector,
        &signing_key,
        OP_GET_CHANNEL,
        json!({"channel_id": CHANNEL_ID}),
    )
    .await
    .expect("get_channel should succeed");
    let channels = invoke(
        &connector,
        &signing_key,
        OP_LIST_CHANNELS,
        json!({"guild_id": GUILD_ID}),
    )
    .await
    .expect("list_channels should succeed");
    let typing = invoke(
        &connector,
        &signing_key,
        OP_TRIGGER_TYPING,
        json!({"channel_id": CHANNEL_ID}),
    )
    .await
    .expect("trigger_typing should succeed");
    let observations = fixture.join();

    assert_eq!(observations.len(), 4);
    assert_eq!(observations[0].request_line, "GET /users/@me HTTP/1.1");
    assert_eq!(
        observations[1].request_line,
        "GET /channels/111111111 HTTP/1.1"
    );
    assert_eq!(
        observations[2].request_line,
        "GET /guilds/222222222/channels HTTP/1.1"
    );
    assert_eq!(
        observations[3].request_line,
        "POST /channels/111111111/typing HTTP/1.1"
    );
    assert_auth_headers(&observations);
    assert_eq!(
        observations[3].header_value("content-type"),
        Some("application/json")
    );
    assert_eq!(observations[3].body, "{}");

    assert_eq!(channel["id"], CHANNEL_ID);
    assert_eq!(channels["channels"].as_array().map_or(0, Vec::len), 1);
    assert_eq!(typing["triggered"], true);

    let logs = vec![
        evidence_log(OP_GET_CHANNEL, Some(&observations[1]), "passed"),
        evidence_log(OP_LIST_CHANNELS, Some(&observations[2]), "passed"),
        evidence_log(OP_TRIGGER_TYPING, Some(&observations[3]), "passed"),
    ];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_without_secret_logging() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, USER_RESPONSE_BODY),
        ResponseSpec::json_with_headers(429, RATE_LIMIT_HEADERS, RATE_LIMIT_BODY),
    ]);
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = configured_connector(fixture.base_url()).await;
    handshake_connector(&mut connector, &signing_key).await;

    let err = invoke(
        &connector,
        &signing_key,
        OP_GET_CHANNEL,
        json!({"channel_id": CHANNEL_ID}),
    )
    .await
    .expect_err("rate-limited get_channel should map to FCP error");
    let observations = fixture.join();

    assert_eq!(observations.len(), 2);
    assert_eq!(observations[1].method(), "GET");
    assert_eq!(observations[1].target(), "/channels/111111111");
    assert_auth_headers(&observations);
    match err {
        FcpError::RateLimited {
            retry_after_ms: 2_500,
            ..
        } => {}
        other => panic!("expected rate limit error, got {other:?}"),
    }

    let logs = vec![evidence_log(
        OP_GET_CHANNEL,
        Some(&observations[1]),
        "rate_limited",
    )];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn evidence_schema_carries_connector_and_tracker_identity() {
    let log = evidence_log(OP_GET_CHANNEL, None, "passed");
    let value = serde_json::to_value(log).expect("evidence JSON");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(
        ConnectorId::from_static(CONNECTOR_ID).as_str(),
        CONNECTOR_ID
    );
    assert_eq!(
        OperationId::from_static(OP_GET_CHANNEL).as_str(),
        OP_GET_CHANNEL
    );
    assert_eq!(RequestId::new("discord-local").to_string(), "discord-local");
    assert_eq!(ZoneId::work().as_str(), "z:work");

    let introspection = DiscordConnector::new()
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    assert_eq!(
        introspection["operations"].as_array().map_or(0, Vec::len),
        9
    );
}

async fn configured_connector(base_url: &str) -> DiscordConnector {
    let mut connector = DiscordConnector::new();
    connector
        .handle_configure(json!({
            "bot_credential": BOT_TOKEN,
            "api_url": base_url,
            "gateway_url": "ws://127.0.0.1:1/",
            "intents": ALL_REQUIRED_INTENTS,
            "retry": {
                "max_attempts": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter": 0.0
            }
        }))
        .await
        .expect("configure Discord connector");
    connector
}

async fn handshake_connector(connector: &mut DiscordConnector, signing_key: &Ed25519SigningKey) {
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "zone_dir": zone_dir("discord-local"),
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![23_u8; 32],
            "capabilities_requested": [CAP_READ, CAP_SEND]
        }))
        .await
        .expect("handshake Discord connector");
}

fn zone_dir(label: &str) -> String {
    std::env::temp_dir()
        .join("fcp-discord-acceptance")
        .join(format!("{label}-{}", Uuid::new_v4()))
        .to_string_lossy()
        .into_owned()
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_GET_CHANNEL | OP_LIST_CHANNELS => CAP_READ,
        OP_TRIGGER_TYPING => CAP_SEND,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    connector: &DiscordConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
) -> fcp_core::CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:discord-local")
        .operations(&[operation])
        .issuer("node:local-acceptance")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_ref())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &DiscordConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_for(connector, signing_key, operation)
        }))
        .await
}

fn assert_auth_headers(observations: &[RequestObservation]) {
    for observation in observations {
        assert_eq!(
            observation.header_value("authorization"),
            Some("Bot local-discord-bot-token")
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
        redaction: "bot_token_channel_ids_content_and_provider_body_not_logged",
    }
}

fn route_label(request: &RequestObservation) -> &'static str {
    match (request.method(), request.target()) {
        ("GET", "/channels/111111111") => "get_channel",
        ("GET", "/guilds/222222222/channels") => "list_channels",
        ("POST", "/channels/111111111/typing") => "trigger_typing",
        _ => "unrecognized",
    }
}

fn assert_redacted(logs: &[EvidenceLog]) {
    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [
        BOT_TOKEN,
        CONTENT_SENTINEL,
        "provider body",
        "provider topic",
        "AcceptanceBot",
        CHANNEL_ID,
        GUILD_ID,
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
