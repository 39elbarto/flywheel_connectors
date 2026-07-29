//! Local loopback acceptance coverage for the Tlon connector.

#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration as StdDuration, Instant},
};

use fcp_prelude::FcpError;
use fcp_tlon::TlonConnector;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "fcp.tlon";
const BEAD_ID: &str = "flywheel_connectors-angoc.16.5";
const DM_OPERATION: &str = "tlon.dm.send";
const CHANNEL_OPERATION: &str = "tlon.channel.send";
const RESOLVE_OPERATION: &str = "tlon.target.resolve";
const SHIP_FIXTURE: &str = "~zod";
const CHANNEL_FIXTURE: &str = "/ship/~zod/general";
const MESSAGE_FIXTURE: &str = "body text that must stay out of evidence";
const SESSION_COOKIE: &str = "urbauth-ship=fixture-session";
const EYRE_CHANNEL_PATH: &str = "/~/channel/fcp-tlon";

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    body: &'static str,
}

#[derive(Debug)]
struct RecordedRequest {
    request_line: String,
    headers: String,
    body: Option<Value>,
}

struct LoopbackEyre {
    base_url: String,
    join: JoinHandle<Vec<RecordedRequest>>,
}

impl LoopbackEyre {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind Tlon loopback listener");
        let base_url = format!(
            "http://{}",
            listener.local_addr().expect("read Tlon loopback address")
        );

        let join = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept Tlon connector request");
                    handle_request(stream, response)
                })
                .collect()
        });

        Self { base_url, join }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(self) -> Vec<RecordedRequest> {
        self.join
            .join()
            .expect("Tlon loopback thread should finish")
    }
}

fn handle_request(mut stream: TcpStream, response: HttpResponse) -> RecordedRequest {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set Tlon loopback read timeout");

    let request = read_complete_request(&mut stream);
    let body_bytes = response.body.as_bytes();
    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        body_bytes.len(),
        response.body
    )
    .expect("write Tlon loopback response");
    request
}

fn read_complete_request(stream: &mut TcpStream) -> RecordedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut header_end = None;
    let mut expected_len = None;

    loop {
        let read = stream
            .read(&mut buffer)
            .expect("read Tlon loopback request");
        assert_ne!(read, 0, "connection closed before Tlon request completed");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 64 * 1024, "Tlon request should stay bounded");

        if header_end.is_none()
            && let Some(end) = find_header_end(&bytes)
        {
            let headers =
                String::from_utf8(bytes[..end].to_vec()).expect("Tlon headers should be UTF-8");
            let content_length = content_length(&headers);
            header_end = Some(end);
            expected_len = Some(end + b"\r\n\r\n".len() + content_length);
        }

        if let (Some(end), Some(total_len)) = (header_end, expected_len)
            && bytes.len() >= total_len
        {
            let headers =
                String::from_utf8(bytes[..end].to_vec()).expect("Tlon headers should be UTF-8");
            let request_line = headers
                .lines()
                .next()
                .expect("request line should be present")
                .to_owned();
            let body_start = end + b"\r\n\r\n".len();
            let body_slice = &bytes[body_start..total_len];
            let body = if body_slice.is_empty() {
                None
            } else {
                Some(serde_json::from_slice(body_slice).expect("Tlon body should be JSON"))
            };
            return RecordedRequest {
                request_line,
                headers,
                body,
            };
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid content-length"))
        })
        .unwrap_or(0)
}

fn header_equals(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn stable_hash(kind: &str, raw: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in kind.bytes().chain(*b":").chain(raw.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{kind}:{hash:016x}")
}

fn test_command_line() -> String {
    std::env::var("FCP_TEST_COMMAND_LINE").unwrap_or_else(|_| {
        "cargo test -p fcp-tlon --test local_non_mock -- --nocapture".to_owned()
    })
}

fn git_revision() -> String {
    std::env::var("FCP_TEST_GIT_REVISION").unwrap_or_else(|_| "unknown".to_owned())
}

fn assert_redacted(serialized: &str) {
    for forbidden in [
        SHIP_FIXTURE,
        CHANNEL_FIXTURE,
        MESSAGE_FIXTURE,
        SESSION_COOKIE,
        "/Users/",
        "/private/",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "sensitive Tlon fixture leaked in local evidence: {forbidden}"
        );
    }
}

fn emit_redacted_evidence(started: Instant, request_count: usize, cleanup_result: &str) {
    let event = json!({
        "schema_version": "1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command_line": test_command_line(),
        "git_revision": git_revision(),
        "connector_id": CONNECTOR_ID,
        "fixture_id": "tlon-local-eyre-loopback",
        "zone": "z:community",
        "operations": [DM_OPERATION, CHANNEL_OPERATION, RESOLVE_OPERATION],
        "ship_hash": stable_hash("ship", SHIP_FIXTURE),
        "channel_hash": stable_hash("channel", CHANNEL_FIXTURE),
        "auth_mode": "session_cookie",
        "provider_boundary": "raw_tcp_loopback_eyre_channel",
        "http_request_count": request_count,
        "latency_ms": started.elapsed().as_millis(),
        "cleanup_result": cleanup_result,
        "skip_reason": null,
    });
    let serialized = event.to_string();
    assert_redacted(&serialized);
    eprintln!("{serialized}");
}

async fn configured_connector(base_url: &str) -> TlonConnector {
    let mut connector = TlonConnector::new();
    connector
        .handle_configure(json!({
            "base_url": base_url,
            "session_cookie": SESSION_COOKIE,
            "allow_private_network": true,
            "ship": SHIP_FIXTURE
        }))
        .await
        .expect("configure should accept dedicated local Eyre loopback");
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:community"
        }))
        .await
        .expect("handshake should complete before local invoke proof");
    connector
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_tlon_eyre_boundary_and_redaction() {
    let started = Instant::now();
    let eyre = LoopbackEyre::start(vec![
        HttpResponse {
            status: "204 No Content",
            body: "",
        },
        HttpResponse {
            status: "204 No Content",
            body: "",
        },
    ]);
    let mut connector = configured_connector(eyre.base_url()).await;

    let resolved_ship = connector
        .handle_invoke(json!({
            "operation_id": RESOLVE_OPERATION,
            "input": { "target": SHIP_FIXTURE }
        }))
        .await
        .expect("ship target should resolve locally");
    assert!(resolved_ship["resolved"].as_bool().unwrap_or(false));

    let invalid_channel = connector
        .handle_invoke(json!({
            "operation_id": RESOLVE_OPERATION,
            "input": { "target": "/ship/~zod/../secret" }
        }))
        .await
        .expect_err("path traversal target should be denied before provider socket");
    assert!(
        matches!(invalid_channel, FcpError::InvalidRequest { code: 1005, .. }),
        "expected local invalid-channel denial, got {invalid_channel:?}"
    );

    let dm_result = connector
        .handle_invoke(json!({
            "operation_id": DM_OPERATION,
            "input": { "ship": SHIP_FIXTURE, "message": MESSAGE_FIXTURE }
        }))
        .await
        .expect("DM send should reach raw Eyre loopback");
    assert!(dm_result["ok"].as_bool().unwrap_or(false));
    assert_eq!(dm_result["provider_status"], "accepted");

    let channel_result = connector
        .handle_invoke(json!({
            "operation_id": CHANNEL_OPERATION,
            "input": { "channel": CHANNEL_FIXTURE, "message": MESSAGE_FIXTURE }
        }))
        .await
        .expect("channel send should reach raw Eyre loopback");
    assert!(channel_result["ok"].as_bool().unwrap_or(false));
    assert_eq!(
        channel_result["provider_status_class"],
        "eyre_channel_accepted"
    );

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should clear local connector state");

    let requests = eyre.join();
    assert_eq!(
        requests.len(),
        2,
        "local validation denials must not open a provider socket"
    );

    let expected_request_line = format!("PUT {EYRE_CHANNEL_PATH} HTTP/1.1");
    for request in &requests {
        assert_eq!(
            request.request_line.as_str(),
            expected_request_line.as_str()
        );
        assert!(
            header_equals(&request.headers, "cookie", SESSION_COOKIE),
            "Tlon loopback request should carry the configured Eyre session cookie"
        );
        assert!(
            header_equals(&request.headers, "content-type", "application/json"),
            "Tlon loopback request should send JSON actions"
        );
    }

    let dm_body = requests[0]
        .body
        .as_ref()
        .expect("DM request should carry an Eyre action array");
    let channel_body = requests[1]
        .body
        .as_ref()
        .expect("channel request should carry an Eyre action array");

    assert_eq!(dm_body[0]["action"], "poke");
    assert_eq!(dm_body[0]["ship"], "zod");
    assert_eq!(dm_body[0]["mark"], "tlon-dm-action");
    assert_eq!(dm_body[0]["json"]["kind"], "dm.send");
    assert_eq!(dm_body[0]["json"]["ship"], SHIP_FIXTURE);
    assert_eq!(dm_body[0]["json"]["message"], MESSAGE_FIXTURE);
    assert_eq!(channel_body[0]["action"], "poke");
    assert_eq!(channel_body[0]["ship"], "zod");
    assert_eq!(channel_body[0]["mark"], "tlon-channel-action");
    assert_eq!(channel_body[0]["json"]["kind"], "channel.send");
    assert_eq!(channel_body[0]["json"]["channel"], CHANNEL_FIXTURE);
    assert_eq!(channel_body[0]["json"]["message"], MESSAGE_FIXTURE);

    emit_redacted_evidence(started, requests.len(), "loopback_server_joined");
}
