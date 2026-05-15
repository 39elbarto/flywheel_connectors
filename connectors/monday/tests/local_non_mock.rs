//! Local loopback acceptance coverage for the `Monday.com` GraphQL boundary.

#![allow(
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_monday::client::{MondayAuth, MondayClient};
use serde_json::json;

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const API_TOKEN: &str = "monday_local_token";
const RESPONSE_BODY: &str = r#"{
  "data": {
    "boards": [
      {
        "id": "123",
        "name": "Local Acceptance Board",
        "state": "active",
        "board_kind": "public"
      }
    ]
  }
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: Vec<String>,
    body: String,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream)
        });

        Self {
            base_url: format!("http://{address}/v2"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> FixtureObservation {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let raw = read_http_request(&mut stream);
    let request = String::from_utf8_lossy(&raw);
    let (head, body) = request.split_once("\r\n\r\n").unwrap_or((&request, ""));
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        headers,
        body: body.to_string(),
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut header_end = None;
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        if header_end.is_none() {
            header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4);
        }
        if let Some(end) = header_end {
            let content_length = content_length(&request[..end]);
            if request.len() >= end + content_length {
                return request;
            }
        }
        assert!(request.len() < 8192, "request should stay bounded");
    }
}

fn content_length(header_bytes: &[u8]) -> usize {
    String::from_utf8_lossy(header_bytes)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn has_header(headers: &[String], name: &str, expected_value: &str) -> bool {
    headers.iter().any(|line| {
        let Some((actual_name, actual_value)) = line.split_once(':') else {
            return false;
        };
        actual_name.eq_ignore_ascii_case(name) && actual_value.trim() == expected_value
    })
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_boards_uses_loopback_graphql_boundary() {
    let fixture = LoopbackFixture::start();
    let client = MondayClient::new(
        MondayAuth::ApiToken(API_TOKEN.into()),
        Some(fixture.base_url()),
    )
    .expect("construct Monday.com client");

    let response = client
        .list_boards(2)
        .await
        .expect("list boards through loopback fixture");
    client.shutdown();
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(observation.request_line, "POST /v2 HTTP/1.1");
    assert!(has_header(&observation.headers, "authorization", API_TOKEN));
    assert!(has_header(
        &observation.headers,
        "content-type",
        "application/json"
    ));
    assert!(has_header(
        &observation.headers,
        "accept",
        "application/json"
    ));
    assert!(has_header(
        &observation.headers,
        "user-agent",
        "fcp-monday/0.1.0 (FCP connector)"
    ));
    assert!(observation.body.contains("boards(limit: 2)"));
    assert_eq!(response["boards"][0]["id"], "123");
    assert_eq!(response["boards"][0]["name"], "Local Acceptance Board");

    let artifact = json!({
        "connector": "monday",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-sgxsn",
        "command": "cargo test -p fcp-monday --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "sandbox_required",
        "request_response_boundary": {
            "method": "POST",
            "path": "/v2",
            "graphql_operation": "boards"
        },
        "auth_gate": {
            "mode": "api_token",
            "credentials_used": true,
            "authorization_header_verified": true
        },
        "cleanup": "client_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
