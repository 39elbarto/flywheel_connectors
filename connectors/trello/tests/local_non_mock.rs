//! Local loopback acceptance coverage for the `Trello` connector.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_trello::connector::TrelloConnector;
use serde_json::json;

const OP_BOARDS_LIST: &str = "trello.boards.list";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const API_KEY: &str = "trello_local_acceptance_key";
const API_TOKEN: &str = "trello_local_acceptance_token";
const RESPONSE_BODY: &str = r#"[
  {
    "id": "board_123",
    "name": "Acceptance Engineering",
    "desc": "Loopback acceptance fixture",
    "closed": false,
    "url": "https://trello.com/b/board123/acceptance-engineering"
  }
]"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: Vec<String>,
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
            base_url: format!("http://{address}"),
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

    let raw = read_http_headers(&mut stream);
    let request = String::from_utf8_lossy(&raw);
    let mut lines = request.lines();
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
    }
}

fn read_http_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return request;
        }
        assert!(request.len() < 8192, "request should stay bounded");
    }
}

fn request_target(request_line: &str) -> &str {
    request_line
        .split_ascii_whitespace()
        .nth(1)
        .expect("request line includes target")
}

fn query_params(target: &str) -> Vec<(&str, &str)> {
    let Some((_, query)) = target.split_once('?') else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .collect()
}

fn query_value<'a>(params: &'a [(&str, &str)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find_map(|(name, value)| (*name == key).then_some(*value))
}

#[fcp_async_core::runtime::test]
async fn loopback_boards_list_uses_trello_request_boundary() {
    let fixture = LoopbackFixture::start();
    let mut connector = TrelloConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "token": API_TOKEN,
            "base_url": fixture.base_url()
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({ "session_id": "trello-local-non-mock" }))
        .await
        .expect("handshake connector");

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_BOARDS_LIST,
            "input": {}
        }))
        .await
        .expect("list boards through loopback fixture");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert!(observation.request_line.starts_with("GET "));
    assert!(observation.request_line.ends_with(" HTTP/1.1"));
    let target = request_target(&observation.request_line);
    assert!(target.starts_with("/members/me/boards?"));
    let params = query_params(target);
    assert_eq!(query_value(&params, "key"), Some(API_KEY));
    assert_eq!(query_value(&params, "token"), Some(API_TOKEN));
    assert!(
        observation
            .headers
            .iter()
            .any(|line| line.eq_ignore_ascii_case("accept: application/json"))
    );
    assert!(
        observation.headers.iter().any(|line| {
            line.eq_ignore_ascii_case("user-agent: fcp-trello/0.1.0 (FCP connector)")
        })
    );
    assert_eq!(result["boards"][0]["id"], "board_123");
    assert_eq!(result["boards"][0]["name"], "Acceptance Engineering");

    let artifact = json!({
        "connector": "trello",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-bky21.3.6",
        "command": "cargo test -p fcp-trello --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "GET",
            "path": "/members/me/boards",
            "query_params": ["key", "token"]
        },
        "auth_gate": {
            "mode": "synthetic_api_key_token_query",
            "credentials_used": false
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
