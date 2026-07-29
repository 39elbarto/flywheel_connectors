//! Local loopback acceptance coverage for the FCP Asana connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use fcp_asana::connector::AsanaConnector;
use serde_json::json;

const EXPECTED_PATH_WITH_QUERY: &str = "/workspaces/ws_123/tasks/search?text=login%20bug";
const RESPONSE_BODY: &str = r#"{
  "data": [
    {
      "gid": "task_1",
      "name": "Fix login bug",
      "completed": false,
      "resource_type": "task"
    }
  ]
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    accept_json_seen: bool,
    user_agent_seen: bool,
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

    let request = read_http_request(&mut stream);
    let header_end = find_header_end(&request).expect("request contains complete headers");
    let headers = String::from_utf8_lossy(&request[..header_end]);

    let request_line = headers.lines().next().unwrap_or_default().to_string();
    let authorization_seen = header_seen(&headers, "authorization", "Bearer 1/local_non_mock_pat");
    let accept_json_seen = header_value_contains(&headers, "accept", "application/json");
    let user_agent_seen = header_value_contains(&headers, "user-agent", "fcp-asana/0.1.0");

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
        accept_json_seen,
        user_agent_seen,
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector closed before sending request");
        request.extend_from_slice(&buffer[..bytes_read]);

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let Some(content_length) = content_length(&headers) else {
                request.truncate(header_end + b"\r\n\r\n".len());
                return request;
            };
            let required_len = header_end + b"\r\n\r\n".len() + content_length;
            if request.len() >= required_len {
                request.truncate(required_len);
                return request;
            }
        }
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().expect("content-length is numeric"))
    })
}

fn header_seen(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn header_value_contains(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name)
            && value
                .to_ascii_lowercase()
                .contains(&expected_value.to_ascii_lowercase())
    })
}

async fn setup_connector(base_url: &str) -> AsanaConnector {
    let mut connector = AsanaConnector::new();
    connector
        .handle_configure(json!({
            "access_token": "1/local_non_mock_pat",
            "base_url": base_url,
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({"session_id": "local-non-mock"}))
        .await
        .expect("handshake connector");
    connector
}

#[fcp_async_core::runtime::test]
async fn loopback_search_uses_production_client_request() {
    let fixture = LoopbackFixture::start();
    let mut connector = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": "asana.tasks.search",
            "input": {
                "workspace_gid": "ws_123",
                "query": "login bug"
            }
        }))
        .await
        .expect("search through connector");
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("GET {EXPECTED_PATH_WITH_QUERY} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert!(observation.accept_json_seen);
    assert!(observation.user_agent_seen);
    assert_eq!(result["data"][0]["gid"], json!("task_1"));
    assert_eq!(result["data"][0]["name"], json!("Fix login bug"));
    assert_eq!(result["data"][0]["completed"], json!(false));

    let artifact = json!({
        "connector": "asana",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": "asana.tasks.search",
        "method": "GET",
        "path": "/workspaces/ws_123/tasks/search",
        "query": "text=login%20bug",
        "request_line": observation.request_line,
        "authorization_seen": observation.authorization_seen,
        "token_redacted": true,
        "accept_json_seen": observation.accept_json_seen,
        "user_agent_seen": observation.user_agent_seen,
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
