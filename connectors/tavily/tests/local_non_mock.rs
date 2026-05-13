//! Local loopback acceptance coverage for the FCP Tavily connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
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

use fcp_tavily::TavilyConnector;
use serde_json::{Value, json};

const EXPECTED_PATH: &str = "/search";
const RESPONSE_BODY: &str = r#"{
  "query": "secure connector protocol",
  "answer": "FCP uses capability-gated connectors.",
  "results": [
    {
      "title": "Flywheel Connector Protocol",
      "url": "https://docs.flywheel.test/fcp",
      "content": "Connector acceptance fixtures exercise local HTTP semantics.",
      "score": 0.91
    }
  ],
  "images": []
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    client_source_seen: bool,
    content_type_json_seen: bool,
    body: Value,
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
    let content_length = content_length(&headers).expect("request has content-length");
    let body_start = header_end + b"\r\n\r\n".len();
    let body_end = body_start + content_length;
    let body: Value =
        serde_json::from_slice(&request[body_start..body_end]).expect("request body is JSON");

    let request_line = headers.lines().next().unwrap_or_default().to_string();
    let authorization_seen = headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer test-tavily-token"));
    let client_source_seen = headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("x-client-source: fcp"));
    let content_type_json_seen = headers.lines().any(|line| {
        line.to_ascii_lowercase()
            .starts_with("content-type: application/json")
    });

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
        client_source_seen,
        content_type_json_seen,
        body,
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
                continue;
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

async fn setup_connector(base_url: &str) -> TavilyConnector {
    let mut connector = TavilyConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "test-tavily-token",
            "base_url": base_url,
            "request_timeout_ms": 1_000
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
            "operation_id": "tavily.search",
            "input": {
                "query": " secure connector protocol ",
                "search_depth": "advanced",
                "topic": "general",
                "time_range": "week",
                "max_results": 3,
                "include_answer": true,
                "include_raw_content": false,
                "include_images": false,
                "include_domains": ["docs.flywheel.test", ""],
                "exclude_domains": ["ads.flywheel.test"],
                "days": 7
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
        format!("POST {EXPECTED_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert!(observation.client_source_seen);
    assert!(observation.content_type_json_seen);
    assert_eq!(
        observation.body,
        json!({
            "query": "secure connector protocol",
            "search_depth": "advanced",
            "topic": "general",
            "time_range": "week",
            "max_results": 3,
            "include_answer": true,
            "include_raw_content": false,
            "include_images": false,
            "include_domains": ["docs.flywheel.test"],
            "exclude_domains": ["ads.flywheel.test"],
            "days": 7
        })
    );
    assert_eq!(result["answer"], "FCP uses capability-gated connectors.");
    assert_eq!(result["results"][0]["title"], "Flywheel Connector Protocol");
    assert_eq!(result["results"][0]["score"], 0.91);

    let artifact = json!({
        "connector": "tavily",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": "tavily.search",
        "method": "POST",
        "path": EXPECTED_PATH,
        "request_line": observation.request_line,
        "authorization_seen": observation.authorization_seen,
        "client_source_seen": observation.client_source_seen,
        "content_type_json_seen": observation.content_type_json_seen,
        "request_body": observation.body,
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
