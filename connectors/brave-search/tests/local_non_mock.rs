//! Local loopback acceptance coverage for the `Brave Search` connector.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_brave_search::BraveSearchConnector;
use serde_json::json;

const OP_WEB_SEARCH: &str = "brave-search.web.search";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const TEST_API_KEY: &str = "brave-local-acceptance-token";
const RESPONSE_BODY: &str = r#"{
  "type": "search",
  "web": {
    "results": [
      {
        "title": "Rust Async Book",
        "url": "https://rust-lang.github.io/async-book/",
        "description": "Asynchronous programming in Rust",
        "age": "2024-01-01"
      }
    ]
  }
}"#;

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

#[fcp_async_core::runtime::test]
async fn loopback_web_search_uses_brave_request_boundary() {
    let fixture = LoopbackFixture::start();
    let mut connector = BraveSearchConnector::new();
    connector
        .handle_configure(json!({
            "api_key": TEST_API_KEY,
            "base_url": fixture.base_url(),
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake connector");

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_WEB_SEARCH,
            "input": {
                "query": "rust privacy",
                "count": 2,
                "country": "us",
                "language": "en",
                "ui_lang": "en-us",
                "safesearch": "moderate",
                "freshness": "week"
            }
        }))
        .await
        .expect("web search through loopback fixture");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert!(
        observation
            .request_line
            .starts_with("GET /res/v1/web/search?")
    );
    assert!(observation.request_line.contains("q=rust+privacy"));
    assert!(observation.request_line.contains("country=US"));
    assert!(observation.request_line.contains("search_lang=en"));
    assert!(observation.request_line.contains("ui_lang=en-US"));
    assert!(observation.request_line.contains("safesearch=moderate"));
    assert!(observation.request_line.contains("freshness=pw"));
    assert!(observation.request_line.contains("count=2"));
    assert!(
        observation
            .headers
            .iter()
            .any(|line| line.eq_ignore_ascii_case("accept: application/json"))
    );
    assert!(observation.headers.iter().any(|line| {
        line.eq_ignore_ascii_case(&format!("x-subscription-token: {TEST_API_KEY}"))
    }));
    assert_eq!(result["provider"], "brave");
    assert_eq!(result["mode"], "web");
    assert_eq!(result["count"], 1);
    assert_eq!(result["external_content"]["untrusted"], true);
    assert_eq!(result["external_content"]["wrapped"], true);
    assert!(
        result["results"][0]["title"]
            .as_str()
            .is_some_and(|title| title.contains("Rust Async Book"))
    );
    assert_eq!(
        result["results"][0]["url"],
        "https://rust-lang.github.io/async-book/"
    );
    assert_eq!(result["results"][0]["site_name"], "rust-lang.github.io");

    let artifact = json!({
        "connector": "brave-search",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-bky21.3.6",
        "command": "cargo test -p fcp-brave-search --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "GET",
            "path": "/res/v1/web/search",
            "query_fields": ["q", "country", "search_lang", "ui_lang", "safesearch", "freshness", "count"]
        },
        "auth_gate": {
            "mode": "api_key_header",
            "credentials_used": true,
            "secret_source": "synthetic_test_value"
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
