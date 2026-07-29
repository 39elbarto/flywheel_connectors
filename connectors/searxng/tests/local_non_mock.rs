//! Local loopback acceptance coverage for the `SearXNG` connector.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_searxng::SearxngConnector;
use serde_json::json;

const OP_QUERY: &str = "searxng.search.query";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const RESPONSE_BODY: &str = r#"{
  "results": [
    {
      "title": "Rust Programming Language",
      "url": "https://rust-lang.org/",
      "content": "Rust is fast and memory-efficient.",
      "engine": "duckduckgo",
      "category": "general",
      "score": 1.0
    }
  ],
  "suggestions": ["rust book"],
  "answers": ["Rust is a programming language"],
  "infoboxes": [{"title": "Rust"}]
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
async fn loopback_query_search_uses_json_request_boundary() {
    let fixture = LoopbackFixture::start();
    let mut connector = SearxngConnector::new();
    connector
        .handle_configure(json!({
            "base_url": fixture.base_url(),
            "allow_loopback": true,
            "request_timeout_ms": 5_000,
            "default_language": "en",
            "user_agent": "fcp-searxng-local-acceptance/0.1.0"
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake connector");

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_QUERY,
            "input": {
                "query": "rust privacy",
                "language": "en-us",
                "safe_search": "strict",
                "time_range": "month",
                "page": 2,
                "categories": ["general", "science"],
                "engines": "duckduckgo,brave",
                "max_results": 1
            }
        }))
        .await
        .expect("query search through loopback fixture");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert!(observation.request_line.starts_with("GET /search?"));
    assert!(observation.request_line.contains("q=rust+privacy"));
    assert!(observation.request_line.contains("format=json"));
    assert!(observation.request_line.contains("language=en-us"));
    assert!(observation.request_line.contains("safesearch=2"));
    assert!(observation.request_line.contains("time_range=month"));
    assert!(observation.request_line.contains("pageno=2"));
    assert!(
        observation
            .request_line
            .contains("categories=general%2Cscience")
    );
    assert!(
        observation
            .request_line
            .contains("engines=duckduckgo%2Cbrave")
    );
    assert!(
        observation
            .headers
            .iter()
            .any(|line| { line.eq_ignore_ascii_case("accept: application/json") })
    );
    assert!(observation.headers.iter().any(|line| {
        line.eq_ignore_ascii_case("user-agent: fcp-searxng-local-acceptance/0.1.0")
    }));
    assert_eq!(result["provider"], "searxng");
    assert_eq!(result["mode"], "query");
    assert_eq!(result["base_url_class"], "loopback");
    assert_eq!(result["count"], 1);
    assert_eq!(result["results"][0]["title"], "Rust Programming Language");
    assert_eq!(result["results"][0]["hostname"], "rust-lang.org");
    assert!(
        result["query_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("blake3:"))
    );

    let artifact = json!({
        "connector": "searxng",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-bky21.3.6",
        "command": "cargo test -p fcp-searxng --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "GET",
            "path": "/search",
            "query_fields": ["q", "format", "language", "safesearch", "time_range", "pageno"]
        },
        "auth_gate": {
            "mode": "none",
            "credentials_used": false
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
