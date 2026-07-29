//! Local loopback acceptance coverage for the `DuckDuckGo` connector.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_duckduckgo::DuckDuckGoConnector;
use serde_json::json;

const OP_TEXT: &str = "duckduckgo.search.text";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const RESPONSE_BODY: &str = r#"
<html><body>
  <div class="result results_links web-result">
    <a rel="nofollow" class="result__a" href="https://rust-lang.org/">Rust Programming Language</a>
    <a class="result__snippet" href="https://rust-lang.org/">Rust empowers reliable systems software.</a>
  </div>
  <input type="hidden" name="vqd" value="local-fixture" />
</body></html>
"#;

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

    let raw = read_http_request(&mut stream);
    let request = String::from_utf8_lossy(&raw);
    let header_end = request
        .find("\r\n\r\n")
        .expect("HTTP request contains header terminator");
    let (head, body_with_separator) = request.split_at(header_end);
    let body = body_with_separator
        .trim_start_matches("\r\n\r\n")
        .to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        headers,
        body,
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(expected_len) = expected_request_len(&request) {
            if request.len() >= expected_len {
                return request;
            }
        }
        assert!(request.len() < 8192, "request should stay bounded");
    }
}

fn expected_request_len(request: &[u8]) -> Option<usize> {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?
        + 4;
    let header_text = String::from_utf8_lossy(&request[..header_end]);
    let content_length = header_text.lines().find_map(|line| {
        line.to_ascii_lowercase()
            .strip_prefix("content-length:")
            .and_then(|value| value.trim().parse::<usize>().ok())
    })?;
    Some(header_end + content_length)
}

#[fcp_async_core::runtime::test]
async fn loopback_text_search_uses_html_form_request_boundary() {
    let fixture = LoopbackFixture::start();
    let mut connector = DuckDuckGoConnector::new();
    connector
        .handle_configure(json!({
            "base_url": fixture.base_url(),
            "request_timeout_ms": 5_000,
            "user_agent": "fcp-duckduckgo-local-acceptance/0.1.0"
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake connector");

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_TEXT,
            "input": {
                "query": "rust systems",
                "region": "us-en",
                "safe_search": "moderate",
                "max_results": 1
            }
        }))
        .await
        .expect("text search through loopback fixture");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(observation.request_line, "POST /html/ HTTP/1.1");
    assert!(observation.body.contains("q=rust+systems"));
    assert!(observation.body.contains("kl=us-en"));
    assert!(observation.body.contains("kp=-1"));
    assert!(
        observation
            .headers
            .iter()
            .any(|line| { line.eq_ignore_ascii_case("sec-fetch-mode: navigate") })
    );
    assert!(observation.headers.iter().any(|line| {
        line.eq_ignore_ascii_case("user-agent: fcp-duckduckgo-local-acceptance/0.1.0")
    }));
    assert_eq!(result["provider"], "duckduckgo");
    assert_eq!(result["mode"], "text");
    assert_eq!(result["count"], 1);
    assert_eq!(result["results"][0]["title"], "Rust Programming Language");
    assert_eq!(result["results"][0]["hostname"], "rust-lang.org");
    assert!(
        result["query_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("blake3:"))
    );

    let artifact = json!({
        "connector": "duckduckgo",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-bky21.3.6",
        "command": "cargo test -p fcp-duckduckgo --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "POST",
            "path": "/html/",
            "form_fields": ["q", "kl", "kp"]
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
