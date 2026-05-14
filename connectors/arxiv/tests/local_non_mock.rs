//! Local loopback acceptance coverage for the `arXiv` connector.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_arxiv::connector::ArxivConnector;
use serde_json::json;

const OP_SEARCH_PAPERS: &str = "arxiv.search_papers";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const RESPONSE_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<opensearch:totalResults>1</opensearch:totalResults>
<entry>
<id>http://arxiv.org/abs/2401.01234v1</id>
<title>Rust Async Connectors for Local Acceptance</title>
<summary>A loopback acceptance fixture proves request and response boundaries.</summary>
<author><name>Ada Lovelace</name></author>
<author><name>Grace Hopper</name></author>
<published>2024-01-03T00:00:00Z</published>
<updated>2024-01-04T00:00:00Z</updated>
<arxiv:primary_category term="cs.SE" scheme="http://arxiv.org/schemas/atom"/>
<category term="cs.SE" scheme="http://arxiv.org/schemas/atom"/>
<category term="cs.PL" scheme="http://arxiv.org/schemas/atom"/>
<link title="pdf" href="http://arxiv.org/pdf/2401.01234v1" rel="related" type="application/pdf"/>
<arxiv:doi>10.48550/arXiv.2401.01234</arxiv:doi>
<arxiv:comment>12 pages</arxiv:comment>
</entry>
</feed>"#;

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
        "HTTP/1.1 200 OK\r\ncontent-type: application/atom+xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
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
async fn loopback_search_papers_uses_arxiv_request_boundary() {
    let fixture = LoopbackFixture::start();
    let mut connector = ArxivConnector::new();
    connector
        .handle_configure(json!({
            "arxiv_base_url": fixture.base_url(),
            "scholar_base_url": fixture.base_url(),
            "rate_limit_rps": 3.0
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({ "session_id": "arxiv-local-non-mock" }))
        .await
        .expect("handshake connector");

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_SEARCH_PAPERS,
            "input": {
                "query": "all:rust async",
                "max_results": 2,
                "start": 1,
                "sort_by": "submittedDate",
                "sort_order": "descending"
            }
        }))
        .await
        .expect("search papers through loopback fixture");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert!(
        observation
            .request_line
            .starts_with("GET /api/query?search_query=all:rust+async")
    );
    assert!(observation.request_line.contains("start=1"));
    assert!(observation.request_line.contains("max_results=2"));
    assert!(observation.request_line.contains("sortBy=submittedDate"));
    assert!(observation.request_line.contains("sortOrder=descending"));
    assert!(observation.request_line.ends_with(" HTTP/1.1"));
    assert!(
        observation
            .headers
            .iter()
            .any(|line| line.eq_ignore_ascii_case("accept: application/atom+xml"))
    );
    assert!(
        observation.headers.iter().any(|line| {
            line.eq_ignore_ascii_case("user-agent: fcp-arxiv/0.1.0 (FCP connector)")
        })
    );
    assert!(
        observation
            .headers
            .iter()
            .all(|line| !line.to_ascii_lowercase().starts_with("authorization:"))
    );
    assert_eq!(result["total_results"], 1);
    assert_eq!(result["papers"][0]["arxiv_id"], "2401.01234v1");
    assert_eq!(
        result["papers"][0]["title"],
        "Rust Async Connectors for Local Acceptance"
    );
    assert_eq!(result["papers"][0]["authors"][0], "Ada Lovelace");
    assert_eq!(result["papers"][0]["primary_category"], "cs.SE");

    let artifact = json!({
        "connector": "arxiv",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-bky21.3.6",
        "command": "cargo test -p fcp-arxiv --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "GET",
            "path": "/api/query",
            "query_fields": ["search_query", "start", "max_results", "sortBy", "sortOrder"]
        },
        "auth_gate": {
            "mode": "open_access_no_credentials",
            "credentials_used": false
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
