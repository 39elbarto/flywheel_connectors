//! Local loopback acceptance coverage for the `Evernote` connector.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_evernote::connector::EvernoteConnector;
use serde_json::json;

const OP_NOTEBOOKS_LIST: &str = "evernote.notebooks.list";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const ACCESS_TOKEN: &str = "evernote_local_acceptance_token";
const RESPONSE_BODY: &str = r#"{
  "notebooks": [
    {
      "id": "notebook_123",
      "name": "Acceptance Engineering",
      "default": true
    }
  ]
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
async fn loopback_notebooks_list_uses_evernote_request_boundary() {
    let fixture = LoopbackFixture::start();
    let mut connector = EvernoteConnector::new();
    connector
        .handle_configure(json!({
            "access_token": ACCESS_TOKEN,
            "base_url": fixture.base_url()
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({ "session_id": "evernote-local-non-mock" }))
        .await
        .expect("handshake connector");

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_NOTEBOOKS_LIST,
            "input": {}
        }))
        .await
        .expect("list notebooks through loopback fixture");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(observation.request_line, "GET /notebooks HTTP/1.1");
    assert!(
        observation
            .headers
            .iter()
            .any(|line| line.eq_ignore_ascii_case("accept: application/json"))
    );
    assert!(observation.headers.iter().any(|line| {
        line.eq_ignore_ascii_case("authorization: Bearer evernote_local_acceptance_token")
    }));
    assert!(observation.headers.iter().any(|line| {
        line.eq_ignore_ascii_case("user-agent: fcp-evernote/0.1.0 (FCP connector)")
    }));
    assert_eq!(result["notebooks"][0]["id"], "notebook_123");
    assert_eq!(result["notebooks"][0]["name"], "Acceptance Engineering");

    let artifact = json!({
        "connector": "evernote",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-bky21.3.6",
        "command": "cargo test -p fcp-evernote --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "GET",
            "path": "/notebooks",
            "query_params": []
        },
        "auth_gate": {
            "mode": "synthetic_bearer_token",
            "credentials_used": false
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
