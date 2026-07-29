//! Local loopback acceptance coverage for the Logseq connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use fcp_logseq::connector::LogseqConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};

const LOOPBACK_AUTH_VALUE: &str = "local-loopback-auth-value";
const OP_PAGES_LIST: &str = "logseq.pages.list";
const OP_BLOCKS_CREATE: &str = "logseq.blocks.create";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.36";
const EXPECTED_PAGES_PATH: &str = "/api/pages";
const EXPECTED_CREATE_PATH: &str = "/api/insert-block";
const CREATE_PAGE: &str = "Daily Notes";
const CREATE_CONTENT: &str = "Review local loopback evidence";

const PAGES_RESPONSE: &str = r#"[
  {
    "name": "Daily Notes",
    "uuid": "page-1",
    "original-name": "Daily Notes"
  },
  {
    "name": "Architecture",
    "uuid": "page-2"
  }
]"#;

const CREATE_BLOCK_RESPONSE: &str = r#"{
  "uuid": "block-1",
  "content": "Review local loopback evidence"
}"#;

const RATE_LIMIT_RESPONSE: &str = r#"{
  "error": "too many local requests"
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: String,
    body: String,
}

impl FixtureObservation {
    fn authorization_seen(&self) -> bool {
        header_seen(
            &self.headers,
            "authorization",
            &format!("Bearer {LOOPBACK_AUTH_VALUE}"),
        )
    }

    fn accept_json_seen(&self) -> bool {
        header_value_contains(&self.headers, "accept", "application/json")
    }

    fn content_type_json_seen(&self) -> bool {
        header_value_contains(&self.headers, "content-type", "application/json")
    }

    fn user_agent_seen(&self) -> bool {
        header_value_contains(&self.headers, "user-agent", "fcp-logseq/0.1.0")
    }
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start(
        response_status: &'static str,
        extra_headers: &'static str,
        response_body: &'static str,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream, response_status, extra_headers, response_body)
        });

        Self {
            base_url: format!("http://{address}/api"),
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

fn handle_request(
    mut stream: TcpStream,
    response_status: &str,
    extra_headers: &str,
    response_body: &str,
) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);

    write!(
        stream,
        "HTTP/1.1 {response_status}\r\ncontent-type: application/json\r\n{extra_headers}content-length: {}\r\nconnection: close\r\n\r\n{response_body}",
        response_body.len()
    )
    .expect("write connector response");

    FixtureObservation {
        request_line: request.request_line,
        headers: request.headers,
        body: request.body,
    }
}

struct HttpRequest {
    request_line: String,
    headers: String,
    body: String,
}

fn read_http_request(stream: &mut TcpStream) -> HttpRequest {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector should send request bytes");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(header_end) = find_header_end(&request) {
            break header_end;
        }
        assert!(request.len() < 8192, "request headers should stay bounded");
    };

    let header_bytes = &request[..header_end + 4];
    let headers = String::from_utf8_lossy(header_bytes).to_string();
    let content_length = content_length_from_headers(&headers);
    let mut body = request[header_end + 4..].to_vec();
    while body.len() < content_length {
        let bytes_read = stream.read(&mut buffer).expect("read connector body");
        assert!(bytes_read > 0, "connector body should match content-length");
        body.extend_from_slice(&buffer[..bytes_read]);
        assert!(body.len() <= 8192, "request body should stay bounded");
    }
    body.truncate(content_length);

    HttpRequest {
        request_line: headers.lines().next().unwrap_or_default().to_string(),
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length_from_headers(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
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

fn assert_request_boundary(request_line: &str, expected_path: &str) {
    let mut parts = request_line.split_whitespace();
    assert_eq!(parts.next(), Some("POST"));
    let target = parts.next().expect("request target should be present");
    assert_eq!(parts.next(), Some("HTTP/1.1"));
    assert_eq!(parts.next(), None);

    let target_without_empty_query = target.strip_suffix('?').unwrap_or(target);
    assert_eq!(target_without_empty_query, expected_path);
    assert!(
        !target_without_empty_query.contains('?'),
        "Logseq requests should not add query parameters"
    );
}

async fn setup_connector(base_url: &str) -> LogseqConnector {
    let mut connector = LogseqConnector::new();
    connector
        .handle_configure(json!({
            "access_token": LOOPBACK_AUTH_VALUE,
            "base_url": base_url
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({ "session_id": "local-non-mock" }))
        .await
        .expect("handshake connector");
    connector
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_pages_list_uses_logseq_request_boundary() {
    let fixture = LoopbackFixture::start("200 OK", "", PAGES_RESPONSE);
    let connector = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_PAGES_LIST,
            "input": {}
        }))
        .await
        .expect("list pages through connector");
    let observation = fixture.join();

    assert_request_boundary(&observation.request_line, EXPECTED_PAGES_PATH);
    assert!(observation.authorization_seen());
    assert!(observation.accept_json_seen());
    assert!(observation.content_type_json_seen());
    assert!(observation.user_agent_seen());
    assert_eq!(result["pages"].as_array().expect("pages array").len(), 2);
    assert_eq!(result["pages"][0]["name"], "Daily Notes");
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "logseq",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": BEAD_ID,
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_PAGES_LIST,
        "method": "POST",
        "path": EXPECTED_PAGES_PATH,
        "request_line": observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen()
        },
        "headers": {
            "accept_json_seen": observation.accept_json_seen(),
            "content_type_json_seen": observation.content_type_json_seen(),
            "user_agent_seen": observation.user_agent_seen()
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_blocks_create_posts_json_boundary() {
    let fixture = LoopbackFixture::start("200 OK", "", CREATE_BLOCK_RESPONSE);
    let connector = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_BLOCKS_CREATE,
            "input": {
                "page": CREATE_PAGE,
                "content": CREATE_CONTENT
            }
        }))
        .await
        .expect("create block through connector");
    let observation = fixture.join();
    let body: Value = serde_json::from_str(&observation.body).expect("parse request body");

    assert_request_boundary(&observation.request_line, EXPECTED_CREATE_PATH);
    assert!(observation.authorization_seen());
    assert!(observation.accept_json_seen());
    assert!(observation.content_type_json_seen());
    assert!(observation.user_agent_seen());
    assert_eq!(body["page"], CREATE_PAGE);
    assert_eq!(body["content"], CREATE_CONTENT);
    assert_eq!(result["uuid"], "block-1");
    assert_eq!(result["content"], CREATE_CONTENT);
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "logseq",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": BEAD_ID,
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_BLOCKS_CREATE,
        "method": "POST",
        "path": EXPECTED_CREATE_PATH,
        "request_line": observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen()
        },
        "body": {
            "page_verified": body["page"] == CREATE_PAGE,
            "content_verified": body["content"] == CREATE_CONTENT
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_error_does_not_leak_auth_material() {
    let fixture = LoopbackFixture::start(
        "429 Too Many Requests",
        "retry-after: 2\r\n",
        RATE_LIMIT_RESPONSE,
    );
    let connector = setup_connector(fixture.base_url()).await;

    let error = connector
        .handle_invoke(json!({
            "operation_id": OP_PAGES_LIST,
            "input": {}
        }))
        .await
        .expect_err("429 should map to external retryable error");
    let observation = fixture.join();

    assert!(observation.authorization_seen());
    match &error {
        FcpError::External {
            service,
            status_code,
            retryable,
            retry_after,
            ..
        } => {
            assert_eq!(service, "logseq");
            assert_eq!(*status_code, Some(429));
            assert!(*retryable);
            assert_eq!(retry_after.as_ref().map(Duration::as_secs), Some(2));
        }
        other => panic!("expected retryable external error, got {other:?}"),
    }
    assert!(!error.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "logseq",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": BEAD_ID,
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_PAGES_LIST,
        "error_mapping": "rate_limited",
        "authorization_header_verified": observation.authorization_seen(),
        "auth_material_leaked": false,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unknown_operation_fails_before_loopback_egress() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let base_url = format!(
        "http://{}/api",
        listener.local_addr().expect("read listener address")
    );
    let connector = setup_connector(&base_url).await;

    let error = connector
        .handle_invoke(json!({
            "operation_id": "logseq.unknown",
            "input": {}
        }))
        .await
        .expect_err("unknown operation should fail before egress");

    assert!(matches!(error, FcpError::InvalidRequest { .. }));
    let accept_error = listener
        .accept()
        .expect_err("operation denial should happen before loopback egress");
    assert_eq!(accept_error.kind(), io::ErrorKind::WouldBlock);

    let artifact = json!({
        "connector": "logseq",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": BEAD_ID,
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": "logseq.unknown",
        "denial": "unknown_operation",
        "loopback_egress_attempted": false,
        "result": "passed"
    });
    println!("{artifact}");
}
