//! Local loopback acceptance coverage for the FCP `SendGrid` connector.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    collections::VecDeque,
    fmt::Write as FmtWrite,
    io::{Read, Write as IoWrite},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use fcp_prelude::FcpError;
use fcp_sendgrid::connector::SendGridConnector;
use serde_json::{Value, json};

const CONNECTOR: &str = "sendgrid";
const PACKAGE: &str = "fcp-sendgrid";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.17";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const LOOPBACK_AUTH_MARKER: &str = "SG.loopback-auth-marker";
const OP_MAIL_SEND: &str = "sendgrid.mail.send";
const OP_CONTACTS_LIST: &str = "sendgrid.contacts.list";
const OP_CONTACTS_SEARCH: &str = "sendgrid.contacts.search";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Value,
}

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    body: &'static str,
    retry_after: Option<&'static str>,
}

impl HttpResponse {
    const fn json(status: &'static str, body: &'static str) -> Self {
        Self {
            status,
            body,
            retry_after: None,
        }
    }

    const fn empty(status: &'static str) -> Self {
        Self {
            status,
            body: "",
            retry_after: None,
        }
    }

    const fn rate_limited(body: &'static str, retry_after: &'static str) -> Self {
        Self {
            status: "429 Too Many Requests",
            body,
            retry_after: Some(retry_after),
        }
    }
}

struct LoopbackServer {
    base_url: String,
    join: JoinHandle<Vec<CapturedRequest>>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its address")
        );
        let join = thread::spawn(move || {
            let mut responses = VecDeque::from(responses);
            let mut requests = Vec::new();
            while let Some(response) = responses.pop_front() {
                let (mut stream, _) = listener.accept().expect("accept loopback request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set loopback read timeout");
                let request = read_complete_request(&mut stream);
                requests.push(request);
                write_response(&mut stream, response);
            }
            requests
        });

        Self { base_url, join }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(self) -> Vec<CapturedRequest> {
        self.join
            .join()
            .expect("loopback server thread should finish")
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_mail_send_and_contacts_list_use_production_http_client() {
    let server = LoopbackServer::start(vec![
        HttpResponse::empty("202 Accepted"),
        HttpResponse::json(
            "200 OK",
            r#"{
                "result": [
                    {"id": "contact-1", "email": "ops@example.com", "first_name": "Ops"}
                ]
            }"#,
        ),
    ]);
    let mut connector = setup_connector(server.base_url()).await;

    let sent = connector
        .handle_invoke(json!({
            "operation_id": OP_MAIL_SEND,
            "input": {
                "personalizations": [{"to": [{"email": "ops@example.com"}]}],
                "from": {"email": "noreply@example.com"},
                "subject": "Local acceptance",
                "content": [{"type": "text/plain", "value": "queued"}]
            }
        }))
        .await
        .expect("mail send should invoke SendGrid client path");
    assert_eq!(sent, json!({}));

    let contacts = connector
        .handle_invoke(json!({
            "operation_id": OP_CONTACTS_LIST,
            "input": {}
        }))
        .await
        .expect("contacts list should invoke SendGrid client path");
    assert_eq!(contacts["contacts"][0]["email"], "ops@example.com");

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let requests = server.join();
    assert_eq!(requests.len(), 2);
    assert_request(&requests[0], "POST /mail/send HTTP/1.1");
    assert_request(&requests[1], "GET /marketing/contacts HTTP/1.1");
    assert_eq!(
        requests[0].body["personalizations"][0]["to"][0]["email"],
        "ops@example.com"
    );
    assert_eq!(requests[0].body["subject"], "Local acceptance");

    let rendered = serde_json::to_string(&json!({
        "sent": sent,
        "contacts": contacts,
    }))
    .expect("rendered result should serialize");
    assert!(!rendered.contains(LOOPBACK_AUTH_MARKER));

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "mail_send": {
                "method": "POST",
                "path": "/mail/send",
                "status": 202
            },
            "contacts_list": {
                "method": "GET",
                "path": "/marketing/contacts",
                "status": 200
            }
        },
        "auth_gate": {
            "mode": "bearer_header",
            "authorization_header_verified": true
        },
        "redaction": {
            "auth_marker_redacted_from_output": true
        },
        "cleanup": {
            "connector_shutdown": true,
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retryable_external_error() {
    let server = LoopbackServer::start(vec![HttpResponse::rate_limited(
        r#"{"errors":[{"message":"too many requests"}]}"#,
        "7",
    )]);
    let connector = setup_connector(server.base_url()).await;

    let err = connector
        .handle_invoke(json!({
            "operation_id": OP_CONTACTS_SEARCH,
            "input": {"query": "email LIKE '%@example.com'"}
        }))
        .await
        .expect_err("rate limit should map to retryable FCP external error");
    assert!(
        matches!(
            &err,
            FcpError::External {
                service,
                status_code: Some(429),
                retryable: true,
                retry_after: Some(after),
                ..
            } if service == "sendgrid" && *after == Duration::from_secs(7)
        ),
        "rate-limit response should map to retryable SendGrid external error: {err:?}"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "POST /marketing/contacts/search HTTP/1.1");
    assert_eq!(
        requests[0].body,
        json!({"query": "email LIKE '%@example.com'"})
    );

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "method": "POST",
            "path": "/marketing/contacts/search",
            "status": 429,
            "retry_after_secs": 7
        },
        "error_mapping": {
            "service": "sendgrid",
            "status_code": 429,
            "retryable": true
        },
        "cleanup": {
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

async fn setup_connector(base_url: &str) -> SendGridConnector {
    let mut connector = SendGridConnector::new();
    connector
        .handle_configure(json!({
            "api_key": LOOPBACK_AUTH_MARKER,
            "base_url": base_url
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({"session_id": "local-non-mock"}))
        .await
        .expect("handshake connector");
    connector
}

fn assert_request(captured: &CapturedRequest, request_line: &str) {
    assert_eq!(
        captured
            .head
            .lines()
            .next()
            .expect("captured request should include request line"),
        request_line
    );
    assert!(
        header_seen(
            &captured.head,
            "authorization",
            &format!("Bearer {LOOPBACK_AUTH_MARKER}")
        ),
        "request should carry configured bearer authorization; head={}",
        captured.head
    );
    assert!(
        header_seen(&captured.head, "accept", "application/json"),
        "request should accept JSON; head={}",
        captured.head
    );
}

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        assert_ne!(read, 0, "loopback request ended before headers completed");
        bytes.extend_from_slice(&buffer[..read]);

        if let Some(header_end) = find_header_end(&bytes) {
            let body_start = header_end + 4;
            let head = String::from_utf8(bytes[..header_end].to_vec())
                .expect("HTTP request headers should be UTF-8");
            let content_length = content_length(&head);
            while bytes.len() < body_start + content_length {
                let read = stream
                    .read(&mut buffer)
                    .expect("loopback request body should be readable");
                assert_ne!(read, 0, "loopback request body ended early");
                bytes.extend_from_slice(&buffer[..read]);
            }
            let body = if content_length == 0 {
                json!({})
            } else {
                serde_json::from_slice(&bytes[body_start..body_start + content_length])
                    .expect("request body should be JSON")
            };
            return CapturedRequest { head, body };
        }
    }
}

fn write_response(stream: &mut TcpStream, response: HttpResponse) {
    let mut raw = format!("HTTP/1.1 {}\r\n", response.status);
    raw.push_str("content-type: application/json\r\n");
    if let Some(retry_after) = response.retry_after {
        write!(&mut raw, "retry-after: {retry_after}\r\n").expect("retry-after should format");
    }
    write!(&mut raw, "content-length: {}\r\n", response.body.len())
        .expect("content-length should format");
    raw.push_str("connection: close\r\n\r\n");
    raw.push_str(response.body);
    stream
        .write_all(raw.as_bytes())
        .expect("loopback response should be writable");
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("content-length number")
            })
        })
        .unwrap_or(0)
}

fn header_seen(head: &str, name: &str, expected: &str) -> bool {
    head.lines().any(|line| {
        let Some((header_name, value)) = line.split_once(':') else {
            return false;
        };
        header_name.eq_ignore_ascii_case(name) && value.trim() == expected
    })
}

fn proof_artifact(details: &Value) -> Value {
    json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-sendgrid --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "details": details
    })
}
