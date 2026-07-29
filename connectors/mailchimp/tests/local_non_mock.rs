//! Local loopback acceptance coverage for the FCP `Mailchimp` connector.

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

use base64::{Engine as _, engine::general_purpose};
use fcp_mailchimp::connector::MailchimpConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};

const CONNECTOR: &str = "mailchimp";
const PACKAGE: &str = "fcp-mailchimp";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.19";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const LOOPBACK_API_KEY: &str = "mailchimp-local-non-mock-us1";
const OP_LISTS_LIST: &str = "mailchimp.lists.list";
const OP_MEMBERS_DELETE: &str = "mailchimp.members.delete";
const OP_CAMPAIGNS_SEND: &str = "mailchimp.campaigns.send";
const OP_CAMPAIGNS_LIST: &str = "mailchimp.campaigns.list";

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

    fn mailchimp_base_url(&self) -> String {
        format!("{}/3.0", self.base_url)
    }

    fn join(self) -> Vec<CapturedRequest> {
        self.join
            .join()
            .expect("loopback server thread should finish")
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_lists_delete_and_campaign_send_use_production_http_client() {
    let server = LoopbackServer::start(vec![
        HttpResponse::json(
            "200 OK",
            r#"{"lists":[{"id":"list_abc","name":"Ops"}],"total_items":1}"#,
        ),
        HttpResponse::empty("204 No Content"),
        HttpResponse::empty("204 No Content"),
    ]);
    let mut connector = setup_connector(&server.mailchimp_base_url()).await;

    let lists = connector
        .handle_invoke(json!({
            "operation_id": OP_LISTS_LIST,
            "input": {}
        }))
        .await
        .expect("lists.list should invoke Mailchimp client path");
    assert_eq!(lists["lists"][0]["id"], "list_abc");

    let deleted = connector
        .handle_invoke(json!({
            "operation_id": OP_MEMBERS_DELETE,
            "input": {
                "list_id": "list_abc",
                "subscriber_hash": "d41d8cd98f00b204e9800998ecf8427e"
            }
        }))
        .await
        .expect("members.delete should invoke Mailchimp client path");
    assert_eq!(deleted, json!({}));

    let sent = connector
        .handle_invoke(json!({
            "operation_id": OP_CAMPAIGNS_SEND,
            "input": {"campaign_id": "camp_123"}
        }))
        .await
        .expect("campaigns.send should invoke Mailchimp client path");
    assert_eq!(sent, json!({}));

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let requests = server.join();
    assert_eq!(requests.len(), 3);
    assert_request(&requests[0], "GET /3.0/lists HTTP/1.1");
    assert_request(
        &requests[1],
        "DELETE /3.0/lists/list_abc/members/d41d8cd98f00b204e9800998ecf8427e HTTP/1.1",
    );
    assert_request(
        &requests[2],
        "POST /3.0/campaigns/camp_123/actions/send HTTP/1.1",
    );
    assert_eq!(requests[0].body, json!({}));
    assert_eq!(requests[1].body, json!({}));
    assert_eq!(requests[2].body, json!({}));

    let rendered = serde_json::to_string(&json!({
        "lists": lists,
        "deleted": deleted,
        "sent": sent,
    }))
    .expect("rendered result should serialize");
    assert!(!rendered.contains(LOOPBACK_API_KEY));

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "lists_list": {
                "method": "GET",
                "path": "/3.0/lists",
                "status": 200
            },
            "members_delete": {
                "method": "DELETE",
                "path": "/3.0/lists/list_abc/members/<subscriber_hash>",
                "status": 204
            },
            "campaigns_send": {
                "method": "POST",
                "path": "/3.0/campaigns/camp_123/actions/send",
                "status": 204
            }
        },
        "auth_gate": {
            "mode": "basic_auth_anyuser_api_key",
            "authorization_header_verified": true
        },
        "destructive_operation_shape": {
            "members_delete_exercised_only_against_loopback": true,
            "campaign_send_exercised_only_against_loopback": true
        },
        "redaction": {
            "api_key_redacted_from_output": true
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
        r#"{"title":"Too Many Requests","detail":"slow down","status":429}"#,
        "7",
    )]);
    let connector = setup_connector(&server.mailchimp_base_url()).await;

    let err = connector
        .handle_invoke(json!({
            "operation_id": OP_CAMPAIGNS_LIST,
            "input": {}
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
            } if service == "mailchimp" && *after == Duration::from_secs(7)
        ),
        "rate-limit response should map to retryable Mailchimp external error: {err:?}"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "GET /3.0/campaigns HTTP/1.1");

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "method": "GET",
            "path": "/3.0/campaigns",
            "status": 429,
            "retry_after_secs": 7
        },
        "error_mapping": {
            "service": "mailchimp",
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

async fn setup_connector(base_url: &str) -> MailchimpConnector {
    let mut connector = MailchimpConnector::new();
    connector
        .handle_configure(json!({
            "api_key": LOOPBACK_API_KEY,
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
        header_seen(&captured.head, "authorization", &expected_auth_header()),
        "request should carry configured Mailchimp Basic authorization; head={}",
        captured.head
    );
    assert!(
        header_seen(&captured.head, "accept", "application/json"),
        "request should accept JSON; head={}",
        captured.head
    );
}

fn expected_auth_header() -> String {
    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(format!("anyuser:{LOOPBACK_API_KEY}"))
    )
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
        "command": "cargo test -p fcp-mailchimp --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "details": details
    })
}
