//! Local loopback acceptance coverage for the FCP `Zapier` connector.

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
use fcp_zapier::connector::ZapierConnector;
use serde_json::{Value, json};

const CONNECTOR: &str = "zapier";
const PACKAGE: &str = "fcp-zapier";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.24";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const LOOPBACK_API_TOKEN: &str = "zapier-local-non-mock-token";
const OP_ZAPS_LIST: &str = "zapier.zaps.list";
const OP_ZAPS_EXECUTE: &str = "zapier.zaps.execute";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Value,
}

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    body: &'static str,
}

impl HttpResponse {
    const fn json(status: &'static str, body: &'static str) -> Self {
        Self { status, body }
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

    fn join(self) -> Vec<CapturedRequest> {
        self.join
            .join()
            .expect("loopback server thread should finish")
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_zaps_list_and_execute_use_production_http_client() {
    let server = LoopbackServer::start(vec![
        HttpResponse::json(
            "200 OK",
            r#"{"zaps":[{"id":"zap_123","title":"Notify team","enabled":true}]}"#,
        ),
        HttpResponse::json("200 OK", r#"{"status":"accepted","request_id":"req_abc"}"#),
    ]);
    let mut connector = setup_connector(&server.base_url).await;

    let zaps = connector
        .handle_invoke(json!({
            "operation_id": OP_ZAPS_LIST,
            "input": {}
        }))
        .await
        .expect("zaps.list should invoke Zapier client path");
    assert_eq!(zaps["zaps"][0]["id"], "zap_123");

    let executed = connector
        .handle_invoke(json!({
            "operation_id": OP_ZAPS_EXECUTE,
            "input": {
                "action_id": "act_123",
                "params": {
                    "instructions": "Summarize ticket",
                    "ticket_id": "T-1"
                }
            }
        }))
        .await
        .expect("zaps.execute should invoke Zapier client path");
    assert_eq!(executed["result"]["status"], "accepted");
    assert_eq!(executed["result"]["request_id"], "req_abc");

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let requests = server.join();
    assert_eq!(requests.len(), 2);
    assert_request(&requests[0], "GET /exposed/ HTTP/1.1");
    assert_request(&requests[1], "POST /exposed/act_123/execute/ HTTP/1.1");
    assert_eq!(requests[0].body, json!({}));
    assert_eq!(requests[1].body["instructions"], "Summarize ticket");
    assert_eq!(requests[1].body["ticket_id"], "T-1");

    let rendered = serde_json::to_string(&json!({
        "zaps": zaps,
        "executed": executed,
    }))
    .expect("rendered result should serialize");
    assert!(!rendered.contains(LOOPBACK_API_TOKEN));

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "zaps_list": {
                "method": "GET",
                "path": "/exposed/",
                "status": 200
            },
            "zaps_execute": {
                "method": "POST",
                "path": "/exposed/act_123/execute/",
                "status": 200
            }
        },
        "auth_gate": {
            "mode": "bearer_token",
            "authorization_header_verified": true
        },
        "write_operation_shape": {
            "zaps_execute_exercised_only_against_loopback": true,
            "action_id": "act_123",
            "params": ["instructions", "ticket_id"]
        },
        "redaction": {
            "api_token_redacted_from_output": true
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
async fn local_non_mock_unauthorized_maps_non_retryable_external_error() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "401 Unauthorized",
        r#"{"error":"Unauthorized"}"#,
    )]);
    let connector = setup_connector(&server.base_url).await;

    let err = connector
        .handle_invoke(json!({
            "operation_id": OP_ZAPS_LIST,
            "input": {}
        }))
        .await
        .expect_err("401 should map to an FCP external error");
    assert!(
        matches!(
            &err,
            FcpError::External {
                service,
                status_code: Some(401),
                retryable: false,
                retry_after: None,
                ..
            } if service == "zapier"
        ),
        "unauthorized response should map to non-retryable Zapier external error: {err:?}"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "GET /exposed/ HTTP/1.1");

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "method": "GET",
            "path": "/exposed/",
            "status": 401
        },
        "error_mapping": {
            "service": "zapier",
            "status_code": 401,
            "retryable": false
        },
        "cleanup": {
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rejects_action_path_traversal_before_egress() {
    let server = LoopbackServer::start(Vec::new());
    let connector = setup_connector(&server.base_url).await;

    let err = connector
        .handle_invoke(json!({
            "operation_id": OP_ZAPS_EXECUTE,
            "input": {
                "action_id": "../private",
                "params": {"instructions": "should not leave process"}
            }
        }))
        .await
        .expect_err("path traversal action_id should be rejected before egress");
    assert!(
        matches!(
            &err,
            FcpError::InvalidRequest {
                code: 1005,
                message,
            } if message.contains("action_id") && message.contains("forbidden character")
        ),
        "path traversal should map to invalid request: {err:?}"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 0);

    let artifact = proof_artifact(&json!({
        "egress_gate": {
            "operation": OP_ZAPS_EXECUTE,
            "unsafe_action_id_rejected_before_http": true,
            "requests_sent": requests.len()
        },
        "cleanup": {
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

async fn setup_connector(base_url: &str) -> ZapierConnector {
    let mut connector = ZapierConnector::new();
    connector
        .handle_configure(json!({
            "api_key": LOOPBACK_API_TOKEN,
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
            &format!("Bearer {LOOPBACK_API_TOKEN}")
        ),
        "request should carry configured Zapier bearer authorization; head={}",
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
        "command": "cargo test -p fcp-zapier --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "details": details
    })
}
