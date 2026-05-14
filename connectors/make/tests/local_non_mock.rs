//! Local loopback acceptance coverage for the FCP `Make` connector.

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

use fcp_make::connector::MakeConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};

const CONNECTOR: &str = "make";
const PACKAGE: &str = "fcp-make";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.22";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const LOOPBACK_API_TOKEN: &str = "make-local-non-mock-token";
const OP_SCENARIOS_LIST: &str = "make.scenarios.list";
const OP_SCENARIOS_RUN: &str = "make.scenarios.run";
const OP_EXECUTIONS_LIST: &str = "make.executions.list";

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
async fn local_non_mock_scenarios_run_and_executions_use_production_http_client() {
    let server = LoopbackServer::start(vec![
        HttpResponse::json(
            "200 OK",
            r#"{"scenarios":[{"id":"12345","name":"Ops workflow","enabled":true}]}"#,
        ),
        HttpResponse::json("200 OK", r#"{"executionId":"exec_abc"}"#),
        HttpResponse::json(
            "200 OK",
            r#"{"executions":[{"id":"exec_abc","status":"success"}]}"#,
        ),
    ]);
    let mut connector = setup_connector(&server.base_url).await;

    let scenarios = connector
        .handle_invoke(json!({
            "operation_id": OP_SCENARIOS_LIST,
            "input": {}
        }))
        .await
        .expect("scenarios.list should invoke Make client path");
    assert_eq!(scenarios["scenarios"][0]["id"], "12345");

    let run = connector
        .handle_invoke(json!({
            "operation_id": OP_SCENARIOS_RUN,
            "input": {"scenario_id": "12345"}
        }))
        .await
        .expect("scenarios.run should invoke Make client path");
    assert_eq!(run["execution_id"], "exec_abc");

    let executions = connector
        .handle_invoke(json!({
            "operation_id": OP_EXECUTIONS_LIST,
            "input": {"scenario_id": "12345"}
        }))
        .await
        .expect("executions.list should invoke Make client path");
    assert_eq!(executions["executions"][0]["id"], "exec_abc");

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let requests = server.join();
    assert_eq!(requests.len(), 3);
    assert_request(&requests[0], "GET /scenarios HTTP/1.1");
    assert_request(&requests[1], "POST /scenarios/12345/run HTTP/1.1");
    assert_request(&requests[2], "GET /scenarios/12345/executions HTTP/1.1");
    assert_eq!(requests[0].body, json!({}));
    assert_eq!(requests[1].body, json!({}));
    assert_eq!(requests[2].body, json!({}));

    let rendered = serde_json::to_string(&json!({
        "scenarios": scenarios,
        "run": run,
        "executions": executions,
    }))
    .expect("rendered result should serialize");
    assert!(!rendered.contains(LOOPBACK_API_TOKEN));

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "scenarios_list": {
                "method": "GET",
                "path": "/scenarios",
                "status": 200
            },
            "scenarios_run": {
                "method": "POST",
                "path": "/scenarios/12345/run",
                "status": 200
            },
            "executions_list": {
                "method": "GET",
                "path": "/scenarios/12345/executions",
                "status": 200
            }
        },
        "auth_gate": {
            "mode": "token_header",
            "authorization_header_verified": true
        },
        "write_operation_shape": {
            "scenario_run_exercised_only_against_loopback": true,
            "scenario_id": "12345"
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
        r#"{"message":"Unauthorized"}"#,
    )]);
    let connector = setup_connector(&server.base_url).await;

    let err = connector
        .handle_invoke(json!({
            "operation_id": OP_SCENARIOS_LIST,
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
            } if service == "make"
        ),
        "unauthorized response should map to non-retryable Make external error: {err:?}"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "GET /scenarios HTTP/1.1");

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "method": "GET",
            "path": "/scenarios",
            "status": 401
        },
        "error_mapping": {
            "service": "make",
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
async fn local_non_mock_rejects_scenario_path_traversal_before_egress() {
    let server = LoopbackServer::start(Vec::new());
    let connector = setup_connector(&server.base_url).await;

    let err = connector
        .handle_invoke(json!({
            "operation_id": OP_SCENARIOS_RUN,
            "input": {"scenario_id": "../private"}
        }))
        .await
        .expect_err("path traversal scenario_id should be rejected before egress");
    assert!(
        matches!(
            &err,
            FcpError::InvalidRequest {
                code: 1005,
                message,
            } if message.contains("path traversal")
        ),
        "path traversal should map to invalid request: {err:?}"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 0);

    let artifact = proof_artifact(&json!({
        "egress_gate": {
            "operation": OP_SCENARIOS_RUN,
            "unsafe_scenario_id_rejected_before_http": true,
            "requests_sent": requests.len()
        },
        "cleanup": {
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

async fn setup_connector(base_url: &str) -> MakeConnector {
    let mut connector = MakeConnector::new();
    connector
        .handle_configure(json!({
            "api_token": LOOPBACK_API_TOKEN,
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
            &format!("Token {LOOPBACK_API_TOKEN}")
        ),
        "request should carry configured Make token authorization; head={}",
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
        "command": "cargo test -p fcp-make --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "details": details
    })
}
