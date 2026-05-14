//! Local loopback acceptance coverage for the FCP Runway connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_prelude::FcpError;
use fcp_runway::RunwayConnector;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.46";
const ACCESS_SECRET: &str = "local_runway_acceptance_secret";
const RUNWAY_VERSION: &str = "2024-11-06";
const USER_AGENT: &str =
    "fcp-runway/0.1.0 (+https://github.com/Dicklesworthstone/flywheel_connectors)";
const OP_TEXT_TO_VIDEO: &str = "runway.video.text_to_video";
const OP_STATUS: &str = "runway.job.status";

const TEXT_TO_VIDEO_RESPONSE_BODY: &str = r#"{
  "id": "task-text",
  "status": "PENDING"
}"#;

const DONE_TASK_RESPONSE_BODY: &str = r#"{
  "id": "task-done",
  "status": "SUCCEEDED",
  "createdAt": "2026-05-14T00:00:00Z",
  "updatedAt": "2026-05-14T00:01:00Z",
  "creditsUsed": 12,
  "output": [
    "https://cdn.runway.example/video.mp4?signature=secret",
    {
      "url": "https://cdn.runway.example/poster.png?signature=secret",
      "contentType": "image/png",
      "sizeBytes": 4096
    }
  ]
}"#;

const RATE_LIMIT_BODY: &str = r#"{
  "error": {
    "message": "Too many local requests"
  }
}"#;

#[derive(Debug, Clone, Copy)]
struct ResponseSpec {
    status: u16,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
}

impl ResponseSpec {
    const fn json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            headers: &[],
            body,
        }
    }

    const fn with_headers(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: &'static str,
    ) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
struct RequestObservation {
    request_line: String,
    headers: Vec<String>,
    body: String,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackFixture {
    fn start(responses: Vec<ResponseSpec>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Runway listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, response)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}/v1"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> Vec<RequestObservation> {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: ResponseSpec) -> RequestObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let raw = read_http_message(&mut stream);
    let header_end = find_header_end(&raw).expect("request contains header terminator");
    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();
    let body = String::from_utf8_lossy(&raw[header_end + 4..]).to_string();

    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        status_reason(response.status),
        response.body.len()
    )
    .expect("write response headers");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write extra response header");
    }
    write!(stream, "\r\n{}", response.body).expect("write response body");

    RequestObservation {
        request_line,
        headers,
        body,
    }
}

fn read_http_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let total_len = header_end + 4 + content_length(&headers);
            while request.len() < total_len {
                let bytes_read = stream
                    .read(&mut buffer)
                    .expect("read connector request body");
                assert!(bytes_read > 0, "connector body should not close early");
                request.extend_from_slice(&buffer[..bytes_read]);
                assert!(request.len() < 16384, "request body should stay bounded");
            }
            request.truncate(total_len);
            return request;
        }

        assert!(request.len() < 16384, "request headers should stay bounded");
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("content-length is usize")
            })
        })
        .unwrap_or(0)
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        429 => "Too Many Requests",
        _ => "Status",
    }
}

fn has_header(headers: &[String], name: &str, expected_value: &str) -> bool {
    headers.iter().any(|line| {
        let Some((actual_name, actual_value)) = line.split_once(':') else {
            return false;
        };
        actual_name.eq_ignore_ascii_case(name) && actual_value.trim() == expected_value
    })
}

fn assert_header(headers: &[String], name: &str, expected_value: &str) {
    assert!(
        has_header(headers, name, expected_value),
        "expected header {name}: {expected_value}, got {headers:?}"
    );
}

fn assert_required_headers(observation: &RequestObservation) {
    let expected_auth = format!("Bearer {ACCESS_SECRET}");
    assert_header(&observation.headers, "authorization", &expected_auth);
    assert_header(&observation.headers, "accept", "application/json");
    assert_header(&observation.headers, "user-agent", USER_AGENT);
    assert_header(&observation.headers, "x-runway-version", RUNWAY_VERSION);
}

fn request_path(request_line: &str) -> &str {
    request_line.split_whitespace().nth(1).unwrap_or_default()
}

async fn configured_connector(base_url: &str, request_timeout_ms: u64) -> RunwayConnector {
    let mut connector = RunwayConnector::new();
    connector
        .handle_configure(json!({
            "api_key": ACCESS_SECRET,
            "base_url": base_url,
            "request_timeout_ms": request_timeout_ms,
            "max_retries": 0,
            "default_poll_interval_ms": 1
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake connector");
    connector
}

fn invoke(operation: &str, input: &Value) -> Value {
    json!({
        "operation": operation,
        "input": input
    })
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_submit_and_status_cross_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, TEXT_TO_VIDEO_RESPONSE_BODY),
        ResponseSpec::json(200, DONE_TASK_RESPONSE_BODY),
    ]);
    let connector = configured_connector(fixture.base_url(), 5_000).await;

    let submit = connector
        .handle_invoke(invoke(
            OP_TEXT_TO_VIDEO,
            &json!({
                "model": "gen4.5",
                "promptText": "local acceptance scene",
                "duration": 5
            }),
        ))
        .await
        .expect("text-to-video submit should succeed");
    assert_eq!(submit["provider"], "runway");
    assert_eq!(submit["operation_class"], "text_to_video");
    assert_eq!(submit["task_id"], "task-text");
    assert_eq!(submit["model"], "gen4.5");
    assert_eq!(submit["binary_proxying"], false);

    let status = connector
        .handle_invoke(invoke(OP_STATUS, &json!({"task_id": "task-done"})))
        .await
        .expect("status should succeed");
    assert_eq!(status["provider"], "runway");
    assert_eq!(status["task_id"], "task-done");
    assert_eq!(status["status"], "SUCCEEDED");
    assert_eq!(status["output_summary"]["output_count"], 2);
    assert_eq!(status["output_summary"]["byte_count"], 4096);
    assert_eq!(
        status["output_summary"]["url_hosts"],
        json!(["cdn.runway.example"])
    );
    assert!(
        status["output_summary"]["url_hashes"][0]
            .as_str()
            .expect("hash should be string")
            .starts_with("blake3:")
    );
    assert!(
        !status["output_summary"]["url_hashes"][0]
            .as_str()
            .expect("hash should be string")
            .contains("https://")
    );

    let observations = fixture.join();
    assert_eq!(observations.len(), 2);

    let submit_request = &observations[0];
    assert_eq!(
        submit_request.request_line,
        "POST /v1/text_to_video HTTP/1.1"
    );
    assert_required_headers(submit_request);
    assert_header(&submit_request.headers, "content-type", "application/json");
    let submit_body: Value =
        serde_json::from_str(&submit_request.body).expect("submit body is JSON");
    assert_eq!(submit_body["model"], "gen4.5");
    assert_eq!(submit_body["promptText"], "local acceptance scene");
    assert_eq!(submit_body["duration"], 5);
    assert!(!submit_request.body.contains(ACCESS_SECRET));

    let status_request = &observations[1];
    assert_eq!(
        status_request.request_line,
        "GET /v1/tasks/task-done HTTP/1.1"
    );
    assert_required_headers(status_request);
    assert!(status_request.body.is_empty());

    let evidence = json!({
        "suite": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "connector": "runway",
        "operations": [OP_TEXT_TO_VIDEO, OP_STATUS],
        "request_paths": [
            request_path(&submit_request.request_line),
            request_path(&status_request.request_line),
        ],
        "required_headers_verified": [
            "authorization",
            "accept",
            "user-agent",
            "x-runway-version"
        ],
        "status": status["status"],
        "task_id": submit["task_id"],
        "output_summary": status["output_summary"],
        "binary_proxying": status["binary_proxying"],
    });
    let evidence_text = evidence.to_string();
    assert!(!evidence_text.contains(ACCESS_SECRET));
    assert!(!evidence_text.contains("signature=secret"));
    println!("{evidence}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_metadata() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::with_headers(
        429,
        &[("retry-after", "3")],
        RATE_LIMIT_BODY,
    )]);
    let connector = configured_connector(fixture.base_url(), 5_000).await;

    let limited = connector
        .handle_invoke(invoke(OP_STATUS, &json!({"task_id": "rate"})))
        .await
        .expect_err("rate limit should fail");
    let limited_debug = format!("{limited:?}");
    assert!(!limited_debug.contains(ACCESS_SECRET));
    let retry_after_ms = match limited {
        FcpError::RateLimited {
            retry_after_ms,
            violation,
        } => {
            assert!(violation.is_none());
            retry_after_ms
        }
        other => panic!("expected rate limit, got {other:?}"),
    };
    assert_eq!(retry_after_ms, 3_000);

    let observations = fixture.join();
    assert_eq!(observations.len(), 1);
    let status_request = &observations[0];
    assert_eq!(status_request.request_line, "GET /v1/tasks/rate HTTP/1.1");
    assert_required_headers(status_request);
    assert!(status_request.body.is_empty());

    let evidence = json!({
        "suite": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "connector": "runway",
        "operation": OP_STATUS,
        "request_path": request_path(&status_request.request_line),
        "error_class": "rate_limited",
        "retry_after_ms": retry_after_ms,
        "secret_redaction_checked": true,
    });
    let evidence_text = evidence.to_string();
    assert!(!evidence_text.contains(ACCESS_SECRET));
    assert!(!evidence_text.contains("Too many local requests"));
    println!("{evidence}");
}
