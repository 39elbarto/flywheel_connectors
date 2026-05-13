use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_exa::ExaConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};

const API_KEY: &str = "exa_test_key";

struct CapturedRequest {
    head: String,
    body: Value,
}

struct LoopbackServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackServer {
    fn start(status: &'static str, extra_headers: &[(&str, &str)], body: &'static str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its local address")
        );
        let (request_tx, received) = mpsc::channel();
        let mut extra_headers_text = String::new();
        for &(name, value) in extra_headers {
            write!(&mut extra_headers_text, "{name}: {value}\r\n")
                .expect("loopback headers should format into a string");
        }

        let join = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .expect("loopback listener should accept one request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("loopback stream should set a read timeout");

            let request = read_complete_request(&mut stream);
            request_tx
                .send(request)
                .expect("captured request should be delivered to the test");

            let response = format!(
                "HTTP/1.1 {status}\r\n\
                 content-type: application/json\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\
                 {extra_headers_text}\r\n\
                 {body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("loopback response should be writable");
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn finish(self) -> CapturedRequest {
        let request = self
            .received
            .recv_timeout(Duration::from_secs(5))
            .expect("loopback server should capture one request");
        self.join
            .join()
            .expect("loopback server thread should finish cleanly");
        request
    }
}

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        assert!(count > 0, "client closed before request was complete");
        bytes.extend_from_slice(&buffer[..count]);

        let Some(body_start) = body_start_offset(&bytes) else {
            continue;
        };
        let head = String::from_utf8_lossy(&bytes[..body_start]).into_owned();
        let content_length = content_length(&head);
        if bytes.len() >= body_start + content_length {
            let body_end = body_start + content_length;
            let body = serde_json::from_slice(&bytes[body_start..body_end])
                .expect("loopback request body should be JSON");
            return CapturedRequest { head, body };
        }
    }
}

fn body_start_offset(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|header_end| header_end + 4)
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .expect("loopback request should include content-length")
}

fn header_value<'a>(head: &'a str, wanted: &str) -> &'a str {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case(wanted) {
                Some(value.trim())
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("missing expected header {wanted}"))
}

async fn configured_connector(base_url: &str) -> ExaConnector {
    let mut connector = ExaConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "base_url": base_url,
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("Exa connector should configure against loopback");
    connector
        .handle_handshake(json!({ "session_id": "exa-local-non-mock" }))
        .await
        .expect("Exa connector should handshake after configuration");
    connector
}

fn search_request(test_name: &str) -> Value {
    json!({
        "operation_id": "exa.search",
        "input": {
            "query": test_name,
            "numResults": 2,
            "type": "auto"
        }
    })
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_posts_headers_body_and_returns_json() {
    let server = LoopbackServer::start(
        "200 OK",
        &[],
        r#"{"results":[{"id":"r1","title":"FCP","url":"https://example.test/fcp"}]}"#,
    );
    let connector = configured_connector(&server.base_url).await;

    let result = connector
        .handle_invoke(search_request("secure connector protocol"))
        .await
        .expect("loopback Exa search should succeed");
    let captured = server.finish();
    let health = connector
        .handle_health()
        .await
        .expect("health should be readable after invoke");

    assert!(captured.head.starts_with("POST /search HTTP/1.1"));
    assert_eq!(header_value(&captured.head, "x-api-key"), API_KEY);
    assert_eq!(header_value(&captured.head, "x-exa-integration"), "fcp");
    assert_eq!(captured.body["query"], json!("secure connector protocol"));
    assert_eq!(captured.body["numResults"], json!(2));
    assert_eq!(captured.body["type"], json!("auto"));
    assert_eq!(result["results"][0]["title"], json!("FCP"));
    assert_eq!(health["requests"], json!(1));
    assert_eq!(health["errors"], json!(0));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_reports_retryable_upstream_error() {
    let server = LoopbackServer::start(
        "503 Service Unavailable",
        &[("retry-after", "7")],
        r#"{"error":"upstream unavailable"}"#,
    );
    let connector = configured_connector(&server.base_url).await;

    let error = connector
        .handle_invoke(search_request("retryable upstream failure"))
        .await
        .expect_err("503 loopback response should map to an external error");
    let captured = server.finish();
    let health = connector
        .handle_health()
        .await
        .expect("health should be readable after error");

    assert!(captured.head.starts_with("POST /search HTTP/1.1"));
    assert_eq!(captured.body["query"], json!("retryable upstream failure"));
    assert_eq!(health["requests"], json!(1));
    assert_eq!(health["errors"], json!(1));
    match error {
        FcpError::External {
            service,
            status_code,
            retryable,
            retry_after,
            ..
        } => {
            assert_eq!(service, "exa");
            assert_eq!(status_code, Some(503));
            assert!(retryable);
            assert_eq!(retry_after, Some(Duration::from_secs(7)));
        }
        other => panic!("expected retryable external error, got {other:?}"),
    }
}
