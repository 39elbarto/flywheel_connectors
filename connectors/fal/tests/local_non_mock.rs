#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration as StdDuration, Instant};

use fcp_fal::FalConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};

const API_KEY: &str = "fal-local-acceptance-key";
const OP_SUBMIT: &str = "fal.media.submit";
const OP_STATUS: &str = "fal.job.status";
const MODEL_ROUTE: &str = "fal-ai/flux/schnell";
const REQUEST_ID: &str = "req_local_123";
const SECRET_PROMPT: &str = "secret local prompt";

struct CapturedRequest {
    head: String,
    body: Option<Value>,
}

struct LoopbackResponse {
    status: &'static str,
    body: String,
}

struct LoopbackServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackServer {
    fn start(responses: Vec<LoopbackResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        listener
            .set_nonblocking(true)
            .expect("loopback listener should support bounded accepts");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its address")
        );
        let (request_tx, received) = mpsc::channel();

        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = accept_expected_request(&listener);
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(5)))
                    .expect("loopback stream should set a read timeout");

                let request = read_complete_request(&mut stream);
                request_tx
                    .send(request)
                    .expect("captured request should be delivered to the test");

                let response_text = format!(
                    "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response.status,
                    response.body.len(),
                    response.body
                );
                stream
                    .write_all(response_text.as_bytes())
                    .expect("loopback response should be writable");
            }
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn finish(self) -> Vec<CapturedRequest> {
        let mut requests = Vec::new();
        while let Ok(request) = self.received.recv_timeout(StdDuration::from_millis(100)) {
            requests.push(request);
        }
        self.join
            .join()
            .expect("loopback server thread should finish cleanly");
        requests
    }
}

fn accept_expected_request(listener: &TcpListener) -> (TcpStream, std::net::SocketAddr) {
    let deadline = Instant::now() + StdDuration::from_secs(5);
    loop {
        match listener.accept() {
            Ok(connection) => return connection,
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                panic!("loopback listener timed out waiting for expected request");
            }
            Err(error) => panic!("loopback listener failed while accepting request: {error}"),
        }
    }
}

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut header_end = None;
    let mut content_length = 0_usize;

    loop {
        let count = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        assert!(count > 0, "client closed before request was complete");
        bytes.extend_from_slice(&buffer[..count]);

        if header_end.is_none()
            && let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
        {
            header_end = Some(end);
            let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
            content_length = parse_content_length(&head);
        }

        if let Some(end) = header_end {
            let body_start = end + 4;
            if bytes.len() >= body_start + content_length {
                let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
                let body_bytes = &bytes[body_start..body_start + content_length];
                let body = if body_bytes.is_empty() {
                    None
                } else {
                    Some(
                        serde_json::from_slice(body_bytes)
                            .expect("loopback request body should be JSON"),
                    )
                };
                return CapturedRequest { head, body };
            }
        }
    }
}

fn parse_content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn request_method(head: &str) -> &str {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .expect("request line should include method")
}

fn request_target(head: &str) -> &str {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("request line should include target")
}

fn header_value<'a>(head: &'a str, wanted: &str) -> &'a str {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted).then_some(value.trim())
        })
        .unwrap_or_else(|| panic!("missing expected header {wanted}"))
}

async fn configured_connector(base_url: &str) -> FalConnector {
    let mut connector = FalConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "queue_base_url": base_url,
            "request_timeout_ms": 5_000,
            "max_retries": 0,
            "retry_backoff_ms": 1
        }))
        .await
        .expect("Fal connector should configure against loopback");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("Fal connector should handshake after configuration");
    connector
}

fn invoke(operation: &str, input: Value) -> Value {
    let mut envelope = serde_json::Map::new();
    envelope.insert(
        "operation_id".to_string(),
        Value::String(operation.to_string()),
    );
    envelope.insert("input".to_string(), input);
    Value::Object(envelope)
}

fn submit_response() -> String {
    json!({
        "request_id": REQUEST_ID,
        "status_url": "https://queue.fal.run/fal-ai/flux/schnell/requests/req_local_123/status",
        "response_url": "https://queue.fal.run/fal-ai/flux/schnell/requests/req_local_123/response",
        "cancel_url": "https://queue.fal.run/fal-ai/flux/schnell/requests/req_local_123/cancel",
        "queue_position": 0
    })
    .to_string()
}

fn status_response() -> String {
    json!({
        "status": "IN_PROGRESS",
        "request_id": REQUEST_ID,
        "queue_position": 1,
        "logs": [{"message": "running"}],
        "metrics": {"inference_time": 0.25}
    })
    .to_string()
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_submits_and_reads_status_through_loopback() {
    let server = LoopbackServer::start(vec![
        LoopbackResponse {
            status: "200 OK",
            body: submit_response(),
        },
        LoopbackResponse {
            status: "200 OK",
            body: status_response(),
        },
    ]);
    let connector = configured_connector(server.base_url()).await;

    let submit = connector
        .handle_invoke(invoke(
            OP_SUBMIT,
            json!({
                "model_route": MODEL_ROUTE,
                "params": {"prompt": SECRET_PROMPT, "image_size": "square_hd"},
                "no_retry": true
            }),
        ))
        .await
        .expect("loopback Fal submit should succeed");
    let status = connector
        .handle_invoke(invoke(
            OP_STATUS,
            json!({
                "model_route": MODEL_ROUTE,
                "request_id": REQUEST_ID,
                "logs": true
            }),
        ))
        .await
        .expect("loopback Fal status should succeed");
    let captured = server.finish();

    assert_eq!(submit["provider"], json!("fal"));
    assert_eq!(submit["model_route"], json!(MODEL_ROUTE));
    assert_eq!(submit["request_id"], json!(REQUEST_ID));
    assert_eq!(submit["queue_position"], json!(0));
    assert_eq!(status["status"], json!("IN_PROGRESS"));
    assert_eq!(status["request_id"], json!(REQUEST_ID));
    assert_eq!(status["logs_present"], json!(true));

    assert_eq!(captured.len(), 2);
    assert_eq!(request_method(&captured[0].head), "POST");
    assert_eq!(request_target(&captured[0].head), "/fal-ai/flux/schnell");
    assert_eq!(
        header_value(&captured[0].head, "authorization"),
        format!("Key {API_KEY}")
    );
    assert_eq!(header_value(&captured[0].head, "x-fal-no-retry"), "1");
    assert_eq!(
        captured[0].body.as_ref().expect("submit body should exist"),
        &json!({"prompt": SECRET_PROMPT, "image_size": "square_hd"})
    );

    assert_eq!(request_method(&captured[1].head), "GET");
    assert_eq!(
        request_target(&captured[1].head),
        "/fal-ai/flux/schnell/requests/req_local_123/status?logs=1"
    );
    assert_eq!(
        header_value(&captured[1].head, "authorization"),
        format!("Key {API_KEY}")
    );

    let evidence = redaction_safe_evidence(
        &[
            (OP_SUBMIT, &captured[0].head),
            (OP_STATUS, &captured[1].head),
        ],
        &submit,
        &status,
    );
    let evidence_text = evidence.to_string();
    assert_eq!(evidence["connector"], json!("fal"));
    assert_eq!(evidence["suite_class"], json!("local_non_mock"));
    assert!(!evidence_text.contains(API_KEY));
    assert!(!evidence_text.contains(SECRET_PROMPT));
    assert!(evidence_text.contains("[REDACTED]"));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_provider_auth_denial_maps_to_fcp_unauthorized() {
    let server = LoopbackServer::start(vec![LoopbackResponse {
        status: "401 Unauthorized",
        body: json!({"detail": "invalid Fal API key"}).to_string(),
    }]);
    let connector = configured_connector(server.base_url()).await;

    let error = connector
        .handle_invoke(invoke(
            OP_SUBMIT,
            json!({
                "model_route": MODEL_ROUTE,
                "params": {"prompt": SECRET_PROMPT}
            }),
        ))
        .await
        .expect_err("401 loopback response should map to an auth denial");
    let captured = server.finish();

    assert_eq!(captured.len(), 1);
    assert_eq!(request_method(&captured[0].head), "POST");
    assert_eq!(request_target(&captured[0].head), "/fal-ai/flux/schnell");
    assert_eq!(
        header_value(&captured[0].head, "authorization"),
        format!("Key {API_KEY}")
    );
    match error {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 2001);
            assert!(message.contains("HTTP 401"));
        }
        other => panic!("expected Fal auth denial, got {other:?}"),
    }
}

fn redaction_safe_evidence(requests: &[(&str, &str)], submit: &Value, status: &Value) -> Value {
    let request_entries = requests
        .iter()
        .map(|(operation, head)| {
            json!({
                "operation": operation,
                "method": request_method(head),
                "target": request_target(head),
                "headers": redacted_headers(head),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "connector": "fal",
        "suite_class": "local_non_mock",
        "transport": "local_tcp_http",
        "requests": request_entries,
        "response": {
            "submit_request_id": submit["request_id"],
            "status": status["status"],
            "logs_present": status["logs_present"],
        },
        "cleanup": {
            "result": "loopback_thread_joined"
        }
    })
}

fn redacted_headers(head: &str) -> Vec<Value> {
    let mut headers = Vec::new();
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("authorization") {
            headers.push(json!({"name": name, "value": "[REDACTED]"}));
        } else {
            headers.push(json!({"name": name, "value": value.trim()}));
        }
    }
    headers
}
