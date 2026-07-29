#![allow(
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use std::fmt::Write as FmtWrite;
use std::io::{Read, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use fcp_mistral::MistralConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};

const API_KEY: &str = "mistral-local-acceptance-key";
const OP_CHAT: &str = "mistral.chat.completions";
const OP_EMBEDDINGS: &str = "mistral.embeddings.create";
const OP_MODELS: &str = "mistral.models.list";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Option<Value>,
}

struct LoopbackServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its local address")
        );
        let (request_tx, received) = mpsc::channel();

        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener
                    .accept()
                    .expect("loopback listener should accept the expected request");
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(5)))
                    .expect("loopback stream should set a read timeout");

                let request = read_complete_request(&mut stream);
                request_tx
                    .send(request)
                    .expect("captured request should be delivered to the test");

                let mut raw_response = format!("HTTP/1.1 {}\r\n", response.status);
                raw_response.push_str("content-type: application/json\r\n");
                write!(
                    &mut raw_response,
                    "content-length: {}\r\n",
                    response.body.len()
                )
                .expect("content-length header should format");
                raw_response.push_str("connection: close\r\n");
                for (name, value) in response.headers {
                    raw_response.push_str(name);
                    raw_response.push_str(": ");
                    raw_response.push_str(value);
                    raw_response.push_str("\r\n");
                }
                raw_response.push_str("\r\n");
                raw_response.push_str(response.body);

                stream
                    .write_all(raw_response.as_bytes())
                    .expect("loopback response should be writable");
            }
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn take(&self) -> CapturedRequest {
        self.received
            .recv_timeout(StdDuration::from_secs(5))
            .expect("loopback request should arrive")
    }

    fn join(self) {
        self.join
            .join()
            .expect("loopback server thread should finish");
    }
}

struct HttpResponse {
    status: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static str,
}

impl HttpResponse {
    const fn json(status: &'static str, body: &'static str) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name, value));
        self
    }
}

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let read = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);

        if header_end.is_none() {
            header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n");
            if let Some(end) = header_end {
                let head = String::from_utf8_lossy(&bytes[..end]).to_string();
                content_length = parse_content_length(&head);
            }
        }

        if let Some(end) = header_end {
            let body_start = end + 4;
            if bytes.len() >= body_start + content_length {
                let head = String::from_utf8(bytes[..end].to_vec())
                    .expect("request headers should be valid UTF-8");
                let body_slice = &bytes[body_start..body_start + content_length];
                let body = if body_slice.is_empty() {
                    None
                } else {
                    Some(
                        serde_json::from_slice(body_slice)
                            .expect("request body should be JSON when present"),
                    )
                };
                return CapturedRequest { head, body };
            }
        }
    }

    panic!("loopback request ended before complete headers/body were read");
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

fn assert_request(captured: &CapturedRequest, method: &str, target: &str) {
    let request_line = captured
        .head
        .lines()
        .next()
        .expect("captured request should include a request line");
    assert_eq!(request_line, format!("{method} {target} HTTP/1.1"));
    assert!(
        captured
            .head
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {API_KEY}")),
        "request should carry the configured Mistral bearer token; head={}",
        captured.head
    );
}

async fn setup_connector(base_url: &str) -> MistralConnector {
    let mut connector = MistralConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "base_url": base_url
        }))
        .await
        .expect("Mistral connector should configure against loopback");
    connector
        .handle_handshake(json!({ "session_id": "mistral-local-acceptance" }))
        .await
        .expect("Mistral connector should handshake");
    connector
}

async fn invoke(
    connector: &MistralConnector,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation_id": operation,
            "input": input
        }))
        .await
}

#[fcp_async_core::test]
async fn local_non_mock_chat_completions_posts_expected_json_and_maps_output() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "200 OK",
        r#"{
            "id": "chatcmpl-local",
            "model": "mistral-small-latest",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": "loopback ok"}}
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2}
        }"#,
    )]);
    let connector = setup_connector(&server.base_url).await;

    let result = invoke(
        &connector,
        OP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "Say ok"}],
            "temperature": 0.2,
            "max_tokens": 16,
            "random_seed": 123
        }),
    )
    .await
    .expect("chat completion should invoke against loopback");

    let captured = server.take();
    assert_request(&captured, "POST", "/chat/completions");
    assert_eq!(
        captured.body.expect("chat completion should send JSON"),
        json!({
            "model": "mistral-small-latest",
            "messages": [{"role": "user", "content": "Say ok"}],
            "temperature": 0.2,
            "max_tokens": 16,
            "random_seed": 123
        })
    );
    server.join();

    assert_eq!(result["id"], "chatcmpl-local");
    assert_eq!(result["choices"][0]["message"]["content"], "loopback ok");
    assert_eq!(result["usage"]["prompt_tokens"], 5);
}

#[fcp_async_core::test]
async fn local_non_mock_embeddings_create_posts_default_model_and_maps_output() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "200 OK",
        r#"{
            "object": "list",
            "data": [
                {"object": "embedding", "index": 0, "embedding": [0.1, 0.2]},
                {"object": "embedding", "index": 1, "embedding": [0.3, 0.4]}
            ],
            "model": "mistral-embed"
        }"#,
    )]);
    let connector = setup_connector(&server.base_url).await;

    let result = invoke(
        &connector,
        OP_EMBEDDINGS,
        json!({ "input": ["alpha", "beta"] }),
    )
    .await
    .expect("embeddings should invoke against loopback");

    let captured = server.take();
    assert_request(&captured, "POST", "/embeddings");
    assert_eq!(
        captured.body.expect("embeddings should send JSON"),
        json!({
            "model": "mistral-embed",
            "input": ["alpha", "beta"]
        })
    );
    server.join();

    assert_eq!(result["model"], "mistral-embed");
    assert_eq!(result["data"].as_array().expect("embedding data").len(), 2);
    assert_eq!(result["data"][1]["embedding"][1], 0.4);
}

#[fcp_async_core::test]
async fn local_non_mock_models_list_uses_get_without_body() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "200 OK",
        r#"{
            "object": "list",
            "data": [
                {"id": "mistral-small-latest", "object": "model"},
                {"id": "mistral-embed", "object": "model"}
            ]
        }"#,
    )]);
    let connector = setup_connector(&server.base_url).await;

    let result = invoke(&connector, OP_MODELS, json!({}))
        .await
        .expect("models list should invoke against loopback");

    let captured = server.take();
    assert_request(&captured, "GET", "/models");
    assert!(
        captured.body.is_none(),
        "models list should not send a JSON body"
    );
    server.join();

    assert_eq!(result["object"], "list");
    assert_eq!(result["data"][0]["id"], "mistral-small-latest");
    assert_eq!(result["data"][1]["id"], "mistral-embed");
}

#[fcp_async_core::test]
async fn local_non_mock_rate_limit_maps_retry_after_seconds() {
    let server = LoopbackServer::start(vec![
        HttpResponse::json("429 Too Many Requests", r#"{"message":"rate limited"}"#)
            .with_header("retry-after", "2"),
    ]);
    let connector = setup_connector(&server.base_url).await;

    let error = invoke(&connector, OP_EMBEDDINGS, json!({ "input": "alpha" }))
        .await
        .expect_err("upstream rate limit should map to FcpError::RateLimited");

    let captured = server.take();
    assert_request(&captured, "POST", "/embeddings");
    assert_eq!(
        captured
            .body
            .expect("rate-limited embeddings should send JSON"),
        json!({
            "model": "mistral-embed",
            "input": "alpha"
        })
    );
    server.join();

    match error {
        FcpError::RateLimited {
            retry_after_ms,
            violation,
        } => {
            assert_eq!(retry_after_ms, 2_000);
            assert!(violation.is_none());
        }
        other => panic!("expected rate-limited error, got {other:?}"),
    }
}
