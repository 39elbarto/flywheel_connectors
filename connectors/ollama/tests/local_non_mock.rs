//! Local loopback acceptance coverage for the FCP `Ollama` connector.

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
    io::{ErrorKind, Read, Write as IoWrite},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration as StdDuration,
};

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_ollama::{DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL, OllamaConnector};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError, InstanceId};
use serde_json::{Value, json};

const CONNECTOR: &str = "ollama";
const PACKAGE: &str = "fcp-ollama";
const BEAD_ID: &str = "flywheel_connectors-222k2";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const API_SECRET: &str = "ollama-local-non-mock-secret";

const OP_CHAT: &str = "ollama.chat.completions";
const OP_CHAT_STREAM: &str = "ollama.chat.completions_stream";
const OP_EMBEDDINGS: &str = "ollama.embeddings.create";
const OP_MODELS: &str = "ollama.models.list";
const OP_HEALTH: &str = "ollama.health";

const CAP_CHAT: &str = "ollama.chat";
const CAP_EMBEDDINGS: &str = "ollama.embeddings";
const CAP_MODELS: &str = "ollama.models.read";
const CAP_HEALTH: &str = "ollama.health.read";

const CHAT_RESPONSE: &str = r#"{
  "id": "chatcmpl-ollama-local",
  "object": "chat.completion",
  "created": 1,
  "model": "llama3.2",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "loopback Ollama response"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 4,
    "completion_tokens": 3,
    "total_tokens": 7
  }
}"#;

const EMBEDDINGS_RESPONSE: &str = r#"{
  "object": "list",
  "model": "nomic-embed-text",
  "data": [
    {
      "object": "embedding",
      "index": 0,
      "embedding": [0.1, 0.2, 0.3, 0.4]
    }
  ],
  "usage": {
    "prompt_tokens": 2,
    "total_tokens": 2
  }
}"#;

const MODELS_RESPONSE: &str = r#"{
  "object": "list",
  "data": [
    {
      "id": "llama3.2",
      "object": "model",
      "created": 1693721698,
      "owned_by": "local"
    }
  ]
}"#;

const STREAM_RESPONSE: &str = concat!(
    "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama3.2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"loc\"},\"finish_reason\":null}]}\n\n",
    "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama3.2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"al\"},\"finish_reason\":\"stop\"}]}\n\n",
    "data: [DONE]\n\n"
);

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Option<Value>,
}

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    content_type: &'static str,
    body: &'static str,
}

impl HttpResponse {
    const fn json(status: &'static str, body: &'static str) -> Self {
        Self {
            status,
            content_type: "application/json",
            body,
        }
    }

    const fn sse(status: &'static str, body: &'static str) -> Self {
        Self {
            status,
            content_type: "text/event-stream",
            body,
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
            "http://{}/v1",
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
                    .set_read_timeout(Some(StdDuration::from_secs(5)))
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
async fn local_non_mock_chat_embeddings_models_and_health_use_openai_compat_loopback() {
    let server = LoopbackServer::start(vec![
        HttpResponse::json("200 OK", CHAT_RESPONSE),
        HttpResponse::json("200 OK", EMBEDDINGS_RESPONSE),
        HttpResponse::json("200 OK", MODELS_RESPONSE),
    ]);
    let configured = setup_connector(
        &server.base_url,
        &[CAP_CHAT, CAP_EMBEDDINGS, CAP_MODELS, CAP_HEALTH],
    )
    .await;

    let chat = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "private loopback prompt"}],
            "format": "json",
            "keep_alive": "5m"
        }),
    )
    .await
    .expect("chat completions should invoke the production client path");
    assert_eq!(chat["content"], "loopback Ollama response");
    assert_eq!(chat["model"], DEFAULT_MODEL);
    assert_eq!(chat["usage"]["total_tokens"], 7);

    let embeddings = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({
            "input": ["private embedding input one", "private embedding input two"],
            "encoding_format": "float"
        }),
    )
    .await
    .expect("embeddings should invoke the production client path");
    assert_eq!(embeddings["model"], DEFAULT_EMBEDDING_MODEL);
    assert_eq!(embeddings["data_count"], 1);
    assert_eq!(embeddings["dimensions"], 4);

    let models = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_MODELS,
        CAP_MODELS,
        json!({}),
    )
    .await
    .expect("models.list should invoke the production client path");
    assert_eq!(models["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(models["base_url_class"], "loopback");

    let health = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_HEALTH,
        CAP_HEALTH,
        json!({}),
    )
    .await
    .expect("health should reuse the cached model list");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["model_count"], 1);

    let requests = server.join();
    assert_eq!(requests.len(), 3);
    assert_request(&requests[0], "POST /v1/chat/completions HTTP/1.1");
    assert_request(&requests[1], "POST /v1/embeddings HTTP/1.1");
    assert_request(&requests[2], "GET /v1/models HTTP/1.1");

    let chat_body = requests[0].body.as_ref().expect("chat request sends JSON");
    assert_eq!(chat_body["model"], DEFAULT_MODEL);
    assert_eq!(chat_body["messages"][0]["role"], "user");
    assert_eq!(
        chat_body["messages"][0]["content"],
        "private loopback prompt"
    );
    assert_eq!(chat_body["stream"], false);
    assert_eq!(chat_body["format"], "json");
    assert_eq!(chat_body["keep_alive"], "5m");

    let embedding_body = requests[1]
        .body
        .as_ref()
        .expect("embeddings request sends JSON");
    assert_eq!(embedding_body["model"], DEFAULT_EMBEDDING_MODEL);
    assert_eq!(
        embedding_body["input"],
        json!(["private embedding input one", "private embedding input two"])
    );
    assert_eq!(embedding_body["encoding_format"], "float");
    assert!(requests[2].body.is_none(), "models request has no body");

    let rendered = serde_json::to_string(&json!({
        "chat": chat,
        "embeddings": embeddings,
        "models": models,
        "health": health,
    }))
    .expect("results serialize");
    assert!(!rendered.contains(API_SECRET));
    assert!(!rendered.contains("private loopback prompt"));
    assert!(!rendered.contains("private embedding input"));

    print_artifact(
        "chat_embeddings_models_health",
        &json!({
            "request_response_boundary": {
                "chat_completions": {
                    "method": "POST",
                    "path": "/v1/chat/completions",
                    "status": 200
                },
                "embeddings": {
                    "method": "POST",
                    "path": "/v1/embeddings",
                    "status": 200
                },
                "models_list": {
                    "method": "GET",
                    "path": "/v1/models",
                    "status": 200
                },
                "health_reused_cached_models": true
            },
            "auth_gate": {
                "mode": "bearer_api_key",
                "authorization_header_verified": true
            },
            "redaction": {
                "api_secret_redacted_from_output": true,
                "input_payload_not_reflected_in_output": true
            },
            "cleanup": {
                "fixture_requests_joined": requests.len()
            },
            "result": "passed"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_streaming_chat_uses_sse_loopback() {
    let server = LoopbackServer::start(vec![HttpResponse::sse("200 OK", STREAM_RESPONSE)]);
    let configured = setup_connector(&server.base_url, &[CAP_CHAT]).await;

    let stream = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private streaming prompt"}]}),
    )
    .await
    .expect("streaming chat should invoke the production SSE path");
    assert_eq!(stream["content"], "local");
    assert_eq!(stream["chunk_count"], 2);

    let requests = server.join();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "POST /v1/chat/completions HTTP/1.1");
    let stream_body = requests[0]
        .body
        .as_ref()
        .expect("stream request sends JSON");
    assert_eq!(stream_body["model"], DEFAULT_MODEL);
    assert_eq!(stream_body["messages"][0]["role"], "user");
    assert_eq!(
        stream_body["messages"][0]["content"],
        "private streaming prompt"
    );
    assert_eq!(stream_body["stream"], true);

    let rendered = stream.to_string();
    assert!(!rendered.contains(API_SECRET));
    assert!(!rendered.contains("private streaming prompt"));

    print_artifact(
        "streaming_chat_sse",
        &json!({
            "request_response_boundary": {
                "chat_completions_stream": {
                    "method": "POST",
                    "path": "/v1/chat/completions",
                    "status": 200,
                    "transport": "sse",
                    "stream_chunk_count": stream["chunk_count"],
                    "content_bytes": stream["content"].as_str().unwrap_or_default().len()
                }
            },
            "auth_gate": {
                "mode": "bearer_api_key",
                "authorization_header_verified": true
            },
            "redaction": {
                "api_secret_redacted_from_output": true,
                "input_payload_not_reflected_in_output": true
            },
            "cleanup": {
                "fixture_requests_joined": requests.len()
            },
            "result": "passed"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_authentication_error_maps_without_leaking_secret_material() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "401 Unauthorized",
        r#"{"error":{"type":"authentication_error","message":"bad Bearer should-not-leak","prompt":"private auth prompt"}}"#,
    )]);
    let configured = setup_connector(&server.base_url, &[CAP_CHAT]).await;

    let err = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private auth prompt"}]}),
    )
    .await
    .expect_err("401 should map to an FCP unauthorized error");
    assert!(
        matches!(err, FcpError::Unauthorized { .. }),
        "expected unauthorized error, got {err:?}"
    );
    let rendered = err.to_string();
    assert!(!rendered.contains(API_SECRET));
    assert!(!rendered.contains("should-not-leak"));
    assert!(!rendered.contains("private auth prompt"));

    let requests = server.join();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "POST /v1/chat/completions HTTP/1.1");

    print_artifact(
        "authentication_error_mapping",
        &json!({
            "request_response_boundary": {
                "method": "POST",
                "path": "/v1/chat/completions",
                "status": 401
            },
            "error_mapping": {
                "fcp_error": "Unauthorized",
                "secret_material_logged": false
            },
            "cleanup": {
                "fixture_requests_joined": requests.len()
            },
            "result": "passed"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_wrong_capability_fails_before_egress() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind no-egress listener");
    listener
        .set_nonblocking(true)
        .expect("set no-egress listener nonblocking");
    let base_url = format!(
        "http://{}/v1",
        listener
            .local_addr()
            .expect("no-egress listener should expose its address")
    );
    let configured = setup_connector(&base_url, &[CAP_MODELS]).await;

    let err = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_CHAT,
        CAP_MODELS,
        json!({"messages": [{"role": "user", "content": "must not reach loopback"}]}),
    )
    .await
    .expect_err("wrong capability should fail before egress");
    assert!(
        matches!(
            err,
            FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
        ),
        "expected capability denial before egress, got {err:?}"
    );
    let accept_result = listener.accept();
    assert!(
        matches!(accept_result, Err(ref err) if err.kind() == ErrorKind::WouldBlock),
        "connector should not open a loopback connection; got {accept_result:?}"
    );

    print_artifact(
        "wrong_capability_no_egress",
        &json!({
            "egress_gate": {
                "operation": OP_CHAT,
                "wrong_capability_rejected_before_http": true,
                "requests_sent": 0
            },
            "result": "passed"
        }),
    );
}

struct ConfiguredOllama {
    connector: OllamaConnector,
    signing_key: Ed25519SigningKey,
}

async fn setup_connector(base_url: &str, capabilities: &[&'static str]) -> ConfiguredOllama {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let mut connector = OllamaConnector::new();
    connector
        .handle_configure(json!({
            "base_url": base_url,
            "api_key": API_SECRET,
            "default_model": DEFAULT_MODEL,
            "default_embedding_model": DEFAULT_EMBEDDING_MODEL,
            "request_timeout_ms": 5_000,
            "model_cache_ttl_seconds": 60
        }))
        .await
        .expect("configure Ollama connector");
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:owner",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![46_u8; 32],
            "capabilities_requested": capabilities
        }))
        .await
        .expect("handshake Ollama connector");

    ConfiguredOllama {
        connector,
        signing_key,
    }
}

async fn invoke(
    connector: &OllamaConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let grant = signed_capability(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": grant
        }))
        .await
}

fn signed_capability(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("capability constraints should encode as CBOR");

    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:owner")
        .principal("user:ollama-local-non-mock")
        .operations(&[operation])
        .issuer("node:ollama-local-non-mock")
        .target_instance(instance_id.as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("capability constraints should attach")
        .sign(signing_key)
        .expect("capability should sign");
    CapabilityToken::from_raw(cose)
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
            &format!("Bearer {API_SECRET}")
        ),
        "request should carry configured Ollama bearer auth; head={}",
        captured.head
    );
    assert!(
        header_seen(&captured.head, "accept", "application/json"),
        "request should accept JSON; head={}",
        captured.head
    );
    assert!(
        header_seen(&captured.head, "user-agent", "fcp-ollama/0.1.0"),
        "request should carry the Ollama user agent; head={}",
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
                None
            } else {
                Some(
                    serde_json::from_slice(&bytes[body_start..body_start + content_length])
                        .expect("request body should be JSON"),
                )
            };
            return CapturedRequest { head, body };
        }
    }
}

fn write_response(stream: &mut TcpStream, response: HttpResponse) {
    let mut raw = format!("HTTP/1.1 {}\r\n", response.status);
    write!(&mut raw, "content-type: {}\r\n", response.content_type)
        .expect("content-type should format");
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

fn print_artifact(case_name: &str, details: &Value) {
    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "case": case_name,
        "command": "cargo test -p fcp-ollama --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "details": details
    });
    let rendered = artifact.to_string();
    assert!(!rendered.contains(API_SECRET));
    println!("{artifact}");
}
