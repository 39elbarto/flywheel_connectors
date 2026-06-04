use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_deepseek::connector::test_handshake_request;
use fcp_deepseek::{DeepSeekAuth, DeepSeekClient, DeepSeekConnector, DeepSeekProvider};
use fcp_openai_compat::{ChatCompletionsRequest, ChatMessage, RateLimitPolicy};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpError, InstanceId};
use serde_json::{Value, json};

const OP_CHAT: &str = "deepseek.chat.completions";
const OP_MODELS: &str = "deepseek.models.list";
const CAP_CHAT: &str = "deepseek.chat";
const CAP_MODELS: &str = "deepseek.models.read";

#[derive(Clone)]
struct RawLoopback {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    handle: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
}

impl RawLoopback {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback server");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut handled = 0_usize;
            while handled < expected_requests && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _addr)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("set read timeout");
                        let request = read_http_request(&mut stream);
                        let response = response_for(&request);
                        stream
                            .write_all(response.as_bytes())
                            .expect("write loopback response");
                        stream.flush().expect("flush loopback response");
                        captured.lock().expect("request lock").push(request);
                        handled += 1;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => {
                        eprintln!("loopback accept failed: {err}");
                        break;
                    }
                }
            }
            let observed = captured.lock().expect("request lock").clone();
            assert_eq!(
                handled, expected_requests,
                "loopback request count; captured requests: {observed:#?}"
            );
        });
        Self {
            base_url,
            requests,
            handle: Arc::new(Mutex::new(Some(handle))),
        }
    }

    fn finish(&self) -> Vec<String> {
        let handle = self.handle.lock().expect("handle lock").take();
        if let Some(handle) = handle {
            handle.join().expect("loopback server thread");
        }
        self.requests.lock().expect("request lock").clone()
    }
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).expect("read loopback request");
        assert_ne!(read, 0, "client closed before headers");
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .or_else(|| {
            headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() - header_end < content_length {
        let read = stream.read(&mut chunk).expect("read request body");
        assert_ne!(read, 0, "client closed before body");
        bytes.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8_lossy(&bytes).to_string()
}

fn response_for(request: &str) -> String {
    let body = if request.starts_with("POST /chat/completions ") {
        json!({
            "id": "chatcmpl-local-non-mock",
            "object": "chat.completion",
            "created": 1,
            "model": "deepseek-v4-pro",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "reasoning_content": "private loopback reasoning",
                    "content": "loopback final"
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 4, "completion_tokens": 5, "total_tokens": 9}
        })
    } else if request.starts_with("GET /models ") {
        json!({
            "object": "list",
            "data": [
                {"id": "deepseek-v4-flash", "object": "model", "owned_by": "deepseek"},
                {"id": "deepseek-v4-pro", "object": "model", "owned_by": "deepseek"}
            ]
        })
    } else {
        json!({"error": {"type": "not_found", "message": "unexpected loopback request"}})
    };
    let status = if body.get("error").is_some() {
        "404 Not Found"
    } else {
        "200 OK"
    };
    let body = body.to_string();
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> fcp_prelude::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:deepseek-local-non-mock")
        .operations(&[operation])
        .issuer("node:local-loopback")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    fcp_prelude::CapabilityToken::from_raw(cose)
}

async fn configured_connector(base_url: &str) -> (DeepSeekConnector, Ed25519SigningKey) {
    let mut connector = DeepSeekConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "deepseek-loopback-key",
            "base_url": base_url,
            "default_model": "deepseek-v4-pro",
            "request_timeout_ms": 1_000
        }))
        .await
        .expect("configure should succeed");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(
            serde_json::to_value(test_handshake_request(
                vec![
                    CapabilityId::from_static(CAP_CHAT),
                    CapabilityId::from_static(CAP_MODELS),
                ],
                signing_key.verifying_key().to_bytes(),
            ))
            .expect("serialize handshake"),
        )
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

async fn invoke(
    connector: &DeepSeekConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": grant,
        }))
        .await
}

#[fcp_async_core::runtime::test]
async fn raw_loopback_client_chat_uses_shared_http_client() {
    let loopback = RawLoopback::start(1);
    let provider = DeepSeekProvider::new(
        loopback.base_url.clone(),
        DeepSeekAuth::ApiKey("deepseek-loopback-key".into()),
    );
    let client = DeepSeekClient::new(
        provider,
        Duration::from_secs(1),
        Duration::from_secs(60),
        RateLimitPolicy::FailFast,
    );
    let cx = fcp_async_core::compatibility_cx();
    let response = client
        .chat_completions(
            &cx,
            ChatCompletionsRequest::new(
                "deepseek-v4-pro",
                vec![ChatMessage::user_text("local secret prompt")],
            ),
        )
        .await
        .expect("direct client chat should succeed");

    assert_eq!(response.id, "chatcmpl-local-non-mock");
    assert_eq!(response.choices.len(), 1);
    if let ChatMessage::Assistant {
        content,
        reasoning_content,
        ..
    } = &response.choices[0].message
    {
        assert_eq!(content.as_deref(), Some("loopback final"));
        assert_eq!(
            reasoning_content.as_deref(),
            Some("private loopback reasoning")
        );
    } else {
        panic!("expected assistant message");
    }

    let requests = loopback.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /chat/completions "));
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer deepseek-loopback-key")
    );
}

#[fcp_async_core::runtime::test]
async fn raw_loopback_chat_and_models_exercise_production_paths() {
    let loopback = RawLoopback::start(2);
    let (mut connector, signing_key) = configured_connector(&loopback.base_url).await;

    let chat = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "local secret prompt"}],
            "thinking": {"type": "enabled"},
            "reasoning_effort": "high"
        }),
    )
    .await
    .expect("chat invoke should succeed");
    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models invoke should succeed");

    connector
        .handle_shutdown(json!({"reason": "local_non_mock_complete"}))
        .await
        .expect("shutdown should succeed");

    assert_eq!(chat["content"], "loopback final");
    assert_eq!(chat["reasoning_content"], "private loopback reasoning");
    assert_eq!(chat["finish_reason"], "stop");
    assert!(!chat.to_string().contains("local secret prompt"));
    assert_eq!(models["data"][0]["id"], "deepseek-v4-flash");
    assert_eq!(models["data"][1]["id"], "deepseek-v4-pro");

    let requests = loopback.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /chat/completions "));
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer deepseek-loopback-key")
    );
    assert!(requests[0].contains("\"thinking\":{\"type\":\"enabled\"}"));
    assert!(requests[1].starts_with("GET /models "));
    assert!(
        requests[1]
            .to_ascii_lowercase()
            .contains("authorization: bearer deepseek-loopback-key")
    );

    eprintln!(
        "DEEPSEEK_LOCAL_NON_MOCK_JSONL {}",
        json!({
            "event": "deepseek_local_non_mock_loopback",
            "status": "passed",
            "connector": "fcp-deepseek",
            "fixture_mode": "raw_tcp_loopback",
            "operations": [OP_CHAT, OP_MODELS],
            "http_request_count": requests.len(),
            "content_bytes": chat["content_bytes"],
            "reasoning_content_bytes": chat["reasoning_content_bytes"],
            "model_count": models["data"].as_array().map_or(0, Vec::len),
            "redaction": "prompt_and_reasoning_text_not_logged",
            "cleanup_result": "shutdown_completed"
        })
    );
}

#[fcp_async_core::runtime::test]
async fn embeddings_fail_before_loopback_network_dispatch() {
    let loopback = RawLoopback::start(0);
    let (connector, signing_key) = configured_connector(&loopback.base_url).await;
    let grant = valid_token(
        &signing_key,
        connector.instance_id(),
        "deepseek.embeddings",
        "deepseek.embeddings.create",
    );

    let error = connector
        .handle_invoke(json!({
            "operation": "deepseek.embeddings.create",
            "input": {"model": "text-embedding", "input": "private text"},
            "capability_token": grant,
        }))
        .await
        .expect_err("embeddings should fail before dispatch");
    assert!(matches!(error, FcpError::InvalidRequest { .. }));
    assert!(error.to_string().contains("not supported"));
    assert!(loopback.finish().is_empty());
}
