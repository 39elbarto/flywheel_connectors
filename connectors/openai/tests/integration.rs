//! `OpenAI` connector integration tests (flywheel_connectors-7hb.8).
//!
//! Deterministic integration tests using wiremock to mock the `OpenAI` API.
//! No real API calls. Covers:
//! - Non-streaming generation (chat + `simple_chat`)
//! - Streaming SSE (chunk parsing, error mid-stream)
//! - Tool/function calling shapes
//! - Error taxonomy (401/429/503/5xx)
//! - Usage metrics & cost extraction
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, doctor, `self_check`, shutdown)
//! - Input validation

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_testkit::{AsyncTestContext, MockApiServer};
use futures_util::StreamExt;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

// ──────────────── re-export the connector under test ────────────────
use fcp_openai::client::OpenAIClient;
use fcp_openai::connector::OpenAIConnector;
use fcp_openai::types::Model;

// ============================================================================
// Helpers
// ============================================================================

/// Generate a valid COSE capability token signed by the given key.
fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[cap])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken { raw: cose }
}

/// Perform handshake on a connector, returning the signing key for token generation.
async fn setup_handshake(connector: &mut OpenAIConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

/// Configure connector with a mock server URL.
async fn setup_configure(connector: &mut OpenAIConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-api-key-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

/// Standard `OpenAI` chat completion success response.
fn openai_success_response(
    resp_id: &str,
    text: &str,
    prompt_tokens: u32,
    completion_tokens: u32,
) -> serde_json::Value {
    json!({
        "id": resp_id,
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": text
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens
        }
    })
}

/// `OpenAI` `tool_calls` response.
fn openai_tool_use_response(
    resp_id: &str,
    call_id: &str,
    fn_name: &str,
    fn_args: &str,
    prompt_tokens: u32,
    completion_tokens: u32,
) -> serde_json::Value {
    json!({
        "id": resp_id,
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": fn_name,
                        "arguments": fn_args
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens
        }
    })
}

/// `OpenAI` API error envelope.
fn openai_error(error_type: &str, message: &str, code: Option<&str>) -> serde_json::Value {
    json!({
        "error": {
            "message": message,
            "type": error_type,
            "param": null,
            "code": code
        }
    })
}

/// Build SSE body from data-only events (`OpenAI` uses `data: {json}\n\n`).
fn build_sse_body(events: &[serde_json::Value]) -> String {
    use std::fmt::Write;
    let mut body = String::new();
    for event in events {
        let _ = write!(body, "data: {event}\n\n");
    }
    body.push_str("data: [DONE]\n\n");
    body
}

// ============================================================================
// Non-Streaming Generation Tests
// ============================================================================

/// Happy path: `openai.simple_chat` invoke returns text response.
#[fcp_async_core::runtime::test]
async fn simple_chat_invoke_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("openai.simple_chat.happy_path");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/chat/completions",
        openai_success_response("chatcmpl-001", "Hello from GPT!", 12, 8),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.simple_chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.simple_chat",
            "input": { "message": "Hi there" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["response"], "Hello from GPT!");
    assert_eq!(result["usage"]["prompt_tokens"], 12);
    assert_eq!(result["usage"]["completion_tokens"], 8);
    let cost = result["cost_usd"].as_f64().unwrap();
    assert!(cost > 0.0, "cost should be positive: {cost}");
    mock.assert_received("/v1/chat/completions").await;
}

/// Happy path: openai.chat invoke with multi-turn messages.
#[fcp_async_core::runtime::test]
async fn chat_invoke_multi_turn() {
    let _ctx = AsyncTestContext::for_scenario("openai.chat.multi_turn");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/chat/completions",
        openai_success_response("chatcmpl-002", "The capital of France is Paris.", 25, 12),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [
                    {"role": "user", "content": "What is the capital of France?"},
                    {"role": "assistant", "content": "Let me think..."},
                    {"role": "user", "content": "Go ahead."}
                ],
                "max_tokens": 1024
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["content"], "The capital of France is Paris.");
    assert_eq!(result["id"], "chatcmpl-002");
}

/// `openai.simple_chat` with system prompt.
#[fcp_async_core::runtime::test]
async fn simple_chat_invoke_with_system() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/chat/completions",
        openai_success_response("chatcmpl-003", "42", 30, 3),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.simple_chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.simple_chat",
            "input": {
                "message": "What is 6*7?",
                "system": "You are a calculator. Reply with only the number.",
                "max_tokens": 16
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["response"], "42");
}

// ============================================================================
// Streaming SSE Tests
// ============================================================================

/// Streaming: parse complete SSE chunks.
#[fcp_async_core::runtime::test]
async fn streaming_sse_chunk_parsing() {
    let _ctx = AsyncTestContext::for_scenario("openai.stream.chunk_parsing");
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        json!({
            "id": "chatcmpl-stream-001",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {"role": "assistant", "content": ""},
                "finish_reason": null
            }]
        }),
        json!({
            "id": "chatcmpl-stream-001",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {"content": "Hello"},
                "finish_reason": null
            }]
        }),
        json!({
            "id": "chatcmpl-stream-001",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {"content": " World"},
                "finish_reason": null
            }]
        }),
        json!({
            "id": "chatcmpl-stream-001",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop"
            }]
        }),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("Authorization", "Bearer test-stream-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-stream-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_openai::types::Message::user("Hello")];

    let stream = client
        .chat_completion_stream(Model::Gpt4o, messages, Some(1024), None, None, None)
        .await
        .expect("stream should start");

    let chunks: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.expect("each chunk should parse"))
        .collect();

    assert_eq!(
        chunks.len(),
        4,
        "expected 4 SSE chunks, got {}",
        chunks.len()
    );

    // Verify text deltas
    let mut text_acc = String::new();
    for chunk in &chunks {
        if let Some(choice) = chunk.choices.first() {
            if let Some(content) = &choice.delta.content {
                text_acc.push_str(content);
            }
        }
    }
    assert_eq!(text_acc, "Hello World");
}

/// Streaming: SSE error mid-stream (non-200 status).
#[fcp_async_core::runtime::test]
async fn streaming_sse_error_mid_stream() {
    let _ctx = AsyncTestContext::for_scenario("openai.stream.error_mid_stream");
    let mock_server = MockServer::start().await;

    // OpenAI returns a non-200 status for errors, even on stream requests
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_json(openai_error(
            "server_error",
            "Internal server error",
            None,
        )))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_openai::types::Message::user("Hello")];

    let result = client
        .chat_completion_stream(Model::Gpt4o, messages, Some(1024), None, None, None)
        .await;

    assert!(result.is_err(), "stream should fail on non-200 status");
}

/// Streaming: [DONE] terminates the stream cleanly.
#[fcp_async_core::runtime::test]
async fn streaming_sse_done_terminates() {
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[json!({
        "id": "chatcmpl-done-001",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "delta": {"role": "assistant", "content": "Hi"},
            "finish_reason": null
        }]
    })]);

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_openai::types::Message::user("Hi")];

    let stream = client
        .chat_completion_stream(Model::Gpt4o, messages, Some(256), None, None, None)
        .await
        .expect("stream should start");

    let chunks: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter_map(std::result::Result::ok)
        .collect();

    // Should have exactly 1 chunk (the [DONE] produces None, ending the stream)
    assert_eq!(chunks.len(), 1, "should have 1 chunk before [DONE]");
}

// ============================================================================
// Tool/Function Calling Tests
// ============================================================================

/// Tool use: model requests tool call and response includes `tool_calls`.
#[fcp_async_core::runtime::test]
async fn tool_use_invoke_shape() {
    let _ctx = AsyncTestContext::for_scenario("openai.tool_use.shape");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/chat/completions",
        openai_tool_use_response(
            "chatcmpl-tool-001",
            "call_abc123",
            "get_weather",
            r#"{"city":"San Francisco","unit":"celsius"}"#,
            20,
            15,
        ),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [{"role": "user", "content": "What's the weather in SF?"}],
                "tools": [{
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "description": "Get the weather",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "city": {"type": "string"},
                                "unit": {"type": "string"}
                            }
                        }
                    }
                }]
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    // finish_reason is formatted via `format!("{r:?}").to_lowercase()` -> "toolcalls"
    let fr = result["finish_reason"].as_str().unwrap();
    assert!(
        fr == "tool_calls" || fr == "toolcalls",
        "expected tool_calls or toolcalls, got: {fr}"
    );
    assert_eq!(result["usage"]["prompt_tokens"], 20);
    assert_eq!(result["usage"]["completion_tokens"], 15);
}

/// Tool use streaming: streaming response with tool call deltas.
#[fcp_async_core::runtime::test]
async fn tool_use_streaming_shape() {
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        json!({
            "id": "chatcmpl-tool-stream",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {
                    "role": "assistant",
                    "tool_calls": [{
                        "index": 0,
                        "id": "call_xyz",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": ""}
                    }]
                },
                "finish_reason": null
            }]
        }),
        json!({
            "id": "chatcmpl-tool-stream",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": {"arguments": "{\"city\":\"SF\"}"}
                    }]
                },
                "finish_reason": null
            }]
        }),
        json!({
            "id": "chatcmpl-tool-stream",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "tool_calls"
            }]
        }),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_openai::types::Message::user("Weather?")];

    let stream = client
        .chat_completion_stream(Model::Gpt4o, messages, Some(1024), None, None, None)
        .await
        .expect("stream should start");

    let chunks: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.expect("each chunk should parse"))
        .collect();

    assert_eq!(chunks.len(), 3, "expected 3 tool streaming chunks");

    // First chunk has tool call ID
    let first_tc = chunks[0].choices[0].delta.tool_calls.as_ref().unwrap();
    assert_eq!(first_tc[0].id.as_deref(), Some("call_xyz"));

    // Last chunk has finish_reason = tool_calls
    assert_eq!(
        chunks[2].choices[0].finish_reason,
        Some(fcp_openai::types::FinishReason::ToolCalls)
    );
}

// ============================================================================
// Error Taxonomy Tests
// ============================================================================

/// 401 maps to `OpenAIError::InvalidApiKey` -> `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("openai.error.401_unauthorized");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(openai_error(
            "invalid_request_error",
            "Incorrect API key",
            Some("invalid_api_key"),
        )))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("bad-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    let err = result.unwrap_err();
    assert!(matches!(err, fcp_openai::error::OpenAIError::InvalidApiKey));

    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }));
}

/// 429 maps to `OpenAIError::RateLimited` -> `FcpError::RateLimited`.
/// Constructs the error directly to avoid the 30s `retry_after` delay from `RateLimited`
/// that the `RetryLoop` honors during retries.
#[fcp_async_core::runtime::test]
async fn error_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("openai.error.429_rate_limited");

    let err = fcp_openai::error::OpenAIError::RateLimited {
        retry_after_ms: 30_000,
    };

    assert!(err.is_retryable());
    assert_eq!(
        err.retry_after(),
        Some(std::time::Duration::from_secs(30))
    );

    let fcp_err = err.to_fcp_error();
    match fcp_err {
        fcp_core::FcpError::RateLimited { retry_after_ms, .. } => {
            assert_eq!(retry_after_ms, 30_000);
        }
        other => panic!("expected RateLimited, got: {other:?}"),
    }
}

/// 503 maps to `OpenAIError::Overloaded` -> `FcpError::External` (retryable).
/// Constructs the error directly to avoid the 60s `retry_after` delay from Overloaded
/// that the `RetryLoop` honors during retries.
#[fcp_async_core::runtime::test]
async fn error_503_maps_to_overloaded() {
    let _ctx = AsyncTestContext::for_scenario("openai.error.503_overloaded");

    // Verify the error type and FCP mapping directly (avoids 60s retry delay)
    let err = fcp_openai::error::OpenAIError::Overloaded {
        retry_after_ms: 60_000,
    };

    assert!(err.is_retryable());
    assert_eq!(
        err.retry_after(),
        Some(std::time::Duration::from_secs(60))
    );

    let fcp_err = err.to_fcp_error();
    match fcp_err {
        fcp_core::FcpError::External {
            retryable,
            service,
            status_code,
            ..
        } => {
            assert!(retryable, "Overloaded should map to retryable External");
            assert_eq!(service, "openai");
            assert_eq!(status_code, Some(503));
        }
        other => panic!("expected External, got: {other:?}"),
    }
}

/// Context length exceeded maps to `FcpError::InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn error_context_length_maps_to_invalid_request() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(openai_error(
            "invalid_request_error",
            "maximum context length exceeded",
            None,
        )))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    let err = result.unwrap_err();
    assert!(matches!(
        err,
        fcp_openai::error::OpenAIError::ContextLengthExceeded { .. }
    ));

    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, fcp_core::FcpError::InvalidRequest { .. }));
}

/// Content filter error maps to `FcpError::InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn error_content_filter_maps_to_invalid_request() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(openai_error(
            "invalid_request_error",
            "Content filtered",
            Some("content_filter"),
        )))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    let err = result.unwrap_err();
    assert!(matches!(
        err,
        fcp_openai::error::OpenAIError::ContentFiltered { .. }
    ));

    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, fcp_core::FcpError::InvalidRequest { .. }));
}

// ============================================================================
// Usage Metrics Tests
// ============================================================================

/// Usage metrics accumulate across requests.
#[fcp_async_core::runtime::test]
async fn usage_metrics_accumulate() {
    let _ctx = AsyncTestContext::for_scenario("openai.usage.accumulate");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_success_response(
                "chatcmpl-usage-001",
                "First response",
                100,
                50,
            )),
        )
        .expect(2)
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    client
        .chat(Model::Gpt4o, "Hi", None, Some(1024))
        .await
        .unwrap();
    client
        .chat(Model::Gpt4o, "Hi again", None, Some(1024))
        .await
        .unwrap();

    assert_eq!(client.total_prompt_tokens(), 200);
    assert_eq!(client.total_completion_tokens(), 100);
}

/// Usage cost is model-dependent.
#[fcp_async_core::runtime::test]
async fn usage_cost_is_model_dependent() {
    let usage = fcp_openai::types::Usage {
        prompt_tokens: 1_000_000,
        completion_tokens: 1_000_000,
        total_tokens: 2_000_000,
        prompt_tokens_details: None,
    };

    let cost_4o = usage.calculate_cost(Model::Gpt4o);
    let cost_mini = usage.calculate_cost(Model::Gpt4oMini);

    // GPT-4o: $2.50 input + $10.00 output = $12.50
    assert!((cost_4o - 12.50).abs() < 0.01, "gpt-4o cost = {cost_4o}");
    // GPT-4o-mini: $0.15 input + $0.60 output = $0.75
    assert!(
        (cost_mini - 0.75).abs() < 0.01,
        "gpt-4o-mini cost = {cost_mini}"
    );
    assert!(
        cost_4o > cost_mini,
        "gpt-4o should be more expensive than mini"
    );
}

// ============================================================================
// FCP2 Default-Deny Tests
// ============================================================================

/// Missing `capability_token` in invoke fails.
#[fcp_async_core::runtime::test]
async fn capability_missing_token_fails() {
    let _ctx = AsyncTestContext::for_scenario("openai.cap.missing_token");
    let mock = MockApiServer::start().await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let _signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}]
            }
            // no capability_token
        }))
        .await;

    assert!(result.is_err(), "should fail without capability token");
}

/// Invoke without handshake fails.
#[fcp_async_core::runtime::test]
async fn capability_no_handshake_fails() {
    let mock = MockApiServer::start().await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    // no handshake

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}]
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::NotConfigured),
        "should get NotConfigured without handshake"
    );
}

/// Invoke without configure fails.
#[fcp_async_core::runtime::test]
async fn capability_no_configure_fails() {
    let mut connector = OpenAIConnector::new();
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.simple_chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.simple_chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::NotConfigured
    ));
}

/// Wrong operation returns `OperationNotGranted`.
#[fcp_async_core::runtime::test]
async fn capability_wrong_operation_fails() {
    let mock = MockApiServer::start().await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.nonexistent_op",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            fcp_core::FcpError::OperationNotGranted { .. }
                | fcp_core::FcpError::Unauthorized { .. }
                | fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "expected denial error, got: {err:?}"
    );
}

/// Unknown operation is rejected.
#[fcp_async_core::runtime::test]
async fn capability_unknown_operation_fails() {
    let mock = MockApiServer::start().await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.unknown");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.unknown",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

/// Health before configure returns `not_configured`.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_before_configure() {
    let connector = OpenAIConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
}

/// Health after configure returns healthy.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;

    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
    assert!(result.get("metrics").is_some());
}

/// Handshake grants capabilities.
#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_grants_capabilities() {
    let mut connector = OpenAIConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["openai.chat"]
        }))
        .await
        .unwrap();

    assert_eq!(result["status"], "accepted");
    assert!(result.get("session_id").is_some());
    let caps = result["capabilities_granted"].as_array().unwrap();
    assert!(!caps.is_empty(), "should grant capabilities");
}

/// Shutdown returns clean status.
#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown_clean() {
    let connector = OpenAIConnector::new();
    let result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(result["status"], "shutdown");
}

/// Introspect lists operations.
#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_operations() {
    let connector = OpenAIConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    let op_ids: Vec<&str> = ops.iter().filter_map(|o| o["id"].as_str()).collect();

    assert!(
        op_ids.contains(&"openai.chat"),
        "should include openai.chat"
    );
    assert!(
        op_ids.contains(&"openai.simple_chat"),
        "should include openai.simple_chat"
    );
    assert!(
        op_ids.contains(&"openai.get_usage"),
        "should include openai.get_usage"
    );
}

/// Doctor before configure shows unhealthy.
#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_before_configure() {
    let connector = OpenAIConnector::new();
    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "unhealthy");
}

/// Doctor after configure shows healthy (with API key).
#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_after_configure() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;

    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

// ============================================================================
// Input Validation Tests
// ============================================================================

/// Empty messages array is rejected.
#[fcp_async_core::runtime::test]
async fn validation_empty_messages_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": { "messages": [] },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::InvalidRequest { .. }
    ));
}

/// Unknown model string is rejected.
#[fcp_async_core::runtime::test]
async fn validation_unknown_model_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}],
                "model": "gpt-99-turbo"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::InvalidRequest { .. }
    ));
}

/// Missing message in `simple_chat` is rejected.
#[fcp_async_core::runtime::test]
async fn validation_simple_chat_missing_message_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.simple_chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.simple_chat",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("message"),
                "error should mention missing message: {message}"
            );
        }
        _ => panic!("expected InvalidRequest, got: {err:?}"),
    }
}

// ============================================================================
// Metrics Tests
// ============================================================================

/// Error counter increments on non-retryable errors.
#[fcp_async_core::runtime::test]
async fn metrics_error_counter_increments() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(openai_error(
            "invalid_request_error",
            "Incorrect API key",
            Some("invalid_api_key"),
        )))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    assert_eq!(connector.total_errors(), 0);

    let _result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}]
            },
            "capability_token": token
        }))
        .await;

    assert_eq!(
        connector.total_errors(),
        1,
        "error counter should increment"
    );
}

// ============================================================================
// Get Usage Tests
// ============================================================================

/// `get_usage` returns token and cost stats via invoke.
#[fcp_async_core::runtime::test]
async fn get_usage_returns_stats() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.get_usage");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.get_usage",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["total_prompt_tokens"], 0);
    assert_eq!(result["total_completion_tokens"], 0);
    assert!(result.get("requests_total").is_some());
    assert!(result.get("total_cost_usd").is_some());
}
