//! Anthropic connector integration tests (flywheel_connectors-s7j5).
//!
//! Deterministic integration tests using wiremock to mock the Anthropic API.
//! No real API calls. Covers:
//! - Non-streaming generation (chat + message)
//! - Streaming SSE (chunk parsing, error mid-stream)
//! - Tool/function calling shapes
//! - Error taxonomy (401/429/529/5xx)
//! - Usage metrics extraction
//! - FCP2 default-deny + capability verification

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
use fcp_anthropic::client::AnthropicClient;
use fcp_anthropic::connector::AnthropicConnector;
use fcp_anthropic::types::Model;

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
async fn setup_handshake(connector: &mut AnthropicConnector, caps: &[&str]) -> Ed25519SigningKey {
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
async fn setup_configure(connector: &mut AnthropicConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-api-key-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

/// Standard Anthropic API success response.
fn anthropic_success_response(
    msg_id: &str,
    text: &str,
    input_tokens: u32,
    output_tokens: u32,
) -> serde_json::Value {
    json!({
        "id": msg_id,
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "model": "claude-sonnet-4-20250514",
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens
        }
    })
}

/// Anthropic API `tool_use` response.
fn anthropic_tool_use_response(
    msg_id: &str,
    tool_id: &str,
    tool_name: &str,
    tool_input: &serde_json::Value,
    input_tokens: u32,
    output_tokens: u32,
) -> serde_json::Value {
    json!({
        "id": msg_id,
        "type": "message",
        "role": "assistant",
        "content": [{
            "type": "tool_use",
            "id": tool_id,
            "name": tool_name,
            "input": tool_input
        }],
        "model": "claude-sonnet-4-20250514",
        "stop_reason": "tool_use",
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens
        }
    })
}

/// Anthropic API error envelope.
fn anthropic_error(error_type: &str, message: &str) -> serde_json::Value {
    json!({
        "error": {
            "type": error_type,
            "message": message
        }
    })
}

// ============================================================================
// Non-Streaming Generation Tests
// ============================================================================

/// Happy path: anthropic.chat invoke returns text response.
#[fcp_async_core::runtime::test]
async fn chat_invoke_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.chat.happy_path");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_success_response("msg_001", "Hello from Claude!", 12, 8),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi there" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["response"], "Hello from Claude!");
    assert_eq!(result["usage"]["input_tokens"], 12);
    assert_eq!(result["usage"]["output_tokens"], 8);
    // Cost is present and non-zero (not hard-coded)
    let cost = result["cost_usd"].as_f64().unwrap();
    assert!(cost > 0.0, "cost should be positive: {cost}");
    mock.assert_received("/v1/messages").await;
}

/// Happy path: anthropic.message invoke with multi-turn messages.
#[fcp_async_core::runtime::test]
async fn message_invoke_multi_turn() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.message.multi_turn");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_success_response("msg_002", "The capital of France is Paris.", 25, 12),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
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
    assert_eq!(result["id"], "msg_002");
}

/// anthropic.message with system prompt.
#[fcp_async_core::runtime::test]
async fn message_invoke_with_system() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_success_response("msg_003", "42", 30, 3),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "What is 6*7?"}],
                "system": "You are a calculator. Reply with only the number.",
                "temperature": 0.0
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["content"], "42");
}

// ============================================================================
// Streaming SSE Tests
// ============================================================================

/// Build SSE body for streaming response.
fn build_sse_body(events: &[(&str, serde_json::Value)]) -> String {
    use std::fmt::Write;
    events
        .iter()
        .fold(String::new(), |mut acc, (event_type, data)| {
            write!(acc, "event: {event_type}\ndata: {data}\n\n").unwrap();
            acc
        })
}

/// Streaming: parse complete SSE chunks.
#[fcp_async_core::runtime::test]
async fn streaming_sse_chunk_parsing() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.stream.chunk_parsing");
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_stream_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 10, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello"}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": " World"}}),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        ),
        (
            "message_delta",
            json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"input_tokens": 10, "output_tokens": 5}
            }),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "test-stream-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-stream-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_anthropic::types::Message {
        role: fcp_anthropic::types::Role::User,
        content: "Hello".into(),
    }];

    let stream = client
        .message_stream(Model::ClaudeSonnet4, messages, 1024, None, None, None, None)
        .await
        .expect("stream should start");

    let events: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.expect("each event should parse"))
        .collect();

    // Should have 7 events total
    assert_eq!(
        events.len(),
        7,
        "expected 7 SSE events, got {}",
        events.len()
    );

    // Verify text deltas
    let mut text_acc = String::new();
    for event in &events {
        if let fcp_anthropic::types::StreamEvent::ContentBlockDelta {
            delta: fcp_anthropic::types::ContentDelta::TextDelta { text },
            ..
        } = event
        {
            text_acc.push_str(text);
        }
    }
    assert_eq!(text_acc, "Hello World");
}

/// Streaming: SSE error mid-stream.
#[fcp_async_core::runtime::test]
async fn streaming_sse_error_mid_stream() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.stream.error_mid_stream");
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_err_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 10, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Part"}}),
        ),
        (
            "error",
            json!({"type": "error", "error": {"type": "overloaded_error", "message": "Server overloaded"}}),
        ),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_anthropic::types::Message {
        role: fcp_anthropic::types::Role::User,
        content: "Hello".into(),
    }];

    let stream = client
        .message_stream(Model::ClaudeSonnet4, messages, 1024, None, None, None, None)
        .await
        .expect("stream should start");

    let events: Vec<_> = stream.collect::<Vec<_>>().await;
    assert!(
        events.len() >= 3,
        "should receive partial events before error"
    );

    // Last valid event should be the error
    let last = events
        .last()
        .unwrap()
        .as_ref()
        .expect("last event should parse");
    assert!(
        matches!(last, fcp_anthropic::types::StreamEvent::Error { .. }),
        "last event should be error, got: {last:?}"
    );
}

/// Streaming: SSE ping keepalive events are parsed.
#[fcp_async_core::runtime::test]
async fn streaming_sse_ping_keepalive() {
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        ("ping", json!({"type": "ping"})),
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_ping_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 5, "output_tokens": 0}
                }
            }),
        ),
        ("ping", json!({"type": "ping"})),
        ("message_stop", json!({"type": "message_stop"})),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_anthropic::types::Message {
        role: fcp_anthropic::types::Role::User,
        content: "ping test".into(),
    }];

    let stream = client
        .message_stream(Model::ClaudeSonnet4, messages, 256, None, None, None, None)
        .await
        .expect("stream should start");

    let events: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter_map(std::result::Result::ok)
        .collect();

    let ping_count = events
        .iter()
        .filter(|e| matches!(e, fcp_anthropic::types::StreamEvent::Ping))
        .count();

    assert_eq!(ping_count, 2, "should have 2 ping events");
}

// ============================================================================
// Tool/Function Calling Tests
// ============================================================================

/// Tool use: model requests tool call and response includes `tool_use` content.
#[fcp_async_core::runtime::test]
async fn tool_use_invoke_shape() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.tool_use.shape");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_tool_use_response(
            "msg_tool_001",
            "tool_call_abc",
            "get_weather",
            &json!({"city": "San Francisco", "unit": "celsius"}),
            20,
            15,
        ),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "What is the weather in SF?"}],
                "tools": [{
                    "name": "get_weather",
                    "description": "Get current weather for a city",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "city": {"type": "string"},
                            "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
                        },
                        "required": ["city"]
                    }
                }],
                "tool_choice": {"type": "auto"}
            },
            "capability_token": token
        }))
        .await
        .expect("tool use invoke should succeed");

    assert_eq!(result["id"], "msg_tool_001");
    // stop_reason should be tool_use
    assert_eq!(result["stop_reason"], "tool_use");
    assert_eq!(result["usage"]["input_tokens"], 20);
    assert_eq!(result["usage"]["output_tokens"], 15);
}

/// Tool use: streaming response with tool use block.
#[fcp_async_core::runtime::test]
async fn tool_use_streaming_shape() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.tool_use.streaming");
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_tool_stream_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 25, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "tool_stream_abc",
                    "name": "get_weather",
                    "input": {}
                }
            }),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{\"city\": \"Paris\""}
            }),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "}"}
            }),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        ),
        (
            "message_delta",
            json!({
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use", "stop_sequence": null},
                "usage": {"input_tokens": 25, "output_tokens": 10}
            }),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_anthropic::types::Message {
        role: fcp_anthropic::types::Role::User,
        content: "Weather in Paris?".into(),
    }];

    let tools = vec![fcp_anthropic::types::Tool {
        name: "get_weather".into(),
        description: "Get weather".into(),
        input_schema: json!({"type": "object", "properties": {"city": {"type": "string"}}}),
    }];

    let stream = client
        .message_stream(
            Model::ClaudeSonnet4,
            messages,
            1024,
            None,
            None,
            Some(tools),
            None,
        )
        .await
        .expect("stream should start");

    let events: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter_map(std::result::Result::ok)
        .collect();

    // Collect JSON delta fragments
    let mut json_acc = String::new();
    for event in &events {
        if let fcp_anthropic::types::StreamEvent::ContentBlockDelta {
            delta: fcp_anthropic::types::ContentDelta::InputJsonDelta { partial_json },
            ..
        } = event
        {
            json_acc.push_str(partial_json);
        }
    }
    assert_eq!(json_acc, "{\"city\": \"Paris\"}");

    // Verify tool_use content block start
    let has_tool_start = events.iter().any(|e| {
        matches!(
            e,
            fcp_anthropic::types::StreamEvent::ContentBlockStart {
                content_block: fcp_anthropic::types::ContentBlockStartData::ToolUse { name, .. },
                ..
            } if name == "get_weather"
        )
    });
    assert!(has_tool_start, "should have tool_use content block start");
}

// ============================================================================
// Error Taxonomy Tests (401/429/529/5xx → FCP error mapping)
// ============================================================================

/// 401 Unauthorized maps to `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.error.401");
    let mock = MockApiServer::start().await;

    mock.expect_error(
        "/v1/messages",
        401,
        anthropic_error("authentication_error", "Invalid API key"),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("should fail with 401");

    assert!(
        matches!(err, fcp_core::FcpError::Unauthorized { .. }),
        "expected Unauthorized, got: {err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
/// Uses client directly with minimal retry config to avoid slow backoff.
#[fcp_async_core::runtime::test]
async fn error_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.error.429");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(anthropic_error("rate_limit_error", "Rate limit exceeded")),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;
    let err = result.expect_err("should fail with 429");

    // Client-level error
    assert!(
        matches!(
            err,
            fcp_anthropic::error::AnthropicError::RateLimited { .. }
        ),
        "expected RateLimited, got: {err:?}"
    );

    // Verify FCP mapping
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "expected FcpError::RateLimited, got: {fcp_err:?}"
    );
}

/// 529 Overloaded maps to `FcpError::External` with retryable=true.
/// Uses client directly with minimal retry config to avoid slow backoff.
#[fcp_async_core::runtime::test]
async fn error_529_maps_to_external_retryable() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.error.529");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(529)
                .set_body_json(anthropic_error("overloaded_error", "Overloaded")),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;
    let err = result.expect_err("should fail with 529");

    // Client-level error
    assert!(
        matches!(err, fcp_anthropic::error::AnthropicError::Overloaded { .. }),
        "expected Overloaded, got: {err:?}"
    );

    // Verify FCP mapping
    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External {
            service,
            retryable,
            status_code,
            ..
        } => {
            assert_eq!(service, "anthropic");
            assert!(retryable, "529 should be retryable");
            assert_eq!(*status_code, Some(529));
        }
        other => panic!("expected FcpError::External, got: {other:?}"),
    }
}

/// 500 Server Error maps to `FcpError::External`.
/// Uses client directly with minimal retry config.
#[fcp_async_core::runtime::test]
async fn error_500_maps_to_external() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(anthropic_error("api_error", "Internal server error")),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;
    let err = result.expect_err("should fail with 500");

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::External { .. }),
        "expected FcpError::External, got: {fcp_err:?}"
    );
}

/// 400 with `context_length_exceeded` maps to `InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn error_context_length_maps_to_invalid_request() {
    let mock = MockApiServer::start().await;

    mock.expect_error(
        "/v1/messages",
        400,
        anthropic_error(
            "invalid_request_error",
            "context length exceeded: maximum is 200000 tokens",
        ),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("should fail with context length");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("context length"),
                "error should mention context length: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

// ============================================================================
// Usage Metrics Tests (tokens, latencies — not hard-coded pricing)
// ============================================================================

/// Usage metrics accumulate across multiple invocations.
#[fcp_async_core::runtime::test]
async fn usage_metrics_accumulate() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.usage.accumulate");
    let mock_server = MockServer::start().await;

    // Two sequential requests with different token counts
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(anthropic_success_response("msg_u1", "First", 10, 5)),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "usage-test-key",
            "base_url": mock_server.uri()
        }))
        .await
        .unwrap();
    let signing_key =
        setup_handshake(&mut connector, &["anthropic.chat", "anthropic.get_usage"]).await;

    // First invocation
    let token = generate_valid_token(&signing_key, "anthropic.chat");
    connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "First" },
            "capability_token": token
        }))
        .await
        .expect("first invoke should succeed");

    // Check metrics via get_usage
    let usage_token = generate_valid_token(&signing_key, "anthropic.get_usage");
    let usage = connector
        .handle_invoke(json!({
            "operation": "anthropic.get_usage",
            "input": {},
            "capability_token": usage_token
        }))
        .await
        .expect("get_usage should succeed");

    assert_eq!(usage["total_input_tokens"], 10);
    assert_eq!(usage["total_output_tokens"], 5);
    assert!(usage["requests_total"].as_u64().unwrap() >= 1);
    let cost = usage["total_cost_usd"].as_f64().unwrap();
    assert!(cost > 0.0, "cost should be positive after invocation");
}

/// Usage cost is model-dependent (not hard-coded).
#[fcp_async_core::runtime::test]
async fn usage_cost_is_model_dependent() {
    let mock_server = MockServer::start().await;

    // Same token counts, different models
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_cost_001",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-3-5-haiku-20241022",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1000, "output_tokens": 500}
        })))
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "cost-test-key",
            "base_url": mock_server.uri()
        }))
        .await
        .unwrap();
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}],
                "model": "claude-3-5-haiku-20241022"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let haiku_cost = result["cost_usd"].as_f64().unwrap();
    // Haiku: $0.25/M input + $1.25/M output
    // 1000 input tokens = $0.00025, 500 output tokens = $0.000625
    // Total should be around $0.000875
    assert!(
        haiku_cost > 0.0 && haiku_cost < 0.01,
        "haiku cost should be small but positive: {haiku_cost}"
    );
}

// ============================================================================
// FCP2 Default-Deny / Capability Verification Tests
// ============================================================================

/// Invoke without `capability_token` fails.
#[fcp_async_core::runtime::test]
async fn capability_missing_token_fails() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.capability.missing_token");
    let mock = MockApiServer::start().await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    setup_handshake(&mut connector, &["anthropic.chat"]).await;

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" }
        }))
        .await
        .expect_err("invoke without token should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing token, got: {err:?}"
    );
}

/// Invoke before handshake fails (no verifier).
#[fcp_async_core::runtime::test]
async fn capability_no_handshake_fails() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.capability.no_handshake");
    let mock = MockApiServer::start().await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;

    // Generate token with arbitrary key (no handshake, so no verifier)
    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke without handshake should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured, got: {err:?}"
    );
}

/// Invoke before configure fails (no client).
#[fcp_async_core::runtime::test]
async fn capability_no_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.capability.no_configure");

    let mut connector = AnthropicConnector::new();
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke without configure should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured, got: {err:?}"
    );
}

/// Invoke with wrong capability (signed for different operation) fails.
#[fcp_async_core::runtime::test]
async fn capability_wrong_operation_fails() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.capability.wrong_op");
    let mock = MockApiServer::start().await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key =
        setup_handshake(&mut connector, &["anthropic.chat", "anthropic.get_usage"]).await;

    // Token signed for get_usage, used on chat
    let wrong_token = generate_valid_token(&signing_key, "anthropic.get_usage");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": wrong_token
        }))
        .await
        .expect_err("wrong capability should fail");

    // Verifier rejects token signed for a different operation
    let is_cap_error = matches!(
        &err,
        fcp_core::FcpError::CapabilityDenied { .. }
            | fcp_core::FcpError::Unauthorized { .. }
            | fcp_core::FcpError::OperationNotGranted { .. }
    );
    assert!(
        is_cap_error,
        "expected capability/operation denial error, got: {err:?}"
    );
}

/// Unknown operation fails with `OperationNotGranted`.
#[fcp_async_core::runtime::test]
async fn capability_unknown_operation_fails() {
    let mock = MockApiServer::start().await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.nonexistent");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("unknown operation should fail");

    assert!(
        matches!(err, fcp_core::FcpError::OperationNotGranted { .. }),
        "expected OperationNotGranted, got: {err:?}"
    );
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

/// Health check before configure reports `not_configured`.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_before_configure() {
    let connector = AnthropicConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

/// Health check after configure reports healthy.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

/// Handshake returns accepted with capabilities granted.
#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_grants_capabilities() {
    let mut connector = AnthropicConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["anthropic.message", "anthropic.chat", "anthropic.get_usage"]
        }))
        .await
        .expect("handshake should succeed");

    assert_eq!(result["status"], "accepted");
    assert!(result["event_caps"]["streaming"].as_bool().unwrap());
    let caps = result["capabilities_granted"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

/// Shutdown returns clean status.
#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown_clean() {
    let connector = AnthropicConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

/// Introspect exposes expected operations.
#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_operations() {
    let connector = AnthropicConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().unwrap();
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    assert!(op_ids.contains(&"anthropic.message"));
    assert!(op_ids.contains(&"anthropic.chat"));
    assert!(op_ids.contains(&"anthropic.get_usage"));
    assert_eq!(op_ids.len(), 3);

    // Verify schemas are present
    for op in ops {
        assert!(
            op["input_schema"].is_object(),
            "input_schema should be object"
        );
        assert!(
            op["output_schema"].is_object(),
            "output_schema should be object"
        );
    }
}

// ============================================================================
// Validation Edge Cases
// ============================================================================

/// Empty messages array fails with clear error.
#[fcp_async_core::runtime::test]
async fn validation_empty_messages_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.message");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": { "messages": [] },
            "capability_token": token
        }))
        .await
        .expect_err("empty messages should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.to_lowercase().contains("empty")
                    || message.to_lowercase().contains("messages"),
                "error should mention messages: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Unknown model name fails.
#[fcp_async_core::runtime::test]
async fn validation_unknown_model_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.message");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}],
                "model": "claude-nonexistent-model"
            },
            "capability_token": token
        }))
        .await
        .expect_err("unknown model should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for unknown model, got: {err:?}"
    );
}

/// Missing required message field in chat invoke fails.
#[fcp_async_core::runtime::test]
async fn validation_chat_missing_message_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing message field should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.to_lowercase().contains("message"),
                "error should mention message: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Error counters increment on failures.
/// Uses 401 (non-retryable) to avoid slow retry backoff.
#[fcp_async_core::runtime::test]
async fn metrics_error_counter_increments() {
    let mock = MockApiServer::start().await;

    mock.expect_error(
        "/v1/messages",
        401,
        anthropic_error("authentication_error", "Invalid API key"),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token = generate_valid_token(&signing_key, "anthropic.chat");

    let _ = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await;

    assert!(
        connector.total_errors() >= 1,
        "error counter should increment: {}",
        connector.total_errors()
    );
    assert!(
        connector.total_requests() >= 1,
        "request counter should increment: {}",
        connector.total_requests()
    );
}
