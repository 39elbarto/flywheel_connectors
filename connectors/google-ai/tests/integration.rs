//! Integration tests for the Google AI (Gemini) connector.
//!
//! Covers the connector testing requirements (flywheel_connectors-e27.6):
//! - Streaming parsing (JSON array and single-object fallback)
//! - Error taxonomy mapping (`GoogleAiError` → `FcpError`)
//! - Redaction (API keys not leaked in error messages)
//! - Usage metrics (token counting across requests)
//!
//! All tests are deterministic — no real API calls.

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_core::{CapabilityToken, FcpError};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_google_ai::{client::GoogleAiClient, connector::GoogleAiConnector, error::GoogleAiError};

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
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
    CapabilityToken { raw: cose }
}

async fn setup_handshake(connector: &mut GoogleAiConnector, caps: &[&str]) -> Ed25519SigningKey {
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

async fn setup_configure(connector: &mut GoogleAiConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-key-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

fn success_response(text: &str, prompt_tokens: u64, candidates_tokens: u64) -> serde_json::Value {
    json!({
        "candidates": [{
            "content": {
                "parts": [{"text": text}],
                "role": "model"
            },
            "finishReason": "STOP",
            "index": 0
        }],
        "usageMetadata": {
            "promptTokenCount": prompt_tokens,
            "candidatesTokenCount": candidates_tokens,
            "totalTokenCount": prompt_tokens + candidates_tokens
        }
    })
}

// ============================================================================
// Streaming parsing tests
// ============================================================================

/// Streaming endpoint returns JSON array of chunks; all should be parsed.
#[fcp_async_core::runtime::test]
async fn streaming_json_array_parses_all_chunks() {
    let mock_server = MockServer::start().await;

    let chunks = json!([
        {
            "candidates": [{
                "content": { "parts": [{"text": "Hello"}], "role": "model" },
                "index": 0
            }]
        },
        {
            "candidates": [{
                "content": { "parts": [{"text": " world"}], "role": "model" },
                "finishReason": "STOP",
                "index": 0
            }],
            "usageMetadata": {
                "promptTokenCount": 8,
                "candidatesTokenCount": 2,
                "totalTokenCount": 10
            }
        }
    ]);

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(chunks))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let result = client
        .generate_content_stream("gemini-2.0-flash", &body)
        .await
        .unwrap();

    assert_eq!(result.len(), 2);
    let text: String = result
        .iter()
        .flat_map(|r| &r.candidates)
        .filter_map(|c| c.content.as_ref())
        .flat_map(|c| &c.parts)
        .filter_map(|p| match p {
            fcp_google_ai::types::Part::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(text, "Hello world");
}

/// Streaming endpoint may return a single object instead of array.
#[fcp_async_core::runtime::test]
async fn streaming_single_object_fallback() {
    let mock_server = MockServer::start().await;

    let single = success_response("single chunk", 5, 3);

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(single))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let result = client
        .generate_content_stream("gemini-2.0-flash", &body)
        .await
        .unwrap();

    assert_eq!(result.len(), 1, "single object should be wrapped in vec");
    assert_eq!(result[0].candidates.len(), 1);
}

/// Streaming accumulates usage across all chunks.
#[fcp_async_core::runtime::test]
async fn streaming_usage_accumulates_across_chunks() {
    let mock_server = MockServer::start().await;

    let chunks = json!([
        {
            "candidates": [{"content": {"parts": [{"text": "a"}], "role": "model"}}],
            "usageMetadata": { "promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15 }
        },
        {
            "candidates": [{"content": {"parts": [{"text": "b"}], "role": "model"}}],
            "usageMetadata": { "promptTokenCount": 0, "candidatesTokenCount": 8, "totalTokenCount": 8 }
        }
    ]);

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(chunks))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    client
        .generate_content_stream("gemini-2.0-flash", &body)
        .await
        .unwrap();

    let usage = client.get_usage();
    assert_eq!(usage.input_tokens, 10, "prompt tokens from both chunks");
    assert_eq!(usage.output_tokens, 13, "candidate tokens from both chunks");
    assert_eq!(usage.requests_total, 1);
}

// ============================================================================
// Error taxonomy mapping tests
// ============================================================================

/// 401 Unauthorized maps to `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(401).set_body_string("API key not valid."))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("bad-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        GoogleAiError::Api {
            status_code: Some(401),
            ..
        }
    ));
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { code: 2001, .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 403 Forbidden also maps to `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_403_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("bad-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let err = client.list_models(None, None).await.unwrap_err();
    assert!(matches!(
        err,
        GoogleAiError::Api {
            status_code: Some(403),
            ..
        }
    ));
    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, FcpError::Unauthorized { .. }));
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[test]
fn error_429_rate_limit_maps_correctly() {
    let err = GoogleAiError::RateLimit {
        retry_after_ms: 30_000,
    };
    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::RateLimited {
                retry_after_ms: 30_000,
                ..
            }
        ),
        "expected RateLimited with 30s, got: {fcp_err:?}"
    );
}

/// 404 Not Found returns specific error (not retryable).
#[fcp_async_core::runtime::test]
async fn error_404_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models/nonexistent-model"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not found"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_model("nonexistent-model").await.unwrap_err();
    assert!(matches!(
        err,
        GoogleAiError::Api {
            status_code: Some(404),
            ..
        }
    ));
    assert!(!err.is_retryable());
}

/// 500 Server Error is retryable and maps to `FcpError::External`.
#[fcp_async_core::runtime::test]
async fn error_500_maps_to_external_retryable() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::External {
                retryable: true,
                status_code: Some(500),
                ..
            }
        ),
        "expected External(500, retryable), got: {fcp_err:?}"
    );
}

/// Malformed JSON body triggers serialization error.
#[fcp_async_core::runtime::test]
async fn error_malformed_json_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not valid json"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    // Should be a serialization error since the JSON is invalid
    assert!(!err.is_retryable());
}

/// `InvalidConfig` maps to `FcpError::InvalidRequest`.
#[test]
fn error_invalid_config_maps_to_invalid_request() {
    let err = GoogleAiError::InvalidConfig("missing api_key".into());
    assert!(!err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::InvalidRequest { code: 1003, .. }),
        "expected InvalidRequest, got: {fcp_err:?}"
    );
}

// ============================================================================
// Redaction tests
// ============================================================================

/// API key should not appear in error messages from the connector.
#[fcp_async_core::runtime::test]
async fn redaction_api_key_not_in_error_message() {
    let mock_server = MockServer::start().await;
    let secret_key = "AIzaSyDSuperSecretKeyThatShouldNotLeak123";

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new(secret_key)
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    let err_string = format!("{err:?}");
    assert!(
        !err_string.contains(secret_key),
        "API key should not appear in error debug output"
    );

    let fcp_err = err.to_fcp_error();
    let fcp_err_string = format!("{fcp_err:?}");
    assert!(
        !fcp_err_string.contains(secret_key),
        "API key should not appear in FCP error debug output"
    );
}

/// API key should not appear in connector-level errors during configure.
#[fcp_async_core::runtime::test]
async fn redaction_api_key_not_in_configure_error() {
    let mut connector = GoogleAiConnector::new();
    let secret_key = "AIzaSyDSuperSecretKeyThatShouldNotLeak456";

    // Configure with a key but with an unreachable URL to trigger error
    let result = connector
        .handle_configure(json!({
            "api_key": secret_key,
            "base_url": "http://127.0.0.1:1/v1beta"
        }))
        .await;

    // The configure should succeed (doesn't validate the URL on configure,
    // or if it fails the error should not contain the key)
    if let Err(err) = result {
        let err_string = format!("{err:?}");
        assert!(
            !err_string.contains(secret_key),
            "API key should not appear in configure error"
        );
    }
}

/// Error messages from invoke should not leak the API key.
#[fcp_async_core::runtime::test]
async fn redaction_api_key_not_in_invoke_error() {
    let mock_server = MockServer::start().await;
    let secret_key = "AIzaSyDSuperSecretKeyThatShouldNotLeak789";

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "message": "Invalid argument",
                "status": "INVALID_ARGUMENT",
                "code": 400
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    connector
        .handle_configure(json!({
            "api_key": secret_key,
            "base_url": format!("{}/v1beta", mock_server.uri())
        }))
        .await
        .unwrap();

    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content"]).await;
    let token = generate_valid_token(&signing_key, "google-ai.generate_content");

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {"contents": [{"role": "user", "parts": [{"text": "test"}]}]},
            "capability_token": token
        }))
        .await;

    if let Err(err) = result {
        let err_string = format!("{err:?}");
        assert!(
            !err_string.contains(secret_key),
            "API key should not appear in invoke error: {err_string}"
        );
    }
}

// ============================================================================
// Usage metrics tests
// ============================================================================

/// Single request accumulates token usage correctly.
#[fcp_async_core::runtime::test]
async fn usage_single_request() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response("ok", 12, 8)))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();

    let usage = client.get_usage();
    assert_eq!(usage.input_tokens, 12);
    assert_eq!(usage.output_tokens, 8);
    assert_eq!(usage.requests_total, 1);
    assert_eq!(usage.requests_error, 0);
}

/// Multiple requests accumulate token usage.
#[fcp_async_core::runtime::test]
async fn usage_multiple_requests_accumulate() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response("ok", 10, 20)))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();
    client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();
    client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();

    let usage = client.get_usage();
    assert_eq!(usage.input_tokens, 30, "10 * 3 requests");
    assert_eq!(usage.output_tokens, 60, "20 * 3 requests");
    assert_eq!(usage.requests_total, 3);
    assert_eq!(usage.requests_error, 0);
}

/// Error requests increment error counter.
#[fcp_async_core::runtime::test]
async fn usage_error_requests_counted() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("bad-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let _ = client.generate_content("gemini-2.0-flash", &body).await;

    let usage = client.get_usage();
    assert_eq!(usage.requests_total, 1);
    assert_eq!(usage.requests_error, 1);
    assert_eq!(usage.input_tokens, 0, "no tokens on error");
    assert_eq!(usage.output_tokens, 0);
}

/// Usage is exposed via the google-ai.get_usage connector operation.
#[fcp_async_core::runtime::test]
async fn usage_exposed_via_connector_operation() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response("hello", 15, 25)))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(
        &mut connector,
        &["google-ai.generate_content", "google-ai.get_usage"],
    )
    .await;

    // Make a generate request to populate usage
    let gen_token = generate_valid_token(&signing_key, "google-ai.generate_content");
    connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {"contents": [{"role": "user", "parts": [{"text": "test"}]}]},
            "capability_token": gen_token
        }))
        .await
        .unwrap();

    // Get usage via operation
    let usage_token = generate_valid_token(&signing_key, "google-ai.get_usage");
    let usage_result = connector
        .handle_invoke(json!({
            "operation": "google-ai.get_usage",
            "input": {},
            "capability_token": usage_token
        }))
        .await
        .unwrap();

    assert_eq!(usage_result["total_input_tokens"], 15);
    assert_eq!(usage_result["total_output_tokens"], 25);
    assert_eq!(usage_result["requests_total"], 1);
    assert_eq!(usage_result["requests_error"], 0);
}

// ============================================================================
// Tool use (function calling) tests
// ============================================================================

/// Generate content returning a function call should parse correctly.
#[fcp_async_core::runtime::test]
async fn tool_use_function_call_in_response() {
    let mock_server = MockServer::start().await;

    let resp = json!({
        "candidates": [{
            "content": {
                "parts": [{
                    "functionCall": {
                        "name": "get_weather",
                        "args": {"location": "San Francisco", "unit": "celsius"}
                    }
                }],
                "role": "model"
            },
            "finishReason": "STOP",
            "index": 0
        }],
        "usageMetadata": {
            "promptTokenCount": 20,
            "candidatesTokenCount": 15,
            "totalTokenCount": 35
        }
    });

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resp))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "what is the weather?"}]}],
        "tools": [{"functionDeclarations": [{
            "name": "get_weather",
            "description": "Get the weather",
            "parameters": {
                "type": "object",
                "properties": {"location": {"type": "string"}, "unit": {"type": "string"}}
            }
        }]}]
    });
    let result = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();

    assert_eq!(result.candidates.len(), 1);
    let parts = &result.candidates[0].content.as_ref().unwrap().parts;
    assert_eq!(parts.len(), 1);
    assert!(
        matches!(&parts[0], fcp_google_ai::types::Part::FunctionCall { .. }),
        "expected FunctionCall part"
    );
}

/// Provenance metadata from non-streaming generate should flag tool calls.
#[fcp_async_core::runtime::test]
async fn provenance_flags_tool_calls_in_generate() {
    let mock_server = MockServer::start().await;

    let resp = json!({
        "candidates": [{
            "content": {
                "parts": [{
                    "functionCall": {
                        "name": "search",
                        "args": {"query": "rust"}
                    }
                }],
                "role": "model"
            },
            "finishReason": "STOP",
            "index": 0
        }],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 8,
            "totalTokenCount": 18
        }
    });

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resp))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content"]).await;
    let token = generate_valid_token(&signing_key, "google-ai.generate_content");

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {
                "contents": [{"role": "user", "parts": [{"text": "search for rust"}]}],
                "tools": [{"functionDeclarations": [{"name": "search", "parameters": {"type": "object"}}]}]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    let prov = &result["provenance"];
    assert_eq!(prov["source"], "google-ai");
    assert_eq!(prov["model"], "gemini-2.0-flash");
    assert_eq!(prov["integrity"], "untrusted");
    assert_eq!(prov["has_tool_calls"], true);
    assert_eq!(prov["chunk_count"], 1);
}

/// Provenance metadata from non-streaming generate should NOT flag tool calls for text-only.
#[fcp_async_core::runtime::test]
async fn provenance_no_tool_calls_for_text_only() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response(
            "hello world",
            5,
            3,
        )))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content"]).await;
    let token = generate_valid_token(&signing_key, "google-ai.generate_content");

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]},
            "capability_token": token
        }))
        .await
        .unwrap();

    let prov = &result["provenance"];
    assert_eq!(prov["has_tool_calls"], false);
    assert_eq!(prov["chunk_count"], 1);
}

// ============================================================================
// Streaming through connector tests
// ============================================================================

/// Streaming through the connector returns provenance with `chunk_count` > 1.
#[fcp_async_core::runtime::test]
async fn streaming_through_connector_has_provenance() {
    let mock_server = MockServer::start().await;

    let chunks = json!([
        {
            "candidates": [{
                "content": { "parts": [{"text": "Hello"}], "role": "model" },
                "index": 0
            }]
        },
        {
            "candidates": [{
                "content": { "parts": [{"text": " world"}], "role": "model" },
                "finishReason": "STOP",
                "index": 0
            }],
            "usageMetadata": {
                "promptTokenCount": 8,
                "candidatesTokenCount": 2,
                "totalTokenCount": 10
            }
        }
    ]);

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(chunks))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content_stream"]).await;
    let token = generate_valid_token(&signing_key, "google-ai.generate_content_stream");

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content_stream",
            "input": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]},
            "capability_token": token
        }))
        .await
        .unwrap();

    let prov = &result["provenance"];
    assert_eq!(prov["source"], "google-ai");
    assert_eq!(prov["model"], "gemini-2.0-flash");
    assert_eq!(prov["integrity"], "untrusted");
    assert_eq!(prov["has_tool_calls"], false);
    assert_eq!(prov["chunk_count"], 2);
}

/// Streaming with tool calls in one of the chunks should flag `has_tool_calls`.
#[fcp_async_core::runtime::test]
async fn streaming_tool_call_detected_in_provenance() {
    let mock_server = MockServer::start().await;

    let chunks = json!([
        {
            "candidates": [{
                "content": { "parts": [{"text": "Let me search"}], "role": "model" },
                "index": 0
            }]
        },
        {
            "candidates": [{
                "content": {
                    "parts": [{
                        "functionCall": {
                            "name": "web_search",
                            "args": {"query": "weather today"}
                        }
                    }],
                    "role": "model"
                },
                "finishReason": "STOP",
                "index": 0
            }],
            "usageMetadata": {
                "promptTokenCount": 12,
                "candidatesTokenCount": 10,
                "totalTokenCount": 22
            }
        }
    ]);

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(chunks))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content_stream"]).await;
    let token = generate_valid_token(&signing_key, "google-ai.generate_content_stream");

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content_stream",
            "input": {"contents": [{"role": "user", "parts": [{"text": "weather?"}]}]},
            "capability_token": token
        }))
        .await
        .unwrap();

    let prov = &result["provenance"];
    assert_eq!(prov["has_tool_calls"], true);
    assert_eq!(prov["chunk_count"], 2);
}

/// Wrong capability token rejects `generate_content` invocation.
#[fcp_async_core::runtime::test]
async fn wrong_capability_rejects_generate() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response("ok", 1, 1)))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.list_models"]).await;
    // Use a token for list_models, not generate_content
    let token = generate_valid_token(&signing_key, "google-ai.list_models");

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {"contents": [{"role": "user", "parts": [{"text": "test"}]}]},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject mismatched capability");
}
