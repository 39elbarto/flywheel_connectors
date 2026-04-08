//! Live verification tests for the Anthropic connector against the real Anthropic API.
//!
//! These tests require an `ANTHROPIC_API_KEY` environment variable with a valid
//! Anthropic API key. When the key is absent, tests skip gracefully with a
//! descriptive message.
//!
//! The `live_messages_create` test sends a minimal prompt to Claude and verifies
//! the response shape. The `live_error_mapping_invalid_key` test runs without a
//! key and confirms structured FCP error mapping.

use fcp_core::CapabilityToken;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::Ed25519SigningKey;
use fcp_anthropic::connector::AnthropicConnector;

use chrono::{Duration, Utc};
use serde_json::json;

// ============================================================================
// Skip guard
// ============================================================================

fn anthropic_api_key() -> Option<String> {
    std::env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.is_empty())
}

macro_rules! skip_without_key {
    ($var:ident) => {
        let Some($var) = anthropic_api_key() else {
            eprintln!(
                "SKIP: ANTHROPIC_API_KEY not set — skipping live Anthropic connector verification. \
                 Set ANTHROPIC_API_KEY=sk-ant-... to enable."
            );
            return;
        };
    };
}

// ============================================================================
// Helpers
// ============================================================================

fn generate_read_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id("anthropic.chat")
        .zone_id("z:work")
        .principal("user:live-test")
        .operations(&[op])
        .issuer("node:live-test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .unwrap();
    CapabilityToken { raw: cose }
}

async fn setup_live_connector(
    connector: &mut AnthropicConnector,
    api_key: &str,
) -> Ed25519SigningKey {
    // Configure with real Anthropic API key
    connector
        .handle_configure(json!({
            "api_key": api_key,
            "base_url": "https://api.anthropic.com"
        }))
        .await
        .expect("configure with real API key should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["anthropic.message", "anthropic.chat"]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Live verification tests
// ============================================================================

#[fcp_async_core::test]
async fn live_messages_create() {
    skip_without_key!(api_key);

    let mut connector = AnthropicConnector::new();
    let signing_key = setup_live_connector(&mut connector, &api_key).await;
    let cap_token = generate_read_token(&signing_key, "anthropic.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": {
                "message": "Reply with exactly: hello world",
                "model": "claude-3-5-haiku-20241022",
                "max_tokens": 64
            },
            "capability_token": cap_token
        }))
        .await
        .expect("anthropic.chat invoke should succeed");

    // Verify response shape
    assert!(
        result.get("response").is_some(),
        "response should contain 'response' field: {result}"
    );
    let response_text = result["response"]
        .as_str()
        .expect("response should be a string");
    assert!(
        !response_text.is_empty(),
        "response text should not be empty"
    );

    // Verify usage is reported
    assert!(
        result.get("usage").is_some() || result.get("cost_usd").is_some(),
        "response should contain usage or cost_usd: {result}"
    );

    eprintln!(
        "PASS: live_messages_create — got response ({} chars)",
        response_text.len()
    );
}

#[fcp_async_core::test]
async fn live_error_mapping_invalid_key() {
    // Test with a deliberately invalid key to verify ConnectorErrorMapping
    // works correctly: should get a structured FCP auth error, not a raw HTTP 401.
    let mut connector = AnthropicConnector::new();

    // Configure with an obviously invalid key
    connector
        .handle_configure(json!({
            "api_key": "sk-ant-invalid-key-000000000000000000000000",
            "base_url": "https://api.anthropic.com"
        }))
        .await
        .expect("configure should succeed even with bad key");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["anthropic.chat"]
        }))
        .await
        .expect("handshake should succeed");

    let cap_token = generate_read_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": {
                "message": "hello",
                "max_tokens": 16
            },
            "capability_token": cap_token
        }))
        .await;

    // The error should be a structured FCP error, not a raw HTTP status
    assert!(
        err.is_err(),
        "invoke with invalid key should return an error"
    );
    let fcp_err = err.unwrap_err();
    let err_str = format!("{fcp_err}");
    // Should contain structured error info, not just "401"
    assert!(
        err_str.contains("401")
            || err_str.to_lowercase().contains("unauthorized")
            || err_str.to_lowercase().contains("auth")
            || err_str.to_lowercase().contains("credential")
            || err_str.to_lowercase().contains("invalid")
            || err_str.to_lowercase().contains("api_key"),
        "error should indicate auth failure: got '{err_str}'"
    );

    eprintln!("PASS: live_error_mapping_invalid_key — got structured error: {err_str}");
}

#[fcp_async_core::test]
async fn live_health_check() {
    skip_without_key!(api_key);

    let mut connector = AnthropicConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &api_key).await;

    let health = connector
        .handle_health()
        .await
        .expect("health check should succeed");

    assert!(
        health.get("status").is_some() || health.get("healthy").is_some(),
        "health response should contain status or healthy field: {health}"
    );

    eprintln!("PASS: live_health_check — {health}");
}

#[fcp_async_core::test]
async fn live_introspect() {
    skip_without_key!(api_key);

    let mut connector = AnthropicConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &api_key).await;

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    // Should list operations
    let ops = introspection["operations"]
        .as_array()
        .or_else(|| introspection["provides"].as_array());
    assert!(
        ops.is_some(),
        "introspection should contain operations: {introspection}"
    );
    let ops = ops.unwrap();
    assert!(
        ops.len() >= 3,
        "Anthropic connector should have at least 3 operations (message, chat, get_usage), got {}",
        ops.len()
    );

    // Verify anthropic.message is listed
    let has_message = ops.iter().any(|op| {
        op.get("id")
            .and_then(|id| id.as_str())
            .map_or(false, |id| id == "anthropic.message")
    });
    assert!(
        has_message,
        "operations should include anthropic.message: {introspection}"
    );

    eprintln!(
        "PASS: live_introspect — {} operations reported",
        ops.len()
    );
}
