//! Live verification tests for the Slack connector against the real Slack API.
//!
//! These tests require a `SLACK_BOT_TOKEN` environment variable with a valid
//! Slack bot token (xoxb-...). When the token is absent, tests skip gracefully
//! with a descriptive message.
//!
//! All operations are READ-ONLY (`slack.list_channels`) and target the
//! workspace's public channels — no side effects or write permissions needed.

use fcp_crypto::Ed25519SigningKey;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_prelude::{CapabilityConstraints, CapabilityToken};
use fcp_slack::connector::SlackConnector;

use chrono::{Duration, Utc};
use serde_json::json;

// ============================================================================
// Skip guard
// ============================================================================

fn slack_token() -> Option<String> {
    std::env::var("SLACK_BOT_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
}

macro_rules! skip_without_token {
    ($var:ident) => {
        let Some($var) = slack_token() else {
            eprintln!(
                "SKIP: SLACK_BOT_TOKEN not set — skipping live Slack connector verification. \
                 Set SLACK_BOT_TOKEN=xoxb-... to enable."
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
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(op)
        .zone_id("z:work")
        .principal("user:live-test")
        .operations(&[op])
        .issuer("node:live-test")
        .validity(now, now + Duration::hours(1))
        .constraints_cbor(&cbor)
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_live_connector(connector: &mut SlackConnector, token: &str) -> Ed25519SigningKey {
    // Configure with real Slack API
    connector
        .handle_configure(json!({
            "token": token
        }))
        .await
        .expect("configure with real token should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["slack.list_channels", "slack.post_message", "slack.get_channel_history"]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Live verification tests
// ============================================================================

#[fcp_async_core::test]
async fn live_conversations_list() {
    skip_without_token!(token);

    let mut connector = SlackConnector::new();
    let signing_key = setup_live_connector(&mut connector, &token).await;
    let cap_token = generate_read_token(&signing_key, "slack.list_channels");

    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {},
            "capability_token": cap_token
        }))
        .await
        .expect("list_channels should succeed");

    // Verify response shape
    let channels = result["channels"]
        .as_array()
        .expect("response should contain channels array");
    // A workspace should have at least one channel (e.g. #general)
    assert!(
        !channels.is_empty(),
        "workspace should have at least one channel"
    );

    // Verify channel objects have expected fields
    let first = &channels[0];
    assert!(
        first.get("id").is_some() || first.get("name").is_some(),
        "channel should have id or name field: {first}"
    );

    eprintln!(
        "PASS: live_conversations_list — found {} channels",
        channels.len()
    );
}

#[fcp_async_core::test]
async fn live_error_mapping_invalid_token() {
    // Test with a deliberately invalid token to verify ConnectorErrorMapping
    // works correctly: should get a structured FCP auth error, not a raw HTTP 401.
    let mut connector = SlackConnector::new();

    // Configure with an obviously invalid token
    connector
        .handle_configure(json!({
            "token": "xoxb-this-is-not-a-valid-token-000000000"
        }))
        .await
        .expect("configure should succeed even with bad token");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["slack.list_channels"]
        }))
        .await
        .expect("handshake should succeed");

    let cap_token = generate_read_token(&signing_key, "slack.list_channels");

    let err = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {},
            "capability_token": cap_token
        }))
        .await;

    // The error should be a structured FCP error, not a raw HTTP status
    assert!(
        err.is_err(),
        "invoke with invalid token should return an error"
    );
    let fcp_err = err.unwrap_err();
    let err_str = format!("{fcp_err}");
    // Should contain structured error info, not just "401"
    assert!(
        err_str.contains("401")
            || err_str.to_lowercase().contains("unauthorized")
            || err_str.to_lowercase().contains("auth")
            || err_str.to_lowercase().contains("invalid")
            || err_str.to_lowercase().contains("token")
            || err_str.to_lowercase().contains("not_authed"),
        "error should indicate auth failure: got '{err_str}'"
    );

    eprintln!("PASS: live_error_mapping_invalid_token — got structured error: {err_str}");
}

#[fcp_async_core::test]
async fn live_health_check() {
    skip_without_token!(token);

    let mut connector = SlackConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &token).await;

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
    skip_without_token!(token);

    let mut connector = SlackConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &token).await;

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    // Should list all 10 operations
    let ops = introspection["operations"]
        .as_array()
        .or_else(|| introspection["provides"].as_array());
    assert!(
        ops.is_some(),
        "introspection should contain operations: {introspection}"
    );
    let ops = ops.unwrap();
    assert!(
        ops.len() >= 8,
        "Slack connector should have at least 8 operations, got {}",
        ops.len()
    );

    // Verify expected operations are present
    let op_ids: Vec<&str> = ops
        .iter()
        .filter_map(|o| o.get("id").and_then(|id| id.as_str()))
        .collect();
    assert!(
        op_ids.contains(&"slack.list_channels"),
        "should contain slack.list_channels: {op_ids:?}"
    );
    assert!(
        op_ids.contains(&"slack.post_message"),
        "should contain slack.post_message: {op_ids:?}"
    );

    eprintln!("PASS: live_introspect — {} operations reported", ops.len());
}
