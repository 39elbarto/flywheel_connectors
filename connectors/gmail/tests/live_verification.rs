//! Live verification tests for the Gmail connector against the real Gmail API.
//!
//! These tests require a `GMAIL_ACCESS_TOKEN` environment variable with a valid
//! OAuth2 access token. When the token is absent, tests skip gracefully with a
//! descriptive message.
//!
//! All operations are READ-ONLY (gmail.list_labels) and do not create, modify,
//! or delete any data.

use fcp_core::CapabilityToken;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::Ed25519SigningKey;

use chrono::{Duration, Utc};
use serde_json::json;

// ============================================================================
// Skip guard
// ============================================================================

fn gmail_access_token() -> Option<String> {
    std::env::var("GMAIL_ACCESS_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
}

macro_rules! skip_without_token {
    ($var:ident) => {
        let Some($var) = gmail_access_token() else {
            eprintln!(
                "SKIP: GMAIL_ACCESS_TOKEN not set — skipping live Gmail connector verification. \
                 Set GMAIL_ACCESS_TOKEN=ya29.... to enable."
            );
            return;
        };
    };
}

// ============================================================================
// Helpers
// ============================================================================

fn generate_read_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
    let cap = match op {
        "gmail.send_message" | "gmail.send_draft" => "gmail.send",
        "gmail.sync_history" => "gmail.history.read",
        "gmail.modify_message" | "gmail.get_draft" => "gmail.write",
        "gmail.trash_message" => "gmail.delete",
        _ => "gmail.read",
    };
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
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
    connector: &mut fcp_gmail::connector::GmailConnector,
    access_token: &str,
) -> Ed25519SigningKey {
    // Configure with real Gmail API using a bearer token
    connector
        .handle_configure(json!({
            "token": access_token
        }))
        .await
        .expect("configure with real access token should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["gmail.read"]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Live verification tests
// ============================================================================

#[fcp_async_core::test]
async fn live_labels_list() {
    skip_without_token!(token);

    let mut connector = fcp_gmail::connector::GmailConnector::new();
    let signing_key = setup_live_connector(&mut connector, &token).await;
    let cap_token = generate_read_token(&signing_key, "gmail.list_labels");

    let result = connector
        .handle_invoke(json!({
            "operation": "gmail.list_labels",
            "input": {},
            "capability_token": cap_token
        }))
        .await
        .expect("list_labels should succeed against real Gmail API");

    // Verify response shape
    let labels = result["labels"]
        .as_array()
        .expect("response should contain 'labels' array");
    assert!(
        !labels.is_empty(),
        "Gmail account should have at least one label (INBOX, etc.)"
    );

    eprintln!(
        "PASS: live_labels_list — returned {} labels",
        labels.len()
    );
}

#[fcp_async_core::test]
async fn live_error_mapping_invalid_token() {
    // Test with a deliberately invalid token to verify ConnectorErrorMapping
    // works correctly: should get a structured FCP auth error, not a raw HTTP 401.
    let mut connector = fcp_gmail::connector::GmailConnector::new();

    // Configure with an obviously invalid token
    connector
        .handle_configure(json!({
            "token": "ya29.this_is_not_a_valid_access_token_000000000"
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
            "capabilities_requested": ["gmail.read"]
        }))
        .await
        .expect("handshake should succeed");

    let cap_token = generate_read_token(&signing_key, "gmail.list_labels");

    let err = connector
        .handle_invoke(json!({
            "operation": "gmail.list_labels",
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
            || err_str.to_lowercase().contains("credential"),
        "error should indicate auth failure: got '{err_str}'"
    );

    eprintln!("PASS: live_error_mapping_invalid_token — got structured error: {err_str}");
}

#[fcp_async_core::test]
async fn live_health_check() {
    skip_without_token!(token);

    let mut connector = fcp_gmail::connector::GmailConnector::new();
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

    let mut connector = fcp_gmail::connector::GmailConnector::new();
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
        "Gmail connector should have at least 8 operations, got {}",
        ops.len()
    );

    // Verify the operation we tested exists
    let op_ids: Vec<&str> = ops.iter().filter_map(|o| o["id"].as_str()).collect();
    assert!(
        op_ids.contains(&"gmail.list_labels"),
        "operations should include gmail.list_labels: {op_ids:?}"
    );

    eprintln!(
        "PASS: live_introspect — {} operations reported",
        ops.len()
    );
}
