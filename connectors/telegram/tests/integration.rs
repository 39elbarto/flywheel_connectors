//! Telegram connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the Telegram Bot API.
//! No real API calls. Covers:
//! - Happy-path operations (send_message, get_file, answer_callback_query)
//! - Error taxonomy (401/429 -> FcpError mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::unreadable_literal)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_telegram::connector::TelegramConnector;

// ============================================================================
// Constants
// ============================================================================

const TEST_BOT_TOKEN: &str = "123456:ABCDEFGHIJKLMNOPQRSTUVWXyz012345";

fn token_path(api_method: &str) -> String {
    format!("/bot{TEST_BOT_TOKEN}/{api_method}")
}

// ============================================================================
// Helpers
// ============================================================================

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

/// Mock the `getMe` endpoint (used by configure + handshake + health).
async fn mount_get_me_mock(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(token_path("getMe")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "id": 123456789,
                "is_bot": true,
                "first_name": "Test Bot",
                "username": "test_bot_fcp"
            }
        })))
        .mount(mock_server)
        .await;
}

/// Mock the `getUpdates` endpoint (polling loop started by handshake).
async fn mount_get_updates_mock(mock_server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(token_path("getUpdates")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": []
        })))
        .mount(mock_server)
        .await;
}

async fn setup_configure(connector: &mut TelegramConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "credential": TEST_BOT_TOKEN,
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_handshake(
    connector: &mut TelegramConnector,
    mock_server: &MockServer,
    caps: &[&str],
) -> Ed25519SigningKey {
    mount_get_me_mock(mock_server).await;
    mount_get_updates_mock(mock_server).await;

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

/// Full setup: configure + mount mocks + handshake. Returns signing key and mock server.
async fn full_setup(
    connector: &mut TelegramConnector,
    caps: &[&str],
) -> (MockServer, Ed25519SigningKey) {
    let mock_server = MockServer::start().await;
    // Mount getMe for configure (which calls getMe to validate the token)
    mount_get_me_mock(&mock_server).await;
    setup_configure(connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(connector, &mock_server, caps).await;
    (mock_server, signing_key)
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn send_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_message.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 42,
                "chat": { "id": 123456, "type": "private", "first_name": "Test" },
                "date": 1234567890,
                "text": "Hello from FCP!"
            }
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "Hello from FCP!" },
            "capability_token": token
        }))
        .await
        .expect("send_message invoke should succeed");

    assert_eq!(result["message_id"], 42);
    assert_eq!(result["chat_id"], 123456);
}

#[fcp_async_core::runtime::test]
async fn get_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.get_file.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.get_file"]).await;

    // getFile uses GET with query params
    Mock::given(method("GET"))
        .and(path(token_path("getFile")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "file_id": "BQACAgIAAxkBAAIsK2Y",
                "file_unique_id": "AgADrwYAAoF",
                "file_size": 12345,
                "file_path": "documents/file_0.pdf"
            }
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "telegram.get_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.get_file",
            "input": { "file_id": "BQACAgIAAxkBAAIsK2Y" },
            "capability_token": token
        }))
        .await
        .expect("get_file invoke should succeed");

    assert_eq!(result["file_id"], "BQACAgIAAxkBAAIsK2Y");
    assert!(result.get("download_url").is_some());
}

#[fcp_async_core::runtime::test]
async fn answer_callback_query_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.answer_callback_query.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["telegram.answer_callback_query"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("answerCallbackQuery")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": true
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "telegram.answer_callback_query");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.answer_callback_query",
            "input": { "callback_query_id": "cq-12345", "text": "Acknowledged!" },
            "capability_token": token
        }))
        .await
        .expect("answer_callback_query invoke should succeed");

    assert_eq!(result["success"], true);
}

// ============================================================================
// Error taxonomy tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn unauthorized_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.unauthorized");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    // Override sendMessage to return 401
    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "ok": false,
            "error_code": 401,
            "description": "Unauthorized"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "fail" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn rate_limited_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.rate_limited");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "ok": false,
            "error_code": 429,
            "description": "Too Many Requests: retry after 1",
            "parameters": { "retry_after": 1 }
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "rate limited" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// FCP2 default-deny + capability verification
// ============================================================================

#[fcp_async_core::runtime::test]
async fn invoke_without_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.deny.not_configured");
    let connector = TelegramConnector::new();

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(&signing_key, "telegram.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "should fail" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_with_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("telegram.deny.wrong_capability");
    let mut connector = TelegramConnector::new();
    // Handshake grants get_file but we invoke send_message
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.get_file"]).await;
    let token = generate_valid_token(&signing_key, "telegram.get_file");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "wrong cap" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_denied() {
    let _ctx = AsyncTestContext::for_scenario("telegram.deny.unknown_operation");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "telegram.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn health_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.health_not_configured");
    let connector = TelegramConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn health_configured_and_ready() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.health_configured");
    let mock_server = MockServer::start().await;
    mount_get_me_mock(&mock_server).await;

    let mut connector = TelegramConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Health calls getMe to verify connectivity -> returns "ready"
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "ready");
}

#[fcp_async_core::runtime::test]
async fn introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.introspect");
    let connector = TelegramConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    assert!(op_ids.contains(&"telegram.send_message"));
    assert!(op_ids.contains(&"telegram.send_media"));
    assert!(op_ids.contains(&"telegram.get_file"));
    assert!(op_ids.contains(&"telegram.answer_callback_query"));
    assert_eq!(ops.len(), 4);
}

#[fcp_async_core::runtime::test]
async fn shutdown_succeeds() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.shutdown");
    let mut connector = TelegramConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Input validation edge cases
// ============================================================================

#[fcp_async_core::runtime::test]
async fn send_message_missing_chat_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.send_message_missing_chat_id");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;
    let token = generate_valid_token(&signing_key, "telegram.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "text": "no chat_id" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("chat_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn send_message_missing_text_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.send_message_missing_text");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;
    let token = generate_valid_token(&signing_key, "telegram.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("text"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}
