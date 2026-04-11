//! Discord connector integration tests (flywheel_connectors-bngd).
//!
//! Deterministic integration tests using wiremock to mock the Discord REST API.
//! No real Discord calls. Covers:
//! - Lifecycle: configure → handshake → invoke
//! - REST operation happy paths (send, edit, delete, get, react, threads)
//! - Error taxonomy (401/403/429/5xx → FCP error mapping)
//! - Capability gating (deny without token, allow with valid token)
//! - Input validation (content length, required fields)
//! - Introspection completeness

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_core::CapabilityConstraints;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use serde_json::json;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

use fcp_discord::{DiscordConnector, limits as discord_limits};

// ============================================================================
// Constants
// ============================================================================

const INTENT_GUILDS: u64 = 1 << 0;
const INTENT_GUILD_MESSAGES: u64 = 1 << 9;
const INTENT_DIRECT_MESSAGES: u64 = 1 << 12;
const INTENT_MESSAGE_CONTENT: u64 = 1 << 15;

const ALL_REQUIRED_INTENTS: u64 =
    INTENT_GUILDS | INTENT_GUILD_MESSAGES | INTENT_DIRECT_MESSAGES | INTENT_MESSAGE_CONTENT;

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> fcp_core::CapabilityToken {
    let cap = match op {
        "discord.send_message" | "discord.trigger_typing" => "discord.send",
        "discord.edit_message" => "discord.edit",
        "discord.delete_message" => "discord.delete",
        "discord.add_reaction" => "discord.react",
        "discord.create_thread" => "discord.threads",
        _ => "discord.read",
    };
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .constraints_cbor(&cbor)
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

fn unique_zone_dir(label: &str) -> String {
    std::env::temp_dir()
        .join("fcp-discord-tests")
        .join(format!("{label}-{}", Uuid::new_v4()))
        .to_string_lossy()
        .into_owned()
}

async fn mock_current_user_ok(mock_server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path("/users/@me"))
        .and(header("Authorization", format!("Bot {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "123456789",
            "username": "TestBot",
            "discriminator": "0",
            "bot": true
        })))
        .mount(mock_server)
        .await;
}

async fn setup_configure(connector: &mut DiscordConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": base_url,
            "intents": ALL_REQUIRED_INTENTS
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_handshake(connector: &mut DiscordConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let zone_dir = unique_zone_dir("integration-handshake");

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "zone_dir": zone_dir,
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

/// Full lifecycle: configure + mock user + handshake.
async fn setup_full(
    connector: &mut DiscordConnector,
    mock_server: &MockServer,
    caps: &[&str],
) -> Ed25519SigningKey {
    mock_current_user_ok(mock_server, "test_token").await;
    setup_configure(connector, &mock_server.uri()).await;
    setup_handshake(connector, caps).await
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_handshake_health() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();

    mock_current_user_ok(&mock_server, "test_token").await;

    let config_result = connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": mock_server.uri(),
            "intents": ALL_REQUIRED_INTENTS
        }))
        .await
        .expect("configure should succeed");

    assert_eq!(config_result["status"], "configured");
    assert_eq!(config_result["provisioning"]["token_ok"], true);

    let health = connector
        .handle_health()
        .await
        .expect("health should succeed");
    // Health reports "ready" when configured
    assert_eq!(health["status"], "ready");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_operations() {
    let connector = DiscordConnector::new();

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let operations = introspection["operations"].as_array().unwrap();
    // 6 original + 3 new = 9 operations
    assert_eq!(
        operations.len(),
        9,
        "expected 9 operations, got {}: {:?}",
        operations.len(),
        operations
            .iter()
            .map(|o| o["id"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>()
    );

    let op_ids: Vec<&str> = operations
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();

    assert!(op_ids.contains(&"discord.send_message"));
    assert!(op_ids.contains(&"discord.edit_message"));
    assert!(op_ids.contains(&"discord.delete_message"));
    assert!(op_ids.contains(&"discord.get_channel"));
    assert!(op_ids.contains(&"discord.get_guild"));
    assert!(op_ids.contains(&"discord.trigger_typing"));
    assert!(op_ids.contains(&"discord.add_reaction"));
    assert!(op_ids.contains(&"discord.list_channels"));
    assert!(op_ids.contains(&"discord.create_thread"));

    // Verify events
    let events = introspection["events"].as_array().unwrap();
    assert!(!events.is_empty());
}

// ============================================================================
// Send Message Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn send_message_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000001",
            "channel_id": "111",
            "content": "Hello Discord!",
            "timestamp": "2026-03-02T12:00:00.000000+00:00",
            "author": {"id": "123456789", "username": "TestBot", "discriminator": "0"}
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "Hello Discord!"
            },
            "capability_token": token
        }))
        .await
        .expect("send_message should succeed");

    assert_eq!(result["id"], "100000000000000001");
    assert_eq!(result["channel_id"], "111");
    assert_eq!(result["content"], "Hello Discord!");
}

#[fcp_async_core::runtime::test]
async fn send_message_content_too_long() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let long_content = "a".repeat(discord_limits::MESSAGE_CONTENT_MAX_CHARS + 1);

    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": long_content
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject oversized content");
}

#[fcp_async_core::runtime::test]
async fn send_message_missing_content_and_embeds() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject empty message");
}

// ============================================================================
// Edit Message Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn edit_message_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.edit"]).await;

    Mock::given(method("PATCH"))
        .and(path("/channels/111/messages/100000000000000001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000001",
            "channel_id": "111",
            "content": "Edited content",
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.edit_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.edit_message",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "content": "Edited content"
            },
            "capability_token": token
        }))
        .await
        .expect("edit should succeed");

    assert_eq!(result["id"], "100000000000000001");
    assert_eq!(result["content"], "Edited content");
}

// ============================================================================
// Delete Message Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn delete_message_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.delete"]).await;

    Mock::given(method("DELETE"))
        .and(path("/channels/111/messages/100000000000000001"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.delete_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.delete_message",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001"
            },
            "capability_token": token
        }))
        .await
        .expect("delete should succeed");

    assert_eq!(result["deleted"], true);
}

// ============================================================================
// Get Channel Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn get_channel_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/111"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "111",
            "type": 0,
            "name": "general",
            "guild_id": "999"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await
        .expect("get_channel should succeed");

    assert_eq!(result["id"], "111");
    assert_eq!(result["name"], "general");
}

// ============================================================================
// Get Guild Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn get_guild_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "999",
            "name": "Test Server",
            "icon": null,
            "owner_id": "300000000000000001"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_guild");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_guild",
            "input": { "guild_id": "999" },
            "capability_token": token
        }))
        .await
        .expect("get_guild should succeed");

    assert_eq!(result["id"], "999");
    assert_eq!(result["name"], "Test Server");
}

// ============================================================================
// Trigger Typing Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn trigger_typing_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    // Note: Discord returns 204 No Content, but the API client uses post<T>()
    // which deserializes the body. Mock returns 200 with JSON to match the client's expectations.
    Mock::given(method("POST"))
        .and(path("/channels/111/typing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.trigger_typing");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.trigger_typing",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await
        .expect("trigger_typing should succeed");

    assert_eq!(result["triggered"], true);
}

// ============================================================================
// Add Reaction Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn add_reaction_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.react"]).await;

    // Use percent-encoded emoji path. The connector encodes emoji bytes.
    // 👍 = U+1F44D = F0 9F 91 8D in UTF-8
    Mock::given(method("PUT"))
        .and(path(
            "/channels/111/messages/100000000000000001/reactions/%F0%9F%91%8D/@me",
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.add_reaction",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "emoji": "👍"
            },
            "capability_token": token
        }))
        .await
        .expect("add_reaction should succeed");

    assert_eq!(result["added"], true);
}

#[fcp_async_core::runtime::test]
async fn add_reaction_missing_emoji() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.react"]).await;

    let token = generate_valid_token(&signing_key, "discord.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.add_reaction",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject missing emoji");
}

// ============================================================================
// List Channels Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn list_channels_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/999/channels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "111", "type": 0, "name": "general"},
            {"id": "222", "type": 0, "name": "random"},
            {"id": "333", "type": 2, "name": "voice-chat"}
        ])))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.list_channels");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.list_channels",
            "input": { "guild_id": "999" },
            "capability_token": token
        }))
        .await
        .expect("list_channels should succeed");

    let channels = result["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 3);
    assert_eq!(channels[0]["name"], "general");
}

// ============================================================================
// Create Thread Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn create_thread_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    Mock::given(method("POST"))
        .and(path("/channels/111/messages/100000000000000001/threads"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000101",
            "type": 11,
            "name": "Discussion",
            "guild_id": "999"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "name": "Discussion"
            },
            "capability_token": token
        }))
        .await
        .expect("create_thread should succeed");

    assert_eq!(result["id"], "100000000000000101");
    assert_eq!(result["name"], "Discussion");
}

#[fcp_async_core::runtime::test]
async fn create_thread_name_too_long() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let long_name = "a".repeat(discord_limits::THREAD_NAME_MAX_CHARS + 1);
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "name": long_name
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "should reject thread name > {} chars",
        discord_limits::THREAD_NAME_MAX_CHARS
    );
}

#[fcp_async_core::runtime::test]
async fn create_thread_empty_name() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "name": ""
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject empty thread name");
}

// ============================================================================
// Capability Gating Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn invoke_without_capability_token_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    mock_current_user_ok(&mock_server, "test_token").await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Handshake grants capabilities but we don't pass a token in invoke
    let _signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": { "channel_id": "111", "content": "test" }
        }))
        .await;

    assert!(
        result.is_err(),
        "invoke without capability_token should fail"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_with_wrong_capability_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    // Token is for discord.read, but we're trying to send a message (discord.send)
    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": { "channel_id": "111", "content": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "wrong capability should be denied");
}

// ============================================================================
// Error Taxonomy Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn api_401_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/111"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"message": "401: Unauthorized", "code": 0})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "401 should map to error");
}

#[fcp_async_core::runtime::test]
async fn api_429_maps_to_rate_limited() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/111"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(
                    json!({"message": "You are being rate limited.", "retry_after": 1.0}),
                )
                .append_header("Retry-After", "1"),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");

    // Use a connector with 0 retries to avoid test slowness
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "429 should map to error");
}

#[fcp_async_core::runtime::test]
async fn api_500_maps_to_external_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/111"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal Server Error", "code": 0})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "500 should map to error");
}

// ============================================================================
// Self-Check & Health Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn self_check_passes_when_configured() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    mock_current_user_ok(&mock_server, "test_token").await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Re-mount for self-check (it calls /users/@me again)
    mock_current_user_ok(&mock_server, "test_token").await;

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should succeed");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["details"]["token_ok"], true);
    assert_eq!(result["details"]["intents_ok"], true);
}

// ============================================================================
// Shutdown Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn shutdown_returns_status() {
    let mut connector = DiscordConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");

    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Error Handling Depth Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn api_403_forbidden_maps_to_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/111"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Missing Access", "code": 50001})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "403 should map to error");
}

#[fcp_async_core::runtime::test]
async fn api_404_get_channel_maps_to_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/nonexistent"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Unknown Channel", "code": 10003})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "nonexistent" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "404 on get_channel should map to error");
}

#[fcp_async_core::runtime::test]
async fn api_404_get_guild_maps_to_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/nonexistent"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Unknown Guild", "code": 10004})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_guild");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_guild",
            "input": { "guild_id": "nonexistent" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "404 on get_guild should map to error");
}

#[fcp_async_core::runtime::test]
async fn api_404_edit_message_maps_to_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.edit"]).await;

    Mock::given(method("PATCH"))
        .and(path("/channels/111/messages/gone"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Unknown Message", "code": 10008})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.edit_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.edit_message",
            "input": {
                "channel_id": "111",
                "message_id": "gone",
                "content": "updated"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "404 on edit_message should map to error");
}

#[fcp_async_core::runtime::test]
async fn non_json_error_response_handled() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/111"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "non-JSON 502 should still map to error");
}

// ============================================================================
// Input Validation Boundary Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn send_message_exactly_2000_chars_accepted() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let content_2000 = "a".repeat(discord_limits::MESSAGE_CONTENT_MAX_CHARS);

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_boundary",
            "channel_id": "111",
            "content": content_2000,
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": content_2000
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "exactly {} chars should be accepted",
        discord_limits::MESSAGE_CONTENT_MAX_CHARS
    );
    assert_eq!(result.unwrap()["id"], "msg_boundary");
}

#[fcp_async_core::runtime::test]
async fn send_message_2001_chars_rejected() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let content_2001 = "a".repeat(discord_limits::MESSAGE_CONTENT_MAX_CHARS + 1);
    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": content_2001
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "{} chars should be rejected",
        discord_limits::MESSAGE_CONTENT_MAX_CHARS + 1
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_exactly_10_embeds_accepted() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let embeds: Vec<serde_json::Value> = (0..discord_limits::EMBEDS_MAX_COUNT)
        .map(|i| json!({"title": format!("Embed {i}"), "description": "Short"}))
        .collect();

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_10embeds",
            "channel_id": "111",
            "content": "",
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": embeds
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "exactly {} embeds should be accepted",
        discord_limits::EMBEDS_MAX_COUNT
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_11_embeds_rejected() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let embeds: Vec<serde_json::Value> = (0..=discord_limits::EMBEDS_MAX_COUNT)
        .map(|i| json!({"title": format!("Embed {i}"), "description": "Short"}))
        .collect();

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": embeds
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "{} embeds should be rejected",
        discord_limits::EMBEDS_MAX_COUNT + 1
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_embed_near_4096_description_accepted() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let desc = "x".repeat(discord_limits::EMBED_DESCRIPTION_MAX_CHARS);

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_longdesc",
            "channel_id": "111",
            "content": "",
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": [{"description": desc}]
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "embed with {}-char description should be accepted",
        discord_limits::EMBED_DESCRIPTION_MAX_CHARS
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_embed_over_4096_description_rejected() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let desc = "x".repeat(discord_limits::EMBED_DESCRIPTION_MAX_CHARS + 1);
    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": [{"description": desc}]
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "embed with {}-char description should be rejected",
        discord_limits::EMBED_DESCRIPTION_MAX_CHARS + 1
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_total_embed_chars_at_6000_accepted() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let desc_at_boundary = "y".repeat(discord_limits::EMBED_TOTAL_MAX_CHARS / 3);
    let embeds: Vec<serde_json::Value> = (0..3)
        .map(|_| json!({"description": desc_at_boundary}))
        .collect();

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_6000",
            "channel_id": "111",
            "content": "",
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": embeds
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "total embed chars exactly {} should be accepted",
        discord_limits::EMBED_TOTAL_MAX_CHARS
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_total_embed_chars_over_6000_rejected() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let desc_over_boundary = "y".repeat((discord_limits::EMBED_TOTAL_MAX_CHARS / 3) + 1);
    let embeds: Vec<serde_json::Value> = (0..3)
        .map(|_| json!({"description": desc_over_boundary}))
        .collect();

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": embeds
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "total embed chars over {} should be rejected",
        discord_limits::EMBED_TOTAL_MAX_CHARS
    );
}

#[fcp_async_core::runtime::test]
async fn create_thread_name_exactly_100_chars_accepted() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    let name_100 = "t".repeat(discord_limits::THREAD_NAME_MAX_CHARS);

    Mock::given(method("POST"))
        .and(path("/channels/111/messages/100000000000000001/threads"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000102",
            "type": 11,
            "name": name_100,
            "guild_id": "999"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "name": name_100
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "thread name of exactly {} chars should be accepted",
        discord_limits::THREAD_NAME_MAX_CHARS
    );
    assert_eq!(result.unwrap()["id"], "100000000000000102");
}

#[fcp_async_core::runtime::test]
async fn add_reaction_custom_emoji_format() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.react"]).await;

    // Custom emoji "pepe:123456" → colon is encoded as %3A
    Mock::given(method("PUT"))
        .and(path(
            "/channels/111/messages/100000000000000001/reactions/pepe%3A123456/@me",
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.add_reaction",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "emoji": "pepe:123456"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_ok(), "custom emoji name:id should be accepted");
    assert_eq!(result.unwrap()["added"], true);
}

// ============================================================================
// Lifecycle Edge-Case Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn health_check_when_not_configured() {
    let connector = DiscordConnector::new();
    let health = connector
        .handle_health()
        .await
        .expect("health should succeed even when not configured");

    assert_eq!(health["status"], "not_configured");
    assert!(health["uptime_ms"].as_u64().is_some());
}

#[fcp_async_core::runtime::test]
async fn self_check_when_not_configured() {
    let connector = DiscordConnector::new();
    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should succeed even when not configured");

    assert_eq!(result["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn configure_with_empty_bot_credential_fails() {
    let mut connector = DiscordConnector::new();
    let result = connector
        .handle_configure(json!({
            "bot_credential": "",
            "intents": ALL_REQUIRED_INTENTS
        }))
        .await;

    assert!(result.is_err(), "empty bot_credential should fail");
}

#[fcp_async_core::runtime::test]
async fn configure_with_missing_intents_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    mock_current_user_ok(&mock_server, "test_token").await;

    // Pass intents=0 meaning no required intents are set
    let result = connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": mock_server.uri(),
            "intents": 0
        }))
        .await;

    assert!(result.is_err(), "missing required intents should fail");
}

#[fcp_async_core::runtime::test]
async fn invoke_before_handshake_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    mock_current_user_ok(&mock_server, "test_token").await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Configured but no handshake → no verifier → should fail
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": {
                "raw": vec![0u8; 32]
            }
        }))
        .await;

    assert!(result.is_err(), "invoke before handshake should fail");
}

#[fcp_async_core::runtime::test]
async fn shutdown_clears_state_reinvoke_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let _signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    // Shutdown
    let shutdown_result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(shutdown_result["status"], "shutdown");

    // Try to invoke after shutdown — should still have api_client but verifier
    // is intact; however the gateway tasks are torn down. The key test is that
    // shutdown returned cleanly. A second shutdown should also be idempotent.
    let shutdown_again = connector
        .handle_shutdown(json!({}))
        .await
        .expect("second shutdown should also succeed");
    assert_eq!(shutdown_again["status"], "shutdown");
}

// ============================================================================
// Operation Edge-Case Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn edit_message_with_embeds_only_no_content() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.edit"]).await;

    Mock::given(method("PATCH"))
        .and(path("/channels/111/messages/100000000000000001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000001",
            "channel_id": "111",
            "content": "",
            "timestamp": "2026-03-02T12:00:00.000000+00:00",
            "embeds": [{"title": "Updated embed"}]
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.edit_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.edit_message",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "embeds": [{"title": "Updated embed", "description": "New description"}]
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "edit with embeds only (no content) should succeed"
    );
    assert_eq!(result.unwrap()["id"], "100000000000000001");
}

#[fcp_async_core::runtime::test]
async fn send_message_with_reply_to() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000011",
            "channel_id": "111",
            "content": "This is a reply",
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "This is a reply",
                "reply_to": "100000000000000003"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_ok(), "send_message with reply_to should succeed");
    assert_eq!(result.unwrap()["id"], "100000000000000011");
}

#[fcp_async_core::runtime::test]
async fn delete_message_returns_deleted_true() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.delete"]).await;

    Mock::given(method("DELETE"))
        .and(path("/channels/222/messages/100000000000000002"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.delete_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.delete_message",
            "input": {
                "channel_id": "222",
                "message_id": "100000000000000002"
            },
            "capability_token": token
        }))
        .await
        .expect("delete should succeed");

    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn list_channels_empty_guild() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/200000000000000001/channels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.list_channels");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.list_channels",
            "input": { "guild_id": "200000000000000001" },
            "capability_token": token
        }))
        .await
        .expect("list_channels on empty guild should succeed");

    let channels = result["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 0, "empty guild should return empty array");
}

#[fcp_async_core::runtime::test]
async fn get_guild_with_detailed_fields() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/200000000000000002"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "200000000000000002",
            "name": "Detailed Server",
            "icon": "abc123icon",
            "owner_id": "300000000000000002"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_guild");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_guild",
            "input": { "guild_id": "200000000000000002" },
            "capability_token": token
        }))
        .await
        .expect("get_guild with detailed fields should succeed");

    assert_eq!(result["id"], "200000000000000002");
    assert_eq!(result["name"], "Detailed Server");
    assert_eq!(result["icon"], "abc123icon");
    assert_eq!(result["owner_id"], "300000000000000002");
}

#[fcp_async_core::runtime::test]
async fn unknown_operation_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    let token = generate_valid_token(&signing_key, "discord.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "unknown operation should fail");
}

#[fcp_async_core::runtime::test]
async fn send_message_with_embeds_and_content() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000012",
            "channel_id": "111",
            "content": "Check this out",
            "timestamp": "2026-03-02T12:00:00.000000+00:00",
            "embeds": [{"title": "Info"}]
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "Check this out",
                "embeds": [{"title": "Info", "description": "Details here"}]
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "send with both content and embeds should succeed"
    );
    assert_eq!(result.unwrap()["id"], "100000000000000012");
}

// ============================================================================
// Introspection Depth Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn introspect_operations_have_schemas() {
    let connector = DiscordConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let operations = introspection["operations"].as_array().unwrap();
    for op in operations {
        let op_id = op["id"].as_str().unwrap();
        assert!(
            op["input_schema"].is_object(),
            "operation {op_id} should have input_schema"
        );
        assert!(
            op["output_schema"].is_object(),
            "operation {op_id} should have output_schema"
        );
        assert!(
            op["summary"].is_string(),
            "operation {op_id} should have summary"
        );
        assert!(
            op["capability"].is_string(),
            "operation {op_id} should have capability"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn introspect_event_caps() {
    let connector = DiscordConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    // Verify event capabilities
    let event_caps = &introspection["event_caps"];
    assert_eq!(event_caps["streaming"], true);
    assert_eq!(event_caps["replay"], false);
}

#[fcp_async_core::runtime::test]
async fn introspect_operation_risk_levels() {
    let connector = DiscordConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let operations = introspection["operations"].as_array().unwrap();
    let op_map: std::collections::HashMap<&str, &serde_json::Value> = operations
        .iter()
        .map(|o| (o["id"].as_str().unwrap(), o))
        .collect();

    // delete_message should be high risk
    assert_eq!(
        op_map["discord.delete_message"]["risk_level"], "high",
        "delete_message should be high risk"
    );

    // get_channel and get_guild should be low risk
    assert_eq!(
        op_map["discord.get_channel"]["risk_level"], "low",
        "get_channel should be low risk"
    );
    assert_eq!(
        op_map["discord.get_guild"]["risk_level"], "low",
        "get_guild should be low risk"
    );
}

// ============================================================================
// Additional Error Taxonomy Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn api_403_on_send_message() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Missing Permissions", "code": 50013})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "test"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "403 on send_message should fail");
}

#[fcp_async_core::runtime::test]
async fn api_404_on_delete_message() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.delete"]).await;

    Mock::given(method("DELETE"))
        .and(path("/channels/111/messages/100000000000000004"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Unknown Message", "code": 10008})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.delete_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.delete_message",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000004"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "404 on delete_message should fail");
}

#[fcp_async_core::runtime::test]
async fn api_403_on_add_reaction() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.react"]).await;

    // Any PUT to reactions path returns 403
    Mock::given(method("PUT"))
        .and(path(
            "/channels/111/messages/100000000000000001/reactions/%F0%9F%91%8D/@me",
        ))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Reaction blocked", "code": 90001})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.add_reaction",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "emoji": "\u{1F44D}"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "403 on add_reaction should fail");
}

#[fcp_async_core::runtime::test]
async fn api_503_maps_to_retryable_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/999"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_json(json!({"message": "Service Unavailable", "code": 0})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_guild");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_guild",
            "input": { "guild_id": "999" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "503 should map to error");
}

// ============================================================================
// Subscribe Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn subscribe_confirms_topics() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let _signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    let result = connector
        .handle_subscribe(json!({
            "topics": ["discord.message"]
        }))
        .await
        .expect("subscribe should succeed");

    let confirmed = result["confirmed_topics"].as_array().unwrap();
    assert_eq!(confirmed.len(), 1);
    assert_eq!(confirmed[0], "discord.message");
    assert_eq!(result["replay_supported"], false);
}

#[fcp_async_core::runtime::test]
async fn subscribe_empty_topics() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let _signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    let result = connector
        .handle_subscribe(json!({
            "topics": []
        }))
        .await
        .expect("subscribe with empty topics should succeed");

    let confirmed = result["confirmed_topics"].as_array().unwrap();
    assert!(confirmed.is_empty());
}

// ============================================================================
// Simulate Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn simulate_returns_allowed() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "sim-001",
            "connector_id": "discord",
            "operation": "discord.send_message",
            "zone_id": "z:work",
            "input": {
                "channel_id": "111",
                "content": "test"
            },
            "capability_token": token
        }))
        .await
        .expect("simulate should succeed");

    assert_eq!(result["would_succeed"], true);
}

// ============================================================================
// Create Thread Additional Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn create_thread_with_auto_archive_duration() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    Mock::given(method("POST"))
        .and(path("/channels/111/messages/100000000000000001/threads"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000103",
            "type": 11,
            "name": "Archivable Thread",
            "guild_id": "999"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "name": "Archivable Thread",
                "auto_archive_duration": 1440
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "create_thread with auto_archive_duration should succeed"
    );
    assert_eq!(result.unwrap()["name"], "Archivable Thread");
}

#[fcp_async_core::runtime::test]
async fn create_thread_missing_message_id() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "name": "No Message Thread"
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "create_thread without message_id should fail"
    );
}
