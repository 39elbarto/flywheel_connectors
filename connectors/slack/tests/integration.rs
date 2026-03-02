//! Slack connector integration tests (flywheel_connectors-i1b.6).
//!
//! Deterministic integration tests using wiremock to mock the Slack Web API.
//! No real API calls. Covers:
//! - Messages (post, reply, history, search)
//! - Channels (list, set topic)
//! - Users (get info)
//! - Files (upload, download/info)
//! - Reactions (add)
//! - Error taxonomy (`not_authed`/`channel_not_found`/`ratelimited` -> `FcpError` mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_testkit::AsyncTestContext;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::time::Duration as StdDuration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message as WsMessage};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_slack::client::SlackClient;
use fcp_slack::connector::SlackConnector;

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

async fn setup_handshake(connector: &mut SlackConnector, caps: &[&str]) -> Ed25519SigningKey {
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

async fn setup_configure(connector: &mut SlackConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "token": "xoxb-test-token-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

/// Standard Slack message response.
fn slack_message(text: &str, ts: &str) -> serde_json::Value {
    json!({
        "type": "message",
        "user": "U01234567",
        "text": text,
        "ts": ts
    })
}

/// Standard Slack channel response.
fn slack_channel(id: &str, name: &str) -> serde_json::Value {
    json!({
        "id": id,
        "name": name,
        "is_channel": true,
        "is_group": false,
        "is_im": false,
        "is_archived": false,
        "is_private": false,
        "num_members": 42
    })
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn post_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.post_message.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.123456",
            "message": slack_message("Hello from FCP!", "1234567890.123456")
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "Hello from FCP!" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["message"]["text"], "Hello from FCP!");
    assert_eq!(result["message"]["ts"], "1234567890.123456");
}

#[fcp_async_core::runtime::test]
async fn reply_thread_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.reply_thread.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.654321",
            "message": {
                "type": "message",
                "user": "U01234567",
                "text": "Thread reply",
                "ts": "1234567890.654321",
                "thread_ts": "1234567890.123456"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.reply_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "Thread reply",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["message"]["text"], "Thread reply");
    assert_eq!(result["message"]["thread_ts"], "1234567890.123456");
}

#[fcp_async_core::runtime::test]
async fn get_channel_history_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.channel_history.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "messages": [
                slack_message("First message", "1234567890.111111"),
                slack_message("Second message", "1234567890.222222")
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_channel_history"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.get_channel_history");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_channel_history",
            "input": { "channel": "C01234567", "limit": 10 },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let messages = result["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["text"], "First message");
    assert_eq!(messages[1]["text"], "Second message");
}

#[fcp_async_core::runtime::test]
async fn search_messages_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.search_messages.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search.messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "messages": {
                "total": 1,
                "matches": [slack_message("deployment update", "1234567890.333333")]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.search_messages"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.search_messages");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.search_messages",
            "input": { "query": "deployment in:#general" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["total"], 1);
}

#[fcp_async_core::runtime::test]
async fn list_channels_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.list_channels.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channels": [
                slack_channel("C01234567", "general"),
                slack_channel("C07654321", "random")
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.list_channels"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.list_channels");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": { "types": "public_channel" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let channels = result["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 2);
    assert_eq!(channels[0]["name"], "general");
    assert_eq!(channels[1]["name"], "random");
}

#[fcp_async_core::runtime::test]
async fn get_user_info_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.get_user_info.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "user": {
                "id": "U01234567",
                "name": "testuser",
                "real_name": "Test User",
                "is_bot": false,
                "is_admin": false,
                "deleted": false,
                "profile": {
                    "display_name": "testuser",
                    "email": "test@example.com"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_user_info"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.get_user_info");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_user_info",
            "input": { "user": "U01234567" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["user"]["name"], "testuser");
    assert_eq!(result["user"]["id"], "U01234567");
}

#[fcp_async_core::runtime::test]
async fn upload_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.upload_file.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/files.upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "file": {
                "id": "F01234567",
                "name": "output.log",
                "title": "output.log",
                "mimetype": "text/plain",
                "filetype": "text",
                "size": 42
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.upload_file"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
                "content": "log data here",
                "filename": "output.log"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["file"]["id"], "F01234567");
    assert_eq!(result["file"]["name"], "output.log");
}

#[fcp_async_core::runtime::test]
async fn download_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.download_file.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "file": {
                "id": "F01234567",
                "name": "report.pdf",
                "title": "Q4 Report",
                "mimetype": "application/pdf",
                "filetype": "pdf",
                "size": 102_400,
                "url_private": "https://files.slack.com/files-pri/T01234-F01234567/report.pdf",
                "url_private_download": "https://files.slack.com/files-pri/T01234-F01234567/download/report.pdf"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.download_file"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.download_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.download_file",
            "input": { "file_id": "F01234567" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["file"]["id"], "F01234567");
    assert_eq!(result["file"]["name"], "report.pdf");
    assert!(
        result["file"]["url_private_download"]
            .as_str()
            .unwrap()
            .contains("download")
    );
}

#[fcp_async_core::runtime::test]
async fn add_reaction_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.add_reaction.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/reactions.add"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.add_reaction"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.add_reaction",
            "input": {
                "channel": "C01234567",
                "timestamp": "1234567890.123456",
                "name": "thumbsup"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["ok"], true);
}

#[fcp_async_core::runtime::test]
async fn set_channel_topic_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.set_channel_topic.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/conversations.setTopic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "topic": "Sprint 42 - Deployment day"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.set_channel_topic"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.set_channel_topic");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.set_channel_topic",
            "input": {
                "channel": "C01234567",
                "topic": "Sprint 42 - Deployment day"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["topic"], "Sprint 42 - Deployment day");
}

// ============================================================================
// Receipt verification (side-effecting operations)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn post_message_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.post_message");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.123456",
            "message": slack_message("Hello!", "1234567890.123456")
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "Hello!" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.post_message");
    assert_eq!(receipt["effect"], "message_created");
    assert_eq!(receipt["resource"], "channel:C01234567");
    assert_eq!(receipt["timestamp"], "1234567890.123456");
}

#[fcp_async_core::runtime::test]
async fn reply_thread_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.reply_thread");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.654321",
            "message": {
                "type": "message",
                "user": "U01234567",
                "text": "Thread reply",
                "ts": "1234567890.654321",
                "thread_ts": "1234567890.111111"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.reply_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "Thread reply",
                "thread_ts": "1234567890.111111"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.reply_thread");
    assert_eq!(receipt["effect"], "thread_reply_created");
    assert!(receipt["resource"].as_str().unwrap().contains("thread:"));
}

#[fcp_async_core::runtime::test]
async fn upload_file_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.upload_file");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/files.upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "file": {
                "id": "F09876543",
                "name": "data.csv",
                "title": "data.csv",
                "mimetype": "text/csv",
                "filetype": "csv",
                "size": 100
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.upload_file"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": { "channels": "C01234567", "content": "a,b,c", "filename": "data.csv" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.upload_file");
    assert_eq!(receipt["effect"], "file_uploaded");
    assert_eq!(receipt["resource"], "file:F09876543");
}

#[fcp_async_core::runtime::test]
async fn add_reaction_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.add_reaction");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/reactions.add"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.add_reaction"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.add_reaction",
            "input": {
                "channel": "C01234567",
                "timestamp": "1234567890.123456",
                "name": "thumbsup"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.add_reaction");
    assert_eq!(receipt["effect"], "reaction_added");
    assert!(receipt["resource"].as_str().unwrap().contains("message:"));
}

#[fcp_async_core::runtime::test]
async fn set_channel_topic_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.set_channel_topic");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/conversations.setTopic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "topic": "New topic"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.set_channel_topic"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.set_channel_topic");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.set_channel_topic",
            "input": { "channel": "C01234567", "topic": "New topic" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.set_channel_topic");
    assert_eq!(receipt["effect"], "topic_updated");
    assert_eq!(receipt["resource"], "channel:C01234567");
}

// ============================================================================
// Read operations should NOT emit receipts
// ============================================================================

#[fcp_async_core::runtime::test]
async fn read_operations_have_no_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.read_no_receipt");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channels": [slack_channel("C01234567", "general")]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.list_channels"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.list_channels");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert!(result.get("receipt").is_none());
}

// ============================================================================
// Error taxonomy tests (Slack API errors come as 200 OK with ok:false)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn error_not_authed_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.not_authed");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "not_authed"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_invalid_auth_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.invalid_auth");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "invalid_auth"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_token_revoked_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.token_revoked");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "token_revoked"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("revoked-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.list_channels(None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_channel_not_found_maps_to_resource_not_found() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.channel_not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "channel_not_found"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_channel_history("C_NONEXIST", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "Expected ResourceNotFound, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_user_not_found_maps_to_resource_not_found() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.user_not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "user_not_found"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_user_info("U_NONEXIST").await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "Expected ResourceNotFound, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_ratelimited_api_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.ratelimited_api");
    let mock_server = MockServer::start().await;

    // Slack API-level ratelimited error (200 OK with ok:false)
    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "ratelimited"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "test", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "Expected RateLimited, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_http_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.http_429");
    let mock_server = MockServer::start().await;

    // HTTP-level 429 rate limit (checked before response body)
    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "30")
                .set_body_json(json!({"ok": false, "error": "ratelimited"})),
        )
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.list_channels(None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "Expected RateLimited, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_missing_scope_maps_to_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.missing_scope");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "missing_scope"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::CapabilityDenied { .. }),
        "Expected CapabilityDenied, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_not_in_channel_maps_to_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.not_in_channel");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "not_in_channel"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::CapabilityDenied { .. }),
        "Expected CapabilityDenied, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_retryable_classification() {
    use fcp_slack::error::SlackError;

    // API transient errors should be retryable
    let transient = SlackError::Api {
        error: "internal_error".into(),
        code: None,
        ok: false,
    };
    assert!(transient.is_retryable());

    let timeout = SlackError::Api {
        error: "request_timeout".into(),
        code: None,
        ok: false,
    };
    assert!(timeout.is_retryable());

    let unavailable = SlackError::Api {
        error: "service_unavailable".into(),
        code: None,
        ok: false,
    };
    assert!(unavailable.is_retryable());

    // Non-transient errors should NOT be retryable
    let not_authed = SlackError::Api {
        error: "not_authed".into(),
        code: None,
        ok: false,
    };
    assert!(!not_authed.is_retryable());

    let chan_not_found = SlackError::Api {
        error: "channel_not_found".into(),
        code: None,
        ok: false,
    };
    assert!(!chan_not_found.is_retryable());

    // RateLimited is always retryable
    let rate = SlackError::RateLimited {
        retry_after_secs: 30,
    };
    assert!(rate.is_retryable());
}

// ============================================================================
// Invoke-level error tests (401/403/429 through handle_invoke)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn invoke_401_not_authed() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.401_not_authed");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "not_authed"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_401_invalid_auth() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.401_invalid_auth");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "invalid_auth"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_channel_history"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.get_channel_history");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_channel_history",
            "input": { "channel": "C01234567" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_403_missing_scope() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.403_missing_scope");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "missing_scope"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "Expected CapabilityDenied"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_403_not_in_channel() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.403_not_in_channel");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "not_in_channel"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "Expected CapabilityDenied"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_403_restricted_action() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.403_restricted_action");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/conversations.setTopic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "restricted_action"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.set_channel_topic"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.set_channel_topic");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.set_channel_topic",
            "input": { "channel": "C01234567", "topic": "new topic" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "Expected CapabilityDenied"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_429_rate_limited_api() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.429_api");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "ratelimited"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::RateLimited { .. }),
        "Expected RateLimited"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_resource_not_found() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.resource_not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "channel_not_found"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_channel_history"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.get_channel_history");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_channel_history",
            "input": { "channel": "C_INVALID" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::ResourceNotFound { .. }
        ),
        "Expected ResourceNotFound"
    );
}

// ============================================================================
// FCP2 default-deny + capability verification
// ============================================================================

#[fcp_async_core::runtime::test]
async fn fcp2_invoke_requires_handshake() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.no_handshake");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    // No handshake → NotConfigured (no verifier set)
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {},
            "capability_token": { "raw": vec![0u8; 32] }
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn fcp2_invoke_requires_capability_token() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.missing_token");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" }
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("capability_token"));
        }
        e => panic!("Expected InvalidRequest about capability_token, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn fcp2_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.wrong_cap");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    // Handshake grants only slack.read
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Token is for slack.read, but we invoke slack.post_message
    let token = generate_valid_token(&key, "slack.read");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn fcp2_unknown_operation_rejected() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.unknown_op");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.nonexistent"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::OperationNotGranted { .. }
        ),
        "Expected OperationNotGranted"
    );
}

#[fcp_async_core::runtime::test]
async fn fcp2_missing_operation_field() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.missing_op");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_invoke(json!({
            "input": {},
            "capability_token": { "raw": vec![0u8; 32] }
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("operation"));
        }
        e => panic!("Expected InvalidRequest about operation, got: {e:?}"),
    }
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn lifecycle_health_before_configure() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.health_before");
    let connector = SlackConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.health_after");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_returns_accepted() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.handshake");
    let mut connector = SlackConnector::new();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": vec![0u8; 32],
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["slack.read", "slack.write"]
        }))
        .await
        .unwrap();

    assert_eq!(result["status"], "accepted");
    assert!(result["session_id"].as_str().is_some());
    let grants = result["capabilities_granted"].as_array().unwrap();
    assert_eq!(grants.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.introspect");
    let connector = SlackConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 10);

    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
    for expected in &[
        "slack.post_message",
        "slack.reply_thread",
        "slack.get_channel_history",
        "slack.search_messages",
        "slack.list_channels",
        "slack.get_user_info",
        "slack.upload_file",
        "slack.download_file",
        "slack.add_reaction",
        "slack.set_channel_topic",
    ] {
        assert!(op_ids.contains(expected), "Missing op: {expected}");
    }
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.shutdown");
    let mut connector = SlackConnector::new();
    let result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Socket Mode streaming tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn socket_mode_subscribe_emits_event_envelope_and_ack() {
    let _ctx = AsyncTestContext::for_scenario("slack.socket_mode.event_and_ack");
    let mock_server = MockServer::start().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let ws_url = format!(
        "ws://{}",
        listener.local_addr().expect("listener local addr")
    );

    let (ack_tx, ack_rx) = oneshot::channel::<Option<String>>();
    let ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
        let mut ws_stream = accept_async(tcp_stream).await.expect("accept websocket");

        ws_stream
            .send(WsMessage::Text(
                json!({ "type": "hello" }).to_string().into(),
            ))
            .await
            .expect("send hello frame");
        ws_stream
            .send(WsMessage::Text(
                json!({
                    "envelope_id": "envelope-1",
                    "type": "events_api",
                    "payload": {
                        "event_id": "Ev01",
                        "team_id": "T_TEAM_1",
                        "event": {
                            "type": "message",
                            "user": "U_EVT_1",
                            "channel": "C_EVT_1",
                            "text": "hello from socket mode",
                            "ts": "1700000000.000001"
                        }
                    }
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("send events_api frame");

        let ack_payload = if let Some(Ok(WsMessage::Text(text))) = ws_stream.next().await {
            Some(text.to_string())
        } else {
            None
        };
        let _ = ack_tx.send(ack_payload);

        let _ = ws_stream.close(None).await;
    });

    Mock::given(method("POST"))
        .and(path("/apps.connections.open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "url": ws_url
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "token": "xoxb-test-token-xyz",
            "app_token": "xapp-test-token-xyz",
            "base_url": mock_server.uri()
        }))
        .await
        .expect("configure");

    let mut event_rx = connector.subscribe_events();
    let subscribe_result = connector
        .handle_subscribe(json!({
            "topics": ["slack.message.new"]
        }))
        .await
        .expect("subscribe should succeed");
    assert_eq!(subscribe_result["connection_status"], "started");

    let event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
        .await
        .expect("timeout waiting for socket mode event")
        .expect("broadcast receive")
        .expect("event payload");

    assert_eq!(event.topic, "slack.message.new");
    assert_eq!(event.cursor, "Ev01");
    assert_eq!(event.data.principal.kind, "slack_user");
    assert_eq!(event.data.principal.id, "U_EVT_1");
    assert_eq!(event.data.principal.trust, fcp_core::TrustLevel::Untrusted);
    assert_eq!(event.data.zone_id, fcp_core::ZoneId::community());
    assert_eq!(
        event.data.payload["event"]["text"].as_str(),
        Some("hello from socket mode")
    );

    let ack_json = fcp_async_core::time::timeout(StdDuration::from_secs(3), ack_rx)
        .await
        .expect("timeout waiting for socket ack")
        .expect("ack channel should complete")
        .expect("ack payload missing");
    let ack_value: serde_json::Value =
        serde_json::from_str(&ack_json).expect("ack should be valid json");
    assert_eq!(ack_value["envelope_id"], "envelope-1");

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");

    fcp_async_core::time::timeout(StdDuration::from_secs(3), ws_task)
        .await
        .expect("timeout waiting for ws task")
        .expect("ws task join");
}

#[fcp_async_core::runtime::test]
async fn socket_mode_subscribe_reuses_single_connection() {
    let _ctx = AsyncTestContext::for_scenario("slack.socket_mode.singleton_connection");
    let mock_server = MockServer::start().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let ws_url = format!(
        "ws://{}",
        listener.local_addr().expect("listener local addr")
    );

    let (stop_ws_tx, mut stop_ws_rx) = fcp_async_core::channel::watch::channel(false);
    let (connected_tx, connected_rx) = oneshot::channel::<()>();
    let ws_task = fcp_async_core::task::spawn(async move {
        let accepted = fcp_async_core::select! {
            accept_result = listener.accept() => Some(accept_result.expect("accept websocket client")),
            _ = stop_ws_rx.changed() => None,
        };
        let Some((tcp_stream, _)) = accepted else {
            return;
        };
        let mut ws_stream = accept_async(tcp_stream).await.expect("accept websocket");
        let _ = connected_tx.send(());

        ws_stream
            .send(WsMessage::Text(
                json!({ "type": "hello" }).to_string().into(),
            ))
            .await
            .expect("send hello frame");

        fcp_async_core::select! {
            _ = stop_ws_rx.changed() => {}
            () = async {
                while let Some(frame) = ws_stream.next().await {
                    match frame {
                        Ok(WsMessage::Close(_)) | Err(_) => break,
                        _ => {}
                    }
                }
            } => {}
        }

        let _ = ws_stream.close(None).await;
    });

    Mock::given(method("POST"))
        .and(path("/apps.connections.open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "url": ws_url
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "token": "xoxb-test-token-xyz",
            "app_token": "xapp-test-token-xyz",
            "base_url": mock_server.uri()
        }))
        .await
        .expect("configure");

    let first = connector
        .handle_subscribe(json!({
            "topics": ["slack.message.new"]
        }))
        .await
        .expect("first subscribe should succeed");
    assert_eq!(first["connection_status"], "started");
    fcp_async_core::time::timeout(StdDuration::from_secs(3), connected_rx)
        .await
        .expect("timeout waiting for socket connection")
        .expect("socket connection signal should complete");

    let second = connector
        .handle_subscribe(json!({
            "topics": ["slack.message.new", "slack.reaction.added"]
        }))
        .await
        .expect("second subscribe should succeed");
    assert_eq!(second["connection_status"], "already_running");

    let health = connector.handle_health().await.expect("health");
    assert_eq!(health["streaming"]["socket_mode_running"], true);

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");

    let _ = stop_ws_tx.send(true);
    fcp_async_core::time::timeout(StdDuration::from_secs(3), ws_task)
        .await
        .expect("timeout waiting for ws task")
        .expect("ws task join");

    mock_server.verify().await;
}

// ============================================================================
// Input validation edge cases
// ============================================================================

#[fcp_async_core::runtime::test]
async fn validate_post_message_missing_channel() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_channel");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "text": "hello" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("channel"));
        }
        e => panic!("Expected InvalidRequest about channel, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_post_message_missing_text() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_text");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("text"));
        }
        e => panic!("Expected InvalidRequest about text, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_reply_thread_missing_thread_ts() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_thread_ts");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.reply_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": { "channel": "C01234567", "text": "reply" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("thread_ts"));
        }
        e => panic!("Expected InvalidRequest about thread_ts, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_add_reaction_missing_name() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_name");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.add_reaction"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.add_reaction",
            "input": { "channel": "C01234567", "timestamp": "1234567890.123456" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("name"));
        }
        e => panic!("Expected InvalidRequest about name, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_configure_missing_token() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_token");
    let mut connector = SlackConnector::new();
    let result = connector.handle_configure(json!({})).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("token"));
        }
        e => panic!("Expected InvalidRequest about token, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_upload_file_missing_channels() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_channels");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.upload_file"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": { "content": "data" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("channels"));
        }
        e => panic!("Expected InvalidRequest about channels, got: {e:?}"),
    }
}
