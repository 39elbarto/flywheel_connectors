//! Microsoft 365 connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the Microsoft Graph API.
//! No real API calls. Covers:
//! - Happy-path operations across Mail, Files, Calendar, Tasks, Subscriptions, Delta
//! - Error taxonomy (401/403/404/429 -> FcpError mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases
//! - Auth modes: access_token, credential_id

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, path_regex},
};

use fcp_microsoft365::connector::M365Connector;

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

fn unique_zone_dir(label: &str) -> String {
    let mut path = std::env::temp_dir();
    path.push(format!("fcp-m365-integration-{label}-{}", Uuid::new_v4()));
    path.to_string_lossy().into_owned()
}

async fn setup_handshake(connector: &mut M365Connector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let zone_dir = unique_zone_dir("handshake");

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

fn make_jwt_token(scopes: &[&str], roles: &[&str]) -> String {
    let header = BASE64_URL.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = json!({
        "scp": scopes.join(" "),
        "roles": roles,
    });
    let payload = BASE64_URL.encode(serde_json::to_vec(&payload).unwrap());
    format!("{header}.{payload}.signature")
}

async fn setup_configure_access_token(
    connector: &mut M365Connector,
    base_url: &str,
    scopes: &[&str],
) {
    let token = make_jwt_token(scopes, &[]);
    connector
        .handle_configure(json!({
            "access_token": token,
            "allow_test_api_url": true,
            "api_url": base_url,
            "required_permissions": scopes
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_configure_credential_id(connector: &mut M365Connector, base_url: &str) {
    connector
        .handle_configure(json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "allow_test_api_url": true,
            "api_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

// ============================================================================
// Happy-path: Mail operations
// ============================================================================

#[fcp_async_core::runtime::test]
async fn mail_list_messages_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.mail.list_messages.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                { "id": "msg-1", "subject": "Hello", "isRead": false },
                { "id": "msg-2", "subject": "World", "isRead": true }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.mail.list_messages"]).await;
    let token = generate_valid_token(&signing_key, "m365.mail.list_messages");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.mail.list_messages",
            "input": { "user_id": "me" },
            "capability_token": token
        }))
        .await
        .expect("list_messages should succeed");

    let messages = result["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["subject"], "Hello");
}

#[fcp_async_core::runtime::test]
async fn mail_get_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.mail.get_message.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages/msg-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg-123",
            "subject": "Important Update",
            "body": { "contentType": "HTML", "content": "<p>Details here</p>" },
            "from": { "emailAddress": { "name": "Alice", "address": "alice@contoso.com" } }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.mail.get_message"]).await;
    let token = generate_valid_token(&signing_key, "m365.mail.get_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.mail.get_message",
            "input": { "user_id": "me", "message_id": "msg-123" },
            "capability_token": token
        }))
        .await
        .expect("get_message should succeed");

    assert_eq!(result["message"]["id"], "msg-123");
    assert_eq!(result["message"]["subject"], "Important Update");
}

#[fcp_async_core::runtime::test]
async fn mail_send_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.mail.send_message.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/sendMail"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Send"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.mail.send_message"]).await;
    let token = generate_valid_token(&signing_key, "m365.mail.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.mail.send_message",
            "input": {
                "user_id": "me",
                "message": {
                    "subject": "Test Email",
                    "body": { "contentType": "Text", "content": "Hello" },
                    "toRecipients": [{ "emailAddress": { "address": "bob@contoso.com" } }]
                }
            },
            "capability_token": token
        }))
        .await
        .expect("send_message should succeed");

    assert_eq!(result["status"], "sent");
}

// ============================================================================
// Happy-path: Files operations
// ============================================================================

#[fcp_async_core::runtime::test]
async fn files_list_items_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.files.list_items.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/users/me/drive/root/children.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                { "id": "item-1", "name": "Document.docx", "file": { "mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document" } },
                { "id": "item-2", "name": "Photos", "folder": { "childCount": 5 } }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Files.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.files.list_items"]).await;
    let token = generate_valid_token(&signing_key, "m365.files.list_items");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.files.list_items",
            "input": { "user_id": "me" },
            "capability_token": token
        }))
        .await
        .expect("list_items should succeed");

    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn files_upload_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.files.upload_file.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path_regex("/users/me/drive/root.*"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "new-item-1",
            "name": "hello.txt",
            "size": 13
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Files.ReadWrite"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.files.upload_file"]).await;
    let token = generate_valid_token(&signing_key, "m365.files.upload_file");

    let content_b64 = base64::engine::general_purpose::STANDARD.encode("Hello, World!");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.files.upload_file",
            "input": {
                "user_id": "me",
                "path": "/Documents/hello.txt",
                "content": content_b64
            },
            "capability_token": token
        }))
        .await
        .expect("upload_file should succeed");

    assert_eq!(result["item"]["name"], "hello.txt");
}

#[fcp_async_core::runtime::test]
async fn files_get_item_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.files.get_item.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/drive/items/item-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "item-42",
            "name": "report.pdf",
            "size": 204_800,
            "webUrl": "https://onedrive.example.com/item-42",
            "file": { "mimeType": "application/pdf" }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Files.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.files.get_item"]).await;
    let token = generate_valid_token(&signing_key, "m365.files.get_item");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.files.get_item",
            "input": { "user_id": "me", "item_id": "item-42" },
            "capability_token": token
        }))
        .await
        .expect("get_item should succeed");

    assert_eq!(result["item"]["id"], "item-42");
    assert_eq!(result["item"]["name"], "report.pdf");
}

#[fcp_async_core::runtime::test]
async fn files_download_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.files.download_file.happy_path");
    let mock_server = MockServer::start().await;

    // Metadata request
    Mock::given(method("GET"))
        .and(path("/users/me/drive/items/doc-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "doc-1",
            "name": "notes.txt",
            "size": 11
        })))
        .mount(&mock_server)
        .await;

    // Content download
    Mock::given(method("GET"))
        .and(path("/users/me/drive/items/doc-1/content"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello world".to_vec()))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Files.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.files.download_file"]).await;
    let token = generate_valid_token(&signing_key, "m365.files.download_file");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.files.download_file",
            "input": { "user_id": "me", "item_id": "doc-1" },
            "capability_token": token
        }))
        .await
        .expect("download_file should succeed");

    assert_eq!(result["name"], "notes.txt");
    assert_eq!(result["size"], 11);
    // Content should be base64-encoded
    let content_b64 = result["content"].as_str().expect("content string");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(content_b64)
        .expect("valid base64");
    assert_eq!(decoded, b"hello world");
}

#[fcp_async_core::runtime::test]
async fn files_delete_item_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.files.delete_item.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/users/me/drive/items/item-99"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Files.ReadWrite"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.files.delete_item"]).await;
    let token = generate_valid_token(&signing_key, "m365.files.delete_item");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.files.delete_item",
            "input": { "user_id": "me", "item_id": "item-99" },
            "capability_token": token
        }))
        .await
        .expect("delete_item should succeed");

    assert_eq!(result["status"], "deleted");
}

#[fcp_async_core::runtime::test]
async fn files_search_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.files.search.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/users/me/drive/root/search.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                { "id": "item-10", "name": "Q4 Report.xlsx", "size": 51_200 },
                { "id": "item-11", "name": "Q4 Slides.pptx", "size": 102_400 }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Files.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.files.search"]).await;
    let token = generate_valid_token(&signing_key, "m365.files.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.files.search",
            "input": { "user_id": "me", "query": "Q4" },
            "capability_token": token
        }))
        .await
        .expect("search should succeed");

    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn files_create_share_link_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.files.create_share_link.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/drive/items/item-42/createLink"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "link-abc",
            "link": {
                "type": "view",
                "scope": "organization",
                "webUrl": "https://contoso.sharepoint.com/s/link-abc"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Files.ReadWrite"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.files.create_share_link"]).await;
    let token = generate_valid_token(&signing_key, "m365.files.create_share_link");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.files.create_share_link",
            "input": {
                "user_id": "me",
                "item_id": "item-42",
                "type": "view",
                "scope": "organization"
            },
            "capability_token": token
        }))
        .await
        .expect("create_share_link should succeed");

    assert!(result["link"].is_object());
}

#[fcp_async_core::runtime::test]
async fn files_delete_item_missing_item_id() {
    let _ctx = AsyncTestContext::for_scenario("m365.files.delete_item.missing_item_id");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Files.ReadWrite"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.files.delete_item"]).await;
    let token = generate_valid_token(&signing_key, "m365.files.delete_item");

    let err = connector
        .handle_invoke(json!({
            "operation": "m365.files.delete_item",
            "input": { "user_id": "me" },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without item_id");

    assert!(
        format!("{err:?}").contains("item_id"),
        "error should mention missing field: {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn files_search_missing_query() {
    let _ctx = AsyncTestContext::for_scenario("m365.files.search.missing_query");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Files.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.files.search"]).await;
    let token = generate_valid_token(&signing_key, "m365.files.search");

    let err = connector
        .handle_invoke(json!({
            "operation": "m365.files.search",
            "input": { "user_id": "me" },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without query");

    assert!(
        format!("{err:?}").contains("query"),
        "error should mention missing field: {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn introspect_files_risk_levels() {
    let _ctx = AsyncTestContext::for_scenario("m365.introspect.files_risk_levels");
    let connector = M365Connector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    for op in ops {
        let id = op["id"].as_str().unwrap();
        let risk = op["risk_level"].as_str().unwrap();
        match id {
            "m365.files.list_items"
            | "m365.files.get_item"
            | "m365.files.download_file"
            | "m365.files.search" => {
                assert_eq!(risk, "low", "read op {id} should be low risk");
            }
            "m365.files.upload_file" => {
                assert_eq!(risk, "medium", "upload op {id} should be medium risk");
            }
            "m365.files.delete_item" | "m365.files.create_share_link" => {
                assert_eq!(risk, "high", "dangerous op {id} should be high risk");
            }
            _ => {} // non-file ops, skip
        }
    }

    let file_op_count = ops
        .iter()
        .filter_map(|o| o["id"].as_str())
        .filter(|id| id.starts_with("m365.files."))
        .count();
    assert_eq!(file_op_count, 7, "should have exactly 7 file operations");
}

// ============================================================================
// Happy-path: Calendar operations
// ============================================================================

#[fcp_async_core::runtime::test]
async fn calendar_list_events_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.list_events.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/users/me/events.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "id": "evt-1",
                "subject": "Team Standup",
                "start": { "dateTime": "2026-03-03T09:00:00", "timeZone": "UTC" },
                "end": { "dateTime": "2026-03-03T09:30:00", "timeZone": "UTC" }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.list_events"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.list_events");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.list_events",
            "input": { "user_id": "me" },
            "capability_token": token
        }))
        .await
        .expect("list_events should succeed");

    let events = result["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["subject"], "Team Standup");
}

#[fcp_async_core::runtime::test]
async fn calendar_create_event_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.create_event.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/events"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "evt-new-1",
            "subject": "Sprint Planning",
            "start": { "dateTime": "2026-03-04T14:00:00", "timeZone": "UTC" },
            "end": { "dateTime": "2026-03-04T15:00:00", "timeZone": "UTC" }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.ReadWrite"])
        .await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.create_event"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.create_event");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.create_event",
            "input": {
                "user_id": "me",
                "subject": "Sprint Planning",
                "start": { "dateTime": "2026-03-04T14:00:00", "timeZone": "UTC" },
                "end": { "dateTime": "2026-03-04T15:00:00", "timeZone": "UTC" }
            },
            "capability_token": token
        }))
        .await
        .expect("create_event should succeed");

    assert_eq!(result["event"]["subject"], "Sprint Planning");
}

#[fcp_async_core::runtime::test]
async fn calendar_get_event_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.get_event.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/events/evt-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "evt-123",
            "subject": "1:1 with Manager",
            "start": { "dateTime": "2026-03-03T10:00:00", "timeZone": "UTC" },
            "end": { "dateTime": "2026-03-03T10:30:00", "timeZone": "UTC" },
            "attendees": [{ "emailAddress": { "address": "manager@contoso.com" } }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.get_event"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.get_event");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.get_event",
            "input": {
                "user_id": "me",
                "event_id": "evt-123"
            },
            "capability_token": token
        }))
        .await
        .expect("get_event should succeed");

    assert_eq!(result["event"]["id"], "evt-123");
    assert_eq!(result["event"]["subject"], "1:1 with Manager");
}

#[fcp_async_core::runtime::test]
async fn calendar_get_event_missing_event_id() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.get_event.missing_event_id");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.get_event"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.get_event");

    let err = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.get_event",
            "input": { "user_id": "me" },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without event_id");

    assert!(
        format!("{err:?}").contains("event_id"),
        "error should mention missing field: {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn calendar_update_event_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.update_event.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/users/me/events/evt-456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "evt-456",
            "subject": "Updated Standup",
            "start": { "dateTime": "2026-03-03T10:00:00", "timeZone": "America/Chicago" },
            "end": { "dateTime": "2026-03-03T10:30:00", "timeZone": "America/Chicago" }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.ReadWrite"])
        .await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.update_event"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.update_event");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.update_event",
            "input": {
                "user_id": "me",
                "event_id": "evt-456",
                "subject": "Updated Standup",
                "start": { "dateTime": "2026-03-03T10:00:00", "timeZone": "America/Chicago" },
                "end": { "dateTime": "2026-03-03T10:30:00", "timeZone": "America/Chicago" }
            },
            "capability_token": token
        }))
        .await
        .expect("update_event should succeed");

    assert_eq!(result["event"]["subject"], "Updated Standup");
}

#[fcp_async_core::runtime::test]
async fn calendar_update_event_missing_event_id() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.update_event.missing_event_id");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.ReadWrite"])
        .await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.update_event"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.update_event");

    let err = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.update_event",
            "input": {
                "user_id": "me",
                "subject": "No event ID"
            },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without event_id");

    assert!(
        format!("{err:?}").contains("event_id"),
        "error should mention missing field: {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn calendar_delete_event_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.delete_event.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/users/me/events/evt-789"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.ReadWrite"])
        .await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.delete_event"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.delete_event");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.delete_event",
            "input": {
                "user_id": "me",
                "event_id": "evt-789"
            },
            "capability_token": token
        }))
        .await
        .expect("delete_event should succeed");

    assert_eq!(result["status"], "deleted");
}

#[fcp_async_core::runtime::test]
async fn calendar_delete_event_missing_event_id() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.delete_event.missing_event_id");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.ReadWrite"])
        .await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.delete_event"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.delete_event");

    let err = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.delete_event",
            "input": { "user_id": "me" },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without event_id");

    assert!(
        format!("{err:?}").contains("event_id"),
        "error should mention missing field: {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn calendar_get_freebusy_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.get_freebusy.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/me/calendar/getSchedule"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                {
                    "scheduleId": "alice@contoso.com",
                    "availabilityView": "0200000000",
                    "scheduleItems": [
                        {
                            "status": "busy",
                            "start": { "dateTime": "2026-03-03T10:00:00", "timeZone": "UTC" },
                            "end": { "dateTime": "2026-03-03T11:00:00", "timeZone": "UTC" }
                        }
                    ]
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.get_freebusy"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.get_freebusy");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.get_freebusy",
            "input": {
                "schedules": ["alice@contoso.com"],
                "start_time": { "dateTime": "2026-03-03T08:00:00", "timeZone": "UTC" },
                "end_time": { "dateTime": "2026-03-03T18:00:00", "timeZone": "UTC" }
            },
            "capability_token": token
        }))
        .await
        .expect("get_freebusy should succeed");

    let schedules = result["schedules"].as_array().expect("schedules array");
    assert_eq!(schedules.len(), 1);
    assert_eq!(schedules[0]["scheduleId"], "alice@contoso.com");
}

#[fcp_async_core::runtime::test]
async fn calendar_get_freebusy_missing_schedules() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.get_freebusy.missing_schedules");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.get_freebusy"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.get_freebusy");

    let err = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.get_freebusy",
            "input": {
                "start_time": { "dateTime": "2026-03-03T08:00:00", "timeZone": "UTC" },
                "end_time": { "dateTime": "2026-03-03T18:00:00", "timeZone": "UTC" }
            },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without schedules");

    assert!(
        format!("{err:?}").contains("schedules"),
        "error should mention missing field: {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn calendar_get_freebusy_missing_start_time() {
    let _ctx = AsyncTestContext::for_scenario("m365.calendar.get_freebusy.missing_start_time");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.get_freebusy"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.get_freebusy");

    let err = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.get_freebusy",
            "input": {
                "schedules": ["alice@contoso.com"],
                "end_time": { "dateTime": "2026-03-03T18:00:00", "timeZone": "UTC" }
            },
            "capability_token": token
        }))
        .await
        .expect_err("should fail without start_time");

    assert!(
        format!("{err:?}").contains("start_time"),
        "error should mention missing field: {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn introspect_calendar_risk_levels() {
    let _ctx = AsyncTestContext::for_scenario("m365.introspect.calendar_risk_levels");
    let connector = M365Connector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    for op in ops {
        let id = op["id"].as_str().unwrap();
        let risk = op["risk_level"].as_str().unwrap();
        match id {
            "m365.calendar.list_events"
            | "m365.calendar.get_event"
            | "m365.calendar.get_freebusy" => {
                assert_eq!(risk, "low", "read op {id} should be low risk");
            }
            "m365.calendar.create_event" | "m365.calendar.update_event" => {
                assert_eq!(risk, "medium", "write op {id} should be medium risk");
            }
            "m365.calendar.delete_event" => {
                assert_eq!(risk, "high", "delete op {id} should be high risk");
            }
            _ => {} // non-calendar ops, skip
        }
    }

    // Verify all 6 calendar ops are present
    let cal_op_count = ops
        .iter()
        .filter_map(|o| o["id"].as_str())
        .filter(|id| id.starts_with("m365.calendar."))
        .count();
    assert_eq!(cal_op_count, 6, "should have exactly 6 calendar operations");
}

// ============================================================================
// Happy-path: Tasks operations
// ============================================================================

#[fcp_async_core::runtime::test]
async fn tasks_list_task_lists_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.tasks.list_task_lists.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/todo/lists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                { "id": "list-1", "displayName": "Tasks", "isOwner": true },
                { "id": "list-2", "displayName": "Work", "isOwner": true }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Tasks.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.tasks.list_task_lists"]).await;
    let token = generate_valid_token(&signing_key, "m365.tasks.list_task_lists");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.tasks.list_task_lists",
            "input": { "user_id": "me" },
            "capability_token": token
        }))
        .await
        .expect("list_task_lists should succeed");

    let lists = result["task_lists"].as_array().expect("task_lists array");
    assert_eq!(lists.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn tasks_create_task_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.tasks.create_task.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/todo/lists/list-1/tasks"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "task-new-1",
            "title": "Review PR #42",
            "status": "notStarted"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Tasks.ReadWrite"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.tasks.create_task"]).await;
    let token = generate_valid_token(&signing_key, "m365.tasks.create_task");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.tasks.create_task",
            "input": {
                "user_id": "me",
                "task_list_id": "list-1",
                "title": "Review PR #42"
            },
            "capability_token": token
        }))
        .await
        .expect("create_task should succeed");

    assert_eq!(result["task"]["title"], "Review PR #42");
}

// ============================================================================
// Happy-path: Subscription operations
// ============================================================================

#[fcp_async_core::runtime::test]
async fn subscriptions_create_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.subscriptions.create.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/subscriptions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "sub-123",
            "resource": "/me/messages",
            "changeType": "created",
            "notificationUrl": "https://webhook.example.com/m365",
            "expirationDateTime": "2026-03-04T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.subscriptions.create"]).await;
    let token = generate_valid_token(&signing_key, "m365.subscriptions.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.subscriptions.create",
            "input": {
                "change_type": "created",
                "notification_url": "https://webhook.example.com/m365",
                "resource": "/me/messages",
                "expiration_datetime": "2026-03-04T00:00:00Z"
            },
            "capability_token": token
        }))
        .await
        .expect("create subscription should succeed");

    assert_eq!(result["subscription"]["id"], "sub-123");
}

// ============================================================================
// Happy-path: Delta sync
// ============================================================================

#[fcp_async_core::runtime::test]
async fn delta_sync_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("m365.delta.sync.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/me/messages/delta.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                { "id": "msg-new-1", "subject": "New mail" }
            ],
            "@odata.deltaLink": "https://graph.microsoft.com/v1.0/me/messages/delta?$deltatoken=opaque123"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.delta.sync"]).await;
    let token = generate_valid_token(&signing_key, "m365.delta.sync");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.delta.sync",
            "input": { "resource": "/me/messages" },
            "capability_token": token
        }))
        .await
        .expect("delta sync should succeed");

    let changes = result["changes"].as_array().expect("changes array");
    assert_eq!(changes.len(), 1);
    assert_eq!(result["delta_token"], "opaque123");
}

// ============================================================================
// Error taxonomy tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn unauthorized_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("m365.error.unauthorized");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages/msg-123"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": "InvalidAuthenticationToken",
                "message": "Access token is empty."
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.mail.get_message"]).await;
    let token = generate_valid_token(&signing_key, "m365.mail.get_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.mail.get_message",
            "input": { "user_id": "me", "message_id": "msg-123" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn not_found_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("m365.error.not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages/msg-nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": "ErrorItemNotFound",
                "message": "The specified object was not found."
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.mail.get_message"]).await;
    let token = generate_valid_token(&signing_key, "m365.mail.get_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.mail.get_message",
            "input": { "user_id": "me", "message_id": "msg-nonexistent" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn rate_limited_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("m365.error.rate_limited");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": {
                "code": "TooManyRequests",
                "message": "Too many requests. Please retry after 30 seconds."
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.mail.list_messages"]).await;
    let token = generate_valid_token(&signing_key, "m365.mail.list_messages");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.mail.list_messages",
            "input": { "user_id": "me" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn forbidden_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("m365.error.forbidden");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/users/me/events.*"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {
                "code": "Authorization_RequestDenied",
                "message": "Insufficient privileges to complete the operation."
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.list_events"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.list_events");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.list_events",
            "input": { "user_id": "me" },
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
    let _ctx = AsyncTestContext::for_scenario("m365.deny.not_configured");
    let mut connector = M365Connector::new();
    let signing_key = setup_handshake(&mut connector, &["m365.mail.get_message"]).await;
    let token = generate_valid_token(&signing_key, "m365.mail.get_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.mail.get_message",
            "input": { "user_id": "me", "message_id": "msg-1" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::NotConfigured
    ));
}

#[fcp_async_core::runtime::test]
async fn invoke_with_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("m365.deny.wrong_capability");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;
    // Handshake grants mail.list_messages but we invoke mail.get_message
    let signing_key = setup_handshake(&mut connector, &["m365.mail.list_messages"]).await;
    let token = generate_valid_token(&signing_key, "m365.mail.list_messages");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.mail.get_message",
            "input": { "user_id": "me", "message_id": "msg-1" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_denied() {
    let _ctx = AsyncTestContext::for_scenario("m365.deny.unknown_operation");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "m365.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Auth mode tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn configure_credential_id_mode() {
    let _ctx = AsyncTestContext::for_scenario("m365.auth.credential_id");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_credential_id(&mut connector, &mock_server.uri()).await;

    let health = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["auth_mode"], "credential_id");
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_missing_permissions() {
    let _ctx = AsyncTestContext::for_scenario("m365.auth.missing_permissions");
    let mut connector = M365Connector::new();
    let token = make_jwt_token(&["User.Read"], &[]);

    let result = connector
        .handle_configure(json!({
            "access_token": token,
            "required_permissions": ["Mail.Read", "Calendars.Read"]
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("missing required permissions"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_multiple_auth_sources() {
    let _ctx = AsyncTestContext::for_scenario("m365.auth.multiple_sources");
    let mut connector = M365Connector::new();
    let token = make_jwt_token(&["Mail.Read"], &[]);

    let result = connector
        .handle_configure(json!({
            "access_token": token,
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("exactly one auth source"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn health_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("m365.lifecycle.health_not_configured");
    let connector = M365Connector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
    assert_eq!(result["auth_mode"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn health_configured() {
    let _ctx = AsyncTestContext::for_scenario("m365.lifecycle.health_configured");
    let mock_server = MockServer::start().await;
    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
    assert_eq!(result["auth_mode"], "access_token");
}

#[fcp_async_core::runtime::test]
async fn introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("m365.lifecycle.introspect");
    let connector = M365Connector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    // Spot-check representative operations from each domain
    assert!(op_ids.contains(&"m365.mail.list_messages"));
    assert!(op_ids.contains(&"m365.mail.send_message"));
    assert!(op_ids.contains(&"m365.files.list_items"));
    assert!(op_ids.contains(&"m365.files.get_item"));
    assert!(op_ids.contains(&"m365.files.download_file"));
    assert!(op_ids.contains(&"m365.files.upload_file"));
    assert!(op_ids.contains(&"m365.files.delete_item"));
    assert!(op_ids.contains(&"m365.files.search"));
    assert!(op_ids.contains(&"m365.files.create_share_link"));
    assert!(op_ids.contains(&"m365.calendar.list_events"));
    assert!(op_ids.contains(&"m365.calendar.create_event"));
    assert!(op_ids.contains(&"m365.calendar.get_event"));
    assert!(op_ids.contains(&"m365.calendar.update_event"));
    assert!(op_ids.contains(&"m365.calendar.delete_event"));
    assert!(op_ids.contains(&"m365.calendar.get_freebusy"));
    assert!(op_ids.contains(&"m365.tasks.list_task_lists"));
    assert!(op_ids.contains(&"m365.tasks.create_task"));
    assert!(op_ids.contains(&"m365.subscriptions.create"));
    assert!(op_ids.contains(&"m365.delta.sync"));
    assert_eq!(ops.len(), 30);
}

#[fcp_async_core::runtime::test]
async fn shutdown_succeeds() {
    let _ctx = AsyncTestContext::for_scenario("m365.lifecycle.shutdown");
    let connector = M365Connector::new();
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
async fn list_messages_missing_user_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("m365.validation.list_messages_missing_user_id");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Read"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.mail.list_messages"]).await;
    let token = generate_valid_token(&signing_key, "m365.mail.list_messages");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.mail.list_messages",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("user_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn create_event_missing_start_fails() {
    let _ctx = AsyncTestContext::for_scenario("m365.validation.create_event_missing_start");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Calendars.ReadWrite"])
        .await;
    let signing_key = setup_handshake(&mut connector, &["m365.calendar.create_event"]).await;
    let token = generate_valid_token(&signing_key, "m365.calendar.create_event");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.calendar.create_event",
            "input": { "user_id": "me", "subject": "Test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("start"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn create_task_missing_title_fails() {
    let _ctx = AsyncTestContext::for_scenario("m365.validation.create_task_missing_title");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Tasks.ReadWrite"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.tasks.create_task"]).await;
    let token = generate_valid_token(&signing_key, "m365.tasks.create_task");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.tasks.create_task",
            "input": { "user_id": "me", "task_list_id": "list-1" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("title"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn send_message_missing_message_fails() {
    let _ctx = AsyncTestContext::for_scenario("m365.validation.send_message_missing_message");
    let mock_server = MockServer::start().await;

    let mut connector = M365Connector::new();
    setup_configure_access_token(&mut connector, &mock_server.uri(), &["Mail.Send"]).await;
    let signing_key = setup_handshake(&mut connector, &["m365.mail.send_message"]).await;
    let token = generate_valid_token(&signing_key, "m365.mail.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "m365.mail.send_message",
            "input": { "user_id": "me" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("message"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}
