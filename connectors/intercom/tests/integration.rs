//! Integration tests for the FCP `Intercom` connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_intercom::connector::IntercomConnector;

async fn setup_connector(mock_url: &str) -> IntercomConnector {
    let mut c = IntercomConnector::new();
    c.handle_configure(json!({ "access_token": "test-token", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// ── Lifecycle ────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = IntercomConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = IntercomConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 6);
}

// ── Contacts List ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn contacts_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/contacts.*"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "list",
            "data": [
                {"id": "c1", "role": "user", "email": "alice@example.com"},
                {"id": "c2", "role": "lead", "email": "bob@example.com"},
            ],
            "total_count": 2,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "intercom.contacts.list",
            "input": {"per_page": 50}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
    assert_eq!(result["total_count"], 2);
}

#[fcp_async_core::runtime::test]
async fn contacts_list_with_pagination() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/contacts.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "list",
            "data": [{"id": "c3"}],
            "total_count": 100,
            "pages": {"next": {"starting_after": "c3"}}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "intercom.contacts.list",
            "input": {"per_page": 1, "starting_after": "c2"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
}

// ── Contacts Create ─────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn contacts_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/contacts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "new123",
            "type": "contact",
            "role": "user",
            "email": "alice@example.com",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "intercom.contacts.create",
            "input": {"role": "user", "email": "alice@example.com", "name": "Alice"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new123");
}

#[fcp_async_core::runtime::test]
async fn contacts_create_missing_role() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "intercom.contacts.create",
            "input": {"email": "alice@example.com"}
        }))
        .await
        .is_err()
    );
}

// ── Contacts Delete ─────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn contacts_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/contacts/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "abc123",
            "type": "contact",
            "deleted": true,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "intercom.contacts.delete",
            "input": {"contact_id": "abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn contacts_delete_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "intercom.contacts.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ── Conversations List ──────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn conversations_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/conversations.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "conversation.list",
            "conversations": [
                {"id": "conv1", "state": "open"},
                {"id": "conv2", "state": "closed"},
            ],
            "total_count": 2,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "intercom.conversations.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["conversations"].as_array().unwrap().len(), 2);
}

// ── Conversations Reply ─────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn conversations_reply() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/conversations/conv1/reply"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "reply1",
            "type": "conversation_part",
            "body": "Thanks for reaching out!",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "intercom.conversations.reply",
            "input": {
                "conversation_id": "conv1",
                "body": "Thanks for reaching out!",
                "message_type": "comment"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "reply1");
}

#[fcp_async_core::runtime::test]
async fn conversations_reply_missing_conversation_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "intercom.conversations.reply",
            "input": {"body": "Hi", "message_type": "comment"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn conversations_reply_missing_body() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "intercom.conversations.reply",
            "input": {"conversation_id": "conv1", "message_type": "comment"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn conversations_reply_missing_message_type() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "intercom.conversations.reply",
            "input": {"conversation_id": "conv1", "body": "Hi"}
        }))
        .await
        .is_err()
    );
}

// ── Tags List ───────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn tags_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "list",
            "data": [
                {"id": "t1", "type": "tag", "name": "VIP"},
                {"id": "t2", "type": "tag", "name": "Urgent"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "intercom.tags.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

// ── Error handling ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/contacts.*"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "Unauthorized"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "intercom.contacts.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/contacts.*"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "Forbidden"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "intercom.contacts.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path_regex("/contacts/.*"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "intercom.contacts.delete",
            "input": {"contact_id": "missing"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/contacts.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "intercom.contacts.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ── Unknown op / Simulate ───────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "intercom.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "intercom.contacts.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "intercom.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// ── Counters ────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/contacts.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "list",
            "data": [],
            "total_count": 0,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "intercom.contacts.list",
        "input": {}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/contacts.*"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "intercom.contacts.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
