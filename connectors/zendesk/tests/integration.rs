//! Zendesk connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the Zendesk API.
//! No real API calls. Covers:
//! - Happy-path operations (tickets, search, comments, articles, macros)
//! - Error taxonomy (401/404/429/500)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, introspect, shutdown)
//! - Input validation (missing required fields)

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_zendesk::connector::ZendeskConnector;

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
async fn setup_handshake(connector: &mut ZendeskConnector, caps: &[&str]) -> Ed25519SigningKey {
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
async fn setup_configure(connector: &mut ZendeskConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "subdomain": "testco",
            "email": "agent@testco.com",
            "api_token": "test-api-token-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_create_ticket() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-create-ticket");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v2/tickets.json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "ticket": {
                "id": 42,
                "subject": "Login broken after update",
                "status": "new",
                "priority": "high",
                "requester_id": 1001
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.create_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.create_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.create_ticket",
            "input": {
                "subject": "Login broken after update",
                "description": "Cannot log in since the 2.0 update",
                "priority": "high",
                "type": "problem"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["ticket"]["id"], 42);
    assert_eq!(result["ticket"]["subject"], "Login broken after update");
    assert_eq!(result["ticket"]["priority"], "high");
}

#[fcp_async_core::runtime::test]
async fn test_get_ticket() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-get-ticket");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/123.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ticket": {
                "id": 123,
                "subject": "Password reset help",
                "status": "open",
                "priority": "normal",
                "tags": ["password", "account"]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": { "ticket_id": 123 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["ticket"]["id"], 123);
    assert_eq!(result["ticket"]["status"], "open");
    assert_eq!(result["ticket"]["tags"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn test_update_ticket() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-update-ticket");
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/api/v2/tickets/123.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ticket": {
                "id": 123,
                "subject": "Password reset help",
                "status": "solved",
                "priority": "normal"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.update_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.update_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.update_ticket",
            "input": {
                "ticket_id": 123,
                "status": "solved",
                "comment": { "body": "Issue resolved.", "public": true }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["ticket"]["id"], 123);
    assert_eq!(result["ticket"]["status"], "solved");
}

#[fcp_async_core::runtime::test]
async fn test_delete_ticket() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-delete-ticket");
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/api/v2/tickets/999.json"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.delete_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.delete_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.delete_ticket",
            "input": { "ticket_id": 999 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn test_search_tickets() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-search-tickets");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/search.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                { "id": 1, "subject": "Urgent: Server down" },
                { "id": 2, "subject": "Performance degraded" }
            ],
            "count": 2,
            "next_page": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.search_tickets"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.search_tickets");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.search_tickets",
            "input": {
                "query": "status:open priority:urgent",
                "sort_by": "created_at",
                "sort_order": "desc"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["count"], 2);
    let results = result["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["subject"], "Urgent: Server down");
}

#[fcp_async_core::runtime::test]
async fn test_list_ticket_comments() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-list-comments");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/123/comments.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "comments": [
                { "id": 1, "body": "Customer: I cannot log in", "public": true, "author_id": 1001 },
                { "id": 2, "body": "Agent: Please try clearing cache", "public": true, "author_id": 2001 }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.list_ticket_comments"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.list_ticket_comments");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.list_ticket_comments",
            "input": { "ticket_id": 123, "sort_order": "asc" },
            "capability_token": token
        }))
        .await
        .unwrap();

    let comments = result["comments"].as_array().unwrap();
    assert_eq!(comments.len(), 2);
    assert_eq!(comments[0]["author_id"], 1001);
}

#[fcp_async_core::runtime::test]
async fn test_search_articles() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-search-articles");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/help_center/articles/search.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                { "id": 360_001_234_567_i64, "title": "How to Reset Your Password", "locale": "en-us" }
            ],
            "count": 1
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.search_articles"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.search_articles");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.search_articles",
            "input": { "query": "password reset", "locale": "en-us" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["count"], 1);
    let articles = result["results"].as_array().unwrap();
    assert_eq!(articles[0]["title"], "How to Reset Your Password");
}

#[fcp_async_core::runtime::test]
async fn test_get_article() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-get-article");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/help_center/articles/100.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "article": {
                "id": 100,
                "title": "Password Reset Guide",
                "body": "<p>To reset your password, go to Settings...</p>",
                "locale": "en-us"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_article"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.get_article");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_article",
            "input": { "article_id": 100 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["article"]["id"], 100);
    assert_eq!(result["article"]["title"], "Password Reset Guide");
}

#[fcp_async_core::runtime::test]
async fn test_apply_macro() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-apply-macro");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/123/macros/456/apply.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "ticket": {
                    "id": 123,
                    "status": "solved",
                    "comment": { "body": "Resolved via macro" }
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.apply_macro"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.apply_macro");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.apply_macro",
            "input": { "ticket_id": 123, "macro_id": 456 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(result["result"]["ticket"].is_object());
    assert_eq!(result["result"]["ticket"]["status"], "solved");
}

// ============================================================================
// Error taxonomy
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_error_401_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-error-401");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/1.json"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Couldn't authenticate you"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": { "ticket_id": 1 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::Unauthorized { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn test_error_404_not_found() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-error-404");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/999_999.json"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "RecordNotFound",
            "description": "Not found"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": { "ticket_id": 999_999 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::ResourceNotFound { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn test_error_429_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-error-429");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/1.json"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": { "ticket_id": 1 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::RateLimited { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn test_error_500_server_error() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-error-500");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v2/tickets.json"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.create_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.create_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.create_ticket",
            "input": { "subject": "Test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::External {
            retryable, service, ..
        } => {
            assert!(retryable);
            assert_eq!(service, "zendesk");
        }
        e => panic!("Expected External(retryable), got: {e:?}"),
    }
}

// ============================================================================
// FCP2 default-deny
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_invoke_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-not-configured");

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    // Skip configure

    let token = generate_valid_token(&key, "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": { "ticket_id": 1 },
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
async fn test_invoke_wrong_capability() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-wrong-capability");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    // Try to invoke create_ticket with a get_ticket token
    let token = generate_valid_token(&key, "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.create_ticket",
            "input": { "subject": "Sneaky ticket" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn test_invoke_unknown_operation() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-unknown-operation");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.nonexistent"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::OperationNotGranted { operation } => {
            assert_eq!(operation, "zendesk.nonexistent");
        }
        e => panic!("Expected OperationNotGranted, got: {e:?}"),
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_health_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-health-not-configured");
    let connector = ZendeskConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn test_health_configured() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-health-configured");
    let mut connector = ZendeskConnector::new();
    setup_configure(&mut connector, "https://testco.zendesk.com/api/v2").await;

    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn test_introspect_operations() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-introspect");
    let connector = ZendeskConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 10);

    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
    assert!(op_ids.contains(&"zendesk.create_ticket"));
    assert!(op_ids.contains(&"zendesk.get_ticket"));
    assert!(op_ids.contains(&"zendesk.update_ticket"));
    assert!(op_ids.contains(&"zendesk.delete_ticket"));
    assert!(op_ids.contains(&"zendesk.search_tickets"));
    assert!(op_ids.contains(&"zendesk.list_ticket_comments"));
    assert!(op_ids.contains(&"zendesk.search_articles"));
    assert!(op_ids.contains(&"zendesk.get_article"));
    assert!(op_ids.contains(&"zendesk.search_users"));
    assert!(op_ids.contains(&"zendesk.apply_macro"));
}

#[fcp_async_core::runtime::test]
async fn test_shutdown() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-shutdown");
    let connector = ZendeskConnector::new();
    let result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Input validation
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_create_ticket_missing_subject() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-missing-subject");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.create_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.create_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.create_ticket",
            "input": { "priority": "high" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("subject"));
        }
        e => panic!("Expected InvalidRequest about 'subject', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_get_ticket_missing_ticket_id() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-missing-ticket-id");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("ticket_id"));
        }
        e => panic!("Expected InvalidRequest about 'ticket_id', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_search_tickets_missing_query() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-missing-query");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.search_tickets"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.search_tickets");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.search_tickets",
            "input": { "sort_by": "created_at" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("query"));
        }
        e => panic!("Expected InvalidRequest about 'query', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_apply_macro_missing_macro_id() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-missing-macro-id");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.apply_macro"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, "zendesk.apply_macro");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.apply_macro",
            "input": { "ticket_id": 123 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("macro_id"));
        }
        e => panic!("Expected InvalidRequest about 'macro_id', got: {e:?}"),
    }
}
