//! Integration tests for the Notion connector.
//!
//! Covers the connector testing requirements (u56.5):
//! - Error taxonomy mapping (`NotionError` -> `FcpError`)
//! - Redaction (integration token not leaked in errors)
//! - Pagination handling
//! - Operation dispatch through connector
//! - Capability verification
//!
//! All tests are deterministic -- no real API calls.

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_core::{CapabilityToken, FcpError};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

use fcp_notion::{client::NotionClient, connector::NotionConnector, error::NotionError};

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

async fn setup_handshake(connector: &mut NotionConnector, caps: &[&str]) -> Ed25519SigningKey {
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

async fn setup_configure(connector: &mut NotionConnector, api_url: &str) {
    connector
        .handle_configure(json!({
            "token": "ntn_test_integration_key",
            "api_url": api_url
        }))
        .await
        .expect("configure should succeed");
}

fn page_json(id: &str, title: &str) -> serde_json::Value {
    json!({
        "object": "page",
        "id": id,
        "properties": {
            "title": {
                "title": [{ "text": { "content": title } }]
            }
        },
        "created_time": "2026-01-01T00:00:00.000Z",
        "last_edited_time": "2026-01-01T00:00:00.000Z"
    })
}

// ============================================================================
// Error taxonomy mapping tests
// ============================================================================

/// 401 Unauthorized maps to `NotionError::Unauthorized` -> `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("bad-token")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("page-1").await.unwrap_err();
    assert!(matches!(err, NotionError::Unauthorized));

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { code: 2001, .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 403 Forbidden also maps to Unauthorized.
#[fcp_async_core::runtime::test]
async fn error_403_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-1"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("bad-token")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("page-1").await.unwrap_err();
    assert!(matches!(err, NotionError::Unauthorized));
}

/// 404 Not Found maps to `NotionError::NotFound`.
#[fcp_async_core::runtime::test]
async fn error_404_maps_to_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "object": "error",
            "status": 404,
            "code": "object_not_found",
            "message": "Could not find page"
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("missing").await.unwrap_err();

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::ResourceNotFound { .. }),
        "expected ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[fcp_async_core::runtime::test]
async fn error_429_rate_limited() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-1"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("page-1").await.unwrap_err();
    assert!(err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::RateLimited { .. }),
        "expected RateLimited, got: {fcp_err:?}"
    );
}

/// 500 Server Error is retryable.
#[fcp_async_core::runtime::test]
async fn error_500_server_is_retryable() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-1"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("page-1").await.unwrap_err();
    assert!(err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::External {
                retryable: true,
                ..
            }
        ),
        "expected External retryable, got: {fcp_err:?}"
    );
}

/// Resource not found via error enum.
#[test]
fn error_not_found_maps_correctly() {
    let err = NotionError::NotFound {
        resource: "page:abc-123".into(),
    };
    assert!(!err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, FcpError::ResourceNotFound { .. }));
}

/// Validation error maps to `InvalidRequest`.
#[test]
fn error_validation_maps_to_invalid_request() {
    let err = NotionError::Validation {
        message: "Title is required".into(),
    };
    assert!(!err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::InvalidRequest { .. }),
        "expected InvalidRequest, got: {fcp_err:?}"
    );
}

// ============================================================================
// Redaction tests
// ============================================================================

/// Integration token should not appear in error messages.
#[fcp_async_core::runtime::test]
async fn redaction_token_not_in_error_message() {
    let mock_server = MockServer::start().await;
    let secret = "ntn_SuperSecretIntegrationTokenThatShouldNotLeak";

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new(secret)
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("page-1").await.unwrap_err();
    let err_string = format!("{err:?}");
    assert!(
        !err_string.contains(secret),
        "Token should not appear in error debug output"
    );

    let fcp_err = err.to_fcp_error();
    let fcp_err_string = format!("{fcp_err:?}");
    assert!(
        !fcp_err_string.contains(secret),
        "Token should not appear in FCP error debug output"
    );
}

/// Token is sent as Bearer auth header.
#[fcp_async_core::runtime::test]
async fn token_sent_as_bearer_auth() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("authorization", "Bearer ntn_test_auth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test_auth")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let result = client.search(None, None).await.unwrap();
    assert!(result.results.is_empty());
}

// ============================================================================
// Client operation tests
// ============================================================================

/// `get_page` returns a parsed page.
#[fcp_async_core::runtime::test]
async fn get_page_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_json("page-42", "My Page")))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let page = client.get_page("page-42").await.unwrap();
    assert_eq!(page.id, "page-42");
}

/// `create_page` returns the created page.
#[fcp_async_core::runtime::test]
async fn create_page_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_json("page-new", "New Page")))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let page = client
        .create_page(json!({
            "parent": { "database_id": "db-1" },
            "properties": { "title": { "title": [{ "text": { "content": "New Page" } }] } }
        }))
        .await
        .unwrap();
    assert_eq!(page.id, "page-new");
}

/// `update_page` returns the updated page.
#[fcp_async_core::runtime::test]
async fn update_page_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/pages/page-42"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_json("page-42", "Updated Title")),
        )
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let page = client
        .update_page("page-42", json!({ "properties": {} }))
        .await
        .unwrap();
    assert_eq!(page.id, "page-42");
}

/// `delete_page` archives the page.
#[fcp_async_core::runtime::test]
async fn delete_page_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/pages/page-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json({
            let mut p = page_json("page-42", "Archived");
            p["archived"] = json!(true);
            p
        }))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let page = client.delete_page("page-42").await.unwrap();
    assert_eq!(page.id, "page-42");
}

/// `query_database` returns paginated results.
#[fcp_async_core::runtime::test]
async fn query_database_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/databases/db-1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [
                page_json("page-1", "Result 1"),
                page_json("page-2", "Result 2")
            ],
            "has_more": true,
            "next_cursor": "cursor-abc"
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let result = client.query_database("db-1", None, None).await.unwrap();
    assert_eq!(result.results.len(), 2);
    assert!(result.has_more);
    assert_eq!(result.next_cursor.as_deref(), Some("cursor-abc"));
}

/// `search` returns results.
#[fcp_async_core::runtime::test]
async fn search_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [page_json("page-found", "Found")],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let result = client.search(Some("test"), None).await.unwrap();
    assert_eq!(result.results.len(), 1);
    assert!(!result.has_more);
}

/// `get_block_children` returns block list.
#[fcp_async_core::runtime::test]
async fn get_block_children_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/blocks/block-1/children"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [
                { "object": "block", "id": "child-1", "type": "paragraph" }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let result = client.get_block_children("block-1").await.unwrap();
    assert_eq!(result.results.len(), 1);
}

/// `list_comments` returns comments.
#[fcp_async_core::runtime::test]
async fn list_comments_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [
                { "object": "comment", "id": "cmt-1" }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let result = client.list_comments("block-1").await.unwrap();
    assert_eq!(result.results.len(), 1);
}

// ============================================================================
// Connector-level invoke tests
// ============================================================================

/// Invoke `notion.search` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_search_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [page_json("pg-1", "Found Page")],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.search"]).await;
    let token = generate_valid_token(&signing_key, "notion.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.search",
            "input": { "query": "test" },
            "capability_token": token
        }))
        .await
        .unwrap();

    let results = result["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
}

/// Invoke `notion.get_page` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_get_page_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/pg-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_json("pg-42", "My Page")))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.get_page"]).await;
    let token = generate_valid_token(&signing_key, "notion.get_page");

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.get_page",
            "input": { "page_id": "pg-42" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["page"]["id"], "pg-42");
}

/// Invoke `notion.query_database` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_query_database_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/databases/db-1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [page_json("pg-r1", "Row 1")],
            "has_more": false,
            "next_cursor": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.query_database"]).await;
    let token = generate_valid_token(&signing_key, "notion.query_database");

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.query_database",
            "input": { "database_id": "db-1" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["results"].as_array().unwrap().len(), 1);
    assert_eq!(result["has_more"], false);
}

/// Wrong capability token is rejected.
#[fcp_async_core::runtime::test]
async fn wrong_capability_rejected() {
    let mock_server = MockServer::start().await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.search"]).await;
    let token = generate_valid_token(&signing_key, "notion.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.get_page",
            "input": { "page_id": "pg-1" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject mismatched capability");
}

/// Missing required field returns `InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn missing_required_field_returns_invalid_request() {
    let mock_server = MockServer::start().await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.get_page"]).await;
    let token = generate_valid_token(&signing_key, "notion.get_page");

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.get_page",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing page_id"
    );
}

/// Unknown operation is rejected.
#[fcp_async_core::runtime::test]
async fn unknown_operation_rejected() {
    let mock_server = MockServer::start().await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "notion.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}
