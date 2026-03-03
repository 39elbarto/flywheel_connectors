//! Figma connector integration tests (flywheel_connectors-vuwy.3 + 9c0).
//!
//! Deterministic integration tests using wiremock to mock the Figma REST API.
//! No real API calls. Covers:
//! - Resource discovery (list team projects, list project files, file meta)
//! - Files (get file, get nodes, components, styles)
//! - Image export
//! - Version history
//! - Comments (list, post, delete)
//! - Webhooks (list, create, delete) via v2 API
//! - Error taxonomy (401/403/404/429/500 -> `FcpError` mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown, risk levels)
//! - Input validation edge cases

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

use fcp_figma::client::FigmaClient;
use fcp_figma::connector::FigmaConnector;

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

async fn setup_handshake(connector: &mut FigmaConnector, caps: &[&str]) -> Ed25519SigningKey {
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

async fn setup_configure(connector: &mut FigmaConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "token": "figma-test-token-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

/// Standard Figma file response.
fn figma_file_response() -> serde_json::Value {
    json!({
        "name": "Test Design File",
        "document": {
            "id": "0:0",
            "type": "DOCUMENT",
            "children": [{
                "id": "1:1",
                "name": "Page 1",
                "type": "CANVAS",
                "children": []
            }]
        },
        "lastModified": "2026-01-15T10:00:00Z",
        "version": "456789",
        "components": {},
        "styles": {}
    })
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn get_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.get_file.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(figma_file_response()))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.get_file"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.get_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.get_file",
            "input": { "file_key": "abc123" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["name"], "Test Design File");
    assert_eq!(result["version"], "456789");
}

#[fcp_async_core::runtime::test]
async fn get_file_nodes_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.get_file_nodes.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "nodes": {
                "1:2": {
                    "document": { "id": "1:2", "type": "FRAME", "name": "Header" }
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.get_file_nodes"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.get_file_nodes");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.get_file_nodes",
            "input": { "file_key": "abc123", "ids": "1:2" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert!(result["nodes"]["1:2"].is_object());
}

#[fcp_async_core::runtime::test]
async fn get_file_components_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.get_file_components.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123/components"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta": {
                "components": [
                    { "key": "comp1", "name": "Button", "description": "Primary button" }
                ]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.get_file_components"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.get_file_components");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.get_file_components",
            "input": { "file_key": "abc123" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert!(result["meta"]["components"].is_array());
}

#[fcp_async_core::runtime::test]
async fn get_file_styles_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.get_file_styles.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123/styles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta": {
                "styles": [
                    { "key": "s1", "name": "Primary Color", "style_type": "FILL" }
                ]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.get_file_styles"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.get_file_styles");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.get_file_styles",
            "input": { "file_key": "abc123" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert!(result["meta"]["styles"].is_array());
}

#[fcp_async_core::runtime::test]
async fn export_images_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.export_images.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/images/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "images": {
                "1:2": "https://figma-alpha.s3.amazonaws.com/img/abc.png"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.export_images"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.export_images");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.export_images",
            "input": { "file_key": "abc123", "ids": "1:2", "format": "png" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert!(
        result["images"]["1:2"]
            .as_str()
            .unwrap()
            .contains("s3.amazonaws.com")
    );
}

#[fcp_async_core::runtime::test]
async fn list_file_versions_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.list_file_versions.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123/versions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "versions": [
                {
                    "id": "v1",
                    "label": "Initial design",
                    "created_at": "2026-01-15T09:00:00Z"
                },
                {
                    "id": "v2",
                    "label": "Updated header",
                    "created_at": "2026-01-15T10:00:00Z"
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.list_file_versions"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.list_file_versions");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.list_file_versions",
            "input": { "file_key": "abc123" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let versions = result["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["id"], "v1");
}

#[fcp_async_core::runtime::test]
async fn list_comments_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.list_comments.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "comments": [
                {
                    "id": "c1",
                    "message": "Looks great!",
                    "created_at": "2026-01-15T10:00:00Z"
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.list_comments"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.list_comments");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.list_comments",
            "input": { "file_key": "abc123" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let comments = result["comments"].as_array().unwrap();
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0]["message"], "Looks great!");
}

#[fcp_async_core::runtime::test]
async fn post_comment_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.post_comment.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/files/abc123/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "c2",
            "message": "Need more contrast here",
            "created_at": "2026-01-15T11:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.post_comment"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.post_comment");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.post_comment",
            "input": { "file_key": "abc123", "message": "Need more contrast here" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["id"], "c2");
    assert_eq!(result["message"], "Need more contrast here");
}

#[fcp_async_core::runtime::test]
async fn delete_comment_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.delete_comment.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/files/abc123/comments/c1"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.delete_comment"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.delete_comment");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.delete_comment",
            "input": { "file_key": "abc123", "comment_id": "c1" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert!(result.is_object());
}

// ── Webhook operations ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn webhook_list_webhooks_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.list_webhooks.happy_path");
    let mock_server = MockServer::start().await;

    // Webhook v2 paths resolve via `../v2/webhooks` → /v2/webhooks/{team_id}
    Mock::given(method("GET"))
        .and(path("/v2/webhooks/team-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "webhooks": [
                {
                    "id": "wh-1",
                    "team_id": "team-42",
                    "event_type": "FILE_UPDATE",
                    "endpoint": "https://hooks.example.com/figma",
                    "status": "ACTIVE"
                },
                {
                    "id": "wh-2",
                    "team_id": "team-42",
                    "event_type": "FILE_DELETE",
                    "endpoint": "https://hooks.example.com/figma-delete",
                    "status": "ACTIVE",
                    "description": "File deletion watcher"
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.list_webhooks"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.list_webhooks");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.list_webhooks",
            "input": { "team_id": "team-42" },
            "capability_token": token
        }))
        .await
        .expect("list_webhooks should succeed");

    let webhooks = result["webhooks"].as_array().unwrap();
    assert_eq!(webhooks.len(), 2);
    assert_eq!(webhooks[0]["id"], "wh-1");
    assert_eq!(webhooks[0]["event_type"], "FILE_UPDATE");
    assert_eq!(webhooks[1]["id"], "wh-2");
    assert_eq!(webhooks[1]["description"], "File deletion watcher");
}

#[fcp_async_core::runtime::test]
async fn webhook_create_webhook_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.create_webhook.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/webhooks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "wh-new",
            "team_id": "team-42",
            "event_type": "FILE_UPDATE",
            "endpoint": "https://hooks.example.com/figma",
            "status": "ACTIVE",
            "passcode": "secret123"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.create_webhook"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.create_webhook");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.create_webhook",
            "input": {
                "team_id": "team-42",
                "event_type": "FILE_UPDATE",
                "endpoint": "https://hooks.example.com/figma",
                "passcode": "secret123"
            },
            "capability_token": token
        }))
        .await
        .expect("create_webhook should succeed");

    assert_eq!(result["id"], "wh-new");
    assert_eq!(result["team_id"], "team-42");
    assert_eq!(result["event_type"], "FILE_UPDATE");
    assert_eq!(result["status"], "ACTIVE");
}

#[fcp_async_core::runtime::test]
async fn webhook_delete_webhook_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.delete_webhook.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v2/webhooks/wh-123"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.delete_webhook"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.delete_webhook");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.delete_webhook",
            "input": { "webhook_id": "wh-123" },
            "capability_token": token
        }))
        .await
        .expect("delete_webhook should succeed");

    assert!(result.is_object());
}

// ============================================================================
// Error taxonomy tests (Figma uses HTTP status codes for errors)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("figma.error.401");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "status": 401, "err": "Invalid token"
        })))
        .mount(&mock_server)
        .await;

    let client = FigmaClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_file("abc123", None, None, None, None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_403_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("figma.error.403");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "status": 403, "err": "Forbidden"
        })))
        .mount(&mock_server)
        .await;

    let client = FigmaClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_file("abc123", None, None, None, None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_404_maps_to_resource_not_found() {
    let _ctx = AsyncTestContext::for_scenario("figma.error.404");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "status": 404, "err": "Not found"
        })))
        .mount(&mock_server)
        .await;

    let client = FigmaClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_file("nonexistent", None, None, None, None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "Expected ResourceNotFound, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("figma.error.429");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
        .mount(&mock_server)
        .await;

    let client = FigmaClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_file("abc123", None, None, None, None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "Expected RateLimited, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_500_maps_to_external() {
    let _ctx = AsyncTestContext::for_scenario("figma.error.500");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let client = FigmaClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_file("abc123", None, None, None, None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::External { .. }),
        "Expected External, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_retryable_classification() {
    use fcp_figma::error::FigmaError;

    // 429 API error is retryable
    let rate_err = FigmaError::Api {
        status: 429,
        message: "rate limited".into(),
    };
    assert!(rate_err.is_retryable());

    // 500+ server errors are retryable
    let server_err = FigmaError::Api {
        status: 500,
        message: "server error".into(),
    };
    assert!(server_err.is_retryable());

    // "timeout" in message is retryable
    let timeout_err = FigmaError::Api {
        status: 408,
        message: "request timeout".into(),
    };
    assert!(timeout_err.is_retryable());

    // RateLimited is always retryable
    let rate = FigmaError::RateLimited {
        retry_after_secs: 30,
    };
    assert!(rate.is_retryable());

    // 404 is NOT retryable
    let not_found = FigmaError::Api {
        status: 404,
        message: "Not found".into(),
    };
    assert!(!not_found.is_retryable());

    // Unauthorized is NOT retryable
    let unauth = FigmaError::Unauthorized;
    assert!(!unauth.is_retryable());
}

// ============================================================================
// FCP2 default-deny + capability verification
// ============================================================================

#[fcp_async_core::runtime::test]
async fn fcp2_invoke_requires_handshake() {
    let _ctx = AsyncTestContext::for_scenario("figma.capability.no_handshake");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "figma.get_file",
            "input": { "file_key": "abc123" },
            "capability_token": { "raw": vec![0u8; 32] }
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn fcp2_invoke_requires_capability_token() {
    let _ctx = AsyncTestContext::for_scenario("figma.capability.missing_token");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let _key = setup_handshake(&mut connector, &["figma.get_file"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "figma.get_file",
            "input": { "file_key": "abc123" }
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
    let _ctx = AsyncTestContext::for_scenario("figma.capability.wrong_cap");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.read"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.read");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.post_comment",
            "input": { "file_key": "abc123", "message": "test" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn fcp2_unknown_operation_rejected() {
    let _ctx = AsyncTestContext::for_scenario("figma.capability.unknown_op");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.nonexistent"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.nonexistent",
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
    let _ctx = AsyncTestContext::for_scenario("figma.capability.missing_op");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let _key = setup_handshake(&mut connector, &["figma.read"]).await;
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
    let _ctx = AsyncTestContext::for_scenario("figma.lifecycle.health_before");
    let connector = FigmaConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let _ctx = AsyncTestContext::for_scenario("figma.lifecycle.health_after");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_returns_accepted() {
    let _ctx = AsyncTestContext::for_scenario("figma.lifecycle.handshake");
    let mut connector = FigmaConnector::new();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": vec![0u8; 32],
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["figma.read", "figma.write"]
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
    let _ctx = AsyncTestContext::for_scenario("figma.lifecycle.introspect");
    let connector = FigmaConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 15);

    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
    for expected in &[
        "figma.list_team_projects",
        "figma.list_project_files",
        "figma.get_file_meta",
        "figma.get_file",
        "figma.get_file_nodes",
        "figma.get_file_components",
        "figma.get_file_styles",
        "figma.export_images",
        "figma.list_file_versions",
        "figma.list_comments",
        "figma.post_comment",
        "figma.delete_comment",
        "figma.list_webhooks",
        "figma.create_webhook",
        "figma.delete_webhook",
    ] {
        assert!(op_ids.contains(expected), "Missing op: {expected}");
    }
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let _ctx = AsyncTestContext::for_scenario("figma.lifecycle.shutdown");
    let connector = FigmaConnector::new();
    let result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(result["status"], "shutdown");
}

#[fcp_async_core::runtime::test]
async fn introspect_risk_levels() {
    let _ctx = AsyncTestContext::for_scenario("figma.lifecycle.risk_levels");
    let connector = FigmaConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 15);

    // Low-risk: all read ops + post_comment + list_webhooks
    let low_ops = [
        "figma.list_team_projects",
        "figma.list_project_files",
        "figma.get_file_meta",
        "figma.get_file",
        "figma.get_file_nodes",
        "figma.get_file_components",
        "figma.get_file_styles",
        "figma.export_images",
        "figma.list_file_versions",
        "figma.list_comments",
        "figma.post_comment",
        "figma.list_webhooks",
    ];
    // Medium-risk: delete_comment, create_webhook, delete_webhook
    let medium_ops = [
        "figma.delete_comment",
        "figma.create_webhook",
        "figma.delete_webhook",
    ];

    for op in ops {
        let id = op["id"].as_str().unwrap();
        let risk = op["risk_level"].as_str().unwrap();
        if low_ops.contains(&id) {
            assert_eq!(risk, "low", "op {id} should be low risk");
        } else if medium_ops.contains(&id) {
            assert_eq!(risk, "medium", "op {id} should be medium risk");
        } else {
            panic!("Unexpected operation: {id}");
        }
    }

    let low_count = ops
        .iter()
        .filter(|o| o["risk_level"].as_str() == Some("low"))
        .count();
    let medium_count = ops
        .iter()
        .filter(|o| o["risk_level"].as_str() == Some("medium"))
        .count();
    assert_eq!(low_count, 12, "should have 12 low-risk ops");
    assert_eq!(medium_count, 3, "should have 3 medium-risk ops");
}

// ============================================================================
// Input validation edge cases
// ============================================================================

#[fcp_async_core::runtime::test]
async fn validate_get_file_missing_file_key() {
    let _ctx = AsyncTestContext::for_scenario("figma.validation.missing_file_key");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.get_file"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.get_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.get_file",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("file_key"));
        }
        e => panic!("Expected InvalidRequest about file_key, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_get_file_nodes_missing_ids() {
    let _ctx = AsyncTestContext::for_scenario("figma.validation.missing_ids");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.get_file_nodes"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.get_file_nodes");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.get_file_nodes",
            "input": { "file_key": "abc123" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("ids"));
        }
        e => panic!("Expected InvalidRequest about ids, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_export_images_missing_format() {
    let _ctx = AsyncTestContext::for_scenario("figma.validation.missing_format");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.export_images"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.export_images");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.export_images",
            "input": { "file_key": "abc123", "ids": "1:2" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("format"));
        }
        e => panic!("Expected InvalidRequest about format, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_post_comment_missing_message() {
    let _ctx = AsyncTestContext::for_scenario("figma.validation.missing_message");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.post_comment"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.post_comment");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.post_comment",
            "input": { "file_key": "abc123" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("message"));
        }
        e => panic!("Expected InvalidRequest about message, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_configure_missing_token() {
    let _ctx = AsyncTestContext::for_scenario("figma.validation.missing_token");
    let mut connector = FigmaConnector::new();
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
async fn validate_delete_comment_missing_comment_id() {
    let _ctx = AsyncTestContext::for_scenario("figma.validation.missing_comment_id");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.delete_comment"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.delete_comment");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.delete_comment",
            "input": { "file_key": "abc123" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("comment_id"));
        }
        e => panic!("Expected InvalidRequest about comment_id, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_list_webhooks_missing_team_id() {
    let _ctx = AsyncTestContext::for_scenario("figma.validation.missing_team_id");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.list_webhooks"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.list_webhooks");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.list_webhooks",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("team_id"));
        }
        e => panic!("Expected InvalidRequest about team_id, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_create_webhook_missing_fields() {
    let _ctx = AsyncTestContext::for_scenario("figma.validation.missing_webhook_fields");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.create_webhook"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Missing event_type, endpoint, passcode
    let token = generate_valid_token(&key, "figma.create_webhook");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.create_webhook",
            "input": { "team_id": "team-42" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("event_type"));
        }
        e => panic!("Expected InvalidRequest about event_type, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn validate_delete_webhook_missing_webhook_id() {
    let _ctx = AsyncTestContext::for_scenario("figma.validation.missing_webhook_id");
    let mock_server = MockServer::start().await;
    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.delete_webhook"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.delete_webhook");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.delete_webhook",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("webhook_id"));
        }
        e => panic!("Expected InvalidRequest about webhook_id, got: {e:?}"),
    }
}

// ============================================================================
// Large data / bounded memory tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn get_file_nodes_large_tree() {
    let _ctx = AsyncTestContext::for_scenario("figma.nodes.large_tree");
    let mock_server = MockServer::start().await;

    // Generate a tree with many nodes to verify bounded processing
    let mut nodes = serde_json::Map::new();
    for i in 0..100 {
        let id = format!("{i}:0");
        nodes.insert(
            id.clone(),
            json!({
                "document": {
                    "id": id,
                    "name": format!("Node {i}"),
                    "type": "FRAME",
                    "children": []
                }
            }),
        );
    }

    Mock::given(method("GET"))
        .and(path("/files/bigfile/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "Big File",
            "nodes": nodes,
            "lastModified": "2026-01-01T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    let client = FigmaClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let result = client.get_file_nodes("bigfile", "0:0,1:0,2:0", None).await;
    assert!(result.is_ok(), "should handle large node responses");
    let nodes_response = result.unwrap();
    let nodes_map = nodes_response
        .nodes
        .as_object()
        .expect("nodes should be object");
    assert!(!nodes_map.is_empty(), "should return non-empty node map");
}

#[fcp_async_core::runtime::test]
async fn export_images_multiple_nodes() {
    let _ctx = AsyncTestContext::for_scenario("figma.export.multiple_nodes");
    let mock_server = MockServer::start().await;

    // Export images for multiple node IDs at once
    let mut images = serde_json::Map::new();
    for i in 0..10 {
        images.insert(
            format!("{i}:0"),
            json!(format!(
                "https://figma-alpha.s3.amazonaws.com/img/export_{i}.png"
            )),
        );
    }

    Mock::given(method("GET"))
        .and(path("/images/multifile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "images": images
        })))
        .mount(&mock_server)
        .await;

    let client = FigmaClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let ids = (0..10)
        .map(|i| format!("{i}:0"))
        .collect::<Vec<_>>()
        .join(",");
    let result = client
        .export_images("multifile", &ids, "png", None, None, None, None)
        .await;
    assert!(result.is_ok(), "should export multiple images");
    let export = result.unwrap();
    let images_map = export.images.as_object().expect("images should be object");
    assert_eq!(images_map.len(), 10, "should return 10 image URLs");
}

#[fcp_async_core::runtime::test]
async fn get_file_nodes_through_connector() {
    let _ctx = AsyncTestContext::for_scenario("figma.invoke.get_file_nodes");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "Test File",
            "nodes": {
                "1:2": {
                    "document": {
                        "id": "1:2",
                        "name": "Frame A",
                        "type": "FRAME",
                        "children": [
                            { "id": "1:3", "name": "Child", "type": "RECTANGLE" }
                        ]
                    }
                }
            },
            "lastModified": "2026-01-01T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.get_file_nodes"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.get_file_nodes");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.get_file_nodes",
            "input": {
                "file_key": "abc123",
                "ids": "1:2"
            },
            "capability_token": token
        }))
        .await
        .expect("get_file_nodes should succeed");

    assert!(result.get("nodes").is_some(), "should return nodes");
}

// ============================================================================
// Rate limit + backoff tests (via client-level)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn rate_limit_429_includes_retry_after_seconds() {
    let _ctx = AsyncTestContext::for_scenario("figma.rate_limit.retry_after");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "45"))
        .mount(&mock_server)
        .await;

    let client = FigmaClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 100, 200);

    let result = client.get_file("abc123", None, None, None, None).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_figma::error::FigmaError::RateLimited { retry_after_secs } => {
            assert_eq!(retry_after_secs, 45, "should capture retry-after value");
        }
        e => panic!("Expected RateLimited, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn rate_limit_429_without_retry_after_defaults() {
    let _ctx = AsyncTestContext::for_scenario("figma.rate_limit.no_retry_after");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&mock_server)
        .await;

    let client = FigmaClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 100, 200);

    let result = client.get_file("abc123", None, None, None, None).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_figma::error::FigmaError::RateLimited { retry_after_secs } => {
            assert_eq!(
                retry_after_secs, 60,
                "should default to 60s without retry-after header"
            );
        }
        e => panic!("Expected RateLimited, got: {e:?}"),
    }
}

// ============================================================================
// Resource Discovery tests (flywheel_connectors-9c0)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn list_team_projects_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.list_team_projects.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/teams/12345/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "Design Team",
            "projects": [
                { "id": 111, "name": "Web App" },
                { "id": 222, "name": "Mobile App" },
                { "id": 333, "name": "Brand Assets" }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.list_team_projects"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.list_team_projects");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.list_team_projects",
            "input": { "team_id": "12345" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["name"], "Design Team");
    let projects = result["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 3);
    assert_eq!(projects[0]["id"], 111);
    assert_eq!(projects[0]["name"], "Web App");
    assert_eq!(projects[2]["name"], "Brand Assets");

    // Verify provenance/taint metadata
    assert_eq!(result["provenance"]["source"], "figma.teams");
    assert_eq!(result["provenance"]["scope"], "team");
    let taint = result["taint"].as_array().unwrap();
    assert!(taint.contains(&json!("external_input")));
}

#[fcp_async_core::runtime::test]
async fn list_project_files_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.list_project_files.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/projects/67890/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "Web App",
            "files": [
                {
                    "key": "abc123",
                    "name": "Homepage Design",
                    "thumbnail_url": "https://s3-alpha.figma.com/thumbnails/abc123.png",
                    "last_modified": "2026-03-01T10:00:00Z"
                },
                {
                    "key": "def456",
                    "name": "Settings Page",
                    "thumbnail_url": "https://s3-alpha.figma.com/thumbnails/def456.png",
                    "last_modified": "2026-02-28T15:30:00Z"
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.list_project_files"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.list_project_files");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.list_project_files",
            "input": { "project_id": "67890" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["name"], "Web App");
    let files = result["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["key"], "abc123");
    assert_eq!(files[0]["name"], "Homepage Design");
    assert!(
        files[0]["thumbnail_url"]
            .as_str()
            .unwrap()
            .starts_with("https://")
    );
    assert_eq!(files[1]["key"], "def456");

    // Verify provenance/taint metadata
    assert_eq!(result["provenance"]["source"], "figma.projects");
    assert_eq!(result["provenance"]["scope"], "project");
    let taint = result["taint"].as_array().unwrap();
    assert!(taint.contains(&json!("external_input")));
}

#[fcp_async_core::runtime::test]
async fn get_file_meta_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("figma.get_file_meta.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/meta123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "Dashboard Design",
            "document": { "id": "0:0", "type": "DOCUMENT", "children": [] },
            "lastModified": "2026-03-02T12:00:00Z",
            "version": "789012"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.get_file_meta"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.get_file_meta");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.get_file_meta",
            "input": { "file_key": "meta123" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["name"], "Dashboard Design");
    assert_eq!(result["lastModified"], "2026-03-02T12:00:00Z");
    assert_eq!(result["version"], "789012");

    // Should NOT include the full document tree
    assert!(result.get("document").is_none());

    // Verify provenance/taint metadata
    assert_eq!(result["provenance"]["source"], "figma.files");
    assert_eq!(result["provenance"]["scope"], "file");
    let taint = result["taint"].as_array().unwrap();
    assert!(taint.contains(&json!("external_input")));
}

#[fcp_async_core::runtime::test]
async fn list_team_projects_requires_capability() {
    let _ctx = AsyncTestContext::for_scenario("figma.list_team_projects.cap_required");

    let mut connector = FigmaConnector::new();
    // Handshake with only figma.get_file capability (not figma.list_team_projects)
    let key = setup_handshake(&mut connector, &["figma.get_file"]).await;

    let mock_server = MockServer::start().await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Generate token for figma.get_file, but try to call list_team_projects
    let token = generate_valid_token(&key, "figma.get_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.list_team_projects",
            "input": { "team_id": "12345" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject: wrong capability");
}

#[fcp_async_core::runtime::test]
async fn list_team_projects_missing_team_id() {
    let _ctx = AsyncTestContext::for_scenario("figma.list_team_projects.missing_team_id");

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.list_team_projects"]).await;

    let mock_server = MockServer::start().await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.list_team_projects");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.list_team_projects",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("team_id"));
        }
        e => panic!("Expected InvalidRequest about team_id, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn list_project_files_empty_result() {
    let _ctx = AsyncTestContext::for_scenario("figma.list_project_files.empty");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/projects/99999/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "Empty Project",
            "files": []
        })))
        .mount(&mock_server)
        .await;

    let mut connector = FigmaConnector::new();
    let key = setup_handshake(&mut connector, &["figma.list_project_files"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, "figma.list_project_files");
    let result = connector
        .handle_invoke(json!({
            "operation": "figma.list_project_files",
            "input": { "project_id": "99999" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["name"], "Empty Project");
    assert_eq!(result["files"].as_array().unwrap().len(), 0);
    // Still has provenance/taint even with empty results
    assert_eq!(result["provenance"]["source"], "figma.projects");
    let taint = result["taint"].as_array().unwrap();
    assert!(taint.contains(&json!("external_input")));
}

#[fcp_async_core::runtime::test]
async fn list_team_projects_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("figma.list_team_projects.unauthorized");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/teams/12345/projects"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "status": 403,
            "err": "Forbidden: insufficient permissions for team"
        })))
        .mount(&mock_server)
        .await;

    let client = FigmaClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 100, 200);

    let result = client.list_team_projects("12345").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_figma::error::FigmaError::Api { status, .. } => {
            assert_eq!(status, 403);
        }
        fcp_figma::error::FigmaError::Unauthorized => {}
        e => panic!("Expected Api(403) or Unauthorized, got: {e:?}"),
    }
}
