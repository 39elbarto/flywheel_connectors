//! Qdrant connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the Qdrant REST API.
//! No real API calls. Covers:
//! - Happy-path operations (list_collections, search, upsert_points, collection_info)
//! - Error taxonomy (401/404/429 -> FcpError mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_qdrant::connector::QdrantConnector;

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

async fn setup_configure(connector: &mut QdrantConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-qdrant-key",
            "cluster_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_handshake(connector: &mut QdrantConnector, caps: &[&str]) -> Ed25519SigningKey {
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

async fn full_setup(
    connector: &mut QdrantConnector,
    caps: &[&str],
) -> (MockServer, Ed25519SigningKey) {
    let mock_server = MockServer::start().await;
    setup_configure(connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(connector, caps).await;
    (mock_server, signing_key)
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn list_collections_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.list_collections.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.list_collections"]).await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "collections": [
                    { "name": "embeddings" },
                    { "name": "documents" }
                ]
            },
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "qdrant.list_collections");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("list_collections invoke should succeed");

    let collections = result["collections"].as_array().expect("collections array");
    assert_eq!(collections.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn search_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.search.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.search"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                { "id": 1, "version": 0, "score": 0.95, "payload": { "text": "hello" } },
                { "id": 2, "version": 0, "score": 0.88, "payload": { "text": "world" } }
            ],
            "status": "ok",
            "time": 0.005
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "qdrant.search");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.search",
            "input": {
                "collection_name": "embeddings",
                "vector": [0.1, 0.2, 0.3],
                "limit": 5
            },
            "capability_token": token
        }))
        .await
        .expect("search invoke should succeed");

    let results = result["result"].as_array().expect("result array");
    assert_eq!(results.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn upsert_points_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.upsert_points.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.upsert_points"]).await;

    Mock::given(method("PUT"))
        .and(path("/collections/embeddings/points"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "operation_id": 0, "status": "completed" },
            "status": "ok",
            "time": 0.01
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "qdrant.upsert_points");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.upsert_points",
            "input": {
                "collection_name": "embeddings",
                "points": [
                    { "id": 1, "vector": [0.1, 0.2, 0.3], "payload": { "text": "hello" } }
                ]
            },
            "capability_token": token
        }))
        .await
        .expect("upsert_points invoke should succeed");

    assert_eq!(result["status"], "completed");
}

#[fcp_async_core::runtime::test]
async fn collection_info_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.collection_info.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.collection_info"]).await;

    Mock::given(method("GET"))
        .and(path("/collections/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "status": "green",
                "optimizer_status": "ok",
                "vectors_count": 1000,
                "points_count": 1000,
                "segments_count": 2,
                "config": {
                    "params": {
                        "vectors": { "size": 3, "distance": "Cosine" }
                    }
                }
            },
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "qdrant.collection_info");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.collection_info",
            "input": { "collection_name": "embeddings" },
            "capability_token": token
        }))
        .await
        .expect("collection_info invoke should succeed");

    assert!(result.get("result").is_some());
}

// ============================================================================
// Error taxonomy tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn unauthorized_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.error.unauthorized");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.list_collections"]).await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "status": { "error": "Invalid API key" },
            "time": 0.0
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "qdrant.list_collections");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn not_found_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.error.not_found");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.collection_info"]).await;

    Mock::given(method("GET"))
        .and(path("/collections/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "status": { "error": "Not found: Collection `nonexistent` doesn't exist!" },
            "time": 0.0
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "qdrant.collection_info");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.collection_info",
            "input": { "collection_name": "nonexistent" },
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
    let _ctx = AsyncTestContext::for_scenario("qdrant.deny.not_configured");
    let connector = QdrantConnector::new();

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(&signing_key, "qdrant.list_collections");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_with_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.deny.wrong_capability");
    let mut connector = QdrantConnector::new();
    // Handshake grants search but we invoke list_collections
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.search"]).await;
    let token = generate_valid_token(&signing_key, "qdrant.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_denied() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.deny.unknown_operation");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "qdrant.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.nonexistent",
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
    let _ctx = AsyncTestContext::for_scenario("qdrant.lifecycle.health_not_configured");
    let connector = QdrantConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn health_configured() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.lifecycle.health_configured");
    let mock_server = MockServer::start().await;
    let mut connector = QdrantConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.lifecycle.introspect");
    let connector = QdrantConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    assert!(op_ids.contains(&"qdrant.list_collections"));
    assert!(op_ids.contains(&"qdrant.search"));
    assert!(op_ids.contains(&"qdrant.upsert_points"));
    assert!(op_ids.contains(&"qdrant.delete_points"));
    assert_eq!(ops.len(), 12);
}

#[fcp_async_core::runtime::test]
async fn shutdown_succeeds() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.lifecycle.shutdown");
    let connector = QdrantConnector::new();
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
async fn search_missing_collection_name_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.search_missing_collection");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.search"]).await;
    let token = generate_valid_token(&signing_key, "qdrant.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.search",
            "input": { "vector": [0.1, 0.2, 0.3], "limit": 5 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn upsert_points_missing_points_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.upsert_missing_points");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.upsert_points"]).await;
    let token = generate_valid_token(&signing_key, "qdrant.upsert_points");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.upsert_points",
            "input": { "collection_name": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("points"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}
