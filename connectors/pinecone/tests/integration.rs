//! Integration tests for the Pinecone connector.
//!
//! Covers the connector testing requirements (flywheel_connectors-gif.3):
//! - Request/response parsing (index CRUD, vector query/upsert/fetch/delete)
//! - Error taxonomy mapping (`PineconeError` → `FcpError`)
//! - Redaction (API keys not leaked in error messages)
//! - Dual-plane routing (control plane vs data plane)
//!
//! All tests are deterministic — no real API calls.

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_core::{CapabilityToken, FcpError};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_pinecone::{client::PineconeClient, connector::PineconeConnector, error::PineconeError};

// ============================================================================
// Helpers
// ============================================================================

fn capability_for_operation(operation: &str) -> &'static str {
    match operation {
        "pinecone.create_index" | "pinecone.delete_index" => "pinecone.indexes.write",
        "pinecone.query" | "pinecone.fetch" => "pinecone.vectors.read",
        "pinecone.upsert" | "pinecone.delete" => "pinecone.vectors.write",
        _ => "pinecone.indexes.read",
    }
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, operation: &str) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(
    connector: &mut PineconeConnector,
    operations: &[&str],
) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let capabilities: Vec<&str> = operations
        .iter()
        .map(|operation| capability_for_operation(operation))
        .collect();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": capabilities
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

async fn setup_configure(connector: &mut PineconeConnector, control_url: &str, data_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-key-xyz",
            "control_plane_url": control_url,
            "data_plane_url": data_url
        }))
        .await
        .expect("configure should succeed");
}

// ============================================================================
// Request/response parsing — control plane
// ============================================================================

/// `list_indexes` correctly parses the control plane response.
#[fcp_async_core::runtime::test]
async fn parse_list_indexes_response() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "indexes": [
                { "name": "idx-1", "dimension": 768, "metric": "cosine" },
                { "name": "idx-2", "dimension": 1536, "metric": "dotproduct", "host": "idx-2.svc.pinecone.io" }
            ]
        })))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_control_plane_url(&mock.uri());

    let resp = client.list_indexes().await.unwrap();
    assert_eq!(resp.indexes.len(), 2);
    assert_eq!(resp.indexes[0].name, "idx-1");
    assert_eq!(resp.indexes[0].dimension, 768);
    assert_eq!(
        resp.indexes[1].host.as_deref(),
        Some("idx-2.svc.pinecone.io")
    );
}

/// `describe_index` parses index details including status.
#[fcp_async_core::runtime::test]
async fn parse_describe_index_with_status() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/indexes/my-idx"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "my-idx",
            "dimension": 1536,
            "metric": "cosine",
            "host": "my-idx.svc.pinecone.io",
            "status": { "ready": true, "state": "Ready" },
            "spec": { "serverless": { "cloud": "aws", "region": "us-east-1" } }
        })))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_control_plane_url(&mock.uri());

    let idx = client.describe_index("my-idx").await.unwrap();
    assert_eq!(idx.name, "my-idx");
    assert_eq!(idx.metric, "cosine");
    assert!(idx.status.as_ref().unwrap().ready.unwrap());
    assert!(idx.spec.is_some());
}

// ============================================================================
// Request/response parsing — control plane (index CRUD)
// ============================================================================

/// `create_index` sends POST and parses the created index response.
#[fcp_async_core::runtime::test]
async fn parse_create_index_response() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "name": "new-idx",
            "dimension": 1536,
            "metric": "cosine",
            "host": "new-idx-abc123.svc.pinecone.io",
            "status": { "ready": false, "state": "Initializing" },
            "spec": { "serverless": { "cloud": "aws", "region": "us-east-1" } }
        })))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_control_plane_url(&mock.uri());

    let idx = client
        .create_index(
            "new-idx",
            1536,
            "cosine",
            Some(&json!({"serverless": {"cloud": "aws", "region": "us-east-1"}})),
        )
        .await
        .unwrap();
    assert_eq!(idx.name, "new-idx");
    assert_eq!(idx.dimension, 1536);
    assert_eq!(idx.metric, "cosine");
    assert_eq!(idx.host.as_deref(), Some("new-idx-abc123.svc.pinecone.io"));
    assert!(!idx.status.as_ref().unwrap().ready.unwrap());
}

/// `delete_index` sends DELETE and returns success on 202.
#[fcp_async_core::runtime::test]
async fn parse_delete_index_response() {
    let mock = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/indexes/old-idx"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_control_plane_url(&mock.uri());

    let result = client.delete_index("old-idx").await;
    assert!(result.is_ok());
}

/// `delete_index` returns 404 for non-existent index.
#[fcp_async_core::runtime::test]
async fn delete_index_not_found() {
    let mock = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/indexes/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "Index not found: missing"
        })))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_control_plane_url(&mock.uri())
        .with_retry_config(0);

    let err = client.delete_index("missing").await.unwrap_err();
    assert!(matches!(
        err,
        PineconeError::Api {
            status_code: Some(404),
            ..
        }
    ));
}

// ============================================================================
// Request/response parsing — data plane
// ============================================================================

/// `query` with vector input parses matches with scores and metadata.
#[fcp_async_core::runtime::test]
async fn parse_query_with_metadata() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "matches": [
                { "id": "v1", "score": 0.99, "metadata": { "source": "doc-a" } },
                { "id": "v2", "score": 0.87, "metadata": { "source": "doc-b" } },
                { "id": "v3", "score": 0.42 }
            ],
            "namespace": "ns1"
        })))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_data_plane_url(&mock.uri());

    let resp = client
        .query(
            Some(&[0.1, 0.2, 0.3]),
            None,
            5,
            Some("ns1"),
            None,
            true,
            false,
        )
        .await
        .unwrap();

    assert_eq!(resp.matches.len(), 3);
    assert_eq!(resp.namespace.as_deref(), Some("ns1"));
    assert!(
        resp.matches[2].metadata.is_none(),
        "third match has no metadata"
    );
}

/// `upsert` returns correct count.
#[fcp_async_core::runtime::test]
async fn parse_upsert_response() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/vectors/upsert"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "upserted_count": 5
        })))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_data_plane_url(&mock.uri());

    let vectors = vec![fcp_pinecone::types::Vector {
        id: "v1".into(),
        values: Some(vec![0.1, 0.2]),
        metadata: Some(json!({"key": "val"})),
        sparse_values: None,
    }];
    let resp = client.upsert(&vectors, None).await.unwrap();
    assert_eq!(resp.upserted_count, 5);
}

/// `fetch` returns vectors keyed by ID.
#[fcp_async_core::runtime::test]
async fn parse_fetch_response() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/vectors/fetch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vectors": {
                "v1": { "id": "v1", "values": [0.1, 0.2, 0.3] },
                "v2": { "id": "v2", "values": [0.4, 0.5, 0.6] }
            },
            "namespace": ""
        })))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_data_plane_url(&mock.uri());

    let ids = vec!["v1".to_string(), "v2".to_string()];
    let resp = client.fetch(&ids, None).await.unwrap();
    assert_eq!(resp.vectors.len(), 2);
    let v1 = &resp.vectors["v1"];
    assert_eq!(v1.values.as_ref().unwrap().len(), 3);
}

/// `delete` with empty body returns success.
#[fcp_async_core::runtime::test]
async fn parse_delete_empty_response() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/vectors/delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_data_plane_url(&mock.uri());

    let result = client.delete(None, true, Some("ns"), None).await;
    assert!(result.is_ok());
}

// ============================================================================
// Error taxonomy mapping tests
// ============================================================================

/// 401 Unauthorized maps to `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("bad-key")
        .unwrap()
        .with_control_plane_url(&mock.uri())
        .with_retry_config(0);

    let err = client.list_indexes().await.unwrap_err();
    assert!(matches!(
        err,
        PineconeError::Api {
            status_code: Some(401),
            ..
        }
    ));
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { code: 2001, .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 403 Forbidden also maps to `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_403_maps_to_unauthorized() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("bad-key")
        .unwrap()
        .with_control_plane_url(&mock.uri())
        .with_retry_config(0);

    let err = client.list_indexes().await.unwrap_err();
    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, FcpError::Unauthorized { .. }));
}

/// 404 Not Found maps to `FcpError::ResourceNotFound`.
#[fcp_async_core::runtime::test]
async fn error_404_maps_to_resource_not_found() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/indexes/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not found"))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_control_plane_url(&mock.uri())
        .with_retry_config(0);

    let err = client.describe_index("missing").await.unwrap_err();
    assert!(!err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::ResourceNotFound { .. }),
        "expected ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[test]
fn error_429_rate_limit_maps_correctly() {
    let err = PineconeError::RateLimit {
        retry_after_ms: 30_000,
    };
    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::RateLimited {
                retry_after_ms: 30_000,
                ..
            }
        ),
        "expected RateLimited with 30s, got: {fcp_err:?}"
    );
}

/// 500 Server Error is retryable and maps to `FcpError::External`.
#[fcp_async_core::runtime::test]
async fn error_500_maps_to_external_retryable() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/query"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock)
        .await;

    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_data_plane_url(&mock.uri())
        .with_retry_config(0);

    let err = client
        .query(Some(&[0.1]), None, 1, None, None, false, false)
        .await
        .unwrap_err();

    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::External {
                retryable: true,
                status_code: Some(500),
                ..
            }
        ),
        "expected External(500, retryable), got: {fcp_err:?}"
    );
}

/// `InvalidConfig` maps to `FcpError::InvalidRequest`.
#[test]
fn error_invalid_config_maps_to_invalid_request() {
    let err = PineconeError::InvalidConfig("missing api_key".into());
    assert!(!err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::InvalidRequest { code: 1003, .. }),
        "expected InvalidRequest, got: {fcp_err:?}"
    );
}

/// Data plane URL not configured triggers `InvalidConfig`.
#[fcp_async_core::runtime::test]
async fn error_data_plane_not_configured() {
    let client = PineconeClient::new("test-key")
        .unwrap()
        .with_control_plane_url("http://localhost:1");
    // No data_plane_url set — data plane operations should fail
    let err = client
        .query(Some(&[0.1]), None, 1, None, None, false, false)
        .await
        .unwrap_err();
    assert!(matches!(err, PineconeError::InvalidConfig(..)));
}

// ============================================================================
// Redaction tests
// ============================================================================

/// API key should not appear in error messages from the client.
#[fcp_async_core::runtime::test]
async fn redaction_api_key_not_in_error_message() {
    let mock = MockServer::start().await;
    let secret_key = "pc-SuperSecretPineconeKeyThatShouldNotLeak123";

    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&mock)
        .await;

    let client = PineconeClient::new(secret_key)
        .unwrap()
        .with_control_plane_url(&mock.uri())
        .with_retry_config(0);

    let err = client.list_indexes().await.unwrap_err();

    let err_string = format!("{err:?}");
    assert!(
        !err_string.contains(secret_key),
        "API key should not appear in error debug output"
    );

    let fcp_err = err.to_fcp_error();
    let fcp_err_string = format!("{fcp_err:?}");
    assert!(
        !fcp_err_string.contains(secret_key),
        "API key should not appear in FCP error debug output"
    );
}

/// API key should not appear in connector invoke errors.
#[fcp_async_core::runtime::test]
async fn redaction_api_key_not_in_invoke_error() {
    let ctrl = MockServer::start().await;
    let data = MockServer::start().await;
    let secret_key = "pc-AnotherSecretKeyThatMustNotLeak456";

    Mock::given(method("POST"))
        .and(path("/query"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": "Invalid query parameters"
        })))
        .mount(&data)
        .await;

    let mut connector = PineconeConnector::new();
    connector
        .handle_configure(json!({
            "api_key": secret_key,
            "control_plane_url": ctrl.uri(),
            "data_plane_url": data.uri()
        }))
        .await
        .unwrap();

    let signing_key = setup_handshake(&mut connector, &["pinecone.query"]).await;
    let token = generate_valid_token(&signing_key, "pinecone.query");

    let result = connector
        .handle_invoke(json!({
            "operation": "pinecone.query",
            "input": {
                "index_name": "test-idx",
                "vector": [0.1, 0.2],
                "top_k": 5
            },
            "capability_token": token
        }))
        .await;

    if let Err(err) = result {
        let err_string = format!("{err:?}");
        assert!(
            !err_string.contains(secret_key),
            "API key should not appear in invoke error: {err_string}"
        );
    }
}

/// API key should not appear in configure errors.
#[fcp_async_core::runtime::test]
async fn redaction_api_key_not_in_configure_error() {
    let mut connector = PineconeConnector::new();
    let secret_key = "pc-ThirdSecretKeyMustNotLeak789";

    // Configure with unreachable URL — configure succeeds (lazy connect)
    let result = connector
        .handle_configure(json!({
            "api_key": secret_key,
            "control_plane_url": "http://127.0.0.1:1",
            "data_plane_url": "http://127.0.0.1:1"
        }))
        .await;

    if let Err(err) = result {
        let err_string = format!("{err:?}");
        assert!(
            !err_string.contains(secret_key),
            "API key should not appear in configure error"
        );
    }
}

// ============================================================================
// Connector-level integration (invoke dispatch)
// ============================================================================

/// `invoke` dispatches `pinecone.query` through capability verification.
#[fcp_async_core::runtime::test]
async fn invoke_query_through_connector() {
    let ctrl = MockServer::start().await;
    let data = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "matches": [
                { "id": "v1", "score": 0.95 }
            ],
            "namespace": ""
        })))
        .mount(&data)
        .await;

    let mut connector = PineconeConnector::new();
    setup_configure(&mut connector, &ctrl.uri(), &data.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["pinecone.query"]).await;
    let token = generate_valid_token(&signing_key, "pinecone.query");

    let result = connector
        .handle_invoke(json!({
            "operation": "pinecone.query",
            "input": {
                "index_name": "my-idx",
                "vector": [0.1, 0.2, 0.3],
                "top_k": 10
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["matches"][0]["id"], "v1");
}

/// `invoke` dispatches `pinecone.upsert` and returns upserted count.
#[fcp_async_core::runtime::test]
async fn invoke_upsert_through_connector() {
    let ctrl = MockServer::start().await;
    let data = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/vectors/upsert"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "upserted_count": 2
        })))
        .mount(&data)
        .await;

    let mut connector = PineconeConnector::new();
    setup_configure(&mut connector, &ctrl.uri(), &data.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["pinecone.upsert"]).await;
    let token = generate_valid_token(&signing_key, "pinecone.upsert");

    let result = connector
        .handle_invoke(json!({
            "operation": "pinecone.upsert",
            "input": {
                "index_name": "my-idx",
                "vectors": [
                    { "id": "v1", "values": [0.1, 0.2, 0.3] },
                    { "id": "v2", "values": [0.4, 0.5, 0.6] }
                ]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["upserted_count"], 2);
}

/// `invoke` dispatches `pinecone.create_index` and returns the created index.
#[fcp_async_core::runtime::test]
async fn invoke_create_index_through_connector() {
    let ctrl = MockServer::start().await;
    let data = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "name": "test-idx",
            "dimension": 768,
            "metric": "dotproduct",
            "host": "test-idx-abc.svc.pinecone.io",
            "status": { "ready": false, "state": "Initializing" }
        })))
        .mount(&ctrl)
        .await;

    let mut connector = PineconeConnector::new();
    setup_configure(&mut connector, &ctrl.uri(), &data.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["pinecone.create_index"]).await;
    let token = generate_valid_token(&signing_key, "pinecone.create_index");

    let result = connector
        .handle_invoke(json!({
            "operation": "pinecone.create_index",
            "input": {
                "name": "test-idx",
                "dimension": 768,
                "metric": "dotproduct"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["name"], "test-idx");
    assert_eq!(result["dimension"], 768);
    assert_eq!(result["metric"], "dotproduct");
}

/// `invoke` dispatches `pinecone.delete_index` and returns success.
#[fcp_async_core::runtime::test]
async fn invoke_delete_index_through_connector() {
    let ctrl = MockServer::start().await;
    let data = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/indexes/doomed-idx"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&ctrl)
        .await;

    let mut connector = PineconeConnector::new();
    setup_configure(&mut connector, &ctrl.uri(), &data.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["pinecone.delete_index"]).await;
    let token = generate_valid_token(&signing_key, "pinecone.delete_index");

    let result = connector
        .handle_invoke(json!({
            "operation": "pinecone.delete_index",
            "input": { "index_name": "doomed-idx" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["deleted"], true);
    assert_eq!(result["index_name"], "doomed-idx");
}

/// Invoking `pinecone.create_index` with wrong capability token is rejected.
#[fcp_async_core::runtime::test]
async fn invoke_create_index_wrong_cap_rejected() {
    let ctrl = MockServer::start().await;
    let data = MockServer::start().await;

    let mut connector = PineconeConnector::new();
    setup_configure(&mut connector, &ctrl.uri(), &data.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["pinecone.list_indexes"]).await;
    // Token is for list_indexes, not create_index
    let token = generate_valid_token(&signing_key, "pinecone.list_indexes");

    let result = connector
        .handle_invoke(json!({
            "operation": "pinecone.create_index",
            "input": { "name": "test-idx", "dimension": 768 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "Should reject mismatched capability");
}

/// `invoke` dispatches `pinecone.list_indexes` via control plane.
#[fcp_async_core::runtime::test]
async fn invoke_list_indexes_through_connector() {
    let ctrl = MockServer::start().await;
    let data = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "indexes": [
                { "name": "idx-a", "dimension": 512, "metric": "euclidean" }
            ]
        })))
        .mount(&ctrl)
        .await;

    let mut connector = PineconeConnector::new();
    setup_configure(&mut connector, &ctrl.uri(), &data.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["pinecone.list_indexes"]).await;
    let token = generate_valid_token(&signing_key, "pinecone.list_indexes");

    let result = connector
        .handle_invoke(json!({
            "operation": "pinecone.list_indexes",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["indexes"][0]["name"], "idx-a");
}
