//! Integration tests for the FCP Elasticsearch connector.
//!
//! Uses wiremock to simulate Elasticsearch API responses.

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

use fcp_elasticsearch::client::{ElasticsearchAuth, ElasticsearchClient};
use fcp_elasticsearch::connector::ElasticsearchConnector;

// ── Helper ───────────────────────────────────────────────────────────

/// Configure and handshake a connector against a mock server.
async fn setup_connector(mock_url: &str) -> ElasticsearchConnector {
    let mut connector = ElasticsearchConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "test-api-key",
            "base_url": mock_url,
        }))
        .await
        .unwrap();
    connector
        .handle_handshake(json!({"session_id": "test-session"}))
        .await
        .unwrap();
    connector
}

/// Build a test client pointing at a mock server.
fn test_client(mock_url: &str) -> ElasticsearchClient {
    ElasticsearchClient::with_client(
        reqwest::Client::new(),
        ElasticsearchAuth::ApiKey("test-key".into()),
        mock_url,
    )
}

// ── Lifecycle tests ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = ElasticsearchConnector::new();
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
    assert!(!health["configured"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_and_health() {
    let server = MockServer::start().await;
    let mut c = ElasticsearchConnector::new();
    c.handle_configure(json!({
        "api_key": "test-key",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();

    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "degraded");
    assert!(health["configured"].as_bool().unwrap());
    assert!(!health["handshaken"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full_handshake() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;

    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "healthy");
    assert!(health["handshaken"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = ElasticsearchConnector::new();
    let result = c.handle_handshake(json!({})).await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_invoke_before_handshake_fails() {
    let server = MockServer::start().await;
    let mut c = ElasticsearchConnector::new();
    c.handle_configure(json!({
        "api_key": "test-key",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();

    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.search",
            "input": {"index": "test"}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;

    c.handle_shutdown(json!({})).await.unwrap();
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
    assert_eq!(check["connector_id"], "fcp.elasticsearch");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let doctor = c.handle_doctor().await.unwrap();
    assert_eq!(doctor["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 7);
    assert_eq!(ops[0]["id"], "elasticsearch.search");
}

// ── Search ───────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn search_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/logs/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "took": 5,
            "timed_out": false,
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [{"_index": "logs", "_id": "1", "_source": {"msg": "hello"}}]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.search",
            "input": {"index": "logs", "query": {"match_all": {}}, "size": 10}
        }))
        .await
        .unwrap();

    assert_eq!(result["took"], 5);
    assert_eq!(result["hits"]["hits"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn search_missing_index_fails() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.search",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Get Document ─────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn get_document_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/products/_doc/abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "_index": "products",
            "_id": "abc",
            "_version": 1,
            "found": true,
            "_source": {"name": "Widget", "price": 9.99}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.get_document",
            "input": {"index": "products", "id": "abc"}
        }))
        .await
        .unwrap();

    assert!(result["found"].as_bool().unwrap());
    assert_eq!(result["_source"]["name"], "Widget");
}

#[fcp_async_core::runtime::test]
async fn get_document_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/products/_doc/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "type": "resource_not_found_exception",
                "reason": "Document not found"
            },
            "status": 404
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.get_document",
            "input": {"index": "products", "id": "missing"}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn get_document_missing_fields() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;

    // Missing index
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.get_document",
            "input": {"id": "abc"}
        }))
        .await;
    assert!(result.is_err());

    // Missing id
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.get_document",
            "input": {"index": "products"}
        }))
        .await;
    assert!(result.is_err());
}

// ── Index Document ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn index_document_with_id() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/products/_doc/1"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "_index": "products",
            "_id": "1",
            "_version": 1,
            "result": "created"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.index_document",
            "input": {
                "index": "products",
                "id": "1",
                "document": {"name": "Widget", "price": 9.99}
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["result"], "created");
}

#[fcp_async_core::runtime::test]
async fn index_document_auto_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/products/_doc"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "_index": "products",
            "_id": "auto-generated-id",
            "_version": 1,
            "result": "created"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.index_document",
            "input": {
                "index": "products",
                "document": {"name": "Gadget"}
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["_id"], "auto-generated-id");
}

#[fcp_async_core::runtime::test]
async fn index_document_missing_document_field() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.index_document",
            "input": {"index": "products", "id": "1"}
        }))
        .await;
    assert!(result.is_err());
}

// ── Bulk ─────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn bulk_operations() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_bulk"))
        .and(header("Content-Type", "application/x-ndjson"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "took": 30,
            "errors": false,
            "items": [
                {"index": {"_index": "products", "_id": "1", "status": 201, "result": "created"}}
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.bulk",
            "input": {
                "operations": [
                    {"index": {"_index": "products", "_id": "1"}},
                    {"name": "Widget"}
                ]
            }
        }))
        .await
        .unwrap();

    assert!(!result["errors"].as_bool().unwrap());
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn bulk_missing_operations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.bulk",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Indices List ─────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn indices_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/_cat/indices/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"health": "green", "status": "open", "index": "logs-2026.03", "docs.count": "1000"},
            {"health": "yellow", "status": "open", "index": "logs-2026.02", "docs.count": "5000"}
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.indices.list",
            "input": {"pattern": "logs-*"}
        }))
        .await
        .unwrap();

    assert_eq!(result["indices"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn indices_list_no_pattern() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_cat/indices/*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.indices.list",
            "input": {}
        }))
        .await
        .unwrap();

    assert!(result["indices"].as_array().unwrap().is_empty());
}

// ── Indices Delete ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn indices_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/old-logs-2024"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.indices.delete",
            "input": {"index": "old-logs-2024"}
        }))
        .await
        .unwrap();

    assert!(result["acknowledged"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn indices_delete_missing_index() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.indices.delete",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Cluster Health ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn cluster_health() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_cluster/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cluster_name": "my-cluster",
            "status": "green",
            "number_of_nodes": 3,
            "active_primary_shards": 10,
            "active_shards": 20
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.cluster.health",
            "input": {}
        }))
        .await
        .unwrap();

    assert_eq!(result["cluster_name"], "my-cluster");
    assert_eq!(result["status"], "green");
}

// ── Error handling ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_401_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_cluster/health"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {"type": "security_exception", "reason": "missing authentication"},
            "status": 401
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.cluster.health",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_403_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_cluster/health"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {"type": "security_exception", "reason": "action not allowed"},
            "status": 403
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.cluster.health",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_404_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/missing/_doc/x"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {"type": "index_not_found_exception", "reason": "no such index [missing]"},
            "status": 404
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.get_document",
            "input": {"index": "missing", "id": "x"}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_429_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/logs/_search"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "error": {"type": "circuit_breaking_exception", "reason": "too many requests"},
                    "status": 429
                }))
                .insert_header("retry-after", "5"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.search",
            "input": {"index": "logs"}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_500_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_cluster/health"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": {"type": "internal_server_error", "reason": "something broke"},
            "status": 500
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.cluster.health",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Unknown operation ────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.nonexistent",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// ── Simulate ─────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn simulate_known_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_simulate(json!({
            "operation_id": "elasticsearch.search"
        }))
        .await
        .unwrap();
    assert!(result["allowed"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_simulate(json!({
            "operation_id": "elasticsearch.nonexistent"
        }))
        .await
        .unwrap();
    assert!(!result["allowed"].as_bool().unwrap());
}

// ── Client auth header ──────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn client_sends_api_key_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_cluster/health"))
        .and(header("Authorization", "ApiKey test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cluster_name": "test",
            "status": "green"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server.uri());
    let result = client.cluster_health().await.unwrap();
    assert_eq!(result["status"], "green");
}

// ── Request/error counters ──────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/_cluster/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cluster_name": "test",
            "status": "green"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/missing/_doc/x"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {"type": "not_found", "reason": "not found"},
            "status": 404
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;

    // Successful request
    c.handle_invoke(json!({
        "operation_id": "elasticsearch.cluster.health",
        "input": {}
    }))
    .await
    .unwrap();

    let health = c.handle_health().await.unwrap();
    assert_eq!(health["requests"], 1);
    assert_eq!(health["errors"], 0);

    // Failed request
    let _ = c
        .handle_invoke(json!({
            "operation_id": "elasticsearch.get_document",
            "input": {"index": "missing", "id": "x"}
        }))
        .await;

    let health = c.handle_health().await.unwrap();
    assert_eq!(health["requests"], 2);
    assert_eq!(health["errors"], 1);
}
