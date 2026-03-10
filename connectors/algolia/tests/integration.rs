//! Integration tests for the FCP `Algolia` connector.

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

use fcp_algolia::connector::AlgoliaConnector;

async fn setup_connector(mock_url: &str) -> AlgoliaConnector {
    let mut c = AlgoliaConnector::new();
    c.handle_configure(json!({
        "application_id": "TESTAPP",
        "api_key": "test-api-key",
        "base_url": mock_url,
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle ---------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = AlgoliaConnector::new();
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
    let mut c = AlgoliaConnector::new();
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
    assert_eq!(check["status"], "ok");
    assert!(
        check["details"]["provisioning"]["network_ok"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = AlgoliaConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = AlgoliaConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 4);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_not_handshaken() {
    let mut c = AlgoliaConnector::new();
    c.handle_configure(json!({
        "application_id": "APP",
        "api_key": "KEY",
        "base_url": "https://example.com",
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Search ------------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn search_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/indexes/products/query"))
        .and(header("X-Algolia-Application-Id", "TESTAPP"))
        .and(header("X-Algolia-API-Key", "test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": [
                {"objectID": "h1", "name": "Laptop", "_highlightResult": {}},
                {"objectID": "h2", "name": "Mouse", "_highlightResult": {}},
            ],
            "nbHits": 2,
            "page": 0,
            "hitsPerPage": 20,
            "query": "laptop",
            "processingTimeMS": 2
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "algolia.search",
            "input": {"index_name": "products", "query": "laptop"}
        }))
        .await
        .unwrap();
    assert_eq!(result["hits"].as_array().unwrap().len(), 2);
    assert_eq!(result["nbHits"], 2);
}

#[fcp_async_core::runtime::test]
async fn search_with_hits_per_page() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/indexes/products/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": [{"objectID": "h1"}],
            "nbHits": 1,
            "hitsPerPage": 5,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "algolia.search",
            "input": {"index_name": "products", "query": "test", "hits_per_page": 5}
        }))
        .await
        .unwrap();
    assert_eq!(result["hits"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn search_empty_results() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/indexes/products/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": [],
            "nbHits": 0,
            "query": "nonexistent",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "algolia.search",
            "input": {"index_name": "products", "query": "nonexistent"}
        }))
        .await
        .unwrap();
    assert!(result["hits"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn search_missing_index_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.search",
            "input": {"query": "test"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn search_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.search",
            "input": {"index_name": "products"}
        }))
        .await
        .is_err()
    );
}

// -- Indices List ------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn indices_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/indexes"))
        .and(header("X-Algolia-Application-Id", "TESTAPP"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"name": "products", "entries": 5000, "dataSize": 1048576},
                {"name": "articles", "entries": 200, "dataSize": 524288},
            ],
            "nbPages": 1
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "algolia.indices.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn indices_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "algolia.indices.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["items"].as_array().unwrap().is_empty());
}

// -- Records Get -------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn records_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/indexes/products/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "objectID": "abc123",
            "name": "Laptop Pro",
            "price": 1299,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "algolia.records.get",
            "input": {"index_name": "products", "object_id": "abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["objectID"], "abc123");
    assert_eq!(result["name"], "Laptop Pro");
}

#[fcp_async_core::runtime::test]
async fn records_get_missing_index_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.records.get",
            "input": {"object_id": "abc123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn records_get_missing_object_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.records.get",
            "input": {"index_name": "products"}
        }))
        .await
        .is_err()
    );
}

// -- Records Delete ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn records_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/indexes/products/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "deletedAt": "2025-06-15T12:00:00Z",
            "taskID": 12345
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "algolia.records.delete",
            "input": {"index_name": "products", "object_id": "abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["taskID"], 12345);
}

#[fcp_async_core::runtime::test]
async fn records_delete_missing_index_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.records.delete",
            "input": {"object_id": "abc123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn records_delete_missing_object_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.records.delete",
            "input": {"index_name": "products"}
        }))
        .await
        .is_err()
    );
}

// -- Error handling ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(
                json!({"message": "Invalid Application-Id or API key", "status": 401}),
            ),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.indices.list",
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
        .and(path("/indexes"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Forbidden", "status": 403})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.indices.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/indexes/.*"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Index not found", "status": 404})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.records.get",
            "input": {"index_name": "missing", "object_id": "x"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests", "status": 429}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.indices.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal server error", "status": 500})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.indices.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate ---------------------------------------------------

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_search() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "algolia.search"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_indices_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "algolia.indices.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_records_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "algolia.records.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_records_delete() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "algolia.records.delete"}))
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
        !c.handle_simulate(json!({"operation_id": "algolia.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters ----------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "algolia.indices.list",
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
        .and(path("/indexes"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal error", "status": 500})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "algolia.indices.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[fcp_async_core::runtime::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "algolia.indices.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

// -- Handshake response ------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn handshake_returns_capabilities() {
    let server = MockServer::start().await;
    let mut c = AlgoliaConnector::new();
    c.handle_configure(json!({
        "application_id": "APP",
        "api_key": "KEY",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.algolia");
    assert_eq!(hs["protocol_version"], "2.0");
    let caps = hs["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "algolia.search.read"));
    assert!(caps.iter().any(|c| c == "algolia.records.write"));
}

// -- Invoke before ready -----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = AlgoliaConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "algolia.indices.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}
