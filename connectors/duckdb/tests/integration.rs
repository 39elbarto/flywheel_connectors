//! Integration tests for the FCP `DuckDB` `MotherDuck` connector.

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
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_duckdb::connector::DuckDbConnector;

async fn setup_connector(mock_url: &str) -> DuckDbConnector {
    let mut c = DuckDbConnector::new();
    c.handle_configure(json!({ "service_token": "sk_test_token_123", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = DuckDbConnector::new();
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
    let mut c = DuckDbConnector::new();
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 9);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_degraded() {
    let server = MockServer::start().await;
    let mut c = DuckDbConnector::new();
    c.handle_configure(json!({ "service_token": "sk_test", "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Query Execute --

#[fcp_async_core::runtime::test]
async fn query_execute() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sql"))
        .and(header("Authorization", "Bearer sk_test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "columns": [{"name": "count", "type_name": "BIGINT"}],
            "data": [[42]],
            "row_count": 1,
            "query_id": "q-abc123",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.query.execute",
            "input": {"sql": "SELECT count(*) FROM sales", "database": "analytics"}
        }))
        .await
        .unwrap();
    assert_eq!(result["query_id"], "q-abc123");
}

#[fcp_async_core::runtime::test]
async fn query_execute_missing_sql() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.query.execute",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Databases List --

#[fcp_async_core::runtime::test]
async fn databases_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases"))
        .and(header("Authorization", "Bearer sk_test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "databases": [
                {"name": "analytics", "size_bytes": 1048576},
                {"name": "staging", "size_bytes": 2097152},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.databases.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["databases"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn databases_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "databases": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.databases.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["databases"].as_array().unwrap().is_empty());
}

// -- Databases Get --

#[fcp_async_core::runtime::test]
async fn databases_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases/analytics"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "analytics",
            "size_bytes": 1048576,
            "created_at": "2025-06-15T10:30:00Z",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.databases.get",
            "input": {"database": "analytics"}
        }))
        .await
        .unwrap();
    assert_eq!(result["database"]["name"], "analytics");
}

#[fcp_async_core::runtime::test]
async fn databases_get_missing_database() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.databases.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tables List --

#[fcp_async_core::runtime::test]
async fn tables_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases/analytics/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {"name": "sales", "column_count": 8, "row_count": 50000},
                {"name": "customers", "column_count": 5, "row_count": 1200},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.tables.list",
            "input": {"database": "analytics"}
        }))
        .await
        .unwrap();
    assert_eq!(result["tables"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn tables_list_missing_database() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.tables.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tables Get --

#[fcp_async_core::runtime::test]
async fn tables_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases/analytics/tables/sales"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "sales",
            "column_count": 8,
            "row_count": 50000,
            "schema": "main",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.tables.get",
            "input": {"database": "analytics", "table": "sales"}
        }))
        .await
        .unwrap();
    assert_eq!(result["table"]["name"], "sales");
}

#[fcp_async_core::runtime::test]
async fn tables_get_missing_database() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.tables.get",
            "input": {"table": "sales"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn tables_get_missing_table() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.tables.get",
            "input": {"database": "analytics"}
        }))
        .await
        .is_err()
    );
}

// -- Schemas List --

#[fcp_async_core::runtime::test]
async fn schemas_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases/analytics/schemas"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "schemas": [
                {"name": "main"},
                {"name": "staging"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.schemas.list",
            "input": {"database": "analytics"}
        }))
        .await
        .unwrap();
    assert_eq!(result["schemas"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn schemas_list_missing_database() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.schemas.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Queries Status --

#[fcp_async_core::runtime::test]
async fn queries_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/queries/q-abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "query_id": "q-abc123",
            "status": "completed",
            "result": {"row_count": 42},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.queries.status",
            "input": {"query_id": "q-abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["status"]["status"], "completed");
}

#[fcp_async_core::runtime::test]
async fn queries_status_missing_query_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.queries.status",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Shares List --

#[fcp_async_core::runtime::test]
async fn shares_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shares"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "shares": [
                {"name": "team_share", "database": "analytics"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.shares.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["shares"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn shares_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shares"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "shares": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.shares.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["shares"].as_array().unwrap().is_empty());
}

// -- Shares Create --

#[fcp_async_core::runtime::test]
async fn shares_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/shares"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "team_analytics",
            "database": "analytics",
            "created_at": "2025-07-01T08:00:00Z",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "duckdb.shares.create",
            "input": {"name": "team_analytics", "database": "analytics"}
        }))
        .await
        .unwrap();
    assert_eq!(result["share"]["name"], "team_analytics");
}

#[fcp_async_core::runtime::test]
async fn shares_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.shares.create",
            "input": {"database": "analytics"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn shares_create_missing_database() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.shares.create",
            "input": {"name": "team_analytics"}
        }))
        .await
        .is_err()
    );
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"error": "unauthorized", "message": "Invalid token"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.databases.list",
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
        .and(path("/databases"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"error": "forbidden", "message": "Access denied"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.databases.list",
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
        .and(path("/databases/nonexistent"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"error": "not_found", "message": "Database not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.databases.get",
            "input": {"database": "nonexistent"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"error": "rate_limit", "message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.databases.list",
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
        .and(path("/databases"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.databases.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "duckdb.nope",
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
        c.handle_simulate(json!({"operation_id": "duckdb.databases.list"}))
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
        !c.handle_simulate(json!({"operation_id": "duckdb.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_all_operations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let ops = [
        "duckdb.query.execute",
        "duckdb.databases.list",
        "duckdb.databases.get",
        "duckdb.tables.list",
        "duckdb.tables.get",
        "duckdb.schemas.list",
        "duckdb.queries.status",
        "duckdb.shares.list",
        "duckdb.shares.create",
    ];
    for op in &ops {
        let r = c
            .handle_simulate(json!({"operation_id": op}))
            .await
            .unwrap();
        assert!(
            r["allowed"].as_bool().unwrap(),
            "expected {op} to be allowed"
        );
    }
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"databases": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "duckdb.databases.list",
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
        .and(path("/databases"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "duckdb.databases.list",
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
        .and(path("/databases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"databases": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "duckdb.databases.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}
