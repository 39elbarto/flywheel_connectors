//! Integration tests for the FCP `Snowflake` connector.

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
use wiremock::matchers::{bearer_token, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_snowflake::connector::SnowflakeConnector;

async fn setup_connector(mock_url: &str) -> SnowflakeConnector {
    let mut c = SnowflakeConnector::new();
    c.handle_configure(json!({
        "access_token": "test-token",
        "account_identifier": "testaccount",
        "base_url": mock_url,
        "warehouse": "COMPUTE_WH",
        "database": "ANALYTICS",
        "schema": "PUBLIC",
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
    let c = SnowflakeConnector::new();
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
    let mut c = SnowflakeConnector::new();
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
async fn lifecycle_self_check_unconfigured() {
    let c = SnowflakeConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = SnowflakeConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_not_handshaken() {
    let mut c = SnowflakeConnector::new();
    c.handle_configure(json!({
        "access_token": "TOKEN",
        "account_identifier": "ACC",
        "base_url": "https://example.com",
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Databases List ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn databases_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases"))
        .and(bearer_token("test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"name": "ANALYTICS", "created_on": "2025-01-01T00:00:00Z", "owner": "SYSADMIN"},
            {"name": "DEV", "created_on": "2025-02-01T00:00:00Z", "owner": "ADMIN"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.databases.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result.get("databases").is_some());
}

#[fcp_async_core::runtime::test]
async fn databases_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.databases.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result.get("databases").is_some());
}

// -- Warehouses List ---------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn warehouses_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/warehouses"))
        .and(bearer_token("test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"name": "COMPUTE_WH", "state": "STARTED", "size": "X-SMALL"},
            {"name": "ETL_WH", "state": "SUSPENDED", "size": "MEDIUM"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.warehouses.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result.get("warehouses").is_some());
}

#[fcp_async_core::runtime::test]
async fn warehouses_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/warehouses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.warehouses.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result.get("warehouses").is_some());
}

// -- SQL Query ---------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn sql_query_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/statements"))
        .and(bearer_token("test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "statementHandle": "01abc-def",
            "message": "Statement executed successfully.",
            "code": "000000",
            "resultSetMetaData": {
                "numRows": 2,
                "rowType": [
                    {"name": "ID", "type": "fixed"},
                    {"name": "NAME", "type": "text"}
                ]
            },
            "data": [
                ["1", "Alice"],
                ["2", "Bob"]
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.sql.query",
            "input": {
                "statement": "SELECT * FROM users LIMIT 10",
                "warehouse": "COMPUTE_WH",
                "database": "ANALYTICS"
            }
        }))
        .await
        .unwrap();
    assert!(result.get("data").is_some());
    assert!(result.get("metadata").is_some());
    assert!(result.get("statement_handle").is_some());
    let data = result["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn sql_query_empty_results() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/statements"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "statementHandle": "01xyz",
            "message": "Statement executed successfully.",
            "code": "000000",
            "resultSetMetaData": {
                "numRows": 0,
                "rowType": [
                    {"name": "ID", "type": "fixed"}
                ]
            },
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.sql.query",
            "input": {"statement": "SELECT * FROM empty_table"}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn sql_query_missing_statement() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "snowflake.sql.query",
            "input": {"warehouse": "WH"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn sql_query_with_schema() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/statements"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "statementHandle": "handle-schema",
            "code": "000000",
            "data": [["val1"]],
            "resultSetMetaData": {"numRows": 1, "rowType": [{"name": "COL1", "type": "text"}]}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.sql.query",
            "input": {
                "statement": "SELECT * FROM schema_test",
                "schema": "RAW_DATA"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
}

// -- SQL Execute -------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn sql_execute_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/statements"))
        .and(bearer_token("test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "statementHandle": "01exec-handle",
            "message": "Statement executed successfully.",
            "code": "000000",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.sql.execute",
            "input": {
                "statement": "CREATE TABLE test_tbl (id INT, name VARCHAR)",
                "warehouse": "COMPUTE_WH",
                "database": "DEV"
            }
        }))
        .await
        .unwrap();
    assert!(result.get("status").is_some());
    assert!(result.get("statement_handle").is_some());
}

#[fcp_async_core::runtime::test]
async fn sql_execute_missing_statement() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "snowflake.sql.execute",
            "input": {"database": "DEV"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn sql_execute_insert() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/statements"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "statementHandle": "insert-handle",
            "message": "1 Row(s) produced.",
            "code": "000000",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.sql.execute",
            "input": {
                "statement": "INSERT INTO users VALUES (1, 'Alice')"
            }
        }))
        .await
        .unwrap();
    assert!(result["status"].as_str().is_some());
}

// -- Tables List -------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn tables_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/statements"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "statementHandle": "tables-handle",
            "code": "000000",
            "data": [
                ["ORDERS", "ANALYTICS", "PUBLIC", "TABLE"],
                ["USERS", "ANALYTICS", "PUBLIC", "TABLE"],
            ],
            "resultSetMetaData": {
                "numRows": 2,
                "rowType": [
                    {"name": "name", "type": "text"},
                    {"name": "database_name", "type": "text"},
                    {"name": "schema_name", "type": "text"},
                    {"name": "kind", "type": "text"}
                ]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.tables.list",
            "input": {"database": "ANALYTICS"}
        }))
        .await
        .unwrap();
    assert!(result.get("tables").is_some());
}

#[fcp_async_core::runtime::test]
async fn tables_list_with_schema() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/statements"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "statementHandle": "tables-schema-handle",
            "code": "000000",
            "data": [["EVENTS", "ANALYTICS", "RAW", "TABLE"]],
            "resultSetMetaData": {
                "numRows": 1,
                "rowType": [{"name": "name", "type": "text"}]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.tables.list",
            "input": {"database": "ANALYTICS", "schema": "RAW"}
        }))
        .await
        .unwrap();
    assert!(result.get("tables").is_some());
}

#[fcp_async_core::runtime::test]
async fn tables_list_missing_database() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "snowflake.tables.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn tables_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/statements"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "statementHandle": "empty-tables",
            "code": "000000",
            "data": [],
            "resultSetMetaData": {"numRows": 0, "rowType": []}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "snowflake.tables.list",
            "input": {"database": "EMPTY_DB"}
        }))
        .await
        .unwrap();
    assert!(result.get("tables").is_some());
}

// -- Error handling ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/databases"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"message": "Invalid token", "code": "390100"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "snowflake.databases.list",
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
                .set_body_json(json!({"message": "Insufficient privileges", "code": "003001"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "snowflake.databases.list",
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
        .and(path("/warehouses"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Warehouse not found", "code": "002003"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "snowflake.warehouses.list",
            "input": {}
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
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "snowflake.databases.list",
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
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal server error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "snowflake.databases.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_sql_compilation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/statements"))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_json(json!({"message": "SQL compilation error", "code": "002043"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "snowflake.sql.query",
            "input": {"statement": "SELCT FROM bad_syntax"}
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
            "operation_id": "snowflake.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_databases_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "snowflake.databases.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_warehouses_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "snowflake.warehouses.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_sql_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "snowflake.sql.query"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_sql_execute() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "snowflake.sql.execute"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_tables_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "snowflake.tables.list"}))
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
        !c.handle_simulate(json!({"operation_id": "snowflake.nope"}))
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
        .and(path("/databases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "snowflake.databases.list",
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
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "snowflake.databases.list",
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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "snowflake.databases.list",
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
    let mut c = SnowflakeConnector::new();
    c.handle_configure(json!({
        "access_token": "TOKEN",
        "account_identifier": "ACC",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.snowflake");
    assert_eq!(hs["protocol_version"], "2.0");
    let caps = hs["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "snowflake.databases.read"));
    assert!(caps.iter().any(|c| c == "snowflake.sql.read"));
    assert!(caps.iter().any(|c| c == "snowflake.sql.write"));
    assert!(caps.iter().any(|c| c == "snowflake.warehouses.read"));
}

// -- Invoke before ready -----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = SnowflakeConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "snowflake.databases.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Configure edge cases ----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn configure_with_minimal_params() {
    let mut c = SnowflakeConnector::new();
    let result = c
        .handle_configure(json!({
            "access_token": "token",
            "account_identifier": "acc",
        }))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_empty_token() {
    let mut c = SnowflakeConnector::new();
    let result = c
        .handle_configure(json!({
            "access_token": "",
            "account_identifier": "acc",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_empty_account() {
    let mut c = SnowflakeConnector::new();
    let result = c
        .handle_configure(json!({
            "access_token": "token",
            "account_identifier": "",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_missing_fields() {
    let mut c = SnowflakeConnector::new();
    assert!(c.handle_configure(json!({})).await.is_err());
}
