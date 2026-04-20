//! Integration tests for the FCP `SQLite` connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use tempfile::tempdir;

use fcp_sqlite::connector::SqliteConnector;
use serde_json::json;

async fn setup_memory_connector() -> SqliteConnector {
    let mut connector = SqliteConnector::new();
    connector
        .handle_configure(json!({ "database_path": ":memory:" }))
        .await
        .unwrap();
    connector
        .handle_handshake(json!({ "session_id": "test-session" }))
        .await
        .unwrap();
    connector
}

async fn setup_configured_memory_connector() -> SqliteConnector {
    let mut connector = SqliteConnector::new();
    connector
        .handle_configure(json!({ "database_path": ":memory:" }))
        .await
        .unwrap();
    connector
}

async fn setup_file_connector() -> (tempfile::TempDir, String, SqliteConnector) {
    let directory = tempdir().unwrap();
    let database_path = directory.path().join("integration.sqlite");
    let database_path = database_path.to_string_lossy().to_string();

    let mut connector = SqliteConnector::new();
    connector
        .handle_configure(json!({ "database_path": database_path }))
        .await
        .unwrap();
    connector
        .handle_handshake(json!({ "session_id": "test-session" }))
        .await
        .unwrap();
    (
        directory,
        connector.handle_health().await.unwrap()["health"]["database_path"]
            .as_str()
            .unwrap()
            .to_string(),
        connector,
    )
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_is_unconfigured_before_configure() {
    let connector = SqliteConnector::new();
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_and_handshake_make_connector_healthy() {
    let connector = setup_memory_connector().await;
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["health"]["query_ok"], true);
}

#[fcp_async_core::runtime::test]
async fn doctor_reports_guidance_for_unconfigured_connector() {
    let connector = SqliteConnector::new();
    let doctor = connector.handle_doctor().await.unwrap();
    assert_eq!(doctor["status"], "unhealthy");
    assert_eq!(doctor["checks"][0]["name"], "configuration");
    assert_eq!(doctor["checks"][0]["passed"], false);
    assert_eq!(
        doctor["guidance"]["rerun_commands"][0],
        "rch exec -- cargo check -p fcp-sqlite --all-targets"
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_degrades_before_handshake() {
    let connector = setup_configured_memory_connector().await;
    let report = connector.handle_self_check().await.unwrap();
    assert_eq!(report["status"], "degraded");
    assert_eq!(report["reason_code"], "handshake_pending");
    assert_eq!(report["details"]["provisioning"]["path_kind"], "memory");
    assert_eq!(
        report["details"]["guidance"]["prerequisites"][0],
        "Use a filesystem path inside the connector sandbox or `:memory:` for ephemeral runs."
    );
}

#[fcp_async_core::runtime::test]
async fn introspect_includes_compliance_and_guidance() {
    let connector = setup_memory_connector().await;
    let introspect = connector.handle_introspect().await.unwrap();
    assert_eq!(introspect["compliance"]["local_filesystem_only"], true);
    assert!(
        introspect["guidance"]["redaction_rules"][0]
            .as_str()
            .unwrap()
            .contains("Redact absolute")
    );
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_parent_dir_paths() {
    let mut connector = SqliteConnector::new();
    let error = connector
        .handle_configure(json!({ "database_path": "../unsafe.sqlite" }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains(".."));
}

#[fcp_async_core::runtime::test]
async fn query_returns_rows_and_columns() {
    let mut connector = setup_memory_connector().await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.query",
            "input": {
                "sql": "SELECT ?1 AS name, ?2 AS count",
                "params": ["widgets", 3]
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["row_count"], 1);
    assert_eq!(result["result"]["columns"][0]["name"], "name");
    assert_eq!(result["result"]["rows"][0][0], "widgets");
    assert_eq!(result["result"]["rows"][0][1], 3);
}

#[fcp_async_core::runtime::test]
async fn query_rejects_mutating_statements() {
    let mut connector = setup_memory_connector().await;
    let error = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.query",
            "input": {
                "sql": "CREATE TABLE nope(id INTEGER)"
            }
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("read-only"));
}

#[fcp_async_core::runtime::test]
async fn execute_rejects_user_supplied_savepoint() {
    // The Write policy allows the batch wrapper's internal SAVEPOINT
    // `fcp_sqlite_batch`, but any other savepoint name supplied directly by a
    // caller must still be rejected so users cannot open nested transactions.
    let mut connector = setup_memory_connector().await;
    let error = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "SAVEPOINT user_sp"
            }
        }))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("safety policy") || error.to_string().contains("denied"),
        "expected savepoint rejection, got: {error}",
    );
}

#[fcp_async_core::runtime::test]
async fn execute_creates_table_and_inserts_rows() {
    let mut connector = setup_memory_connector().await;
    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            }
        }))
        .await
        .unwrap();

    let result = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "INSERT INTO widgets(name) VALUES (?1)",
                "params": ["gizmo"]
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["rows_affected"], 1);

    let query = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.query",
            "input": {
                "sql": "SELECT name FROM widgets"
            }
        }))
        .await
        .unwrap();
    assert_eq!(query["result"]["rows"][0][0], "gizmo");
}

#[fcp_async_core::runtime::test]
async fn execute_rejects_read_only_statements() {
    let mut connector = setup_memory_connector().await;
    let error = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "SELECT 1"
            }
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("mutating"));
}

#[fcp_async_core::runtime::test]
async fn schema_operations_report_tables_and_columns() {
    let mut connector = setup_memory_connector().await;
    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT NOT NULL, qty INTEGER DEFAULT 0)"
            }
        }))
        .await
        .unwrap();

    let tables = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.schema.tables",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(tables["tables"][0]["name"], "widgets");

    let columns = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.schema.columns",
            "input": {
                "table": "widgets"
            }
        }))
        .await
        .unwrap();
    assert_eq!(columns["columns"][1]["name"], "name");
    assert_eq!(columns["columns"][2]["default_value"], "0");
}

#[fcp_async_core::runtime::test]
async fn explain_returns_query_plan_rows() {
    let mut connector = setup_memory_connector().await;
    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT)"
            }
        }))
        .await
        .unwrap();

    let explain = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.explain",
            "input": {
                "sql": "SELECT * FROM widgets WHERE id = ?1",
                "params": [1]
            }
        }))
        .await
        .unwrap();

    assert!(explain["plan"]["row_count"].as_u64().unwrap() >= 1);
}

#[fcp_async_core::runtime::test]
async fn transactions_require_matching_txn_id() {
    let mut connector = setup_memory_connector().await;
    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT)"
            }
        }))
        .await
        .unwrap();

    let begin = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.transaction.begin",
            "input": { "mode": "immediate" }
        }))
        .await
        .unwrap();
    let txn_id = begin["transaction"]["txn_id"].as_str().unwrap().to_string();

    let mismatch = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "INSERT INTO widgets(name) VALUES (?1)",
                "params": ["bad"],
                "txn_id": "wrong"
            }
        }))
        .await
        .unwrap_err();
    assert!(mismatch.to_string().contains("does not match"));

    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "INSERT INTO widgets(name) VALUES (?1)",
                "params": ["good"],
                "txn_id": txn_id
            }
        }))
        .await
        .unwrap();
}

#[fcp_async_core::runtime::test]
async fn commit_persists_transaction_changes() {
    let mut connector = setup_memory_connector().await;
    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT)"
            }
        }))
        .await
        .unwrap();

    let begin = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.transaction.begin",
            "input": {}
        }))
        .await
        .unwrap();
    let txn_id = begin["transaction"]["txn_id"].as_str().unwrap().to_string();

    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "INSERT INTO widgets(name) VALUES (?1)",
                "params": ["kept"],
                "txn_id": txn_id
            }
        }))
        .await
        .unwrap();

    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.transaction.commit",
            "input": {
                "txn_id": begin["transaction"]["txn_id"]
            }
        }))
        .await
        .unwrap();

    let result = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.query",
            "input": {
                "sql": "SELECT count(*) FROM widgets"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["result"]["rows"][0][0], 1);
}

#[fcp_async_core::runtime::test]
async fn rollback_discards_transaction_changes() {
    let mut connector = setup_memory_connector().await;
    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT)"
            }
        }))
        .await
        .unwrap();

    let begin = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.transaction.begin",
            "input": {}
        }))
        .await
        .unwrap();
    let txn_id = begin["transaction"]["txn_id"].as_str().unwrap().to_string();

    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "INSERT INTO widgets(name) VALUES (?1)",
                "params": ["discarded"],
                "txn_id": txn_id
            }
        }))
        .await
        .unwrap();

    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.transaction.rollback",
            "input": {
                "txn_id": begin["transaction"]["txn_id"]
            }
        }))
        .await
        .unwrap();

    let result = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.query",
            "input": {
                "sql": "SELECT count(*) FROM widgets"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["result"]["rows"][0][0], 0);
}

#[fcp_async_core::runtime::test]
async fn batch_is_atomic_on_error() {
    let mut connector = setup_memory_connector().await;
    connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT UNIQUE)"
            }
        }))
        .await
        .unwrap();

    let error = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.batch",
            "input": {
                "statements": [
                    { "sql": "INSERT INTO widgets(name) VALUES (?1)", "params": ["dup"] },
                    { "sql": "INSERT INTO widgets(name) VALUES (?1)", "params": ["dup"] }
                ]
            }
        }))
        .await
        .unwrap_err();
    assert!(!error.to_string().is_empty());

    let query = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.query",
            "input": { "sql": "SELECT count(*) FROM widgets" }
        }))
        .await
        .unwrap();
    assert_eq!(query["result"]["rows"][0][0], 0);
}

#[fcp_async_core::runtime::test]
async fn pragma_reads_allowlisted_values() {
    let mut connector = setup_memory_connector().await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.pragma",
            "input": { "name": "journal_mode" }
        }))
        .await
        .unwrap();
    assert!(result["result"]["row_count"].as_u64().unwrap() >= 1);
}

#[fcp_async_core::runtime::test]
async fn execute_rejects_pragma_writes() {
    let mut connector = setup_memory_connector().await;
    let error = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": { "sql": "PRAGMA journal_mode = delete" }
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("policy"));
}

#[fcp_async_core::runtime::test]
async fn execute_rejects_attach_database() {
    let mut connector = setup_memory_connector().await;
    let error = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.execute",
            "input": { "sql": "ATTACH DATABASE ':memory:' AS other" }
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("policy"));
}

#[fcp_async_core::runtime::test]
async fn health_and_vacuum_work_for_file_backed_database() {
    let (_dir, _path, mut connector) = setup_file_connector().await;
    let health = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.health",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(health["health"]["query_ok"], true);

    let result = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.vacuum",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["result"]["rows_affected"], 0);
}

#[fcp_async_core::runtime::test]
async fn vacuum_is_blocked_while_transaction_is_active() {
    let (_dir, _path, mut connector) = setup_file_connector().await;
    let begin = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.transaction.begin",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(begin["transaction"]["active"].as_bool().unwrap());

    let error = connector
        .handle_invoke(json!({
            "operation_id": "sqlite.vacuum",
            "input": {}
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("transaction"));
}
