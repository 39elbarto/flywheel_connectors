//! `DuckDB` `MotherDuck` API types.

use serde::{Deserialize, Serialize};

/// A query result from the `MotherDuck` SQL endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Column metadata for the result set.
    pub columns: Option<Vec<ColumnMeta>>,
    /// Row data as arrays of values.
    pub data: Option<Vec<Vec<serde_json::Value>>>,
    /// Number of rows returned or affected.
    pub row_count: Option<u64>,
    /// Unique identifier for the query execution.
    pub query_id: Option<String>,
}

/// Column metadata within a `DuckDB` query result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnMeta {
    /// Column name.
    pub name: Option<String>,
    /// `DuckDB` type name (e.g. VARCHAR, INTEGER, TIMESTAMP).
    pub type_name: Option<String>,
}

/// A `MotherDuck` database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    /// Database name.
    pub name: Option<String>,
    /// Size in bytes.
    pub size_bytes: Option<u64>,
    /// Creation timestamp (ISO 8601).
    pub created_at: Option<String>,
}

/// A table within a `MotherDuck` database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Table {
    /// Table name.
    pub name: Option<String>,
    /// Number of columns.
    pub column_count: Option<u64>,
    /// Number of rows.
    pub row_count: Option<u64>,
    /// Schema name the table belongs to.
    pub schema: Option<String>,
}

/// A schema within a `MotherDuck` database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// Schema name.
    pub name: Option<String>,
}

/// A `MotherDuck` database share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Share name.
    pub name: Option<String>,
    /// Database being shared.
    pub database: Option<String>,
    /// Creation timestamp (ISO 8601).
    pub created_at: Option<String>,
}

/// Status of a previously submitted query on `MotherDuck`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryStatus {
    /// Query identifier.
    pub query_id: Option<String>,
    /// Current status (e.g. "running", "completed", "failed").
    pub status: Option<String>,
    /// Result payload if the query has completed.
    pub result: Option<serde_json::Value>,
}

/// `MotherDuck` API error response body.
///
/// `MotherDuck` returns `{"error": "...", "message": "..."}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// Short error code/type from `MotherDuck`.
    pub error: Option<String>,
    /// Human-readable error message.
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn query_result_roundtrip() {
        let qr: QueryResult = serde_json::from_value(json!({
            "columns": [
                {"name": "id", "type_name": "INTEGER"},
                {"name": "name", "type_name": "VARCHAR"},
            ],
            "data": [[1, "Alice"], [2, "Bob"]],
            "row_count": 2,
            "query_id": "q-abc123",
        }))
        .unwrap();
        assert_eq!(qr.columns.as_ref().unwrap().len(), 2);
        assert_eq!(qr.data.as_ref().unwrap().len(), 2);
        assert_eq!(qr.row_count, Some(2));
        assert_eq!(qr.query_id.as_deref(), Some("q-abc123"));
        let re = serde_json::to_value(&qr).unwrap();
        assert_eq!(re["row_count"], 2);
    }

    #[test]
    fn query_result_minimal() {
        let qr: QueryResult = serde_json::from_value(json!({})).unwrap();
        assert!(qr.columns.is_none());
        assert!(qr.data.is_none());
        assert!(qr.row_count.is_none());
        assert!(qr.query_id.is_none());
    }

    #[test]
    fn column_meta_roundtrip() {
        let cm: ColumnMeta = serde_json::from_value(json!({
            "name": "total_sales",
            "type_name": "DOUBLE",
        }))
        .unwrap();
        assert_eq!(cm.name, Some("total_sales".into()));
        assert_eq!(cm.type_name, Some("DOUBLE".into()));
        let re = serde_json::to_value(&cm).unwrap();
        assert_eq!(re["name"], "total_sales");
    }

    #[test]
    fn column_meta_minimal() {
        let cm: ColumnMeta = serde_json::from_value(json!({})).unwrap();
        assert!(cm.name.is_none());
        assert!(cm.type_name.is_none());
    }

    #[test]
    fn database_roundtrip() {
        let db: Database = serde_json::from_value(json!({
            "name": "analytics",
            "size_bytes": 1048576,
            "created_at": "2025-06-15T10:30:00Z",
        }))
        .unwrap();
        assert_eq!(db.name, Some("analytics".into()));
        assert_eq!(db.size_bytes, Some(1_048_576));
        assert_eq!(db.created_at, Some("2025-06-15T10:30:00Z".into()));
        let re = serde_json::to_value(&db).unwrap();
        assert_eq!(re["name"], "analytics");
    }

    #[test]
    fn database_minimal() {
        let db: Database = serde_json::from_value(json!({})).unwrap();
        assert!(db.name.is_none());
        assert!(db.size_bytes.is_none());
        assert!(db.created_at.is_none());
    }

    #[test]
    fn table_roundtrip() {
        let t: Table = serde_json::from_value(json!({
            "name": "sales",
            "column_count": 8,
            "row_count": 50000,
            "schema": "main",
        }))
        .unwrap();
        assert_eq!(t.name, Some("sales".into()));
        assert_eq!(t.column_count, Some(8));
        assert_eq!(t.row_count, Some(50_000));
        assert_eq!(t.schema, Some("main".into()));
        let re = serde_json::to_value(&t).unwrap();
        assert_eq!(re["name"], "sales");
    }

    #[test]
    fn table_minimal() {
        let t: Table = serde_json::from_value(json!({})).unwrap();
        assert!(t.name.is_none());
        assert!(t.column_count.is_none());
        assert!(t.row_count.is_none());
        assert!(t.schema.is_none());
    }

    #[test]
    fn schema_roundtrip() {
        let s: Schema = serde_json::from_value(json!({"name": "public"})).unwrap();
        assert_eq!(s.name, Some("public".into()));
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["name"], "public");
    }

    #[test]
    fn schema_minimal() {
        let s: Schema = serde_json::from_value(json!({})).unwrap();
        assert!(s.name.is_none());
    }

    #[test]
    fn share_roundtrip() {
        let s: Share = serde_json::from_value(json!({
            "name": "team_share",
            "database": "analytics",
            "created_at": "2025-07-01T08:00:00Z",
        }))
        .unwrap();
        assert_eq!(s.name, Some("team_share".into()));
        assert_eq!(s.database, Some("analytics".into()));
        assert_eq!(s.created_at, Some("2025-07-01T08:00:00Z".into()));
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["name"], "team_share");
    }

    #[test]
    fn share_minimal() {
        let s: Share = serde_json::from_value(json!({})).unwrap();
        assert!(s.name.is_none());
        assert!(s.database.is_none());
        assert!(s.created_at.is_none());
    }

    #[test]
    fn query_status_roundtrip() {
        let qs: QueryStatus = serde_json::from_value(json!({
            "query_id": "q-xyz789",
            "status": "completed",
            "result": {"row_count": 42},
        }))
        .unwrap();
        assert_eq!(qs.query_id, Some("q-xyz789".into()));
        assert_eq!(qs.status, Some("completed".into()));
        assert!(qs.result.is_some());
        let re = serde_json::to_value(&qs).unwrap();
        assert_eq!(re["status"], "completed");
    }

    #[test]
    fn query_status_minimal() {
        let qs: QueryStatus = serde_json::from_value(json!({})).unwrap();
        assert!(qs.query_id.is_none());
        assert!(qs.status.is_none());
        assert!(qs.result.is_none());
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "invalid_query",
            "message": "Syntax error at position 12",
        }))
        .unwrap();
        assert_eq!(e.error, Some("invalid_query".into()));
        assert_eq!(e.message, Some("Syntax error at position 12".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Something went wrong",
        }))
        .unwrap();
        assert!(e.error.is_none());
        assert_eq!(e.message, Some("Something went wrong".into()));
    }

    #[test]
    fn query_result_extra_fields_ignored() {
        let qr: QueryResult = serde_json::from_value(json!({
            "row_count": 5,
            "extra_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(qr.row_count, Some(5));
    }

    #[test]
    fn database_extra_fields_ignored() {
        let db: Database = serde_json::from_value(json!({
            "name": "test_db",
            "unknown_field": 99,
        }))
        .unwrap();
        assert_eq!(db.name, Some("test_db".into()));
    }

    #[test]
    fn table_extra_fields_ignored() {
        let t: Table = serde_json::from_value(json!({
            "name": "users",
            "extra": true,
        }))
        .unwrap();
        assert_eq!(t.name, Some("users".into()));
    }

    #[test]
    fn share_extra_fields_ignored() {
        let s: Share = serde_json::from_value(json!({
            "name": "my_share",
            "extra": [1, 2, 3],
        }))
        .unwrap();
        assert_eq!(s.name, Some("my_share".into()));
    }

    #[test]
    fn query_result_serialize_roundtrip() {
        let qr = QueryResult {
            columns: Some(vec![ColumnMeta {
                name: Some("id".into()),
                type_name: Some("INTEGER".into()),
            }]),
            data: Some(vec![vec![serde_json::json!(1)]]),
            row_count: Some(1),
            query_id: Some("q-test".into()),
        };
        let v = serde_json::to_value(&qr).unwrap();
        assert_eq!(v["query_id"], "q-test");
        assert_eq!(v["columns"][0]["name"], "id");
    }

    #[test]
    fn database_serialize_roundtrip() {
        let db = Database {
            name: Some("my_db".into()),
            size_bytes: Some(2048),
            created_at: None,
        };
        let v = serde_json::to_value(&db).unwrap();
        assert_eq!(v["name"], "my_db");
        assert_eq!(v["size_bytes"], 2048);
        assert!(v["created_at"].is_null());
    }

    #[test]
    fn table_serialize_roundtrip() {
        let t = Table {
            name: Some("events".into()),
            column_count: Some(5),
            row_count: Some(100),
            schema: Some("main".into()),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["name"], "events");
        assert_eq!(v["column_count"], 5);
    }

    #[test]
    fn share_serialize_roundtrip() {
        let s = Share {
            name: Some("pub_share".into()),
            database: Some("analytics".into()),
            created_at: Some("2025-01-01T00:00:00Z".into()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["database"], "analytics");
    }

    #[test]
    fn query_status_running() {
        let qs: QueryStatus = serde_json::from_value(json!({
            "query_id": "q-running",
            "status": "running",
        }))
        .unwrap();
        assert_eq!(qs.status, Some("running".into()));
        assert!(qs.result.is_none());
    }

    #[test]
    fn query_status_failed() {
        let qs: QueryStatus = serde_json::from_value(json!({
            "query_id": "q-fail",
            "status": "failed",
            "result": {"error": "timeout"},
        }))
        .unwrap();
        assert_eq!(qs.status, Some("failed".into()));
        assert!(qs.result.is_some());
    }

    #[test]
    fn query_result_clone() {
        let qr = QueryResult {
            columns: Some(vec![ColumnMeta {
                name: Some("id".into()),
                type_name: Some("INTEGER".into()),
            }]),
            data: Some(vec![vec![json!(1)]]),
            row_count: Some(1),
            query_id: Some("q1".into()),
        };
        let c = qr.clone();
        assert_eq!(c.row_count, Some(1));
        assert_eq!(c.query_id, Some("q1".into()));
        assert_eq!(qr.row_count, Some(1));
    }

    #[test]
    fn query_result_debug() {
        let qr = QueryResult {
            columns: None,
            data: None,
            row_count: Some(42),
            query_id: Some("q-dbg".into()),
        };
        let dbg = format!("{qr:?}");
        assert!(dbg.contains("q-dbg"));
    }

    #[test]
    fn column_meta_clone() {
        let cm = ColumnMeta {
            name: Some("col".into()),
            type_name: Some("VARCHAR".into()),
        };
        let c = cm.clone();
        assert_eq!(c.name, Some("col".into()));
        assert_eq!(c.type_name, Some("VARCHAR".into()));
        assert_eq!(cm.name, Some("col".into()));
    }

    #[test]
    fn column_meta_debug() {
        let cm = ColumnMeta {
            name: Some("score".into()),
            type_name: Some("FLOAT".into()),
        };
        let dbg = format!("{cm:?}");
        assert!(dbg.contains("score"));
        assert!(dbg.contains("FLOAT"));
    }

    #[test]
    fn database_clone() {
        let db = Database {
            name: Some("mydb".into()),
            size_bytes: Some(1024),
            created_at: Some("2025-01-01T00:00:00Z".into()),
        };
        let c = db.clone();
        assert_eq!(c.name, Some("mydb".into()));
        assert_eq!(c.size_bytes, Some(1024));
        assert_eq!(db.created_at, Some("2025-01-01T00:00:00Z".into()));
    }

    #[test]
    fn database_debug() {
        let db = Database {
            name: Some("testdb".into()),
            size_bytes: None,
            created_at: None,
        };
        let dbg = format!("{db:?}");
        assert!(dbg.contains("testdb"));
    }

    #[test]
    fn table_clone() {
        let t = Table {
            name: Some("users".into()),
            column_count: Some(5),
            row_count: Some(100),
            schema: Some("main".into()),
        };
        let c = t.clone();
        assert_eq!(c.name, Some("users".into()));
        assert_eq!(c.schema, Some("main".into()));
        assert_eq!(t.column_count, Some(5));
    }

    #[test]
    fn table_debug() {
        let t = Table {
            name: Some("events".into()),
            column_count: Some(3),
            row_count: None,
            schema: None,
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("events"));
    }

    #[test]
    fn schema_clone() {
        let s = Schema {
            name: Some("public".into()),
        };
        let c = s.clone();
        assert_eq!(c.name, Some("public".into()));
        assert_eq!(s.name, Some("public".into()));
    }

    #[test]
    fn schema_debug() {
        let s = Schema {
            name: Some("main".into()),
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("main"));
    }

    #[test]
    fn share_clone() {
        let s = Share {
            name: Some("share1".into()),
            database: Some("db1".into()),
            created_at: None,
        };
        let c = s.clone();
        assert_eq!(c.name, Some("share1".into()));
        assert_eq!(c.database, Some("db1".into()));
        assert_eq!(s.name, Some("share1".into()));
    }

    #[test]
    fn share_debug() {
        let s = Share {
            name: Some("myshare".into()),
            database: None,
            created_at: None,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("myshare"));
    }

    #[test]
    fn query_status_clone() {
        let qs = QueryStatus {
            query_id: Some("q1".into()),
            status: Some("completed".into()),
            result: Some(json!({"rows": 10})),
        };
        let c = qs.clone();
        assert_eq!(c.query_id, Some("q1".into()));
        assert_eq!(c.status, Some("completed".into()));
        assert!(qs.result.is_some());
    }

    #[test]
    fn query_status_debug() {
        let qs = QueryStatus {
            query_id: Some("qdebug".into()),
            status: Some("running".into()),
            result: None,
        };
        let dbg = format!("{qs:?}");
        assert!(dbg.contains("qdebug"));
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            error: Some("invalid".into()),
            message: Some("bad query".into()),
        };
        let c = e.clone();
        assert_eq!(c.error, Some("invalid".into()));
        assert_eq!(c.message, Some("bad query".into()));
        assert_eq!(e.error, Some("invalid".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse {
            error: Some("test_error".into()),
            message: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("test_error"));
    }

    #[test]
    fn schema_serialize_roundtrip() {
        let s = Schema {
            name: Some("information_schema".into()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["name"], "information_schema");
        let back: Schema = serde_json::from_value(v).unwrap();
        assert_eq!(back.name, Some("information_schema".into()));
    }

    #[test]
    fn query_status_serialize_roundtrip() {
        let qs = QueryStatus {
            query_id: Some("q-ser".into()),
            status: Some("completed".into()),
            result: Some(json!({"count": 5})),
        };
        let v = serde_json::to_value(&qs).unwrap();
        assert_eq!(v["query_id"], "q-ser");
        let back: QueryStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back.status, Some("completed".into()));
    }

    #[test]
    fn database_large_size() {
        let db: Database = serde_json::from_value(json!({
            "name": "big_db",
            "size_bytes": 1_073_741_824_u64,
        }))
        .unwrap();
        assert_eq!(db.size_bytes, Some(1_073_741_824));
    }

    #[test]
    fn table_zero_rows() {
        let t: Table = serde_json::from_value(json!({
            "name": "empty_table",
            "row_count": 0,
            "column_count": 3,
        }))
        .unwrap();
        assert_eq!(t.row_count, Some(0));
    }

    #[test]
    fn query_result_empty_data() {
        let qr: QueryResult = serde_json::from_value(json!({
            "columns": [],
            "data": [],
            "row_count": 0,
        }))
        .unwrap();
        assert!(qr.columns.as_ref().unwrap().is_empty());
        assert!(qr.data.as_ref().unwrap().is_empty());
        assert_eq!(qr.row_count, Some(0));
    }

    #[test]
    fn query_result_multiple_types() {
        let qr: QueryResult = serde_json::from_value(json!({
            "columns": [
                {"name": "id", "type_name": "INTEGER"},
                {"name": "name", "type_name": "VARCHAR"},
                {"name": "active", "type_name": "BOOLEAN"},
            ],
            "data": [[1, "Alice", true], [2, "Bob", false]],
            "row_count": 2,
        }))
        .unwrap();
        assert_eq!(qr.columns.as_ref().unwrap().len(), 3);
        assert_eq!(qr.data.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn api_error_response_error_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "unauthorized",
        }))
        .unwrap();
        assert_eq!(e.error, Some("unauthorized".into()));
        assert!(e.message.is_none());
    }
}
