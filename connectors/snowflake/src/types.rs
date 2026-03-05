//! `Snowflake` API types.

use serde::{Deserialize, Serialize};

/// A Snowflake database entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_on: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_time: Option<i64>,
}

/// A Snowflake warehouse entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warehouse {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_suspend: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_resume: Option<bool>,
}

/// A Snowflake table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Table {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_on: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<i64>,
}

/// Column metadata returned from SQL API result set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultSetColumn {
    pub name: String,
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col_type: Option<String>,
}

/// SQL statement response from the Snowflake SQL API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatementResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_status_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_set_meta_data: Option<ResultSetMetaData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<Vec<serde_json::Value>>>,
}

/// Result set metadata from the SQL API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultSetMetaData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_rows: Option<i64>,
    #[serde(default)]
    pub row_type: Vec<ResultSetColumn>,
}

/// `Snowflake` API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<String>,
    pub code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn database_roundtrip() {
        let d: Database = serde_json::from_value(json!({
            "name": "ANALYTICS",
            "created_on": "2025-01-01T00:00:00Z",
            "owner": "SYSADMIN",
            "comment": "Analytics database",
            "retention_time": 1
        }))
        .unwrap();
        assert_eq!(d.name, "ANALYTICS");
        assert_eq!(d.owner, Some("SYSADMIN".into()));
        assert_eq!(d.retention_time, Some(1));
        let re = serde_json::to_value(&d).unwrap();
        assert_eq!(re["name"], "ANALYTICS");
    }

    #[test]
    fn database_minimal() {
        let d: Database = serde_json::from_value(json!({"name": "DB1"})).unwrap();
        assert_eq!(d.name, "DB1");
        assert!(d.created_on.is_none());
        assert!(d.owner.is_none());
        assert!(d.comment.is_none());
        assert!(d.retention_time.is_none());
    }

    #[test]
    fn database_serialize_skips_none() {
        let d = Database {
            name: "DB1".into(),
            created_on: None,
            owner: None,
            comment: None,
            retention_time: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert!(v.get("created_on").is_none());
        assert!(v.get("owner").is_none());
    }

    #[test]
    fn warehouse_roundtrip() {
        let w: Warehouse = serde_json::from_value(json!({
            "name": "COMPUTE_WH",
            "state": "STARTED",
            "size": "X-SMALL",
            "type": "STANDARD",
            "auto_suspend": 600,
            "auto_resume": true
        }))
        .unwrap();
        assert_eq!(w.name, "COMPUTE_WH");
        assert_eq!(w.state, Some("STARTED".into()));
        assert_eq!(w.size, Some("X-SMALL".into()));
        assert_eq!(w.auto_suspend, Some(600));
        assert_eq!(w.auto_resume, Some(true));
    }

    #[test]
    fn warehouse_minimal() {
        let w: Warehouse = serde_json::from_value(json!({"name": "WH1"})).unwrap();
        assert_eq!(w.name, "WH1");
        assert!(w.state.is_none());
        assert!(w.size.is_none());
        assert!(w.auto_suspend.is_none());
    }

    #[test]
    fn warehouse_serialize_skips_none() {
        let w = Warehouse {
            name: "WH1".into(),
            state: None,
            size: None,
            r#type: None,
            auto_suspend: None,
            auto_resume: None,
        };
        let v = serde_json::to_value(&w).unwrap();
        assert!(v.get("state").is_none());
        assert!(v.get("size").is_none());
    }

    #[test]
    fn table_roundtrip() {
        let t: Table = serde_json::from_value(json!({
            "name": "ORDERS",
            "database_name": "ANALYTICS",
            "schema_name": "PUBLIC",
            "kind": "TABLE",
            "created_on": "2025-03-01T00:00:00Z",
            "row_count": 50000,
            "bytes": 2048576
        }))
        .unwrap();
        assert_eq!(t.name, "ORDERS");
        assert_eq!(t.database_name, Some("ANALYTICS".into()));
        assert_eq!(t.schema_name, Some("PUBLIC".into()));
        assert_eq!(t.row_count, Some(50000));
        assert_eq!(t.bytes, Some(2048576));
    }

    #[test]
    fn table_minimal() {
        let t: Table = serde_json::from_value(json!({"name": "T1"})).unwrap();
        assert_eq!(t.name, "T1");
        assert!(t.database_name.is_none());
        assert!(t.schema_name.is_none());
        assert!(t.row_count.is_none());
    }

    #[test]
    fn table_serialize_skips_none() {
        let t = Table {
            name: "T1".into(),
            database_name: None,
            schema_name: None,
            kind: None,
            created_on: None,
            row_count: None,
            bytes: None,
        };
        let v = serde_json::to_value(&t).unwrap();
        assert!(v.get("database_name").is_none());
        assert!(v.get("row_count").is_none());
    }

    #[test]
    fn result_set_column_roundtrip() {
        let c: ResultSetColumn = serde_json::from_value(json!({
            "name": "ID",
            "type": "fixed"
        }))
        .unwrap();
        assert_eq!(c.name, "ID");
        assert_eq!(c.col_type, Some("fixed".into()));
    }

    #[test]
    fn result_set_column_minimal() {
        let c: ResultSetColumn = serde_json::from_value(json!({"name": "COL1"})).unwrap();
        assert_eq!(c.name, "COL1");
        assert!(c.col_type.is_none());
    }

    #[test]
    fn statement_response_full() {
        let r: StatementResponse = serde_json::from_value(json!({
            "statementHandle": "01234-abcd",
            "message": "Statement executed successfully.",
            "code": "000000",
            "statementStatusUrl": "/api/v2/statements/01234-abcd",
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
        }))
        .unwrap();
        assert_eq!(r.statement_handle, Some("01234-abcd".into()));
        assert_eq!(r.code, Some("000000".into()));
        let meta = r.result_set_meta_data.unwrap();
        assert_eq!(meta.num_rows, Some(2));
        assert_eq!(meta.row_type.len(), 2);
        assert_eq!(r.data.unwrap().len(), 2);
    }

    #[test]
    fn statement_response_minimal() {
        let r: StatementResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.statement_handle.is_none());
        assert!(r.message.is_none());
        assert!(r.data.is_none());
    }

    #[test]
    fn statement_response_empty_data() {
        let r: StatementResponse = serde_json::from_value(json!({
            "data": [],
            "resultSetMetaData": {
                "numRows": 0,
                "rowType": []
            }
        }))
        .unwrap();
        assert!(r.data.unwrap().is_empty());
        assert_eq!(r.result_set_meta_data.unwrap().num_rows, Some(0));
    }

    #[test]
    fn result_set_metadata_roundtrip() {
        let m: ResultSetMetaData = serde_json::from_value(json!({
            "numRows": 100,
            "rowType": [
                {"name": "COL1", "type": "text"},
                {"name": "COL2", "type": "fixed"}
            ]
        }))
        .unwrap();
        assert_eq!(m.num_rows, Some(100));
        assert_eq!(m.row_type.len(), 2);
        assert_eq!(m.row_type[0].name, "COL1");
    }

    #[test]
    fn result_set_metadata_minimal() {
        let m: ResultSetMetaData = serde_json::from_value(json!({})).unwrap();
        assert!(m.num_rows.is_none());
        assert!(m.row_type.is_empty());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "SQL compilation error",
            "code": "002043"
        }))
        .unwrap();
        assert_eq!(e.message, Some("SQL compilation error".into()));
        assert_eq!(e.code, Some("002043".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.code.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse =
            serde_json::from_value(json!({"message": "Invalid token"})).unwrap();
        assert_eq!(e.message, Some("Invalid token".into()));
        assert!(e.code.is_none());
    }

    #[test]
    fn database_clone() {
        let d = Database {
            name: "DB1".into(),
            created_on: Some("2025-01-01".into()),
            owner: Some("ADMIN".into()),
            comment: None,
            retention_time: Some(7),
        };
        let cloned = Database::clone(&d);
        assert_eq!(cloned.name, "DB1");
        assert_eq!(cloned.retention_time, Some(7));
        assert_eq!(d.owner, Some("ADMIN".into()));
    }

    #[test]
    fn warehouse_clone() {
        let w = Warehouse {
            name: "WH".into(),
            state: Some("STARTED".into()),
            size: Some("SMALL".into()),
            r#type: Some("STANDARD".into()),
            auto_suspend: Some(300),
            auto_resume: Some(true),
        };
        let cloned = Warehouse::clone(&w);
        assert_eq!(cloned.name, "WH");
        assert_eq!(cloned.auto_suspend, Some(300));
        assert_eq!(w.state, Some("STARTED".into()));
    }

    #[test]
    fn table_clone() {
        let t = Table {
            name: "T".into(),
            database_name: Some("DB".into()),
            schema_name: Some("PUBLIC".into()),
            kind: Some("TABLE".into()),
            created_on: None,
            row_count: Some(1000),
            bytes: Some(4096),
        };
        let cloned = Table::clone(&t);
        assert_eq!(cloned.name, "T");
        assert_eq!(cloned.row_count, Some(1000));
        assert_eq!(t.database_name, Some("DB".into()));
    }

    #[test]
    fn statement_response_serialize_deserialize() {
        let original = StatementResponse {
            statement_handle: Some("handle-1".into()),
            message: Some("Success".into()),
            code: Some("000000".into()),
            statement_status_url: Some("/api/v2/statements/handle-1".into()),
            result_set_meta_data: Some(ResultSetMetaData {
                num_rows: Some(1),
                row_type: vec![ResultSetColumn {
                    name: "ID".into(),
                    col_type: Some("fixed".into()),
                }],
            }),
            data: Some(vec![vec![serde_json::json!("42")]]),
        };
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json["statementHandle"], "handle-1");
        let back: StatementResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.statement_handle, Some("handle-1".into()));
    }

    #[test]
    fn database_debug() {
        let d = Database {
            name: "TEST".into(),
            created_on: None,
            owner: None,
            comment: None,
            retention_time: None,
        };
        let dbg = format!("{d:?}");
        assert!(dbg.contains("TEST"));
    }

    #[test]
    fn warehouse_debug() {
        let w = Warehouse {
            name: "WH_TEST".into(),
            state: None,
            size: None,
            r#type: None,
            auto_suspend: None,
            auto_resume: None,
        };
        let dbg = format!("{w:?}");
        assert!(dbg.contains("WH_TEST"));
    }
}
