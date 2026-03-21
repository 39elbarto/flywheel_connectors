//! `MySQL` connector types.

use serde::{Deserialize, Serialize};

/// Parameters for a SQL query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParams {
    /// The SQL query string (parameterized, use ? placeholders).
    pub sql: String,
    /// Positional parameters for the query.
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
    /// Optional query timeout in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Result of a SQL query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// The result rows.
    pub rows: Vec<serde_json::Value>,
    /// Column metadata.
    pub columns: Vec<ColumnInfo>,
    /// Number of rows returned or affected.
    pub row_count: u64,
}

/// Basic column information returned with query results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnInfo {
    /// Column name.
    pub name: String,
    /// `MySQL` data type.
    pub data_type: String,
    /// Whether the column is nullable.
    pub nullable: bool,
}

/// Result of an EXPLAIN query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainResult {
    /// The query plan as a JSON value.
    pub plan: serde_json::Value,
}

/// Information about a database table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableInfo {
    /// Table name.
    pub name: String,
    /// Database/schema name.
    pub database: String,
    /// Storage engine (`InnoDB`, `MyISAM`, etc.).
    pub engine: String,
    /// Estimated row count.
    pub row_count_estimate: u64,
}

/// Detailed column information from schema introspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDetail {
    /// Column name.
    pub name: String,
    /// `MySQL` data type.
    pub data_type: String,
    /// Whether the column is nullable.
    pub nullable: bool,
    /// Default value expression, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    /// Whether this column is part of the primary key.
    pub is_primary_key: bool,
    /// Character maximum length, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub char_max_length: Option<u64>,
}

/// Information about a database index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexInfo {
    /// Index name.
    pub name: String,
    /// Table the index belongs to.
    pub table: String,
    /// Columns in the index.
    pub columns: Vec<String>,
    /// Whether the index enforces uniqueness.
    pub unique: bool,
    /// Index type (BTREE, HASH, FULLTEXT, SPATIAL).
    #[serde(rename = "type")]
    pub index_type: String,
}

/// Transaction request parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransactionRequest {
    /// Isolation level (`read_committed`, `repeatable_read`, `serializable`, `read_uncommitted`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation_level: Option<String>,
}

/// Batch execution request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRequest {
    /// SQL statements to execute in order.
    pub statements: Vec<String>,
    /// Optional parameters for each statement.
    #[serde(default)]
    pub params: Vec<Vec<serde_json::Value>>,
}

/// `MySQL` REST API response.
#[derive(Debug, Clone, Deserialize)]
pub struct MysqlApiResponse {
    /// The result data on success.
    pub result: Option<serde_json::Value>,
    /// Error message on failure.
    pub error: Option<String>,
    /// Optional `MySQL` error code.
    pub code: Option<String>,
}

/// `MySQL` REST API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// Human-readable error message.
    pub message: Option<String>,
    /// `MySQL` error code (e.g. `"1062"` for duplicate key).
    pub code: Option<String>,
    /// Additional details.
    pub details: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_params_roundtrip() {
        let params = QueryParams {
            sql: "SELECT * FROM users WHERE id = ?".into(),
            params: vec![serde_json::json!(42)],
            timeout_ms: Some(5000),
        };
        let json = serde_json::to_string(&params).unwrap();
        let decoded: QueryParams = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sql, params.sql);
        assert_eq!(decoded.params.len(), 1);
        assert_eq!(decoded.timeout_ms, Some(5000));
    }

    #[test]
    fn query_result_roundtrip() {
        let result = QueryResult {
            rows: vec![serde_json::json!({"id": 1, "name": "test"})],
            columns: vec![ColumnInfo {
                name: "id".into(),
                data_type: "INT".into(),
                nullable: false,
            }],
            row_count: 1,
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: QueryResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.row_count, 1);
    }

    #[test]
    fn table_info_with_engine() {
        let info = TableInfo {
            name: "users".into(),
            database: "mydb".into(),
            engine: "InnoDB".into(),
            row_count_estimate: 1000,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("InnoDB"));
    }

    #[test]
    fn transaction_request_default() {
        let req = TransactionRequest::default();
        assert!(req.isolation_level.is_none());
    }

    #[test]
    fn batch_request_roundtrip() {
        let batch = BatchRequest {
            statements: vec!["INSERT INTO t VALUES (?)".into()],
            params: vec![vec![serde_json::json!(1)]],
        };
        let json = serde_json::to_string(&batch).unwrap();
        let decoded: BatchRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.statements.len(), 1);
    }
}
