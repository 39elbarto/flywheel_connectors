//! `PostgreSQL` connector types.

use serde::{Deserialize, Serialize};

/// Parameters for a SQL query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParams {
    /// The SQL query string.
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
    /// `PostgreSQL` data type.
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
    /// Schema name.
    pub schema: String,
    /// Estimated row count.
    pub row_count_estimate: u64,
}

/// Detailed column information from schema introspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDetail {
    /// Column name.
    pub name: String,
    /// `PostgreSQL` data type.
    pub data_type: String,
    /// Whether the column is nullable.
    pub nullable: bool,
    /// Default value expression, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    /// Whether this column is part of the primary key.
    pub is_primary_key: bool,
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
    /// Index type (btree, hash, gin, gist, etc.).
    #[serde(rename = "type")]
    pub index_type: String,
}

/// Transaction request parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransactionRequest {
    /// Isolation level (`read_committed`, `repeatable_read`, `serializable`).
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

/// Prepared statement execution request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedRequest {
    /// Name of the prepared statement.
    pub name: String,
    /// Parameters to bind.
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
}

/// `PostgREST`-style API response.
#[derive(Debug, Clone, Deserialize)]
pub struct PostgresApiResponse {
    /// The result data on success.
    pub result: Option<serde_json::Value>,
    /// Error message on failure.
    pub error: Option<String>,
    /// Optional error code from `PostgreSQL`.
    pub code: Option<String>,
}

/// `PostgREST`-style API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// Human-readable error message.
    pub message: Option<String>,
    /// `PostgreSQL` error code (e.g. "23505").
    pub code: Option<String>,
    /// Additional details.
    pub details: Option<String>,
}
