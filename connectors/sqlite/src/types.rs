//! SQLite connector types.

#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};

const fn default_busy_timeout_ms() -> u64 {
    5_000
}

const fn default_true() -> bool {
    true
}

/// Configuration for opening the SQLite database.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SqliteConfig {
    /// Database path or `:memory:`.
    pub database_path: String,
    /// Whether the database is opened read-only.
    #[serde(default)]
    pub read_only: bool,
    /// Whether the database should be created if it does not exist.
    #[serde(default = "default_true")]
    pub create_if_missing: bool,
    /// Busy timeout in milliseconds.
    #[serde(default = "default_busy_timeout_ms")]
    pub busy_timeout_ms: u64,
    /// Whether WAL mode should be requested for file-backed databases.
    #[serde(default = "default_true")]
    pub enable_wal: bool,
    /// Whether foreign key enforcement should be enabled.
    #[serde(default = "default_true")]
    pub enforce_foreign_keys: bool,
}

/// Column metadata returned with query results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryColumn {
    /// Zero-based ordinal.
    pub ordinal: usize,
    /// Column name in the result set.
    pub name: String,
    /// Declared SQLite type when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decl_type: Option<String>,
}

/// Result of a query or pragma read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryResult {
    /// Result columns.
    pub columns: Vec<QueryColumn>,
    /// Row values aligned with `columns`.
    pub rows: Vec<Vec<serde_json::Value>>,
    /// Number of rows returned.
    pub row_count: u64,
}

/// Result of a non-returning statement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecuteResult {
    /// Number of affected rows.
    pub rows_affected: u64,
    /// SQLite last insert rowid after the statement finishes.
    pub last_insert_rowid: i64,
}

/// SQLite table descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableInfo {
    /// Schema name (normally `main` for the first slice).
    pub schema: String,
    /// Table name.
    pub name: String,
    /// SQLite object type.
    #[serde(rename = "type")]
    pub table_type: String,
    /// Number of columns.
    pub column_count: u64,
    /// Whether the table uses `WITHOUT ROWID`.
    pub without_rowid: bool,
    /// Whether the table is strict.
    pub strict: bool,
}

/// SQLite column descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaColumn {
    /// Column ordinal (`cid`).
    pub cid: i64,
    /// Column name.
    pub name: String,
    /// Declared SQLite type.
    pub data_type: String,
    /// Whether the column is declared `NOT NULL`.
    pub not_null: bool,
    /// Default value expression, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    /// Whether the column participates in the primary key.
    pub primary_key: bool,
    /// Whether the column is hidden/generated.
    pub hidden: bool,
}

/// Transaction mode for SQLite `BEGIN`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionMode {
    /// `BEGIN DEFERRED`
    Deferred,
    /// `BEGIN IMMEDIATE`
    Immediate,
    /// `BEGIN EXCLUSIVE`
    Exclusive,
}

impl Default for TransactionMode {
    fn default() -> Self {
        Self::Immediate
    }
}

impl TransactionMode {
    /// Parse a transaction mode from user input.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw
            .unwrap_or("immediate")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "deferred" => Ok(Self::Deferred),
            "immediate" => Ok(Self::Immediate),
            "exclusive" => Ok(Self::Exclusive),
            other => Err(format!(
                "unsupported transaction mode `{other}`; expected deferred, immediate, or exclusive"
            )),
        }
    }

    /// SQL fragment used to begin the transaction.
    #[must_use]
    pub const fn begin_sql(self) -> &'static str {
        match self {
            Self::Deferred => "BEGIN DEFERRED",
            Self::Immediate => "BEGIN IMMEDIATE",
            Self::Exclusive => "BEGIN EXCLUSIVE",
        }
    }
}

/// Reported transaction state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionState {
    /// Stable transaction id returned to the caller.
    pub txn_id: String,
    /// Active transaction mode.
    pub mode: TransactionMode,
    /// Whether the transaction is active.
    pub active: bool,
}

/// A statement in a batch execution request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchStatement {
    /// SQL text for the statement.
    pub sql: String,
    /// Positional parameters for the statement.
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
}

/// Result for a single batched statement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchStatementResult {
    /// Zero-based statement index.
    pub index: usize,
    /// Number of affected rows.
    pub rows_affected: u64,
    /// SQLite last insert rowid after the statement finishes.
    pub last_insert_rowid: i64,
}

/// Health probe details for the configured database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SqliteHealth {
    /// Whether the probe query succeeded.
    pub query_ok: bool,
    /// Opened database path or `:memory:`.
    pub database_path: String,
    /// Whether the database is opened read-only.
    pub read_only: bool,
    /// Current journal mode if readable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_mode: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_mode_defaults_to_immediate() {
        assert_eq!(TransactionMode::default(), TransactionMode::Immediate);
        assert_eq!(TransactionMode::default().begin_sql(), "BEGIN IMMEDIATE");
    }

    #[test]
    fn transaction_mode_parses_supported_values() {
        assert_eq!(
            TransactionMode::parse(Some("deferred")).unwrap(),
            TransactionMode::Deferred
        );
        assert_eq!(
            TransactionMode::parse(Some("immediate")).unwrap(),
            TransactionMode::Immediate
        );
        assert_eq!(
            TransactionMode::parse(Some("exclusive")).unwrap(),
            TransactionMode::Exclusive
        );
    }

    #[test]
    fn transaction_mode_rejects_unknown_values() {
        let err = TransactionMode::parse(Some("serializable")).unwrap_err();
        assert!(err.contains("unsupported transaction mode"));
    }

    #[test]
    fn batch_statement_roundtrip() {
        let stmt = BatchStatement {
            sql: "INSERT INTO widgets(name) VALUES (?1)".into(),
            params: vec![serde_json::json!("gizmo")],
        };

        let json = serde_json::to_string(&stmt).unwrap();
        let decoded: BatchStatement = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, stmt);
    }
}
