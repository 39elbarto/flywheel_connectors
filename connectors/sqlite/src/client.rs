//! SQLite client and local query execution helpers.

#![allow(clippy::doc_markdown)]

use std::fmt;
use std::path::Path;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rusqlite::{
    Connection, OpenFlags,
    hooks::{AuthAction, AuthContext, Authorization},
    params_from_iter,
    types::Value as SqlValue,
};
use serde_json::json;
use tracing::warn;

use crate::{
    error::{SqliteError, SqliteResult},
    types::{
        BatchStatement, BatchStatementResult, ExecuteResult, QueryColumn, QueryResult,
        SchemaColumn, SqliteConfig, SqliteHealth, TableInfo, TransactionMode,
    },
};

const ALLOWED_PRAGMAS: &[&str] = &[
    "application_id",
    "auto_vacuum",
    "cache_size",
    "compile_options",
    "encoding",
    "foreign_keys",
    "freelist_count",
    "journal_mode",
    "locking_mode",
    "mmap_size",
    "page_count",
    "page_size",
    "schema_version",
    "synchronous",
    "temp_store",
    "user_version",
    "wal_autocheckpoint",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorizerPolicy {
    ReadOnly,
    Write,
    PragmaRead,
}

fn authorize_read_only(ctx: AuthContext<'_>) -> Authorization {
    authorize(AuthorizerPolicy::ReadOnly, ctx)
}

fn authorize_write(ctx: AuthContext<'_>) -> Authorization {
    authorize(AuthorizerPolicy::Write, ctx)
}

fn authorize_pragma_read(ctx: AuthContext<'_>) -> Authorization {
    authorize(AuthorizerPolicy::PragmaRead, ctx)
}

fn authorize(policy: AuthorizerPolicy, ctx: AuthContext<'_>) -> Authorization {
    match ctx.action {
        AuthAction::Attach { .. }
        | AuthAction::Detach { .. }
        | AuthAction::CreateVtable { .. }
        | AuthAction::DropVtable { .. } => Authorization::Deny,
        AuthAction::Function { function_name }
            if function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Deny
        }
        AuthAction::Pragma { .. } => match policy {
            AuthorizerPolicy::PragmaRead => Authorization::Allow,
            AuthorizerPolicy::ReadOnly | AuthorizerPolicy::Write => Authorization::Deny,
        },
        AuthAction::Transaction { .. } => Authorization::Deny,
        // Only allow the batch wrapper's own savepoint under Write; reject all
        // user-supplied SAVEPOINT/RELEASE/ROLLBACK TO statements so callers
        // cannot implicitly open nested transactions.
        AuthAction::Savepoint { savepoint_name, .. }
            if matches!(policy, AuthorizerPolicy::Write)
                && savepoint_name == "fcp_sqlite_batch" =>
        {
            Authorization::Allow
        }
        AuthAction::Savepoint { .. } => Authorization::Deny,
        AuthAction::Select | AuthAction::Read { .. } | AuthAction::Recursive => {
            Authorization::Allow
        }
        AuthAction::Function { .. } => Authorization::Allow,
        _ => match policy {
            AuthorizerPolicy::ReadOnly | AuthorizerPolicy::PragmaRead => Authorization::Deny,
            AuthorizerPolicy::Write => Authorization::Allow,
        },
    }
}

/// Local SQLite client.
pub struct SqliteClient {
    config: SqliteConfig,
    connection: Connection,
}

impl fmt::Debug for SqliteClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteClient")
            .field("config", &self.config)
            .finish()
    }
}

impl SqliteClient {
    /// Open a SQLite client using the supplied configuration.
    pub fn new(config: SqliteConfig) -> SqliteResult<Self> {
        let connection = open_connection(&config)?;
        apply_connection_settings(&connection, &config)?;
        Ok(Self { config, connection })
    }

    /// Read the client configuration.
    #[must_use]
    pub const fn config(&self) -> &SqliteConfig {
        &self.config
    }

    /// Health probe against the currently open database.
    pub fn health_check(&self) -> SqliteResult<SqliteHealth> {
        let query_ok = self
            .connection
            .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .map(|value| value == 1)?;
        let journal_mode = self
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
            .ok();

        Ok(SqliteHealth {
            query_ok,
            database_path: self.config.database_path.clone(),
            read_only: self.config.read_only,
            journal_mode,
        })
    }

    /// Execute a read-only query.
    pub fn query(&self, sql: &str, params: &[serde_json::Value]) -> SqliteResult<QueryResult> {
        let statement = self.connection.prepare(sql)?;
        if !statement.readonly() {
            return Err(SqliteError::Policy(
                "sqlite.query accepts only read-only statements".into(),
            ));
        }
        drop(statement);

        self.with_authorizer(AuthorizerPolicy::ReadOnly, |connection| {
            let mut statement = connection.prepare(sql)?;
            collect_query_result(&mut statement, params)
        })
    }

    /// Execute `EXPLAIN QUERY PLAN` for a read-only query.
    pub fn explain(&self, sql: &str, params: &[serde_json::Value]) -> SqliteResult<QueryResult> {
        let statement = self.connection.prepare(sql)?;
        if !statement.readonly() {
            return Err(SqliteError::Policy(
                "sqlite.explain accepts only read-only statements".into(),
            ));
        }
        drop(statement);

        self.with_authorizer(AuthorizerPolicy::ReadOnly, |connection| {
            let explain_sql = format!("EXPLAIN QUERY PLAN {sql}");
            let mut statement = connection.prepare(&explain_sql)?;
            collect_query_result(&mut statement, params)
        })
    }

    /// Execute a single non-returning mutating statement.
    pub fn execute(&self, sql: &str, params: &[serde_json::Value]) -> SqliteResult<ExecuteResult> {
        self.with_authorizer(AuthorizerPolicy::Write, |connection| {
            execute_statement(connection, sql, params)
        })
    }

    /// List user tables in the main database.
    pub fn list_tables(&self) -> SqliteResult<Vec<TableInfo>> {
        let mut statement = self.connection.prepare(
            "SELECT schema, name, type, ncol, wr, strict \
             FROM pragma_table_list \
             WHERE schema = 'main' AND type = 'table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name",
        )?;
        let mut rows = statement.query([])?;
        let mut tables = Vec::new();

        while let Some(row) = rows.next()? {
            tables.push(TableInfo {
                schema: row.get::<_, String>(0)?,
                name: row.get::<_, String>(1)?,
                table_type: row.get::<_, String>(2)?,
                column_count: row.get::<_, i64>(3)? as u64,
                without_rowid: row.get::<_, i64>(4)? != 0,
                strict: row.get::<_, i64>(5)? != 0,
            });
        }

        Ok(tables)
    }

    /// Describe columns for a table.
    pub fn list_columns(&self, table: &str) -> SqliteResult<Vec<SchemaColumn>> {
        let mut statement = self.connection.prepare(
            "SELECT cid, name, type, \"notnull\", dflt_value, pk, hidden \
             FROM pragma_table_xinfo(?1) \
             ORDER BY cid",
        )?;
        let params = [serde_json::Value::String(table.to_string())];
        let values = json_params_to_sql_values(&params)?;
        let mut rows = statement.query(params_from_iter(values.iter()))?;
        let mut columns = Vec::new();

        while let Some(row) = rows.next()? {
            columns.push(SchemaColumn {
                cid: row.get::<_, i64>(0)?,
                name: row.get::<_, String>(1)?,
                data_type: row.get::<_, String>(2)?,
                not_null: row.get::<_, i64>(3)? != 0,
                default_value: row.get::<_, Option<String>>(4)?,
                primary_key: row.get::<_, i64>(5)? != 0,
                hidden: row.get::<_, i64>(6)? != 0,
            });
        }

        Ok(columns)
    }

    /// Begin a transaction with the requested mode.
    pub fn begin_transaction(&self, mode: TransactionMode) -> SqliteResult<()> {
        self.connection.execute_batch(mode.begin_sql())?;
        Ok(())
    }

    /// Commit the active transaction.
    pub fn commit_transaction(&self) -> SqliteResult<()> {
        self.connection.execute_batch("COMMIT")?;
        Ok(())
    }

    /// Roll back the active transaction.
    pub fn rollback_transaction(&self) -> SqliteResult<()> {
        self.connection.execute_batch("ROLLBACK")?;
        Ok(())
    }

    /// Execute a batch atomically via a savepoint.
    pub fn batch(&self, statements: &[BatchStatement]) -> SqliteResult<Vec<BatchStatementResult>> {
        if statements.is_empty() {
            return Err(SqliteError::InvalidInput(
                "sqlite.batch requires at least one statement".into(),
            ));
        }

        self.with_authorizer(AuthorizerPolicy::Write, |connection| {
            connection.execute_batch("SAVEPOINT fcp_sqlite_batch")?;

            let result = (|| {
                let mut results = Vec::with_capacity(statements.len());
                for (index, statement) in statements.iter().enumerate() {
                    let exec = execute_statement(connection, &statement.sql, &statement.params)?;
                    results.push(BatchStatementResult {
                        index,
                        rows_affected: exec.rows_affected,
                        last_insert_rowid: exec.last_insert_rowid,
                    });
                }
                Ok(results)
            })();

            match result {
                Ok(results) => {
                    connection.execute_batch("RELEASE SAVEPOINT fcp_sqlite_batch")?;
                    Ok(results)
                }
                Err(error) => {
                    let _ = connection.execute_batch(
                        "ROLLBACK TO SAVEPOINT fcp_sqlite_batch; RELEASE SAVEPOINT fcp_sqlite_batch",
                    );
                    Err(error)
                }
            }
        })
    }

    /// Read an allowlisted pragma.
    pub fn read_pragma(&self, name: &str) -> SqliteResult<QueryResult> {
        let normalized = normalize_pragma_name(name)?;
        if !ALLOWED_PRAGMAS.contains(&normalized.as_str()) {
            return Err(SqliteError::Pragma(format!(
                "pragma `{normalized}` is not allowlisted"
            )));
        }

        self.with_authorizer(AuthorizerPolicy::PragmaRead, |connection| {
            let sql = format!("PRAGMA {normalized}");
            let mut statement = connection.prepare(&sql)?;
            collect_query_result(&mut statement, &[])
        })
    }

    /// Run `VACUUM`.
    pub fn vacuum(&self) -> SqliteResult<ExecuteResult> {
        self.connection.execute_batch("VACUUM")?;
        Ok(ExecuteResult {
            rows_affected: 0,
            last_insert_rowid: self.connection.last_insert_rowid(),
        })
    }

    fn with_authorizer<T>(
        &self,
        policy: AuthorizerPolicy,
        operation: impl FnOnce(&Connection) -> SqliteResult<T>,
    ) -> SqliteResult<T> {
        let hook = match policy {
            AuthorizerPolicy::ReadOnly => {
                authorize_read_only as fn(AuthContext<'_>) -> Authorization
            }
            AuthorizerPolicy::Write => authorize_write as fn(AuthContext<'_>) -> Authorization,
            AuthorizerPolicy::PragmaRead => {
                authorize_pragma_read as fn(AuthContext<'_>) -> Authorization
            }
        };
        self.connection.authorizer(Some(hook))?;

        let operation_result = operation(&self.connection);
        let reset_result = self
            .connection
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

        match (operation_result, reset_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(reset_error)) => Err(SqliteError::from(reset_error)),
            (Err(error), Err(_)) => Err(error),
        }
    }
}

fn open_connection(config: &SqliteConfig) -> SqliteResult<Connection> {
    if config.database_path == ":memory:" {
        return Ok(Connection::open_in_memory()?);
    }

    let mut flags = if config.read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | if config.create_if_missing {
                OpenFlags::SQLITE_OPEN_CREATE
            } else {
                OpenFlags::empty()
            }
    };
    flags |= OpenFlags::SQLITE_OPEN_URI;

    Ok(Connection::open_with_flags(
        Path::new(&config.database_path),
        flags,
    )?)
}

fn apply_connection_settings(connection: &Connection, config: &SqliteConfig) -> SqliteResult<()> {
    connection.busy_timeout(Duration::from_millis(config.busy_timeout_ms))?;

    if !config.read_only {
        if config.enforce_foreign_keys {
            connection.execute_batch("PRAGMA foreign_keys = ON")?;
        }

        if config.enable_wal && config.database_path != ":memory:" {
            match connection
                .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))
            {
                Ok(mode) if mode.eq_ignore_ascii_case("wal") => {}
                Ok(mode) => warn!(mode, "SQLite did not enter WAL mode"),
                Err(error) => warn!(%error, "Failed to request WAL mode"),
            }
        }
    }

    Ok(())
}

fn execute_statement(
    connection: &Connection,
    sql: &str,
    params: &[serde_json::Value],
) -> SqliteResult<ExecuteResult> {
    let mut statement = connection.prepare(sql)?;
    if statement.readonly() {
        return Err(SqliteError::Policy(
            "sqlite.execute accepts only mutating or DDL statements".into(),
        ));
    }
    if statement.column_count() > 0 {
        return Err(SqliteError::Policy(
            "sqlite.execute does not support statements that return rows".into(),
        ));
    }

    let values = json_params_to_sql_values(params)?;
    let rows_affected = statement.execute(params_from_iter(values.iter()))?;

    Ok(ExecuteResult {
        rows_affected: rows_affected as u64,
        last_insert_rowid: connection.last_insert_rowid(),
    })
}

fn collect_query_result(
    statement: &mut rusqlite::Statement<'_>,
    params: &[serde_json::Value],
) -> SqliteResult<QueryResult> {
    let columns = statement
        .columns()
        .into_iter()
        .enumerate()
        .map(|(ordinal, column)| QueryColumn {
            ordinal,
            name: column.name().to_string(),
            decl_type: column.decl_type().map(str::to_string),
        })
        .collect::<Vec<_>>();

    let values = json_params_to_sql_values(params)?;
    let mut rows = statement.query(params_from_iter(values.iter()))?;
    let mut result_rows = Vec::new();

    while let Some(row) = rows.next()? {
        let mut result_row = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            let value = row.get::<_, SqlValue>(index)?;
            result_row.push(sql_value_to_json(value));
        }
        result_rows.push(result_row);
    }

    Ok(QueryResult {
        columns,
        row_count: result_rows.len() as u64,
        rows: result_rows,
    })
}

fn json_params_to_sql_values(params: &[serde_json::Value]) -> SqliteResult<Vec<SqlValue>> {
    params.iter().map(json_to_sql_value).collect()
}

fn json_to_sql_value(value: &serde_json::Value) -> SqliteResult<SqlValue> {
    match value {
        serde_json::Value::Null => Ok(SqlValue::Null),
        serde_json::Value::Bool(flag) => Ok(SqlValue::Integer(i64::from(*flag))),
        serde_json::Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                Ok(SqlValue::Integer(integer))
            } else if let Some(float) = number.as_f64() {
                Ok(SqlValue::Real(float))
            } else {
                Err(SqliteError::InvalidInput(format!(
                    "unsupported JSON number `{number}`"
                )))
            }
        }
        serde_json::Value::String(text) => Ok(SqlValue::Text(text.clone())),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            Ok(SqlValue::Text(serde_json::to_string(value)?))
        }
    }
}

fn sql_value_to_json(value: SqlValue) -> serde_json::Value {
    match value {
        SqlValue::Null => serde_json::Value::Null,
        SqlValue::Integer(integer) => json!(integer),
        SqlValue::Real(real) => serde_json::Number::from_f64(real).map_or_else(
            || serde_json::Value::String(real.to_string()),
            serde_json::Value::Number,
        ),
        SqlValue::Text(text) => serde_json::Value::String(text),
        SqlValue::Blob(bytes) => json!({
            "$blob_base64": BASE64.encode(bytes),
        }),
    }
}

fn normalize_pragma_name(name: &str) -> SqliteResult<String> {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(SqliteError::Pragma("pragma name must not be empty".into()));
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_lowercase() || character == '_' || character.is_ascii_digit()
    }) {
        return Err(SqliteError::Pragma(format!(
            "pragma `{name}` contains unsupported characters"
        )));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_pragma_name_lowercases_supported_names() {
        assert_eq!(
            normalize_pragma_name("Journal_Mode").unwrap(),
            "journal_mode"
        );
    }

    #[test]
    fn normalize_pragma_name_rejects_invalid_characters() {
        let error = normalize_pragma_name("journal-mode").unwrap_err();
        assert!(matches!(error, SqliteError::Pragma(_)));
    }

    #[test]
    fn json_arrays_are_serialized_as_text_parameters() {
        let value = json_to_sql_value(&json!([1, 2, 3])).unwrap();
        assert_eq!(value, SqlValue::Text("[1,2,3]".into()));
    }

    #[test]
    fn sql_blob_values_are_base64_wrapped() {
        let json = sql_value_to_json(SqlValue::Blob(vec![1, 2, 3]));
        assert_eq!(json["$blob_base64"], "AQID");
    }
}
