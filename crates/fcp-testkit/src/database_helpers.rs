//! Database connector test helpers.
//!
//! Provides utilities for testing database-type connectors: mock query results,
//! connection state tracking, parameterized query assertions, and common
//! database response builders.
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::database_helpers::*;
//!
//! let result = QueryResultBuilder::new()
//!     .with_columns(&["id", "name", "email"])
//!     .add_row(vec![json!(1), json!("Alice"), json!("alice@example.com")])
//!     .add_row(vec![json!(2), json!("Bob"), json!("bob@example.com")])
//!     .build();
//!
//! assert_query_has_columns(&result, &["id", "name", "email"]);
//! assert_query_row_count(&result, 2);
//! ```

use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Mock Query Results
// ─────────────────────────────────────────────────────────────────────────────

/// A mock database query result for testing.
#[derive(Debug, Clone)]
pub struct MockQueryResult {
    /// Column names.
    pub columns: Vec<String>,
    /// Rows of values (each row has values matching columns).
    pub rows: Vec<Vec<Value>>,
    /// Number of rows affected (for INSERT/UPDATE/DELETE).
    pub rows_affected: Option<u64>,
    /// Whether the query was a read or write.
    pub is_mutation: bool,
}

impl MockQueryResult {
    /// Convert to a JSON value matching common connector response format.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let rows_json: Vec<Value> = self
            .rows
            .iter()
            .map(|row| {
                let mut obj = serde_json::Map::new();
                for (col, val) in self.columns.iter().zip(row.iter()) {
                    obj.insert(col.clone(), val.clone());
                }
                Value::Object(obj)
            })
            .collect();

        let mut result = json!({
            "columns": self.columns,
            "rows": rows_json,
            "row_count": self.rows.len(),
        });

        if let Some(affected) = self.rows_affected {
            result["rows_affected"] = json!(affected);
        }

        result
    }

    /// Get a column index by name.
    #[must_use]
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c == name)
    }

    /// Get a cell value by row and column name.
    #[must_use]
    pub fn cell(&self, row: usize, column: &str) -> Option<&Value> {
        let col_idx = self.column_index(column)?;
        self.rows.get(row)?.get(col_idx)
    }
}

/// Builder for constructing mock query results.
pub struct QueryResultBuilder {
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
    rows_affected: Option<u64>,
    is_mutation: bool,
}

impl QueryResultBuilder {
    /// Create a new empty query result builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
            rows_affected: None,
            is_mutation: false,
        }
    }

    /// Set the column names.
    #[must_use]
    pub fn with_columns(mut self, columns: &[&str]) -> Self {
        self.columns = columns.iter().map(|c| (*c).to_string()).collect();
        self
    }

    /// Add a row of values.
    #[must_use]
    pub fn add_row(mut self, values: Vec<Value>) -> Self {
        self.rows.push(values);
        self
    }

    /// Set rows affected count (for mutations).
    #[must_use]
    pub fn rows_affected(mut self, count: u64) -> Self {
        self.rows_affected = Some(count);
        self.is_mutation = true;
        self
    }

    /// Mark as a mutation query.
    #[must_use]
    pub fn mutation(mut self) -> Self {
        self.is_mutation = true;
        self
    }

    /// Build the mock query result.
    #[must_use]
    pub fn build(self) -> MockQueryResult {
        MockQueryResult {
            columns: self.columns,
            rows: self.rows,
            rows_affected: self.rows_affected,
            is_mutation: self.is_mutation,
        }
    }
}

impl Default for QueryResultBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Common Response Builders
// ─────────────────────────────────────────────────────────────────────────────

/// Build an empty query result (no rows).
#[must_use]
pub fn empty_result(columns: &[&str]) -> MockQueryResult {
    QueryResultBuilder::new().with_columns(columns).build()
}

/// Build a single-row result.
#[must_use]
pub fn single_row_result(columns: &[&str], values: Vec<Value>) -> MockQueryResult {
    QueryResultBuilder::new()
        .with_columns(columns)
        .add_row(values)
        .build()
}

/// Build a mutation result (INSERT/UPDATE/DELETE).
#[must_use]
pub fn mutation_result(rows_affected: u64) -> MockQueryResult {
    QueryResultBuilder::new()
        .rows_affected(rows_affected)
        .build()
}

/// Build an error response value for database operations.
#[must_use]
pub fn db_error_response(code: &str, message: &str) -> Value {
    json!({
        "error": {
            "code": code,
            "message": message,
        }
    })
}

/// Build a connection error response.
#[must_use]
pub fn connection_error(message: &str) -> Value {
    db_error_response("CONNECTION_ERROR", message)
}

/// Build a query syntax error response.
#[must_use]
pub fn syntax_error(message: &str) -> Value {
    db_error_response("SYNTAX_ERROR", message)
}

/// Build a permission denied error response.
#[must_use]
pub fn permission_denied(message: &str) -> Value {
    db_error_response("PERMISSION_DENIED", message)
}

// ─────────────────────────────────────────────────────────────────────────────
// Query Parameter Tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks queries executed during a test for verification.
#[derive(Debug, Clone, Default)]
pub struct QueryTracker {
    queries: Vec<TrackedQuery>,
}

/// A tracked query with its parameters.
#[derive(Debug, Clone)]
pub struct TrackedQuery {
    /// The SQL or query string.
    pub query: String,
    /// Bound parameters (if parameterized).
    pub params: Vec<Value>,
    /// Whether this was a parameterized query.
    pub parameterized: bool,
}

impl QueryTracker {
    /// Create a new query tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queries: Vec::new(),
        }
    }

    /// Record a raw (non-parameterized) query.
    pub fn record_raw(&mut self, query: &str) {
        self.queries.push(TrackedQuery {
            query: query.to_string(),
            params: Vec::new(),
            parameterized: false,
        });
    }

    /// Record a parameterized query with bound values.
    pub fn record_parameterized(&mut self, query: &str, params: Vec<Value>) {
        self.queries.push(TrackedQuery {
            query: query.to_string(),
            params,
            parameterized: true,
        });
    }

    /// Get the total number of queries executed.
    #[must_use]
    pub fn query_count(&self) -> usize {
        self.queries.len()
    }

    /// Get all tracked queries.
    #[must_use]
    pub fn queries(&self) -> &[TrackedQuery] {
        &self.queries
    }

    /// Check if any raw (non-parameterized) queries were executed.
    #[must_use]
    pub fn has_raw_queries(&self) -> bool {
        self.queries.iter().any(|q| !q.parameterized)
    }

    /// Clear all tracked queries.
    pub fn clear(&mut self) {
        self.queries.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Query Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that a query result has the expected column names.
///
/// # Panics
///
/// Panics if columns don't match.
pub fn assert_query_has_columns(result: &MockQueryResult, expected: &[&str]) {
    let expected_vec: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(
        result.columns, expected_vec,
        "Expected columns {expected_vec:?} but got {:?}",
        result.columns
    );
}

/// Assert that a query result has the expected number of rows.
///
/// # Panics
///
/// Panics if row count doesn't match.
pub fn assert_query_row_count(result: &MockQueryResult, expected: usize) {
    assert_eq!(
        result.rows.len(),
        expected,
        "Expected {expected} rows but got {}",
        result.rows.len()
    );
}

/// Assert that a mutation result affected the expected number of rows.
///
/// # Panics
///
/// Panics if rows_affected doesn't match or is not set.
pub fn assert_rows_affected(result: &MockQueryResult, expected: u64) {
    let actual = result
        .rows_affected
        .expect("Expected rows_affected to be set");
    assert_eq!(
        actual, expected,
        "Expected {expected} rows affected but got {actual}"
    );
}

/// Assert that a cell value matches.
///
/// # Panics
///
/// Panics if cell value doesn't match or row/column is out of bounds.
pub fn assert_cell_eq(result: &MockQueryResult, row: usize, column: &str, expected: &Value) {
    let actual = result
        .cell(row, column)
        .unwrap_or_else(|| panic!("Cell ({row}, {column}) not found"));
    assert_eq!(
        actual, expected,
        "Expected cell ({row}, {column}) = {expected} but got {actual}"
    );
}

/// Assert that no raw (non-parameterized) queries were executed.
///
/// This is a security assertion — raw queries are vulnerable to SQL injection.
///
/// # Panics
///
/// Panics if any raw queries were found.
pub fn assert_no_raw_queries(tracker: &QueryTracker) {
    assert!(
        !tracker.has_raw_queries(),
        "Expected all queries to be parameterized but found {} raw queries: {:?}",
        tracker.queries().iter().filter(|q| !q.parameterized).count(),
        tracker
            .queries()
            .iter()
            .filter(|q| !q.parameterized)
            .map(|q| &q.query)
            .collect::<Vec<_>>()
    );
}

/// Assert that at least one query was executed.
///
/// # Panics
///
/// Panics if no queries were tracked.
pub fn assert_queries_executed(tracker: &QueryTracker) {
    assert!(
        tracker.query_count() > 0,
        "Expected at least one query to be executed but none were tracked"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_result_builder() {
        let result = QueryResultBuilder::new()
            .with_columns(&["id", "name", "email"])
            .add_row(vec![json!(1), json!("Alice"), json!("alice@ex.com")])
            .add_row(vec![json!(2), json!("Bob"), json!("bob@ex.com")])
            .build();

        assert_eq!(result.columns.len(), 3);
        assert_eq!(result.rows.len(), 2);
        assert!(!result.is_mutation);
    }

    #[test]
    fn test_query_result_to_json() {
        let result = QueryResultBuilder::new()
            .with_columns(&["id", "name"])
            .add_row(vec![json!(1), json!("Alice")])
            .build();

        let json_val = result.to_json();
        assert_eq!(json_val["row_count"], 1);
        assert_eq!(json_val["rows"][0]["name"], "Alice");
    }

    #[test]
    fn test_mutation_result() {
        let result = mutation_result(5);
        assert!(result.is_mutation);
        assert_rows_affected(&result, 5);
    }

    #[test]
    fn test_empty_result() {
        let result = empty_result(&["id", "value"]);
        assert_query_row_count(&result, 0);
        assert_query_has_columns(&result, &["id", "value"]);
    }

    #[test]
    fn test_single_row_result() {
        let result = single_row_result(&["count"], vec![json!(42)]);
        assert_query_row_count(&result, 1);
        assert_cell_eq(&result, 0, "count", &json!(42));
    }

    #[test]
    fn test_cell_access() {
        let result = QueryResultBuilder::new()
            .with_columns(&["x", "y"])
            .add_row(vec![json!(10), json!(20)])
            .build();
        assert_eq!(result.cell(0, "x"), Some(&json!(10)));
        assert_eq!(result.cell(0, "y"), Some(&json!(20)));
        assert_eq!(result.cell(0, "z"), None);
        assert_eq!(result.cell(1, "x"), None);
    }

    #[test]
    fn test_query_tracker() {
        let mut tracker = QueryTracker::new();
        tracker.record_parameterized("SELECT * FROM users WHERE id = $1", vec![json!(42)]);
        tracker.record_raw("SELECT 1");

        assert_eq!(tracker.query_count(), 2);
        assert!(tracker.has_raw_queries());
        assert!(tracker.queries()[0].parameterized);
        assert!(!tracker.queries()[1].parameterized);
    }

    #[test]
    fn test_no_raw_queries_assertion() {
        let mut tracker = QueryTracker::new();
        tracker.record_parameterized("SELECT $1", vec![json!("test")]);
        assert_no_raw_queries(&tracker);
    }

    #[test]
    #[should_panic(expected = "Expected all queries to be parameterized")]
    fn test_no_raw_queries_assertion_fails_on_raw() {
        let mut tracker = QueryTracker::new();
        tracker.record_raw("SELECT * FROM users");
        assert_no_raw_queries(&tracker);
    }

    #[test]
    fn test_db_error_responses() {
        let err = connection_error("host unreachable");
        assert_eq!(err["error"]["code"], "CONNECTION_ERROR");
        assert_eq!(err["error"]["message"], "host unreachable");

        let err = syntax_error("unexpected token");
        assert_eq!(err["error"]["code"], "SYNTAX_ERROR");

        let err = permission_denied("insufficient privileges");
        assert_eq!(err["error"]["code"], "PERMISSION_DENIED");
    }

    #[test]
    fn test_column_index() {
        let result = QueryResultBuilder::new()
            .with_columns(&["a", "b", "c"])
            .build();
        assert_eq!(result.column_index("a"), Some(0));
        assert_eq!(result.column_index("c"), Some(2));
        assert_eq!(result.column_index("d"), None);
    }

    #[test]
    fn test_query_tracker_clear() {
        let mut tracker = QueryTracker::new();
        tracker.record_raw("SELECT 1");
        assert_eq!(tracker.query_count(), 1);
        tracker.clear();
        assert_eq!(tracker.query_count(), 0);
    }
}
