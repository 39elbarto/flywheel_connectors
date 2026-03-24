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

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
    pub const fn new() -> Self {
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
    pub const fn rows_affected(mut self, count: u64) -> Self {
        self.rows_affected = Some(count);
        self.is_mutation = true;
        self
    }

    /// Mark as a mutation query.
    #[must_use]
    pub const fn mutation(mut self) -> Self {
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
// Stateful Fixture Contracts
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical family for stateful local non-mock fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatefulFixtureFamily {
    /// Relational engines reached over a local TCP socket or Unix domain socket.
    Relational,
    /// Embedded databases or other single-file state engines.
    Embedded,
    /// Object/blob stores or filesystem-backed bucket emulators.
    ObjectBlob,
    /// Namespaced key-value stores closely related to database acceptance work.
    KeyValue,
}

/// Stable artifact kind for stateful fixture reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatefulFixtureArtifactKind {
    /// Structured JSON payload.
    Json,
    /// JSON Lines event stream.
    Jsonl,
    /// Plain-text summary or stderr capture.
    Text,
    /// Replay script or equivalent command recipe.
    Replay,
    /// Directory-style artifact containing seeded state or snapshots.
    Directory,
}

/// Artifact descriptor for seeded stateful fixture runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatefulFixtureArtifactDescriptor {
    /// Stable artifact label within the run report.
    pub label: String,
    /// Artifact kind (`json`, `jsonl`, `text`, `replay`, etc.).
    pub kind: StatefulFixtureArtifactKind,
    /// Expected file name or bundle-relative path hint.
    pub path_hint: String,
    /// Operator-facing description of the artifact.
    pub description: String,
}

impl StatefulFixtureArtifactDescriptor {
    /// Build a canonical artifact descriptor.
    #[must_use]
    pub fn new(
        label: &str,
        kind: StatefulFixtureArtifactKind,
        path_hint: &str,
        description: &str,
    ) -> Self {
        Self {
            label: label.to_string(),
            kind,
            path_hint: path_hint.to_string(),
            description: description.to_string(),
        }
    }
}

/// Existing helper seam that downstream stateful acceptance work should promote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatefulFixtureHelperReference {
    /// Module or crate path that already owns the behavior.
    pub symbol: String,
    /// Short explanation of why this helper should be reused.
    pub responsibility: String,
}

impl StatefulFixtureHelperReference {
    /// Build a helper reference entry.
    #[must_use]
    pub fn new(symbol: &str, responsibility: &str) -> Self {
        Self {
            symbol: symbol.to_string(),
            responsibility: responsibility.to_string(),
        }
    }
}

/// Canonical startup probe surface for a stateful fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStartupProbeKind {
    /// TCP socket accepts a connection.
    TcpConnect,
    /// Health or ping query succeeds against the local engine.
    SqlPing,
    /// A local file or directory exists and is accessible.
    PathExists,
    /// A namespace, bucket, or prefix can be listed.
    NamespaceList,
}

/// Startup probe that proves the local engine is ready before test execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureStartupProbe {
    /// Stable identifier for the probe.
    pub probe_id: String,
    /// Probe mechanism.
    pub kind: FixtureStartupProbeKind,
    /// Host/path/bucket or other target materializing readiness.
    pub target: String,
    /// Timeout budget for the probe.
    pub timeout_ms: u64,
    /// Human-facing description of what success proves.
    pub success_criteria: String,
}

impl FixtureStartupProbe {
    /// Build a startup probe.
    #[must_use]
    pub fn new(
        probe_id: &str,
        kind: FixtureStartupProbeKind,
        target: &str,
        timeout_ms: u64,
        success_criteria: &str,
    ) -> Self {
        Self {
            probe_id: probe_id.to_string(),
            kind,
            target: target.to_string(),
            timeout_ms,
            success_criteria: success_criteria.to_string(),
        }
    }
}

/// Deterministic record of state preloaded into a truthful local fixture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixtureSeedRecord {
    /// Table, bucket, namespace, or similar scope.
    pub resource: String,
    /// Stable row key, object key, or equivalent identifier.
    pub identifier: String,
    /// Serialized seed payload used by the fixture.
    pub payload: Value,
    /// Stable digest for quick comparisons and artifact summaries.
    pub payload_digest: String,
}

impl FixtureSeedRecord {
    /// Build a seed record and compute its content digest.
    #[must_use]
    pub fn new(resource: &str, identifier: &str, payload: Value) -> Self {
        let payload_digest = digest_json_value(&payload);
        Self {
            resource: resource.to_string(),
            identifier: identifier.to_string(),
            payload,
            payload_digest,
        }
    }
}

/// A state mutation the fixture run is expected to exercise.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixtureMutationRecord {
    /// Mutation operation (`insert`, `update`, `delete`, `put`, etc.).
    pub operation: String,
    /// Table, bucket, namespace, or similar scope.
    pub resource: String,
    /// Stable row key, object key, or equivalent identifier.
    pub identifier: String,
    /// Optional pre-mutation payload or summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    /// Optional post-mutation payload or summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    /// Human-facing statement of what the mutation proves.
    pub expectation: String,
}

impl FixtureMutationRecord {
    /// Build a mutation record.
    #[must_use]
    pub fn new(operation: &str, resource: &str, identifier: &str, expectation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            resource: resource.to_string(),
            identifier: identifier.to_string(),
            before: None,
            after: None,
            expectation: expectation.to_string(),
        }
    }

    /// Attach the pre-mutation payload.
    #[must_use]
    pub fn with_before(mut self, before: Value) -> Self {
        self.before = Some(before);
        self
    }

    /// Attach the post-mutation payload.
    #[must_use]
    pub fn with_after(mut self, after: Value) -> Self {
        self.after = Some(after);
        self
    }
}

/// Cleanup check that must pass before a stateful fixture run is considered rerunnable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureCleanupCheck {
    /// Stable identifier for the cleanup check.
    pub check_id: String,
    /// Table, bucket, namespace, or similar scope.
    pub resource: String,
    /// Verification mechanism (`query_row_digest`, `prefix_empty`, etc.).
    pub method: String,
    /// Expected final state after teardown completes.
    pub expected_state: String,
}

impl FixtureCleanupCheck {
    /// Build a cleanup check.
    #[must_use]
    pub fn new(check_id: &str, resource: &str, method: &str, expected_state: &str) -> Self {
        Self {
            check_id: check_id.to_string(),
            resource: resource.to_string(),
            method: method.to_string(),
            expected_state: expected_state.to_string(),
        }
    }
}

/// Cleanup verification emitted after a stateful fixture teardown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CleanupVerificationResult {
    /// Cleanup check identifier that was exercised.
    pub check_id: String,
    /// Table, bucket, namespace, or similar scope.
    pub resource: String,
    /// Verification mechanism used at runtime.
    pub method: String,
    /// Expected final state.
    pub expected_state: String,
    /// Observed teardown state or summary.
    pub observed: Value,
    /// Whether the verification passed.
    pub passed: bool,
}

impl CleanupVerificationResult {
    /// Build a cleanup verification result.
    #[must_use]
    pub fn new(
        check_id: &str,
        resource: &str,
        method: &str,
        expected_state: &str,
        observed: Value,
        passed: bool,
    ) -> Self {
        Self {
            check_id: check_id.to_string(),
            resource: resource.to_string(),
            method: method.to_string(),
            expected_state: expected_state.to_string(),
            observed,
            passed,
        }
    }
}

/// Serializable contract for a seeded truthful local fixture pack.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SeededStatefulFixturePack {
    /// Version marker for the contract itself.
    pub contract_version: String,
    /// Required suite class from the acceptance taxonomy.
    pub suite_class: String,
    /// Stable fixture pack identifier.
    pub fixture_id: String,
    /// Fixture family.
    pub family: StatefulFixtureFamily,
    /// Concrete engine or emulator name.
    pub engine: String,
    /// Existing helpers that should be promoted rather than replaced.
    pub promoted_helpers: Vec<StatefulFixtureHelperReference>,
    /// Run-level artifacts every compliant harness should emit.
    pub artifacts: Vec<StatefulFixtureArtifactDescriptor>,
    /// Readiness checks that must pass before the suite starts.
    pub startup_probes: Vec<FixtureStartupProbe>,
    /// Deterministic initial state seeded into the local engine.
    pub seeded_state: Vec<FixtureSeedRecord>,
    /// Stateful mutations the suite is expected to exercise.
    pub mutation_plan: Vec<FixtureMutationRecord>,
    /// Teardown checks proving the fixture is safe to rerun.
    pub cleanup_checks: Vec<FixtureCleanupCheck>,
}

impl SeededStatefulFixturePack {
    /// Build a new seeded fixture pack with canonical helpers and artifacts.
    #[must_use]
    pub fn new(fixture_id: &str, family: StatefulFixtureFamily, engine: &str) -> Self {
        Self {
            contract_version: "stateful-fixture-contract/v1".to_string(),
            suite_class: "local_non_mock".to_string(),
            fixture_id: fixture_id.to_string(),
            family,
            engine: engine.to_string(),
            promoted_helpers: canonical_stateful_fixture_helpers(),
            artifacts: canonical_stateful_fixture_artifacts(),
            startup_probes: Vec::new(),
            seeded_state: Vec::new(),
            mutation_plan: Vec::new(),
            cleanup_checks: Vec::new(),
        }
    }

    /// Attach a startup probe.
    #[must_use]
    pub fn with_startup_probe(mut self, probe: FixtureStartupProbe) -> Self {
        self.startup_probes.push(probe);
        self
    }

    /// Attach a seed record.
    #[must_use]
    pub fn with_seed(mut self, seed: FixtureSeedRecord) -> Self {
        self.seeded_state.push(seed);
        self
    }

    /// Attach a mutation record.
    #[must_use]
    pub fn with_mutation(mut self, mutation: FixtureMutationRecord) -> Self {
        self.mutation_plan.push(mutation);
        self
    }

    /// Attach a cleanup check.
    #[must_use]
    pub fn with_cleanup_check(mut self, cleanup_check: FixtureCleanupCheck) -> Self {
        self.cleanup_checks.push(cleanup_check);
        self
    }

    /// Attach an additional artifact descriptor.
    #[must_use]
    pub fn with_artifact(mut self, artifact: StatefulFixtureArtifactDescriptor) -> Self {
        self.artifacts.push(artifact);
        self
    }

    /// Attach an additional helper reference.
    #[must_use]
    pub fn with_promoted_helper(mut self, helper: StatefulFixtureHelperReference) -> Self {
        self.promoted_helpers.push(helper);
        self
    }

    /// Serialize the pack to JSON for manifest/report emission.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).expect("seeded stateful fixture pack should serialize")
    }

    fn has_cleanup_for_resource(&self, resource: &str) -> bool {
        self.cleanup_checks
            .iter()
            .any(|cleanup_check| cleanup_check.resource == resource)
    }
}

/// Canonical artifact inventory for seeded stateful fixture acceptance runs.
#[must_use]
pub fn canonical_stateful_fixture_artifacts() -> Vec<StatefulFixtureArtifactDescriptor> {
    vec![
        StatefulFixtureArtifactDescriptor::new(
            "logs-jsonl",
            StatefulFixtureArtifactKind::Jsonl,
            "logs.jsonl",
            "schema-valid event stream for the stateful acceptance run",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "logs-stable-jsonl",
            StatefulFixtureArtifactKind::Jsonl,
            "logs.stable.jsonl",
            "stable normalized event stream for deterministic diffs",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "report-json",
            StatefulFixtureArtifactKind::Json,
            "report.json",
            "machine-readable run report with step, artifact, and failure metadata",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "summary-txt",
            StatefulFixtureArtifactKind::Text,
            "summary.txt",
            "human-readable triage summary for operators",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "scan-report",
            StatefulFixtureArtifactKind::Json,
            "scan-report.json",
            "secret and PII scan results for the emitted evidence bundle",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "environment-json",
            StatefulFixtureArtifactKind::Json,
            "environment.json",
            "redacted prerequisite and environment snapshot for replay",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "fixture-manifest",
            StatefulFixtureArtifactKind::Json,
            "fixture-manifest.json",
            "serialized seeded fixture contract for the exercised local engine",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "seed-state-json",
            StatefulFixtureArtifactKind::Json,
            "seed-state.json",
            "captured seeded rows, objects, namespaces, and digests",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "mutation-log-jsonl",
            StatefulFixtureArtifactKind::Jsonl,
            "mutations.jsonl",
            "ordered mutation ledger showing what state changed during the run",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "cleanup-report-json",
            StatefulFixtureArtifactKind::Json,
            "cleanup-report.json",
            "cleanup verification results proving the fixture is safe to rerun",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "state-snapshots",
            StatefulFixtureArtifactKind::Directory,
            "state/",
            "optional structured snapshots for seeded and cleaned fixture state",
        ),
        StatefulFixtureArtifactDescriptor::new(
            "replay-sh",
            StatefulFixtureArtifactKind::Replay,
            "replay.sh",
            "deterministic replay command sequence, including any required rch prefix",
        ),
    ]
}

/// Existing helper seams that downstream stateful fixture work should promote.
#[must_use]
pub fn canonical_stateful_fixture_helpers() -> Vec<StatefulFixtureHelperReference> {
    vec![
        StatefulFixtureHelperReference::new(
            "fcp_testkit::SeededStatefulFixturePack",
            "canonical contract for truthful local seeded fixture packs",
        ),
        StatefulFixtureHelperReference::new(
            "fcp_testkit::FixtureStartupProbe",
            "startup readiness checks before a connector touches seeded state",
        ),
        StatefulFixtureHelperReference::new(
            "fcp_testkit::FixtureSeedRecord",
            "stable seeded-state manifest with payload digests",
        ),
        StatefulFixtureHelperReference::new(
            "fcp_testkit::FixtureMutationRecord",
            "ordered mutation ledger describing state changes during the run",
        ),
        StatefulFixtureHelperReference::new(
            "fcp_testkit::FixtureCleanupCheck",
            "cleanup contract proving the fixture can be rerun safely",
        ),
        StatefulFixtureHelperReference::new(
            "fcp_testkit::EvidenceCollector",
            "shared artifact and evidence vocabulary for seeded-stateful runs",
        ),
        StatefulFixtureHelperReference::new(
            "fcp_testkit::LogRedactionScanner",
            "artifact secret and PII scan for acceptance evidence",
        ),
        StatefulFixtureHelperReference::new(
            "fcp_e2e::E2eRunReport",
            "machine-readable run envelope already used by shared E2E reporting",
        ),
        StatefulFixtureHelperReference::new(
            "fcp_e2e::E2eArtifactRecord",
            "stable label/kind/description artifact vocabulary for report emission",
        ),
    ]
}

/// Assert that a seeded fixture pack is complete enough for truthful local reruns.
///
/// # Panics
///
/// Panics if required contract fields or artifact coverage are missing.
pub fn assert_stateful_fixture_pack_complete(pack: &SeededStatefulFixturePack) {
    assert_eq!(
        pack.suite_class, "local_non_mock",
        "stateful fixture packs must target the local_non_mock suite class"
    );
    assert!(
        !pack.fixture_id.is_empty(),
        "seeded stateful fixture packs must have a fixture_id"
    );
    assert!(
        !pack.engine.is_empty(),
        "seeded stateful fixture packs must declare an engine"
    );
    assert!(
        !pack.startup_probes.is_empty(),
        "seeded stateful fixture packs must define at least one startup probe"
    );
    assert!(
        !pack.seeded_state.is_empty(),
        "seeded stateful fixture packs must record seeded state"
    );
    assert!(
        !pack.mutation_plan.is_empty(),
        "seeded stateful fixture packs must declare an expected mutation plan"
    );
    assert!(
        !pack.cleanup_checks.is_empty(),
        "seeded stateful fixture packs must define cleanup verification"
    );

    let probe_ids: BTreeSet<&str> = pack
        .startup_probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect();
    assert_eq!(
        probe_ids.len(),
        pack.startup_probes.len(),
        "stateful fixture startup probe ids must be unique"
    );

    let cleanup_ids: BTreeSet<&str> = pack
        .cleanup_checks
        .iter()
        .map(|cleanup_check| cleanup_check.check_id.as_str())
        .collect();
    assert_eq!(
        cleanup_ids.len(),
        pack.cleanup_checks.len(),
        "stateful fixture cleanup check ids must be unique"
    );

    let declared_artifacts: BTreeSet<&str> = pack
        .artifacts
        .iter()
        .map(|artifact| artifact.label.as_str())
        .collect();
    let missing_labels: Vec<String> = canonical_stateful_fixture_artifacts()
        .into_iter()
        .filter(|artifact| !declared_artifacts.contains(artifact.label.as_str()))
        .map(|artifact| artifact.label)
        .collect();
    assert!(
        missing_labels.is_empty(),
        "stateful fixture packs are missing canonical artifact labels: {missing_labels:?}"
    );

    assert_mutation_plan_has_cleanup(pack);
}

/// Assert that every mutation target has a cleanup contract.
///
/// # Panics
///
/// Panics if any mutation lacks a corresponding cleanup check.
pub fn assert_mutation_plan_has_cleanup(pack: &SeededStatefulFixturePack) {
    let missing_resources: BTreeSet<&str> = pack
        .mutation_plan
        .iter()
        .filter(|mutation| !pack.has_cleanup_for_resource(&mutation.resource))
        .map(|mutation| mutation.resource.as_str())
        .collect();
    assert!(
        missing_resources.is_empty(),
        "stateful fixture mutation targets missing cleanup coverage: {:?}",
        missing_resources.into_iter().collect::<Vec<_>>()
    );
}

fn digest_json_value(value: &Value) -> String {
    let payload =
        serde_json::to_vec(value).expect("serde_json::Value should always serialize to bytes");
    blake3::hash(&payload).to_hex().to_string()
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
    pub const fn new() -> Self {
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
/// Panics if `rows_affected` doesn't match or is not set.
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
        tracker
            .queries()
            .iter()
            .filter(|q| !q.parameterized)
            .count(),
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

    #[test]
    fn seed_record_stores_stable_digest() {
        let left = FixtureSeedRecord::new(
            "users",
            "user-1",
            json!({"id": 1, "email": "alice@example.com"}),
        );
        let right = FixtureSeedRecord::new(
            "users",
            "user-1",
            json!({"id": 1, "email": "alice@example.com"}),
        );

        assert_eq!(left.payload_digest, right.payload_digest);
        assert!(!left.payload_digest.is_empty());
    }

    #[test]
    fn stateful_fixture_pack_complete_when_seeded_and_cleanup_is_declared() {
        let pack = SeededStatefulFixturePack::new(
            "sqlite-local-pack",
            StatefulFixtureFamily::Embedded,
            "sqlite",
        )
        .with_startup_probe(FixtureStartupProbe::new(
            "probe-db-file",
            FixtureStartupProbeKind::PathExists,
            "/tmp/sqlite-fixtures/test.db",
            1_000,
            "fixture database file exists before connector startup",
        ))
        .with_seed(FixtureSeedRecord::new(
            "users",
            "user-1",
            json!({"id": 1, "email": "alice@example.com"}),
        ))
        .with_mutation(
            FixtureMutationRecord::new(
                "update",
                "users",
                "user-1",
                "connector updates a seeded row in the real local database",
            )
            .with_after(json!({"id": 1, "email": "alice+updated@example.com"})),
        )
        .with_cleanup_check(FixtureCleanupCheck::new(
            "cleanup-users",
            "users",
            "query_row_digest",
            "seeded row digest matches the original seeded payload",
        ));

        assert_stateful_fixture_pack_complete(&pack);
        assert_eq!(pack.to_json()["suite_class"], "local_non_mock");
    }

    #[test]
    #[should_panic(expected = "mutation targets missing cleanup coverage")]
    fn stateful_fixture_pack_requires_cleanup_for_mutations() {
        let pack = SeededStatefulFixturePack::new(
            "postgres-pack",
            StatefulFixtureFamily::Relational,
            "postgres",
        )
        .with_startup_probe(FixtureStartupProbe::new(
            "probe-pg",
            FixtureStartupProbeKind::SqlPing,
            "127.0.0.1:5432/fcp_test",
            5_000,
            "database responds to a local health query",
        ))
        .with_seed(FixtureSeedRecord::new(
            "users",
            "user-1",
            json!({"id": 1, "email": "alice@example.com"}),
        ))
        .with_mutation(FixtureMutationRecord::new(
            "insert",
            "sessions",
            "sess-1",
            "connector inserts a session row during the test",
        ))
        .with_cleanup_check(FixtureCleanupCheck::new(
            "cleanup-users",
            "users",
            "query_row_digest",
            "seeded rows return to their original digest",
        ));

        assert_stateful_fixture_pack_complete(&pack);
    }
}
