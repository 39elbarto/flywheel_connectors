//! Heterogeneous batch execution: parse and plan a JSONL file of mixed operations.
//!
//! Each line is a self-contained operation with optional dependency ordering.
//! Independent operations can run in parallel; dependent ones execute in
//! topological order.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Batch operation entry ──────────────────────────────────────────────

/// A single operation in a heterogeneous batch file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOp {
    /// Unique step identifier within the batch.
    pub id: String,
    /// Connector slug (e.g. `github`, `slack`).
    pub connector: String,
    /// Operation name (e.g. `list_issues`, `send_message`).
    pub operation: String,
    /// Input payload for the operation.
    pub input: Value,
    /// IDs of operations that must complete before this one starts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

// ── Parse errors ───────────────────────────────────────────────────────

/// Errors that can occur during batch file parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchFileError {
    /// A line failed to parse as JSON.
    InvalidJson { line: usize, message: String },
    /// A required field is missing.
    MissingField { line: usize, field: &'static str },
    /// Duplicate operation ID.
    DuplicateId { id: String },
    /// A dependency references a non-existent operation.
    UnknownDependency { id: String, dependency: String },
    /// The dependency graph contains a cycle.
    CycleDetected { ids: Vec<String> },
    /// The batch file is empty.
    Empty,
}

impl std::fmt::Display for BatchFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson { line, message } => {
                write!(f, "line {line}: invalid JSON: {message}")
            }
            Self::MissingField { line, field } => {
                write!(f, "line {line}: missing required field '{field}'")
            }
            Self::DuplicateId { id } => write!(f, "duplicate operation id '{id}'"),
            Self::UnknownDependency { id, dependency } => {
                write!(f, "operation '{id}' depends on unknown '{dependency}'")
            }
            Self::CycleDetected { ids } => {
                write!(f, "dependency cycle detected involving: {}", ids.join(", "))
            }
            Self::Empty => f.write_str("batch file is empty"),
        }
    }
}

// ── Batch file ─────────────────────────────────────────────────────────

/// A parsed and validated batch file.
#[derive(Debug, Clone, Serialize)]
pub struct BatchFile {
    /// All operations in file order.
    pub operations: Vec<BatchOp>,
}

impl BatchFile {
    /// Parse a JSONL string into a batch file.
    ///
    /// Validates that:
    /// - Each line is valid JSON with required fields
    /// - All operation IDs are unique
    /// - All dependency references exist
    /// - The dependency graph is acyclic
    pub fn parse(content: &str) -> Result<Self, BatchFileError> {
        let mut operations = Vec::new();
        let mut seen_ids = BTreeSet::new();

        for (i, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let op: BatchOp =
                serde_json::from_str(line).map_err(|e| BatchFileError::InvalidJson {
                    line: i + 1,
                    message: e.to_string(),
                })?;

            if op.id.is_empty() {
                return Err(BatchFileError::MissingField {
                    line: i + 1,
                    field: "id",
                });
            }
            if op.connector.is_empty() {
                return Err(BatchFileError::MissingField {
                    line: i + 1,
                    field: "connector",
                });
            }
            if op.operation.is_empty() {
                return Err(BatchFileError::MissingField {
                    line: i + 1,
                    field: "operation",
                });
            }

            if !seen_ids.insert(op.id.clone()) {
                return Err(BatchFileError::DuplicateId { id: op.id });
            }

            operations.push(op);
        }

        if operations.is_empty() {
            return Err(BatchFileError::Empty);
        }

        // Validate dependency references.
        for op in &operations {
            for dep in &op.depends_on {
                if !seen_ids.contains(dep) {
                    return Err(BatchFileError::UnknownDependency {
                        id: op.id.clone(),
                        dependency: dep.clone(),
                    });
                }
            }
        }

        // Check for cycles via topological sort.
        let batch = Self { operations };
        batch.check_cycles()?;

        Ok(batch)
    }

    /// Verify there are no cycles in the dependency graph.
    fn check_cycles(&self) -> Result<(), BatchFileError> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

        for op in &self.operations {
            in_degree.entry(op.id.as_str()).or_insert(0);
            for dep in &op.depends_on {
                *in_degree.entry(op.id.as_str()).or_insert(0) += 1;
                dependents
                    .entry(dep.as_str())
                    .or_default()
                    .push(op.id.as_str());
            }
        }

        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|(_, deg)| **deg == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut visited = 0;
        while let Some(id) = queue.pop_front() {
            visited += 1;
            if let Some(deps) = dependents.get(id) {
                for &dep_id in deps {
                    if let Some(deg) = in_degree.get_mut(dep_id) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(dep_id);
                        }
                    }
                }
            }
        }

        if visited < self.operations.len() {
            // Collect IDs involved in cycles.
            let cycle_ids: Vec<String> = in_degree
                .iter()
                .filter(|(_, deg)| **deg > 0)
                .map(|(&id, _)| id.to_owned())
                .collect();
            return Err(BatchFileError::CycleDetected { ids: cycle_ids });
        }

        Ok(())
    }

    /// Number of operations in the batch.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Get the set of unique connectors referenced.
    pub fn connectors(&self) -> BTreeSet<String> {
        self.operations
            .iter()
            .map(|op| op.connector.clone())
            .collect()
    }
}

// ── Execution plan ─────────────────────────────────────────────────────

/// A wave of operations that can execute in parallel.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionWave {
    /// Zero-based wave index.
    pub wave: usize,
    /// Operation IDs in this wave.
    pub operation_ids: Vec<String>,
}

/// Execution plan for a batch file.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionPlan {
    /// Total number of operations.
    pub total_operations: usize,
    /// Maximum concurrency per wave.
    pub concurrency: usize,
    /// Error handling mode.
    pub on_error: String,
    /// Waves of operations in execution order.
    pub waves: Vec<ExecutionWave>,
    /// Unique connectors involved.
    pub connectors: Vec<String>,
}

impl ExecutionPlan {
    /// Build an execution plan from a parsed batch file.
    pub fn from_batch(batch: &BatchFile, concurrency: usize, on_error: &str) -> Self {
        let waves = topological_waves(batch);
        let connectors: Vec<String> = batch.connectors().into_iter().collect();

        Self {
            total_operations: batch.len(),
            concurrency,
            on_error: on_error.to_owned(),
            waves,
            connectors,
        }
    }
}

/// Compute topological execution waves.
///
/// Each wave contains operations whose dependencies are all satisfied by
/// previous waves. Within a wave, operations can run in parallel.
fn topological_waves(batch: &BatchFile) -> Vec<ExecutionWave> {
    let mut in_degree: BTreeMap<&str, usize> = BTreeMap::new();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

    for op in &batch.operations {
        in_degree.entry(op.id.as_str()).or_insert(0);
        for dep in &op.depends_on {
            *in_degree.entry(op.id.as_str()).or_insert(0) += 1;
            dependents
                .entry(dep.as_str())
                .or_default()
                .push(op.id.as_str());
        }
    }

    let mut waves = Vec::new();
    let mut wave_idx = 0;

    loop {
        let ready: Vec<String> = in_degree
            .iter()
            .filter(|(_, deg)| **deg == 0)
            .map(|(&id, _)| id.to_owned())
            .collect();

        if ready.is_empty() {
            break;
        }

        // Remove ready nodes and update dependents.
        for id in &ready {
            in_degree.remove(id.as_str());
            if let Some(deps) = dependents.get(id.as_str()) {
                for &dep_id in deps {
                    if let Some(deg) = in_degree.get_mut(dep_id) {
                        *deg -= 1;
                    }
                }
            }
        }

        waves.push(ExecutionWave {
            wave: wave_idx,
            operation_ids: ready,
        });
        wave_idx += 1;
    }

    waves
}

// ── Per-operation result ───────────────────────────────────────────────

/// Status of a single batch operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpStatus {
    Success,
    Error,
    Skipped,
    Pending,
}

/// Result of a single batch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpResult {
    /// Operation ID from the batch file.
    pub id: String,
    /// Connector.operation that was executed.
    pub operation: String,
    /// Execution status.
    pub status: OpStatus,
    /// Wave in which this operation ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wave: Option<usize>,
    /// Result value (if success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error details (if error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Parsing ────────────────────────────────────────────────────

    #[test]
    fn parse_simple_batch() {
        let content = r#"{"id":"s1","connector":"github","operation":"list_issues","input":{"owner":"o","repo":"r"}}
{"id":"s2","connector":"slack","operation":"send_message","input":{"channel":"dev","text":"hi"}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.operations[0].id, "s1");
        assert_eq!(batch.operations[1].connector, "slack");
    }

    #[test]
    fn parse_with_dependencies() {
        let content = r#"{"id":"a","connector":"github","operation":"list_issues","input":{}}
{"id":"b","connector":"slack","operation":"send","input":{},"depends_on":["a"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[1].depends_on, vec!["a"]);
    }

    #[test]
    fn parse_skips_blank_lines_and_comments() {
        let content = r#"# This is a batch file
{"id":"s1","connector":"github","operation":"list","input":{}}

# Another comment
{"id":"s2","connector":"slack","operation":"send","input":{}}
"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn parse_empty_error() {
        let err = BatchFile::parse("").unwrap_err();
        assert_eq!(err, BatchFileError::Empty);
    }

    #[test]
    fn parse_only_comments_error() {
        let err = BatchFile::parse("# comment\n# another").unwrap_err();
        assert_eq!(err, BatchFileError::Empty);
    }

    #[test]
    fn parse_invalid_json_error() {
        let err = BatchFile::parse("not json").unwrap_err();
        match err {
            BatchFileError::InvalidJson { line, .. } => assert_eq!(line, 1),
            other => panic!("expected InvalidJson, got {other}"),
        }
    }

    #[test]
    fn parse_missing_id_error() {
        let content = r#"{"id":"","connector":"github","operation":"list","input":{}}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::MissingField { field, .. } => assert_eq!(field, "id"),
            other => panic!("expected MissingField(id), got {other}"),
        }
    }

    #[test]
    fn parse_missing_connector_error() {
        let content = r#"{"id":"s1","connector":"","operation":"list","input":{}}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::MissingField { field, .. } => assert_eq!(field, "connector"),
            other => panic!("expected MissingField(connector), got {other}"),
        }
    }

    #[test]
    fn parse_missing_operation_error() {
        let content = r#"{"id":"s1","connector":"github","operation":"","input":{}}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::MissingField { field, .. } => assert_eq!(field, "operation"),
            other => panic!("expected MissingField(operation), got {other}"),
        }
    }

    #[test]
    fn parse_duplicate_id_error() {
        let content = r#"{"id":"s1","connector":"github","operation":"list","input":{}}
{"id":"s1","connector":"slack","operation":"send","input":{}}"#;
        let err = BatchFile::parse(content).unwrap_err();
        assert_eq!(
            err,
            BatchFileError::DuplicateId {
                id: "s1".to_owned()
            }
        );
    }

    #[test]
    fn parse_unknown_dependency_error() {
        let content = r#"{"id":"s1","connector":"github","operation":"list","input":{},"depends_on":["nope"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::UnknownDependency { id, dependency } => {
                assert_eq!(id, "s1");
                assert_eq!(dependency, "nope");
            }
            other => panic!("expected UnknownDependency, got {other}"),
        }
    }

    #[test]
    fn parse_cycle_error() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["b"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => {
                assert!(ids.contains(&"a".to_owned()));
                assert!(ids.contains(&"b".to_owned()));
            }
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    #[test]
    fn parse_self_cycle_error() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["a"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { .. } => {}
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    #[test]
    fn parse_three_node_cycle() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["c"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => assert_eq!(ids.len(), 3),
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    // ── BatchFile methods ──────────────────────────────────────────

    #[test]
    fn connectors_returns_unique_set() {
        let content = r#"{"id":"s1","connector":"github","operation":"list","input":{}}
{"id":"s2","connector":"slack","operation":"send","input":{}}
{"id":"s3","connector":"github","operation":"create","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let connectors = batch.connectors();
        assert_eq!(connectors.len(), 2);
        assert!(connectors.contains("github"));
        assert!(connectors.contains("slack"));
    }

    #[test]
    fn batch_file_is_empty() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert!(!batch.is_empty());
    }

    // ── Execution waves ────────────────────────────────────────────

    #[test]
    fn waves_all_independent() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{}}
{"id":"c","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].operation_ids.len(), 3);
    }

    #[test]
    fn waves_linear_chain() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].operation_ids, vec!["a"]);
        assert_eq!(waves[1].operation_ids, vec!["b"]);
        assert_eq!(waves[2].operation_ids, vec!["c"]);
    }

    #[test]
    fn waves_diamond() {
        let content = r#"{"id":"root","connector":"g","operation":"o","input":{}}
{"id":"left","connector":"g","operation":"o","input":{},"depends_on":["root"]}
{"id":"right","connector":"g","operation":"o","input":{},"depends_on":["root"]}
{"id":"join","connector":"g","operation":"o","input":{},"depends_on":["left","right"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].operation_ids, vec!["root"]);
        assert_eq!(waves[1].operation_ids.len(), 2);
        assert!(waves[1].operation_ids.contains(&"left".to_owned()));
        assert!(waves[1].operation_ids.contains(&"right".to_owned()));
        assert_eq!(waves[2].operation_ids, vec!["join"]);
    }

    #[test]
    fn waves_mixed_independent_and_dependent() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 2);
        // Wave 0: a and c (both independent).
        assert!(waves[0].operation_ids.contains(&"a".to_owned()));
        assert!(waves[0].operation_ids.contains(&"c".to_owned()));
        // Wave 1: b (depends on a).
        assert_eq!(waves[1].operation_ids, vec!["b"]);
    }

    // ── ExecutionPlan ──────────────────────────────────────────────

    #[test]
    fn execution_plan_from_batch() {
        let content = r#"{"id":"a","connector":"github","operation":"list","input":{}}
{"id":"b","connector":"slack","operation":"send","input":{},"depends_on":["a"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 5, "abort");
        assert_eq!(plan.total_operations, 2);
        assert_eq!(plan.concurrency, 5);
        assert_eq!(plan.on_error, "abort");
        assert_eq!(plan.waves.len(), 2);
        assert_eq!(plan.connectors.len(), 2);
    }

    #[test]
    fn execution_plan_serializes() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 3, "continue");
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["total_operations"], 1);
        assert_eq!(json["concurrency"], 3);
        assert_eq!(json["on_error"], "continue");
        assert!(json["waves"].is_array());
    }

    // ── OpResult ───────────────────────────────────────────────────

    #[test]
    fn op_result_success_serializes() {
        let result = OpResult {
            id: "s1".to_owned(),
            operation: "github.list_issues".to_owned(),
            status: OpStatus::Success,
            wave: Some(0),
            result: Some(json!({"count": 5})),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"success\""));
        assert!(json.contains("\"wave\":0"));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn op_result_error_serializes() {
        let result = OpResult {
            id: "s2".to_owned(),
            operation: "slack.send".to_owned(),
            status: OpStatus::Error,
            wave: Some(1),
            result: None,
            error: Some(json!({"code": "AUTH_FAILED"})),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("AUTH_FAILED"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn op_result_skipped_serializes() {
        let result = OpResult {
            id: "s3".to_owned(),
            operation: "todoist.create".to_owned(),
            status: OpStatus::Skipped,
            wave: None,
            result: None,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"skipped\""));
        assert!(!json.contains("\"wave\""));
    }

    #[test]
    fn op_result_roundtrip() {
        let result = OpResult {
            id: "r1".to_owned(),
            operation: "github.get".to_owned(),
            status: OpStatus::Success,
            wave: Some(2),
            result: Some(json!({"data": "value"})),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: OpResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "r1");
        assert_eq!(back.status, OpStatus::Success);
        assert_eq!(back.wave, Some(2));
    }

    // ── OpStatus ───────────────────────────────────────────────────

    #[test]
    fn op_status_equality() {
        assert_eq!(OpStatus::Success, OpStatus::Success);
        assert_ne!(OpStatus::Success, OpStatus::Error);
        assert_ne!(OpStatus::Error, OpStatus::Skipped);
        assert_ne!(OpStatus::Skipped, OpStatus::Pending);
    }

    #[test]
    fn op_status_roundtrip() {
        for status in [
            OpStatus::Success,
            OpStatus::Error,
            OpStatus::Skipped,
            OpStatus::Pending,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: OpStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    // ── BatchOp serialization ──────────────────────────────────────

    #[test]
    fn batch_op_roundtrip() {
        let op = BatchOp {
            id: "step1".to_owned(),
            connector: "github".to_owned(),
            operation: "list_issues".to_owned(),
            input: json!({"owner": "o", "repo": "r"}),
            depends_on: vec!["step0".to_owned()],
        };
        let json = serde_json::to_string(&op).unwrap();
        let back: BatchOp = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "step1");
        assert_eq!(back.depends_on, vec!["step0"]);
    }

    #[test]
    fn batch_op_no_depends_on_omitted() {
        let op = BatchOp {
            id: "s1".to_owned(),
            connector: "g".to_owned(),
            operation: "o".to_owned(),
            input: json!({}),
            depends_on: vec![],
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(!json.contains("depends_on"));
    }

    // ── BatchFileError Display ─────────────────────────────────────

    #[test]
    fn error_display_messages() {
        assert!(BatchFileError::Empty.to_string().contains("empty"));
        assert!(
            BatchFileError::InvalidJson {
                line: 3,
                message: "bad".to_owned()
            }
            .to_string()
            .contains("line 3")
        );
        assert!(
            BatchFileError::DuplicateId { id: "x".to_owned() }
                .to_string()
                .contains("'x'")
        );
        assert!(
            BatchFileError::UnknownDependency {
                id: "a".to_owned(),
                dependency: "b".to_owned()
            }
            .to_string()
            .contains("'b'")
        );
        assert!(
            BatchFileError::CycleDetected {
                ids: vec!["x".to_owned(), "y".to_owned()]
            }
            .to_string()
            .contains("x, y")
        );
    }

    // ── Complex graph scenarios ────────────────────────────────────

    #[test]
    fn wide_fan_out_single_wave() {
        let mut lines =
            vec![r#"{"id":"root","connector":"g","operation":"o","input":{}}"#.to_owned()];
        for i in 0..10 {
            lines.push(format!(
                r#"{{"id":"leaf{i}","connector":"g","operation":"o","input":{{}},"depends_on":["root"]}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0].operation_ids.len(), 1);
        assert_eq!(waves[1].operation_ids.len(), 10);
    }

    #[test]
    fn deep_chain_produces_many_waves() {
        let mut lines = Vec::new();
        for i in 0..5 {
            let deps = if i == 0 {
                String::new()
            } else {
                format!(r#","depends_on":["s{}"]"#, i - 1)
            };
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}{deps}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 5);
    }

    #[test]
    fn multi_root_graph() {
        let content = r#"{"id":"r1","connector":"g","operation":"o","input":{}}
{"id":"r2","connector":"g","operation":"o","input":{}}
{"id":"join","connector":"g","operation":"o","input":{},"depends_on":["r1","r2"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0].operation_ids.len(), 2);
    }

    // ── Execution wave serialization ───────────────────────────────

    #[test]
    fn execution_wave_serializes() {
        let wave = ExecutionWave {
            wave: 0,
            operation_ids: vec!["a".to_owned(), "b".to_owned()],
        };
        let json = serde_json::to_value(&wave).unwrap();
        assert_eq!(json["wave"], 0);
        assert_eq!(json["operation_ids"].as_array().unwrap().len(), 2);
    }

    // ── Large batch ────────────────────────────────────────────────

    #[test]
    fn parse_large_batch() {
        let mut lines = Vec::new();
        for i in 0..100 {
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        assert_eq!(batch.len(), 100);
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].operation_ids.len(), 100);
    }

    // ── Additional parsing edge cases ─────────────────────────────

    #[test]
    fn parse_whitespace_only_lines() {
        let content =
            "   \n\t\n{\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}\n  \n";
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn parse_inline_comment_before_op() {
        let content =
            "# header\n{\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}";
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.operations[0].id, "a");
    }

    #[test]
    fn parse_only_whitespace_error() {
        let err = BatchFile::parse("   \n\t\n  ").unwrap_err();
        assert_eq!(err, BatchFileError::Empty);
    }

    #[test]
    fn parse_invalid_json_on_second_line() {
        let content =
            "{\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}\nnot json";
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::InvalidJson { line, .. } => assert_eq!(line, 2),
            other => panic!("expected InvalidJson, got {other}"),
        }
    }

    #[test]
    fn parse_preserves_input_payload() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":{"key":"value","num":42,"nested":{"a":1}}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[0].input["key"], "value");
        assert_eq!(batch.operations[0].input["num"], 42);
        assert_eq!(batch.operations[0].input["nested"]["a"], 1);
    }

    #[test]
    fn parse_null_input() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":null}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert!(batch.operations[0].input.is_null());
    }

    #[test]
    fn parse_array_input() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":[1,2,3]}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert!(batch.operations[0].input.is_array());
    }

    #[test]
    fn parse_empty_depends_on_is_default() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":{},"depends_on":[]}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert!(batch.operations[0].depends_on.is_empty());
    }

    #[test]
    fn parse_multiple_dependencies() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{}}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["a","b"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[2].depends_on.len(), 2);
        assert!(batch.operations[2].depends_on.contains(&"a".to_owned()));
        assert!(batch.operations[2].depends_on.contains(&"b".to_owned()));
    }

    // ── BatchFile methods (additional) ────────────────────────────

    #[test]
    fn batch_file_len() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{}}
{"id":"c","connector":"h","operation":"p","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn connectors_single_connector() {
        let content = r#"{"id":"a","connector":"github","operation":"list","input":{}}
{"id":"b","connector":"github","operation":"create","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let connectors = batch.connectors();
        assert_eq!(connectors.len(), 1);
        assert!(connectors.contains("github"));
    }

    #[test]
    fn connectors_many() {
        let content = r#"{"id":"a","connector":"github","operation":"o","input":{}}
{"id":"b","connector":"slack","operation":"o","input":{}}
{"id":"c","connector":"discord","operation":"o","input":{}}
{"id":"d","connector":"github","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let connectors = batch.connectors();
        assert_eq!(connectors.len(), 3);
    }

    // ── BatchOp additional serde ──────────────────────────────────

    #[test]
    fn batch_op_with_complex_input_roundtrip() {
        let op = BatchOp {
            id: "step1".to_owned(),
            connector: "github".to_owned(),
            operation: "create_issue".to_owned(),
            input: json!({"title": "Bug", "body": "Details", "labels": ["bug", "priority"]}),
            depends_on: vec!["step0".to_owned(), "step-1".to_owned()],
        };
        let json = serde_json::to_string(&op).unwrap();
        let back: BatchOp = serde_json::from_str(&json).unwrap();
        assert_eq!(back.depends_on.len(), 2);
        assert!(back.input["labels"].is_array());
    }

    #[test]
    fn batch_op_clone() {
        let op = BatchOp {
            id: "s1".to_owned(),
            connector: "g".to_owned(),
            operation: "o".to_owned(),
            input: json!({"x": 1}),
            depends_on: vec!["dep".to_owned()],
        };
        let cloned = op.clone();
        assert_eq!(cloned.id, op.id);
        assert_eq!(cloned.depends_on, op.depends_on);
    }

    // ── OpStatus additional ───────────────────────────────────────

    #[test]
    fn op_status_serde_values() {
        assert_eq!(
            serde_json::to_string(&OpStatus::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&OpStatus::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&OpStatus::Skipped).unwrap(),
            "\"skipped\""
        );
        assert_eq!(
            serde_json::to_string(&OpStatus::Pending).unwrap(),
            "\"pending\""
        );
    }

    #[test]
    fn op_status_clone() {
        let s = OpStatus::Success;
        let c = s.clone();
        assert_eq!(s, c);
    }

    // ── OpResult additional ───────────────────────────────────────

    #[test]
    fn op_result_pending_serializes() {
        let result = OpResult {
            id: "s4".to_owned(),
            operation: "jira.create".to_owned(),
            status: OpStatus::Pending,
            wave: None,
            result: None,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"pending\""));
        assert!(!json.contains("\"wave\""));
        assert!(!json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn op_result_with_both_result_and_error() {
        let result = OpResult {
            id: "s5".to_owned(),
            operation: "test.op".to_owned(),
            status: OpStatus::Error,
            wave: Some(3),
            result: Some(json!({"partial": true})),
            error: Some(json!({"code": "PARTIAL_FAILURE"})),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"partial\""));
        assert!(json.contains("PARTIAL_FAILURE"));
    }

    #[test]
    fn op_result_roundtrip_all_fields() {
        let original = OpResult {
            id: "roundtrip".to_owned(),
            operation: "github.list".to_owned(),
            status: OpStatus::Error,
            wave: Some(5),
            result: None,
            error: Some(json!({"msg": "timeout"})),
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: OpResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "roundtrip");
        assert_eq!(back.status, OpStatus::Error);
        assert_eq!(back.wave, Some(5));
        assert!(back.result.is_none());
        assert_eq!(back.error.unwrap()["msg"], "timeout");
    }

    #[test]
    fn op_result_clone() {
        let result = OpResult {
            id: "c1".to_owned(),
            operation: "g.o".to_owned(),
            status: OpStatus::Success,
            wave: Some(0),
            result: Some(json!(42)),
            error: None,
        };
        let cloned = result.clone();
        assert_eq!(cloned.id, result.id);
        assert_eq!(cloned.status, result.status);
    }

    // ── BatchFileError additional ─────────────────────────────────

    #[test]
    fn error_missing_field_display_contains_field_name() {
        let err = BatchFileError::MissingField {
            line: 7,
            field: "connector",
        };
        let msg = err.to_string();
        assert!(msg.contains("line 7"));
        assert!(msg.contains("'connector'"));
    }

    #[test]
    fn error_clone() {
        let err = BatchFileError::DuplicateId {
            id: "abc".to_owned(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn error_debug_format() {
        let err = BatchFileError::Empty;
        let debug = format!("{err:?}");
        assert!(debug.contains("Empty"));
    }

    // ── Execution waves additional ────────────────────────────────

    #[test]
    fn waves_w_shape_graph() {
        // r1 -> m -> join
        // r2 ---^
        let content = r#"{"id":"r1","connector":"g","operation":"o","input":{}}
{"id":"r2","connector":"g","operation":"o","input":{}}
{"id":"m","connector":"g","operation":"o","input":{},"depends_on":["r1","r2"]}
{"id":"join","connector":"g","operation":"o","input":{},"depends_on":["m"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].operation_ids.len(), 2);
        assert_eq!(waves[1].operation_ids, vec!["m"]);
        assert_eq!(waves[2].operation_ids, vec!["join"]);
    }

    #[test]
    fn waves_single_operation() {
        let content = r#"{"id":"solo","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].operation_ids, vec!["solo"]);
        assert_eq!(waves[0].wave, 0);
    }

    // ── ExecutionPlan additional ──────────────────────────────────

    #[test]
    fn execution_plan_concurrency_and_error_mode() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 10, "skip");
        assert_eq!(plan.concurrency, 10);
        assert_eq!(plan.on_error, "skip");
    }

    #[test]
    fn execution_plan_connectors_sorted() {
        let content = r#"{"id":"a","connector":"slack","operation":"o","input":{}}
{"id":"b","connector":"github","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 1, "abort");
        // BTreeSet produces sorted order
        assert_eq!(plan.connectors, vec!["github", "slack"]);
    }

    #[test]
    fn execution_plan_wave_indices() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 4, "abort");
        assert_eq!(plan.waves[0].wave, 0);
        assert_eq!(plan.waves[1].wave, 1);
    }

    #[test]
    fn execution_plan_json_has_all_fields() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 8, "continue");
        let json = serde_json::to_value(&plan).unwrap();
        assert!(json.get("total_operations").is_some());
        assert!(json.get("concurrency").is_some());
        assert!(json.get("on_error").is_some());
        assert!(json.get("waves").is_some());
        assert!(json.get("connectors").is_some());
    }

    // ── ExecutionWave clone and debug ─────────────────────────────

    #[test]
    fn execution_wave_clone() {
        let wave = ExecutionWave {
            wave: 2,
            operation_ids: vec!["x".to_owned(), "y".to_owned()],
        };
        let cloned = wave.clone();
        assert_eq!(wave.wave, 2);
        assert_eq!(cloned.operation_ids.len(), 2);
    }

    #[test]
    fn execution_wave_debug() {
        let wave = ExecutionWave {
            wave: 0,
            operation_ids: vec!["a".to_owned()],
        };
        let debug = format!("{wave:?}");
        assert!(debug.contains("ExecutionWave"));
    }

    // ── BatchFile Serialize ──────────────────────────────────────

    #[test]
    fn batch_file_serializes() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{"k":1}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let json = serde_json::to_value(&batch).unwrap();
        assert!(json["operations"].is_array());
        assert_eq!(json["operations"][0]["id"], "a");
    }

    // ── Cycle detection edge cases ────────────────────────────────

    #[test]
    fn four_node_cycle_detected() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["d"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}
{"id":"d","connector":"g","operation":"o","input":{},"depends_on":["c"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => assert_eq!(ids.len(), 4),
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    #[test]
    fn partial_cycle_with_free_nodes() {
        // a -> b -> c -> a (cycle), d is free
        let content = r#"{"id":"d","connector":"g","operation":"o","input":{}}
{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["c"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => {
                assert_eq!(ids.len(), 3);
                assert!(!ids.contains(&"d".to_owned()));
            }
            other => panic!("expected CycleDetected, got {other}"),
        }
    }
}
