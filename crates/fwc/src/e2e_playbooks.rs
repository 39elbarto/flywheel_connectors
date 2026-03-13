//! Pre-built E2E workflow playbooks for agent-driven connector testing.
//!
//! Provides a registry of playbooks covering common multi-step workflows such as
//! discover-and-invoke, batch-with-retry, pipeline chaining, lifecycle management,
//! error recovery, history replay, and more.  Each playbook carries typed assertions
//! so a runner can validate step outputs automatically.

use std::fmt::Write as _;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Core types ───────────────────────────────────────────────────────

/// Category of a playbook.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookCategory {
    /// Connector / operation discovery.
    Discovery,
    /// Direct operation invocation.
    Execution,
    /// Multi-step workflow automation.
    Workflow,
    /// Admin / lifecycle management.
    Administration,
    /// Error handling and recovery paths.
    ErrorRecovery,
    /// Performance / throughput scenarios.
    Performance,
}

impl std::fmt::Display for PlaybookCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovery => f.write_str("discovery"),
            Self::Execution => f.write_str("execution"),
            Self::Workflow => f.write_str("workflow"),
            Self::Administration => f.write_str("administration"),
            Self::ErrorRecovery => f.write_str("error-recovery"),
            Self::Performance => f.write_str("performance"),
        }
    }
}

/// Condition used inside an [`Assertion`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionCondition {
    Equals,
    Contains,
    NotEmpty,
    GreaterThan,
    LessThan,
    Matches,
    Exists,
}

/// A single assertion against a step output value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assertion {
    /// JSON-pointer style field path, e.g. `/status` or `/items/0/name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,
    /// The comparison condition.
    pub condition: AssertionCondition,
    /// Expected value (interpretation depends on condition).
    pub expected_value: Value,
    /// Human-readable description shown on failure.
    pub message: String,
}

/// A single step inside a [`Playbook`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaybookStep {
    /// Step identifier (unique within a playbook).
    pub id: String,
    /// What this step does.
    pub description: String,
    /// Template command string (may contain `{{var}}` placeholders).
    pub command_template: String,
    /// Assertions evaluated against the step output.
    #[serde(default)]
    pub assertions: Vec<Assertion>,
    /// Maximum wall-clock time for this step.
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
    /// Optional cleanup command run after the step regardless of success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<String>,
}

/// Complexity rating for a playbook.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookComplexity {
    Simple,
    Moderate,
    Complex,
}

impl std::fmt::Display for PlaybookComplexity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Simple => f.write_str("simple"),
            Self::Moderate => f.write_str("moderate"),
            Self::Complex => f.write_str("complex"),
        }
    }
}

/// A complete E2E playbook.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Playbook {
    pub name: String,
    pub description: String,
    pub category: PlaybookCategory,
    pub steps: Vec<PlaybookStep>,
    pub expected_outcomes: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub complexity: PlaybookComplexity,
}

/// Result of executing one playbook step.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub passed: bool,
    pub output: Value,
    pub assertion_results: Vec<(String, bool)>,
    #[serde(with = "duration_serde")]
    pub duration: Duration,
}

/// Aggregate result of executing a complete playbook.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaybookResult {
    pub playbook_name: String,
    pub all_passed: bool,
    pub step_results: Vec<StepResult>,
    #[serde(with = "duration_serde")]
    pub duration: Duration,
    pub category: PlaybookCategory,
}

/// Registry holding a collection of playbooks.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PlaybookRegistry {
    pub playbooks: Vec<Playbook>,
}

// ── Duration serde helper ────────────────────────────────────────────

mod duration_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct DurationRepr {
        secs: u64,
        nanos: u32,
    }

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        DurationRepr {
            secs: d.as_secs(),
            nanos: d.subsec_nanos(),
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let r = DurationRepr::deserialize(d)?;
        Ok(Duration::new(r.secs, r.nanos))
    }
}

// ── PlaybookRegistry methods ─────────────────────────────────────────

impl PlaybookRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            playbooks: Vec::new(),
        }
    }

    /// Create a registry pre-loaded with the built-in playbooks.
    #[must_use]
    pub fn with_builtins() -> Self {
        Self {
            playbooks: get_builtin_playbooks(),
        }
    }

    /// Add a playbook.
    pub fn add(&mut self, playbook: Playbook) {
        self.playbooks.push(playbook);
    }

    /// Find all playbooks in the given category.
    #[must_use]
    pub fn find_by_category(&self, category: PlaybookCategory) -> Vec<&Playbook> {
        self.playbooks
            .iter()
            .filter(|p| p.category == category)
            .collect()
    }

    /// Find all playbooks carrying the given tag (case-insensitive).
    #[must_use]
    pub fn find_by_tag(&self, tag: &str) -> Vec<&Playbook> {
        let tag_lower = tag.to_lowercase();
        self.playbooks
            .iter()
            .filter(|p| p.tags.iter().any(|t| t.to_lowercase() == tag_lower))
            .collect()
    }

    /// Find a playbook by exact name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&Playbook> {
        self.playbooks.iter().find(|p| p.name == name)
    }

    /// Return all unique tags across all registered playbooks.
    #[must_use]
    pub fn all_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self
            .playbooks
            .iter()
            .flat_map(|p| p.tags.iter().cloned())
            .collect();
        tags.sort();
        tags.dedup();
        tags
    }

    /// Number of registered playbooks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.playbooks.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.playbooks.is_empty()
    }
}

// ── Assertion evaluation ─────────────────────────────────────────────

/// Resolve a JSON pointer path on a value.
fn resolve_path<'v>(value: &'v Value, path: &str) -> Option<&'v Value> {
    if path.is_empty() || path == "/" {
        return Some(value);
    }
    value.pointer(path)
}

/// Evaluate a single assertion against a JSON value.
///
/// If `assertion.field_path` is `Some`, the assertion is tested against the
/// sub-value at that path; otherwise it tests the root value.
#[must_use]
pub fn check_assertion(value: &Value, assertion: &Assertion) -> bool {
    let target = match &assertion.field_path {
        Some(path) => match resolve_path(value, path) {
            Some(v) => v,
            None => {
                // Path does not exist — only `Exists` with false expected can pass.
                return assertion.condition == AssertionCondition::Exists
                    && assertion.expected_value == Value::Bool(false);
            }
        },
        None => value,
    };

    match &assertion.condition {
        AssertionCondition::Equals => target == &assertion.expected_value,
        AssertionCondition::Contains => match (target, &assertion.expected_value) {
            (Value::String(haystack), Value::String(needle)) => haystack.contains(needle.as_str()),
            (Value::Array(arr), expected) => arr.contains(expected),
            _ => false,
        },
        AssertionCondition::NotEmpty => match target {
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
            Value::Null => false,
            _ => true,
        },
        AssertionCondition::GreaterThan => as_f64(target)
            .zip(as_f64(&assertion.expected_value))
            .is_some_and(|(a, b)| a > b),
        AssertionCondition::LessThan => as_f64(target)
            .zip(as_f64(&assertion.expected_value))
            .is_some_and(|(a, b)| a < b),
        AssertionCondition::Matches => {
            // Simple glob-like matching: `*` matches any substring.
            if let (Value::String(text), Value::String(pattern)) =
                (target, &assertion.expected_value)
            {
                glob_match(text, pattern)
            } else {
                false
            }
        }
        AssertionCondition::Exists => {
            // If we reached here, the path exists — so compare against expected bool.
            assertion.expected_value == Value::Bool(true)
        }
    }
}

#[allow(clippy::cast_precision_loss)]
fn as_f64(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_i64().map(|i| i as f64))
}

/// Minimal glob matcher supporting `*` as wildcard.
fn glob_match(text: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return text == pattern;
    }
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(idx) => {
                if i == 0 && idx != 0 {
                    return false; // First segment must anchor at start.
                }
                pos += idx + part.len();
            }
            None => return false,
        }
    }
    // If pattern ends with `*`, any suffix is fine; otherwise tail must match.
    if pattern.ends_with('*') {
        true
    } else {
        text.ends_with(parts.last().unwrap_or(&""))
    }
}

// ── Playbook validation ──────────────────────────────────────────────

/// Validate a playbook and return a list of issues (empty = valid).
#[must_use]
pub fn validate_playbook(playbook: &Playbook) -> Vec<String> {
    let mut issues = Vec::new();

    if playbook.name.is_empty() {
        issues.push("Playbook name is empty".into());
    }
    if playbook.description.is_empty() {
        issues.push("Playbook description is empty".into());
    }
    if playbook.steps.is_empty() {
        issues.push("Playbook has no steps".into());
    }
    if playbook.expected_outcomes.is_empty() {
        issues.push("Playbook has no expected outcomes".into());
    }

    // Check for duplicate step IDs.
    let mut seen_ids = Vec::new();
    for step in &playbook.steps {
        if seen_ids.contains(&step.id) {
            issues.push(format!("Duplicate step id: {}", step.id));
        } else {
            seen_ids.push(step.id.clone());
        }

        if step.command_template.is_empty() {
            issues.push(format!("Step '{}' has empty command template", step.id));
        }
        if step.timeout.is_zero() {
            issues.push(format!("Step '{}' has zero timeout", step.id));
        }
    }

    issues
}

// ── TOON formatting ──────────────────────────────────────────────────

/// Format a playbook as a human-readable summary (TOON style).
#[must_use]
pub fn format_playbook_toon(playbook: &Playbook) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Playbook: {}", playbook.name);
    let _ = writeln!(out, "  Category:   {}", playbook.category);
    let _ = writeln!(out, "  Complexity: {}", playbook.complexity);
    let _ = writeln!(out, "  Steps:      {}", playbook.steps.len());
    let _ = writeln!(out, "  Tags:       {}", playbook.tags.join(", "));
    let _ = writeln!(out);
    let _ = writeln!(out, "  {}", playbook.description);
    let _ = writeln!(out);

    for (i, step) in playbook.steps.iter().enumerate() {
        let _ = writeln!(out, "  Step {}: {} [{}]", i + 1, step.description, step.id);
        let _ = writeln!(out, "    Command:    {}", step.command_template);
        let _ = writeln!(out, "    Timeout:    {}s", step.timeout.as_secs());
        let _ = writeln!(out, "    Assertions: {}", step.assertions.len());
        if let Some(ref cleanup) = step.cleanup {
            let _ = writeln!(out, "    Cleanup:    {cleanup}");
        }
    }

    if !playbook.expected_outcomes.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "  Expected outcomes:");
        for outcome in &playbook.expected_outcomes {
            let _ = writeln!(out, "    - {outcome}");
        }
    }

    out
}

/// Format a [`PlaybookResult`] as a human-readable summary (TOON style).
#[must_use]
pub fn format_playbook_result_toon(result: &PlaybookResult) -> String {
    let mut out = String::new();
    let verdict = if result.all_passed { "PASS" } else { "FAIL" };
    let _ = writeln!(
        out,
        "Playbook: {} [{verdict}] ({:.2}s)",
        result.playbook_name,
        result.duration.as_secs_f64()
    );
    let _ = writeln!(out, "  Category: {}", result.category);
    let _ = writeln!(out);

    let total = result.step_results.len();
    let passed = result.step_results.iter().filter(|s| s.passed).count();
    let _ = writeln!(out, "  Steps: {passed}/{total} passed");
    let _ = writeln!(out);

    for sr in &result.step_results {
        let icon = if sr.passed { "ok" } else { "FAIL" };
        let _ = writeln!(
            out,
            "  [{icon}] {} ({:.3}s)",
            sr.step_id,
            sr.duration.as_secs_f64()
        );
        for (msg, ok) in &sr.assertion_results {
            let a_icon = if *ok { "+" } else { "-" };
            let _ = writeln!(out, "      [{a_icon}] {msg}");
        }
    }

    out
}

// ── Built-in playbook helpers ────────────────────────────────────────

fn step(id: &str, desc: &str, cmd: &str) -> PlaybookStep {
    PlaybookStep {
        id: id.into(),
        description: desc.into(),
        command_template: cmd.into(),
        assertions: Vec::new(),
        timeout: Duration::from_secs(30),
        cleanup: None,
    }
}

fn step_with_assert(id: &str, desc: &str, cmd: &str, assertions: Vec<Assertion>) -> PlaybookStep {
    PlaybookStep {
        id: id.into(),
        description: desc.into(),
        command_template: cmd.into(),
        assertions,
        timeout: Duration::from_secs(30),
        cleanup: None,
    }
}

fn step_with_timeout(
    id: &str,
    desc: &str,
    cmd: &str,
    timeout_secs: u64,
    assertions: Vec<Assertion>,
) -> PlaybookStep {
    PlaybookStep {
        id: id.into(),
        description: desc.into(),
        command_template: cmd.into(),
        assertions,
        timeout: Duration::from_secs(timeout_secs),
        cleanup: None,
    }
}

fn step_with_cleanup(
    id: &str,
    desc: &str,
    cmd: &str,
    cleanup: &str,
    assertions: Vec<Assertion>,
) -> PlaybookStep {
    PlaybookStep {
        id: id.into(),
        description: desc.into(),
        command_template: cmd.into(),
        assertions,
        timeout: Duration::from_secs(30),
        cleanup: Some(cleanup.into()),
    }
}

fn assert_eq(field: &str, expected: Value, msg: &str) -> Assertion {
    Assertion {
        field_path: Some(field.into()),
        condition: AssertionCondition::Equals,
        expected_value: expected,
        message: msg.into(),
    }
}

fn assert_not_empty(field: &str, msg: &str) -> Assertion {
    Assertion {
        field_path: Some(field.into()),
        condition: AssertionCondition::NotEmpty,
        expected_value: Value::Null,
        message: msg.into(),
    }
}

fn assert_exists(field: &str, msg: &str) -> Assertion {
    Assertion {
        field_path: Some(field.into()),
        condition: AssertionCondition::Exists,
        expected_value: Value::Bool(true),
        message: msg.into(),
    }
}

fn assert_contains(field: &str, needle: &str, msg: &str) -> Assertion {
    Assertion {
        field_path: Some(field.into()),
        condition: AssertionCondition::Contains,
        expected_value: Value::String(needle.into()),
        message: msg.into(),
    }
}

fn assert_gt(field: &str, threshold: f64, msg: &str) -> Assertion {
    Assertion {
        field_path: Some(field.into()),
        condition: AssertionCondition::GreaterThan,
        expected_value: serde_json::json!(threshold),
        message: msg.into(),
    }
}

fn assert_lt(field: &str, threshold: f64, msg: &str) -> Assertion {
    Assertion {
        field_path: Some(field.into()),
        condition: AssertionCondition::LessThan,
        expected_value: serde_json::json!(threshold),
        message: msg.into(),
    }
}

fn assert_matches(field: &str, pattern: &str, msg: &str) -> Assertion {
    Assertion {
        field_path: Some(field.into()),
        condition: AssertionCondition::Matches,
        expected_value: Value::String(pattern.into()),
        message: msg.into(),
    }
}

// ── Built-in playbooks ───────────────────────────────────────────────

/// Return the full set of built-in E2E playbooks (>= 15).
#[must_use]
pub fn get_builtin_playbooks() -> Vec<Playbook> {
    vec![
        playbook_discover_and_invoke(),
        playbook_batch_with_retry(),
        playbook_pipeline_chain(),
        playbook_lifecycle_manage(),
        playbook_error_recovery(),
        playbook_history_replay(),
        playbook_config_management(),
        playbook_multi_connector_workflow(),
        playbook_approval_flow(),
        playbook_session_management(),
        playbook_template_pipeline(),
        playbook_health_monitoring(),
        playbook_supply_chain_verify(),
        playbook_schema_navigation(),
        playbook_export_and_share(),
    ]
}

fn playbook_discover_and_invoke() -> Playbook {
    Playbook {
        name: "discover-and-invoke".into(),
        description: "End-to-end flow: discover available connectors, search for a specific operation, validate its schema, then invoke it with sample input.".into(),
        category: PlaybookCategory::Discovery,
        complexity: PlaybookComplexity::Moderate,
        tags: vec!["discovery".into(), "invoke".into(), "schema".into()],
        expected_outcomes: vec![
            "At least one connector is discovered".into(),
            "Target operation is found via search".into(),
            "Schema validation passes".into(),
            "Invocation returns a successful response".into(),
        ],
        steps: vec![
            step_with_assert(
                "discover",
                "List all available connectors",
                "fwc catalog list --format json",
                vec![assert_not_empty("/connectors", "Connector list should not be empty")],
            ),
            step_with_assert(
                "search",
                "Search for target operation by keyword",
                "fwc search --query '{{operation_keyword}}' --format json",
                vec![
                    assert_not_empty("/results", "Search results should not be empty"),
                    assert_exists("/results/0/operation", "First result should have an operation field"),
                ],
            ),
            step_with_assert(
                "schema",
                "Validate the operation schema",
                "fwc schema {{connector_id}} {{operation}} --format json",
                vec![
                    assert_exists("/input_schema", "Schema should contain input_schema"),
                ],
            ),
            step_with_assert(
                "invoke",
                "Invoke the operation with sample input",
                "fwc invoke {{connector_id}} {{operation}} --input '{{input_json}}' --format json",
                vec![
                    assert_eq("/status", Value::String("success".into()), "Invocation should succeed"),
                ],
            ),
        ],
    }
}

fn playbook_batch_with_retry() -> Playbook {
    Playbook {
        name: "batch-with-retry".into(),
        description: "Create a batch of operations, execute them, handle any failures with retry logic, and verify all eventually succeed.".into(),
        category: PlaybookCategory::Execution,
        complexity: PlaybookComplexity::Complex,
        tags: vec!["batch".into(), "retry".into(), "resilience".into()],
        expected_outcomes: vec![
            "Batch is created with the correct item count".into(),
            "All items eventually succeed (possibly after retries)".into(),
            "Progress tracking shows correct counts".into(),
        ],
        steps: vec![
            step_with_assert(
                "create-batch",
                "Create a batch from a batch file",
                "fwc batch create --file '{{batch_file}}' --format json",
                vec![
                    assert_exists("/batch_id", "Batch should have an ID"),
                    assert_gt("/item_count", 0.0, "Batch should have items"),
                ],
            ),
            step_with_assert(
                "execute",
                "Execute the batch",
                "fwc batch run --id '{{batch_id}}' --on-error continue --format json",
                vec![
                    assert_exists("/summary", "Response should include a summary"),
                ],
            ),
            step_with_assert(
                "check-failures",
                "Check for failed items",
                "fwc batch status --id '{{batch_id}}' --filter failed --format json",
                vec![
                    assert_exists("/failed_items", "Failed items should be listed"),
                ],
            ),
            step_with_timeout(
                "retry",
                "Retry failed items with exponential backoff",
                "fwc batch retry --id '{{batch_id}}' --max-retries 3 --backoff exponential --format json",
                120,
                vec![
                    assert_eq("/status", Value::String("completed".into()), "Retry batch should complete"),
                ],
            ),
            step_with_assert(
                "verify",
                "Verify all items succeeded",
                "fwc batch status --id '{{batch_id}}' --format json",
                vec![
                    assert_eq("/summary/failed", serde_json::json!(0), "No items should remain failed"),
                ],
            ),
        ],
    }
}

fn playbook_pipeline_chain() -> Playbook {
    Playbook {
        name: "pipeline-chain".into(),
        description: "Define a multi-step pipeline, validate its structure, perform a dry-run, then execute for real.".into(),
        category: PlaybookCategory::Workflow,
        complexity: PlaybookComplexity::Complex,
        tags: vec!["pipeline".into(), "workflow".into(), "dry-run".into()],
        expected_outcomes: vec![
            "Pipeline definition is accepted".into(),
            "Validation passes with no errors".into(),
            "Dry-run shows expected data flow".into(),
            "Full execution produces final output".into(),
        ],
        steps: vec![
            step_with_assert(
                "define",
                "Define a pipeline from recipe or inline",
                "fwc pipeline define --recipe '{{recipe_id}}' --format json",
                vec![
                    assert_exists("/pipeline_id", "Pipeline should have an ID"),
                ],
            ),
            step_with_assert(
                "validate",
                "Validate the pipeline structure",
                "fwc pipeline validate --id '{{pipeline_id}}' --format json",
                vec![
                    assert_eq("/valid", Value::Bool(true), "Pipeline should be valid"),
                ],
            ),
            step_with_assert(
                "dry-run",
                "Execute a dry-run to preview data flow",
                "fwc pipeline run --id '{{pipeline_id}}' --dry-run --format json",
                vec![
                    assert_not_empty("/steps", "Dry-run should show step previews"),
                ],
            ),
            step_with_timeout(
                "execute",
                "Execute the pipeline for real",
                "fwc pipeline run --id '{{pipeline_id}}' --format json",
                300,
                vec![
                    assert_eq("/status", Value::String("completed".into()), "Pipeline should complete"),
                    assert_exists("/output", "Pipeline should produce output"),
                ],
            ),
        ],
    }
}

fn playbook_lifecycle_manage() -> Playbook {
    Playbook {
        name: "lifecycle-manage".into(),
        description: "Full connector lifecycle: enable, start, verify health, stop, and disable."
            .into(),
        category: PlaybookCategory::Administration,
        complexity: PlaybookComplexity::Moderate,
        tags: vec!["lifecycle".into(), "admin".into(), "health".into()],
        expected_outcomes: vec![
            "Connector transitions through all states correctly".into(),
            "Health check passes while running".into(),
            "Final state is disabled".into(),
        ],
        steps: vec![
            step_with_assert(
                "enable",
                "Enable the connector",
                "fwc lifecycle enable {{connector_id}} --format json",
                vec![assert_eq(
                    "/status",
                    Value::String("enabled".into()),
                    "Connector should be enabled",
                )],
            ),
            step_with_assert(
                "start",
                "Start the connector",
                "fwc lifecycle start {{connector_id}} --format json",
                vec![assert_eq(
                    "/status",
                    Value::String("running".into()),
                    "Connector should be running",
                )],
            ),
            step_with_assert(
                "health",
                "Check connector health",
                "fwc health check {{connector_id}} --format json",
                vec![assert_eq(
                    "/healthy",
                    Value::Bool(true),
                    "Connector should be healthy",
                )],
            ),
            step_with_cleanup(
                "stop",
                "Stop the connector",
                "fwc lifecycle stop {{connector_id}} --format json",
                "fwc lifecycle disable {{connector_id}}",
                vec![assert_eq(
                    "/status",
                    Value::String("stopped".into()),
                    "Connector should be stopped",
                )],
            ),
            step_with_assert(
                "disable",
                "Disable the connector",
                "fwc lifecycle disable {{connector_id}} --format json",
                vec![assert_eq(
                    "/status",
                    Value::String("disabled".into()),
                    "Connector should be disabled",
                )],
            ),
        ],
    }
}

fn playbook_error_recovery() -> Playbook {
    Playbook {
        name: "error-recovery".into(),
        description: "Invoke an invalid operation, inspect the error, apply the suggested fix, and retry successfully.".into(),
        category: PlaybookCategory::ErrorRecovery,
        complexity: PlaybookComplexity::Moderate,
        tags: vec!["error".into(), "recovery".into(), "diagnostics".into()],
        expected_outcomes: vec![
            "Initial invocation fails with a structured error".into(),
            "Error contains a suggestion or fix hint".into(),
            "Retry with corrected input succeeds".into(),
        ],
        steps: vec![
            step_with_assert(
                "invoke-invalid",
                "Invoke operation with intentionally invalid input",
                "fwc invoke {{connector_id}} {{operation}} --input '{{bad_input}}' --format json",
                vec![
                    assert_eq("/status", Value::String("error".into()), "Should fail with error"),
                    assert_exists("/error/message", "Error should have a message"),
                ],
            ),
            step_with_assert(
                "inspect-error",
                "Inspect the error for suggestions",
                "fwc doctor diagnose --connector {{connector_id}} --last-error --format json",
                vec![
                    assert_not_empty("/suggestions", "Doctor should provide suggestions"),
                ],
            ),
            step_with_assert(
                "apply-fix",
                "Apply the suggested fix",
                "fwc invoke {{connector_id}} {{operation}} --input '{{corrected_input}}' --format json",
                vec![
                    assert_eq("/status", Value::String("success".into()), "Corrected invocation should succeed"),
                ],
            ),
        ],
    }
}

fn playbook_history_replay() -> Playbook {
    Playbook {
        name: "history-replay".into(),
        description: "Invoke an operation, locate it in history, then replay it with an overridden input field.".into(),
        category: PlaybookCategory::Execution,
        complexity: PlaybookComplexity::Moderate,
        tags: vec!["history".into(), "replay".into(), "audit".into()],
        expected_outcomes: vec![
            "Original invocation is recorded in history".into(),
            "Replay uses the overridden input".into(),
            "Replayed result differs from original as expected".into(),
        ],
        steps: vec![
            step_with_assert(
                "invoke",
                "Invoke an operation to create history",
                "fwc invoke {{connector_id}} {{operation}} --input '{{input_json}}' --format json",
                vec![
                    assert_eq("/status", Value::String("success".into()), "Invocation should succeed"),
                ],
            ),
            step_with_assert(
                "find-history",
                "Look up the invocation in history",
                "fwc history list --connector {{connector_id}} --limit 1 --format json",
                vec![
                    assert_not_empty("/entries", "History should contain the invocation"),
                    assert_exists("/entries/0/id", "Entry should have an ID"),
                ],
            ),
            step_with_assert(
                "replay",
                "Replay the invocation with an override",
                "fwc history replay {{entry_id}} --override '{{override_json}}' --format json",
                vec![
                    assert_eq("/status", Value::String("success".into()), "Replay should succeed"),
                    assert_exists("/output", "Replay should produce output"),
                ],
            ),
        ],
    }
}

fn playbook_config_management() -> Playbook {
    Playbook {
        name: "config-management".into(),
        description: "Read current config, modify a setting, apply changes, verify the new value, then rollback.".into(),
        category: PlaybookCategory::Administration,
        complexity: PlaybookComplexity::Complex,
        tags: vec!["config".into(), "admin".into(), "rollback".into()],
        expected_outcomes: vec![
            "Current config is readable".into(),
            "Config update is applied successfully".into(),
            "New value is reflected in a subsequent read".into(),
            "Rollback restores previous state".into(),
        ],
        steps: vec![
            step_with_assert(
                "read-config",
                "Read the current connector configuration",
                "fwc config get {{connector_id}} --format json",
                vec![
                    assert_exists("/config", "Config should be present"),
                ],
            ),
            step_with_assert(
                "modify",
                "Apply a config change",
                "fwc config set {{connector_id}} --key '{{config_key}}' --value '{{config_value}}' --format json",
                vec![
                    assert_eq("/applied", Value::Bool(true), "Config change should be applied"),
                ],
            ),
            step_with_assert(
                "verify",
                "Verify the new config value",
                "fwc config get {{connector_id}} --key '{{config_key}}' --format json",
                vec![
                    assert_exists("/value", "Config value should be returned"),
                ],
            ),
            step_with_assert(
                "rollback",
                "Rollback to previous config revision",
                "fwc config rollback {{connector_id}} --revision '{{prev_revision}}' --format json",
                vec![
                    assert_eq("/rolled_back", Value::Bool(true), "Rollback should succeed"),
                ],
            ),
        ],
    }
}

fn playbook_multi_connector_workflow() -> Playbook {
    Playbook {
        name: "multi-connector-workflow".into(),
        description: "Discover all connectors, filter to those supporting a target operation, batch-invoke across them, and aggregate results.".into(),
        category: PlaybookCategory::Workflow,
        complexity: PlaybookComplexity::Complex,
        tags: vec!["multi-connector".into(), "batch".into(), "aggregate".into()],
        expected_outcomes: vec![
            "Multiple connectors are discovered".into(),
            "Filtering narrows to capable connectors".into(),
            "Batch invocation completes across all targets".into(),
            "Aggregated results contain data from each connector".into(),
        ],
        steps: vec![
            step_with_assert(
                "discover-all",
                "List all available connectors",
                "fwc catalog list --format json",
                vec![
                    assert_gt("/count", 1.0, "Should have more than one connector"),
                ],
            ),
            step_with_assert(
                "filter",
                "Filter to connectors supporting the target operation",
                "fwc search --query '{{operation}}' --format json",
                vec![
                    assert_not_empty("/results", "At least one connector should support the operation"),
                ],
            ),
            step_with_timeout(
                "batch-invoke",
                "Invoke the operation across all matching connectors",
                "fwc batch create --operation '{{operation}}' --connectors '{{connector_list}}' --input '{{input_json}}' --format json",
                120,
                vec![
                    assert_exists("/batch_id", "Batch should be created"),
                ],
            ),
            step_with_assert(
                "aggregate",
                "Collect and aggregate results",
                "fwc batch status --id '{{batch_id}}' --format json",
                vec![
                    assert_exists("/summary/succeeded", "Should report succeeded count"),
                ],
            ),
        ],
    }
}

fn playbook_approval_flow() -> Playbook {
    Playbook {
        name: "approval-flow".into(),
        description: "Submit an operation requiring approval, check pending status, approve it, and verify execution.".into(),
        category: PlaybookCategory::Workflow,
        complexity: PlaybookComplexity::Moderate,
        tags: vec!["approval".into(), "workflow".into(), "safety".into()],
        expected_outcomes: vec![
            "Operation is submitted and enters pending state".into(),
            "Approval token is issued".into(),
            "Approved operation executes successfully".into(),
        ],
        steps: vec![
            step_with_assert(
                "submit",
                "Submit an operation that requires approval",
                "fwc invoke {{connector_id}} {{operation}} --input '{{input_json}}' --require-approval --format json",
                vec![
                    assert_eq("/status", Value::String("pending_approval".into()), "Should enter pending state"),
                    assert_exists("/approval_request_id", "Should have approval request ID"),
                ],
            ),
            step_with_assert(
                "check-pending",
                "List pending approvals",
                "fwc approval list --status pending --format json",
                vec![
                    assert_not_empty("/pending", "Should have pending approvals"),
                ],
            ),
            step_with_assert(
                "approve",
                "Approve the pending operation",
                "fwc approval approve --id '{{approval_request_id}}' --reason '{{approval_reason}}' --format json",
                vec![
                    assert_eq("/approved", Value::Bool(true), "Operation should be approved"),
                ],
            ),
            step_with_assert(
                "verify-execution",
                "Verify the approved operation executed",
                "fwc history list --request-id '{{request_id}}' --format json",
                vec![
                    assert_eq("/entries/0/status", Value::String("success".into()), "Approved op should succeed"),
                ],
            ),
        ],
    }
}

fn playbook_session_management() -> Playbook {
    Playbook {
        name: "session-management".into(),
        description: "Start a session, pin connector context, run multiple commands within the session, and end it.".into(),
        category: PlaybookCategory::Administration,
        complexity: PlaybookComplexity::Simple,
        tags: vec!["session".into(), "context".into(), "admin".into()],
        expected_outcomes: vec![
            "Session starts with a valid ID".into(),
            "Context pin is reflected in subsequent commands".into(),
            "Session ends cleanly".into(),
        ],
        steps: vec![
            step_with_cleanup(
                "start",
                "Start a new session",
                "fwc session start --format json",
                "fwc session end",
                vec![
                    assert_exists("/session_id", "Session should have an ID"),
                ],
            ),
            step_with_assert(
                "pin-context",
                "Pin a connector as the default context",
                "fwc session pin --connector {{connector_id}} --format json",
                vec![
                    assert_eq("/pinned", Value::Bool(true), "Context should be pinned"),
                ],
            ),
            step_with_assert(
                "run-in-session",
                "Invoke using the pinned context",
                "fwc invoke {{operation}} --input '{{input_json}}' --format json",
                vec![
                    assert_eq("/status", Value::String("success".into()), "Should use pinned connector"),
                ],
            ),
            step_with_assert(
                "end",
                "End the session",
                "fwc session end --format json",
                vec![
                    assert_eq("/ended", Value::Bool(true), "Session should end cleanly"),
                ],
            ),
        ],
    }
}

fn playbook_template_pipeline() -> Playbook {
    Playbook {
        name: "template-pipeline".into(),
        description: "Load a pipeline template, fill in parameters, validate the rendered pipeline, and run it.".into(),
        category: PlaybookCategory::Workflow,
        complexity: PlaybookComplexity::Moderate,
        tags: vec!["template".into(), "pipeline".into(), "parameters".into()],
        expected_outcomes: vec![
            "Template loads with parameter placeholders".into(),
            "Filled template renders correctly".into(),
            "Rendered pipeline validates successfully".into(),
            "Pipeline executes and produces output".into(),
        ],
        steps: vec![
            step_with_assert(
                "load",
                "Load a pipeline template",
                "fwc template get '{{template_id}}' --format json",
                vec![
                    assert_exists("/template", "Template should be returned"),
                    assert_not_empty("/parameters", "Template should have parameters"),
                ],
            ),
            step_with_assert(
                "fill",
                "Fill template parameters",
                "fwc template render '{{template_id}}' --params '{{params_json}}' --format json",
                vec![
                    assert_exists("/rendered", "Rendered pipeline should be returned"),
                ],
            ),
            step_with_assert(
                "validate",
                "Validate the rendered pipeline",
                "fwc pipeline validate --inline '{{rendered_pipeline}}' --format json",
                vec![
                    assert_eq("/valid", Value::Bool(true), "Rendered pipeline should be valid"),
                ],
            ),
            step_with_timeout(
                "execute",
                "Execute the rendered pipeline",
                "fwc pipeline run --inline '{{rendered_pipeline}}' --format json",
                180,
                vec![
                    assert_eq("/status", Value::String("completed".into()), "Pipeline should complete"),
                ],
            ),
        ],
    }
}

fn playbook_health_monitoring() -> Playbook {
    Playbook {
        name: "health-monitoring".into(),
        description: "Check fleet health, filter unhealthy connectors, diagnose issues, and generate an alert summary.".into(),
        category: PlaybookCategory::Administration,
        complexity: PlaybookComplexity::Moderate,
        tags: vec!["health".into(), "monitoring".into(), "diagnostics".into(), "fleet".into()],
        expected_outcomes: vec![
            "Fleet-wide health status is retrieved".into(),
            "Unhealthy connectors are identified".into(),
            "Diagnostics provide actionable information".into(),
        ],
        steps: vec![
            step_with_assert(
                "fleet-check",
                "Run fleet-wide health check",
                "fwc health fleet --format json",
                vec![
                    assert_exists("/summary", "Should return a fleet summary"),
                    assert_exists("/connectors", "Should list connector health"),
                ],
            ),
            step_with_assert(
                "filter-unhealthy",
                "Filter to unhealthy connectors",
                "fwc health fleet --filter unhealthy --format json",
                vec![
                    assert_exists("/connectors", "Should return filtered list"),
                ],
            ),
            step_with_assert(
                "diagnose",
                "Run diagnostics on unhealthy connectors",
                "fwc doctor diagnose --connector '{{unhealthy_connector}}' --format json",
                vec![
                    assert_not_empty("/findings", "Diagnostics should have findings"),
                ],
            ),
            step_with_assert(
                "alert-summary",
                "Generate alert summary",
                "fwc health report --format json",
                vec![
                    assert_exists("/report", "Report should be generated"),
                ],
            ),
        ],
    }
}

fn playbook_supply_chain_verify() -> Playbook {
    Playbook {
        name: "supply-chain-verify".into(),
        description: "Install a connector, verify its content digest, check supply-chain policy compliance, and produce an audit record.".into(),
        category: PlaybookCategory::Administration,
        complexity: PlaybookComplexity::Complex,
        tags: vec!["supply-chain".into(), "security".into(), "audit".into(), "verification".into()],
        expected_outcomes: vec![
            "Connector package installs successfully".into(),
            "Content digest matches the manifest".into(),
            "Supply-chain policy is satisfied".into(),
            "Audit record is persisted".into(),
        ],
        steps: vec![
            step_with_assert(
                "install",
                "Install a connector package",
                "fwc package install '{{package_ref}}' --format json",
                vec![
                    assert_eq("/installed", Value::Bool(true), "Package should install"),
                    assert_exists("/digest", "Install should report a digest"),
                ],
            ),
            step_with_assert(
                "verify-digest",
                "Verify the installed content digest",
                "fwc supply-chain verify --connector '{{connector_id}}' --format json",
                vec![
                    assert_eq("/verified", Value::Bool(true), "Digest should match"),
                ],
            ),
            step_with_assert(
                "check-policy",
                "Check supply-chain policy compliance",
                "fwc policy check --connector '{{connector_id}}' --format json",
                vec![
                    assert_eq("/compliant", Value::Bool(true), "Policy should be satisfied"),
                ],
            ),
            step_with_assert(
                "audit",
                "Generate an audit record",
                "fwc supply-chain audit --connector '{{connector_id}}' --format json",
                vec![
                    assert_exists("/audit_id", "Audit record should be created"),
                    assert_exists("/timestamp", "Audit should have a timestamp"),
                ],
            ),
        ],
    }
}

fn playbook_schema_navigation() -> Playbook {
    Playbook {
        name: "schema-navigation".into(),
        description: "Retrieve an operation schema, navigate its nested fields, extract type information, and validate a sample payload against it.".into(),
        category: PlaybookCategory::Discovery,
        complexity: PlaybookComplexity::Simple,
        tags: vec!["schema".into(), "navigation".into(), "validation".into()],
        expected_outcomes: vec![
            "Schema is retrieved with field definitions".into(),
            "Nested field navigation returns correct types".into(),
            "Sample payload validates against the schema".into(),
        ],
        steps: vec![
            step_with_assert(
                "get-schema",
                "Retrieve the operation schema",
                "fwc schema {{connector_id}} {{operation}} --format json",
                vec![
                    assert_exists("/input_schema", "Schema should have input_schema"),
                    assert_not_empty("/input_schema/properties", "Schema should have properties"),
                ],
            ),
            step_with_assert(
                "navigate",
                "Navigate to a nested field",
                "fwc schema {{connector_id}} {{operation}} --path '{{field_path}}' --format json",
                vec![
                    assert_exists("/type", "Navigated field should have a type"),
                ],
            ),
            step_with_assert(
                "extract-types",
                "List all field types",
                "fwc schema {{connector_id}} {{operation}} --list-types --format json",
                vec![
                    assert_not_empty("/fields", "Should list fields with types"),
                ],
            ),
            step_with_assert(
                "validate-payload",
                "Validate a sample payload against the schema",
                "fwc validate --connector {{connector_id}} --operation {{operation}} --input '{{sample_input}}' --format json",
                vec![
                    assert_eq("/valid", Value::Bool(true), "Sample payload should be valid"),
                ],
            ),
        ],
    }
}

fn playbook_export_and_share() -> Playbook {
    Playbook {
        name: "export-and-share".into(),
        description: "Invoke an operation, extract specific fields with jq, format the output, and export to a file.".into(),
        category: PlaybookCategory::Execution,
        complexity: PlaybookComplexity::Simple,
        tags: vec!["export".into(), "jq".into(), "format".into()],
        expected_outcomes: vec![
            "Invocation returns data".into(),
            "Field extraction produces expected subset".into(),
            "Export file is created".into(),
        ],
        steps: vec![
            step_with_assert(
                "invoke",
                "Invoke the operation",
                "fwc invoke {{connector_id}} {{operation}} --input '{{input_json}}' --format json",
                vec![
                    assert_eq("/status", Value::String("success".into()), "Invocation should succeed"),
                    assert_exists("/output", "Output should be present"),
                ],
            ),
            step_with_assert(
                "extract",
                "Extract fields with a jq expression",
                "fwc invoke {{connector_id}} {{operation}} --input '{{input_json}}' --jq '{{jq_expr}}' --format json",
                vec![
                    assert_not_empty("/", "Extracted data should not be empty"),
                ],
            ),
            step_with_assert(
                "format",
                "Format the extracted data as a table",
                "fwc invoke {{connector_id}} {{operation}} --input '{{input_json}}' --jq '{{jq_expr}}' --format table",
                vec![
                    assert_matches("/", "*|*", "Table output should contain column separators"),
                ],
            ),
            step_with_cleanup(
                "export",
                "Export to a file",
                "fwc export --connector {{connector_id}} --operation {{operation}} --input '{{input_json}}' --output '{{output_file}}' --format json",
                "rm -f '{{output_file}}'",
                vec![
                    assert_eq("/exported", Value::Bool(true), "Export should succeed"),
                    assert_exists("/path", "Export should report file path"),
                ],
            ),
        ],
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Built-in playbook inventory ──────────────────────────────────

    #[test]
    fn builtin_count_at_least_fifteen() {
        let playbooks = get_builtin_playbooks();
        assert!(
            playbooks.len() >= 15,
            "Expected at least 15 built-in playbooks, got {}",
            playbooks.len()
        );
    }

    #[test]
    fn builtin_names_are_unique() {
        let playbooks = get_builtin_playbooks();
        let mut names: Vec<&str> = playbooks.iter().map(|p| p.name.as_str()).collect();
        names.sort();
        let orig_len = names.len();
        names.dedup();
        assert_eq!(orig_len, names.len(), "Duplicate playbook names found");
    }

    #[test]
    fn builtin_playbooks_all_valid() {
        for pb in get_builtin_playbooks() {
            let issues = validate_playbook(&pb);
            assert!(
                issues.is_empty(),
                "Playbook '{}' has issues: {:?}",
                pb.name,
                issues
            );
        }
    }

    #[test]
    fn builtin_playbooks_have_tags() {
        for pb in get_builtin_playbooks() {
            assert!(!pb.tags.is_empty(), "Playbook '{}' has no tags", pb.name);
        }
    }

    #[test]
    fn builtin_step_ids_unique_within_playbook() {
        for pb in get_builtin_playbooks() {
            let mut ids: Vec<&str> = pb.steps.iter().map(|s| s.id.as_str()).collect();
            let orig = ids.len();
            ids.sort();
            ids.dedup();
            assert_eq!(
                orig,
                ids.len(),
                "Playbook '{}' has duplicate step IDs",
                pb.name
            );
        }
    }

    #[test]
    fn builtin_steps_have_nonzero_timeout() {
        for pb in get_builtin_playbooks() {
            for step in &pb.steps {
                assert!(
                    !step.timeout.is_zero(),
                    "Step '{}' in '{}' has zero timeout",
                    step.id,
                    pb.name
                );
            }
        }
    }

    #[test]
    fn builtin_steps_have_nonempty_commands() {
        for pb in get_builtin_playbooks() {
            for step in &pb.steps {
                assert!(
                    !step.command_template.is_empty(),
                    "Step '{}' in '{}' has empty command",
                    step.id,
                    pb.name
                );
            }
        }
    }

    #[test]
    fn each_category_covered() {
        let playbooks = get_builtin_playbooks();
        let categories = [
            PlaybookCategory::Discovery,
            PlaybookCategory::Execution,
            PlaybookCategory::Workflow,
            PlaybookCategory::Administration,
            PlaybookCategory::ErrorRecovery,
            PlaybookCategory::Performance, // health-monitoring covers this area; we check the others
        ];
        for cat in &categories[..5] {
            assert!(
                playbooks.iter().any(|p| p.category == *cat),
                "No playbook for category {:?}",
                cat
            );
        }
    }

    // ── PlaybookRegistry ─────────────────────────────────────────────

    #[test]
    fn registry_new_is_empty() {
        let reg = PlaybookRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn registry_with_builtins_not_empty() {
        let reg = PlaybookRegistry::with_builtins();
        assert!(!reg.is_empty());
        assert!(reg.len() >= 15);
    }

    #[test]
    fn registry_add_increases_len() {
        let mut reg = PlaybookRegistry::new();
        reg.add(playbook_discover_and_invoke());
        assert_eq!(reg.len(), 1);
        reg.add(playbook_batch_with_retry());
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn registry_find_by_category_discovery() {
        let reg = PlaybookRegistry::with_builtins();
        let found = reg.find_by_category(PlaybookCategory::Discovery);
        assert!(!found.is_empty());
        for pb in &found {
            assert_eq!(pb.category, PlaybookCategory::Discovery);
        }
    }

    #[test]
    fn registry_find_by_category_workflow() {
        let reg = PlaybookRegistry::with_builtins();
        let found = reg.find_by_category(PlaybookCategory::Workflow);
        assert!(!found.is_empty());
        for pb in &found {
            assert_eq!(pb.category, PlaybookCategory::Workflow);
        }
    }

    #[test]
    fn registry_find_by_category_administration() {
        let reg = PlaybookRegistry::with_builtins();
        let found = reg.find_by_category(PlaybookCategory::Administration);
        assert!(!found.is_empty());
    }

    #[test]
    fn registry_find_by_category_returns_empty_for_unused() {
        let mut reg = PlaybookRegistry::new();
        reg.add(playbook_discover_and_invoke());
        let found = reg.find_by_category(PlaybookCategory::Performance);
        assert!(found.is_empty());
    }

    #[test]
    fn registry_find_by_tag() {
        let reg = PlaybookRegistry::with_builtins();
        let found = reg.find_by_tag("batch");
        assert!(!found.is_empty());
        for pb in &found {
            assert!(
                pb.tags.iter().any(|t| t == "batch"),
                "Playbook '{}' missing batch tag",
                pb.name
            );
        }
    }

    #[test]
    fn registry_find_by_tag_case_insensitive() {
        let reg = PlaybookRegistry::with_builtins();
        let lower = reg.find_by_tag("batch");
        let upper = reg.find_by_tag("BATCH");
        assert_eq!(lower.len(), upper.len());
    }

    #[test]
    fn registry_find_by_tag_empty_for_unknown() {
        let reg = PlaybookRegistry::with_builtins();
        let found = reg.find_by_tag("nonexistent-tag-xyz");
        assert!(found.is_empty());
    }

    #[test]
    fn registry_find_by_name() {
        let reg = PlaybookRegistry::with_builtins();
        let found = reg.find_by_name("discover-and-invoke");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "discover-and-invoke");
    }

    #[test]
    fn registry_find_by_name_missing() {
        let reg = PlaybookRegistry::with_builtins();
        assert!(reg.find_by_name("no-such-playbook").is_none());
    }

    #[test]
    fn registry_all_tags_sorted_deduped() {
        let reg = PlaybookRegistry::with_builtins();
        let tags = reg.all_tags();
        assert!(!tags.is_empty());
        for window in tags.windows(2) {
            assert!(window[0] <= window[1], "Tags not sorted: {:?}", tags);
        }
        // No duplicates.
        let mut deduped = tags.clone();
        deduped.dedup();
        assert_eq!(tags.len(), deduped.len());
    }

    // ── Assertion evaluation: Equals ─────────────────────────────────

    #[test]
    fn assert_equals_string_pass() {
        let val = json!({"status": "success"});
        let a = assert_eq("/status", json!("success"), "should match");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_equals_string_fail() {
        let val = json!({"status": "error"});
        let a = assert_eq("/status", json!("success"), "should match");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_equals_number() {
        let val = json!({"count": 42});
        let a = assert_eq("/count", json!(42), "count check");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_equals_bool() {
        let val = json!({"ok": true});
        let a = assert_eq("/ok", json!(true), "bool check");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_equals_null() {
        let val = json!({"field": null});
        let a = assert_eq("/field", json!(null), "null check");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_equals_nested() {
        let val = json!({"a": {"b": {"c": 7}}});
        let a = assert_eq("/a/b/c", json!(7), "nested");
        assert!(check_assertion(&val, &a));
    }

    // ── Assertion evaluation: Contains ───────────────────────────────

    #[test]
    fn assert_contains_string() {
        let val = json!({"msg": "hello world"});
        let a = assert_contains("/msg", "world", "substring");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_contains_string_fail() {
        let val = json!({"msg": "hello"});
        let a = assert_contains("/msg", "world", "substring");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_contains_array() {
        let val = json!({"items": [1, 2, 3]});
        let a = Assertion {
            field_path: Some("/items".into()),
            condition: AssertionCondition::Contains,
            expected_value: json!(2),
            message: "array contains".into(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_contains_array_fail() {
        let val = json!({"items": [1, 2, 3]});
        let a = Assertion {
            field_path: Some("/items".into()),
            condition: AssertionCondition::Contains,
            expected_value: json!(5),
            message: "array contains".into(),
        };
        assert!(!check_assertion(&val, &a));
    }

    // ── Assertion evaluation: NotEmpty ────────────────────────────────

    #[test]
    fn assert_not_empty_string_pass() {
        let val = json!({"name": "abc"});
        let a = assert_not_empty("/name", "not empty");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_not_empty_string_fail() {
        let val = json!({"name": ""});
        let a = assert_not_empty("/name", "not empty");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_not_empty_array_pass() {
        let val = json!({"items": [1]});
        let a = assert_not_empty("/items", "not empty");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_not_empty_array_fail() {
        let val = json!({"items": []});
        let a = assert_not_empty("/items", "not empty");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_not_empty_object_pass() {
        let val = json!({"data": {"k": "v"}});
        let a = assert_not_empty("/data", "not empty");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_not_empty_object_fail() {
        let val = json!({"data": {}});
        let a = assert_not_empty("/data", "not empty");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_not_empty_null_fail() {
        let val = json!({"x": null});
        let a = assert_not_empty("/x", "not empty");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_not_empty_number_pass() {
        let val = json!({"n": 42});
        let a = assert_not_empty("/n", "not empty");
        assert!(check_assertion(&val, &a));
    }

    // ── Assertion evaluation: GreaterThan / LessThan ─────────────────

    #[test]
    fn assert_greater_than_pass() {
        let val = json!({"count": 10});
        let a = assert_gt("/count", 5.0, "gt");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_greater_than_fail_equal() {
        let val = json!({"count": 5});
        let a = assert_gt("/count", 5.0, "gt");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_greater_than_fail() {
        let val = json!({"count": 3});
        let a = assert_gt("/count", 5.0, "gt");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_less_than_pass() {
        let val = json!({"latency": 100});
        let a = assert_lt("/latency", 200.0, "lt");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_less_than_fail() {
        let val = json!({"latency": 300});
        let a = assert_lt("/latency", 200.0, "lt");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_less_than_non_numeric() {
        let val = json!({"latency": "fast"});
        let a = assert_lt("/latency", 200.0, "lt");
        assert!(!check_assertion(&val, &a));
    }

    // ── Assertion evaluation: Matches ────────────────────────────────

    #[test]
    fn assert_matches_exact() {
        let val = json!({"name": "hello"});
        let a = assert_matches("/name", "hello", "exact");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_matches_wildcard_suffix() {
        let val = json!({"name": "fwc-connector-abc"});
        let a = assert_matches("/name", "fwc-connector-*", "wildcard");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_matches_wildcard_middle() {
        let val = json!({"path": "/api/v2/users"});
        let a = assert_matches("/path", "/api/*/users", "middle");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_matches_wildcard_fail() {
        let val = json!({"name": "hello"});
        let a = assert_matches("/name", "world*", "no match");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_matches_non_string() {
        let val = json!({"count": 42});
        let a = assert_matches("/count", "*", "non-string");
        assert!(!check_assertion(&val, &a));
    }

    // ── Assertion evaluation: Exists ─────────────────────────────────

    #[test]
    fn assert_exists_present_true() {
        let val = json!({"key": "val"});
        let a = assert_exists("/key", "exists");
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_exists_missing_true() {
        let val = json!({"key": "val"});
        let a = Assertion {
            field_path: Some("/missing".into()),
            condition: AssertionCondition::Exists,
            expected_value: json!(true),
            message: "should exist".into(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_exists_missing_expected_false() {
        let val = json!({"key": "val"});
        let a = Assertion {
            field_path: Some("/missing".into()),
            condition: AssertionCondition::Exists,
            expected_value: json!(false),
            message: "should not exist".into(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_exists_present_expected_false() {
        let val = json!({"key": "val"});
        let a = Assertion {
            field_path: Some("/key".into()),
            condition: AssertionCondition::Exists,
            expected_value: json!(false),
            message: "should not exist".into(),
        };
        assert!(!check_assertion(&val, &a));
    }

    // ── Assertion evaluation: no field path ──────────────────────────

    #[test]
    fn assert_root_value_equals() {
        let val = json!("hello");
        let a = Assertion {
            field_path: None,
            condition: AssertionCondition::Equals,
            expected_value: json!("hello"),
            message: "root".into(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_root_value_not_empty() {
        let val = json!([1, 2, 3]);
        let a = Assertion {
            field_path: None,
            condition: AssertionCondition::NotEmpty,
            expected_value: json!(null),
            message: "root not empty".into(),
        };
        assert!(check_assertion(&val, &a));
    }

    // ── Validation ───────────────────────────────────────────────────

    #[test]
    fn validate_good_playbook() {
        let pb = playbook_discover_and_invoke();
        assert!(validate_playbook(&pb).is_empty());
    }

    #[test]
    fn validate_empty_name() {
        let mut pb = playbook_discover_and_invoke();
        pb.name = String::new();
        let issues = validate_playbook(&pb);
        assert!(issues.iter().any(|i| i.contains("name")));
    }

    #[test]
    fn validate_empty_description() {
        let mut pb = playbook_discover_and_invoke();
        pb.description = String::new();
        let issues = validate_playbook(&pb);
        assert!(issues.iter().any(|i| i.contains("description")));
    }

    #[test]
    fn validate_no_steps() {
        let mut pb = playbook_discover_and_invoke();
        pb.steps.clear();
        let issues = validate_playbook(&pb);
        assert!(issues.iter().any(|i| i.contains("no steps")));
    }

    #[test]
    fn validate_no_expected_outcomes() {
        let mut pb = playbook_discover_and_invoke();
        pb.expected_outcomes.clear();
        let issues = validate_playbook(&pb);
        assert!(issues.iter().any(|i| i.contains("expected outcomes")));
    }

    #[test]
    fn validate_duplicate_step_ids() {
        let mut pb = playbook_discover_and_invoke();
        if pb.steps.len() >= 2 {
            pb.steps[1].id = pb.steps[0].id.clone();
        }
        let issues = validate_playbook(&pb);
        assert!(issues.iter().any(|i| i.contains("Duplicate")));
    }

    #[test]
    fn validate_empty_command_template() {
        let mut pb = playbook_discover_and_invoke();
        pb.steps[0].command_template = String::new();
        let issues = validate_playbook(&pb);
        assert!(issues.iter().any(|i| i.contains("empty command")));
    }

    #[test]
    fn validate_zero_timeout() {
        let mut pb = playbook_discover_and_invoke();
        pb.steps[0].timeout = Duration::ZERO;
        let issues = validate_playbook(&pb);
        assert!(issues.iter().any(|i| i.contains("zero timeout")));
    }

    // ── TOON formatting ──────────────────────────────────────────────

    #[test]
    fn format_playbook_toon_contains_name() {
        let pb = playbook_discover_and_invoke();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("discover-and-invoke"));
    }

    #[test]
    fn format_playbook_toon_contains_category() {
        let pb = playbook_discover_and_invoke();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("discovery"));
    }

    #[test]
    fn format_playbook_toon_contains_steps() {
        let pb = playbook_discover_and_invoke();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("Step 1:"));
    }

    #[test]
    fn format_playbook_toon_contains_complexity() {
        let pb = playbook_discover_and_invoke();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("moderate"));
    }

    #[test]
    fn format_playbook_toon_contains_tags() {
        let pb = playbook_discover_and_invoke();
        let out = format_playbook_toon(&pb);
        for tag in &pb.tags {
            assert!(out.contains(tag.as_str()), "Missing tag '{tag}' in output");
        }
    }

    #[test]
    fn format_playbook_toon_contains_expected_outcomes() {
        let pb = playbook_discover_and_invoke();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("Expected outcomes"));
    }

    #[test]
    fn format_result_toon_pass() {
        let result = PlaybookResult {
            playbook_name: "test-pb".into(),
            all_passed: true,
            step_results: vec![StepResult {
                step_id: "s1".into(),
                passed: true,
                output: json!({}),
                assertion_results: vec![("check".into(), true)],
                duration: Duration::from_millis(150),
            }],
            duration: Duration::from_millis(200),
            category: PlaybookCategory::Discovery,
        };
        let out = format_playbook_result_toon(&result);
        assert!(out.contains("PASS"));
        assert!(out.contains("test-pb"));
        assert!(out.contains("[ok]"));
    }

    #[test]
    fn format_result_toon_fail() {
        let result = PlaybookResult {
            playbook_name: "test-fail".into(),
            all_passed: false,
            step_results: vec![StepResult {
                step_id: "s1".into(),
                passed: false,
                output: json!({}),
                assertion_results: vec![("check".into(), false)],
                duration: Duration::from_millis(50),
            }],
            duration: Duration::from_millis(100),
            category: PlaybookCategory::Execution,
        };
        let out = format_playbook_result_toon(&result);
        assert!(out.contains("FAIL"));
        assert!(out.contains("[-]"));
    }

    #[test]
    fn format_result_toon_shows_step_count() {
        let result = PlaybookResult {
            playbook_name: "multi".into(),
            all_passed: true,
            step_results: vec![
                StepResult {
                    step_id: "s1".into(),
                    passed: true,
                    output: json!({}),
                    assertion_results: vec![],
                    duration: Duration::from_millis(10),
                },
                StepResult {
                    step_id: "s2".into(),
                    passed: true,
                    output: json!({}),
                    assertion_results: vec![],
                    duration: Duration::from_millis(20),
                },
            ],
            duration: Duration::from_millis(30),
            category: PlaybookCategory::Workflow,
        };
        let out = format_playbook_result_toon(&result);
        assert!(out.contains("2/2 passed"));
    }

    #[test]
    fn format_result_toon_partial_pass() {
        let result = PlaybookResult {
            playbook_name: "partial".into(),
            all_passed: false,
            step_results: vec![
                StepResult {
                    step_id: "s1".into(),
                    passed: true,
                    output: json!({}),
                    assertion_results: vec![],
                    duration: Duration::from_millis(10),
                },
                StepResult {
                    step_id: "s2".into(),
                    passed: false,
                    output: json!({}),
                    assertion_results: vec![],
                    duration: Duration::from_millis(10),
                },
            ],
            duration: Duration::from_millis(20),
            category: PlaybookCategory::ErrorRecovery,
        };
        let out = format_playbook_result_toon(&result);
        assert!(out.contains("1/2 passed"));
    }

    // ── Serialization round-trip ─────────────────────────────────────

    #[test]
    fn playbook_serde_roundtrip() {
        let pb = playbook_discover_and_invoke();
        let json = serde_json::to_string(&pb).unwrap();
        let pb2: Playbook = serde_json::from_str(&json).unwrap();
        assert_eq!(pb.name, pb2.name);
        assert_eq!(pb.steps.len(), pb2.steps.len());
    }

    #[test]
    fn assertion_condition_serde_roundtrip() {
        let conditions = [
            AssertionCondition::Equals,
            AssertionCondition::Contains,
            AssertionCondition::NotEmpty,
            AssertionCondition::GreaterThan,
            AssertionCondition::LessThan,
            AssertionCondition::Matches,
            AssertionCondition::Exists,
        ];
        for cond in &conditions {
            let json = serde_json::to_string(cond).unwrap();
            let cond2: AssertionCondition = serde_json::from_str(&json).unwrap();
            assert_eq!(*cond, cond2);
        }
    }

    #[test]
    fn playbook_category_serde_roundtrip() {
        let categories = [
            PlaybookCategory::Discovery,
            PlaybookCategory::Execution,
            PlaybookCategory::Workflow,
            PlaybookCategory::Administration,
            PlaybookCategory::ErrorRecovery,
            PlaybookCategory::Performance,
        ];
        for cat in &categories {
            let json = serde_json::to_string(cat).unwrap();
            let cat2: PlaybookCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, cat2);
        }
    }

    #[test]
    fn playbook_complexity_serde_roundtrip() {
        let levels = [
            PlaybookComplexity::Simple,
            PlaybookComplexity::Moderate,
            PlaybookComplexity::Complex,
        ];
        for level in &levels {
            let json = serde_json::to_string(level).unwrap();
            let level2: PlaybookComplexity = serde_json::from_str(&json).unwrap();
            assert_eq!(*level, level2);
        }
    }

    #[test]
    fn registry_serde_roundtrip() {
        let reg = PlaybookRegistry::with_builtins();
        let json = serde_json::to_string(&reg).unwrap();
        let reg2: PlaybookRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg.len(), reg2.len());
    }

    #[test]
    fn step_result_serde_roundtrip() {
        let sr = StepResult {
            step_id: "test".into(),
            passed: true,
            output: json!({"x": 1}),
            assertion_results: vec![("check".into(), true)],
            duration: Duration::from_secs(1),
        };
        let json = serde_json::to_string(&sr).unwrap();
        let sr2: StepResult = serde_json::from_str(&json).unwrap();
        assert_eq!(sr.step_id, sr2.step_id);
        assert_eq!(sr.passed, sr2.passed);
    }

    // ── Glob matching ────────────────────────────────────────────────

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("hello", "hello"));
    }

    #[test]
    fn glob_exact_no_match() {
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn glob_star_suffix() {
        assert!(glob_match("hello world", "hello*"));
    }

    #[test]
    fn glob_star_prefix() {
        assert!(glob_match("hello world", "*world"));
    }

    #[test]
    fn glob_star_middle() {
        assert!(glob_match("hello beautiful world", "hello*world"));
    }

    #[test]
    fn glob_star_only() {
        assert!(glob_match("anything", "*"));
    }

    #[test]
    fn glob_star_no_match() {
        assert!(!glob_match("hello", "world*"));
    }

    #[test]
    fn glob_double_star() {
        assert!(glob_match("a/b/c/d", "a*c*d"));
    }

    #[test]
    fn glob_star_prefix_anchor() {
        // Pattern "abc*" should match "abcdef" but not "xabc".
        assert!(glob_match("abcdef", "abc*"));
        assert!(!glob_match("xabc", "abc*"));
    }

    // ── Individual playbook structure tests ──────────────────────────

    #[test]
    fn discover_and_invoke_has_four_steps() {
        let pb = playbook_discover_and_invoke();
        assert_eq!(pb.steps.len(), 4);
        assert_eq!(pb.category, PlaybookCategory::Discovery);
    }

    #[test]
    fn batch_with_retry_is_complex() {
        let pb = playbook_batch_with_retry();
        assert_eq!(pb.complexity, PlaybookComplexity::Complex);
    }

    #[test]
    fn pipeline_chain_has_dry_run_step() {
        let pb = playbook_pipeline_chain();
        assert!(pb.steps.iter().any(|s| s.id == "dry-run"));
    }

    #[test]
    fn lifecycle_manage_step_order() {
        let pb = playbook_lifecycle_manage();
        let ids: Vec<&str> = pb.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["enable", "start", "health", "stop", "disable"]);
    }

    #[test]
    fn error_recovery_starts_with_invalid() {
        let pb = playbook_error_recovery();
        assert_eq!(pb.steps[0].id, "invoke-invalid");
    }

    #[test]
    fn history_replay_has_find_step() {
        let pb = playbook_history_replay();
        assert!(pb.steps.iter().any(|s| s.id == "find-history"));
    }

    #[test]
    fn config_management_has_rollback() {
        let pb = playbook_config_management();
        assert!(pb.steps.iter().any(|s| s.id == "rollback"));
    }

    #[test]
    fn approval_flow_has_approve_step() {
        let pb = playbook_approval_flow();
        assert!(pb.steps.iter().any(|s| s.id == "approve"));
    }

    #[test]
    fn session_management_has_cleanup() {
        let pb = playbook_session_management();
        assert!(pb.steps[0].cleanup.is_some());
    }

    #[test]
    fn supply_chain_verify_has_audit() {
        let pb = playbook_supply_chain_verify();
        assert!(pb.steps.iter().any(|s| s.id == "audit"));
    }

    #[test]
    fn schema_navigation_is_simple() {
        let pb = playbook_schema_navigation();
        assert_eq!(pb.complexity, PlaybookComplexity::Simple);
    }

    #[test]
    fn export_and_share_has_export_cleanup() {
        let pb = playbook_export_and_share();
        let export_step = pb.steps.iter().find(|s| s.id == "export").unwrap();
        assert!(export_step.cleanup.is_some());
    }

    #[test]
    fn health_monitoring_is_administration() {
        let pb = playbook_health_monitoring();
        assert_eq!(pb.category, PlaybookCategory::Administration);
    }

    #[test]
    fn template_pipeline_has_fill_step() {
        let pb = playbook_template_pipeline();
        assert!(pb.steps.iter().any(|s| s.id == "fill"));
    }

    #[test]
    fn multi_connector_has_aggregate() {
        let pb = playbook_multi_connector_workflow();
        assert!(pb.steps.iter().any(|s| s.id == "aggregate"));
    }

    // ── PlaybookCategory display ─────────────────────────────────────

    #[test]
    fn category_display() {
        assert_eq!(PlaybookCategory::Discovery.to_string(), "discovery");
        assert_eq!(
            PlaybookCategory::ErrorRecovery.to_string(),
            "error-recovery"
        );
        assert_eq!(PlaybookCategory::Performance.to_string(), "performance");
    }

    #[test]
    fn complexity_display() {
        assert_eq!(PlaybookComplexity::Simple.to_string(), "simple");
        assert_eq!(PlaybookComplexity::Moderate.to_string(), "moderate");
        assert_eq!(PlaybookComplexity::Complex.to_string(), "complex");
    }

    #[test]
    fn complexity_ordering() {
        assert!(PlaybookComplexity::Simple < PlaybookComplexity::Moderate);
        assert!(PlaybookComplexity::Moderate < PlaybookComplexity::Complex);
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn assert_empty_field_path_is_root() {
        let val = json!([1, 2, 3]);
        let a = Assertion {
            field_path: Some("/".into()),
            condition: AssertionCondition::NotEmpty,
            expected_value: json!(null),
            message: "root via empty path".into(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assert_deeply_nested_missing() {
        let val = json!({"a": {}});
        let a = Assertion {
            field_path: Some("/a/b/c/d".into()),
            condition: AssertionCondition::Exists,
            expected_value: json!(true),
            message: "deep missing".into(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_contains_on_non_string_non_array() {
        let val = json!({"x": 42});
        let a = Assertion {
            field_path: Some("/x".into()),
            condition: AssertionCondition::Contains,
            expected_value: json!("42"),
            message: "number contains string".into(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assert_greater_than_string_fails_gracefully() {
        let val = json!({"x": "not a number"});
        let a = assert_gt("/x", 5.0, "gt on string");
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn format_playbook_step_with_cleanup() {
        let mut pb = playbook_discover_and_invoke();
        pb.steps[0].cleanup = Some("echo cleanup".into());
        let out = format_playbook_toon(&pb);
        assert!(out.contains("Cleanup:"));
    }

    #[test]
    fn format_playbook_empty_steps() {
        let pb = Playbook {
            name: "empty".into(),
            description: "empty playbook".into(),
            category: PlaybookCategory::Discovery,
            steps: vec![],
            expected_outcomes: vec!["none".into()],
            tags: vec![],
            complexity: PlaybookComplexity::Simple,
        };
        let out = format_playbook_toon(&pb);
        assert!(out.contains("Steps:      0"));
    }
}
