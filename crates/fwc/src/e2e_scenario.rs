//! E2E scenario runner and artifact bundler for FWC end-to-end testing.
//!
//! Provides a TOML-driven test scenario framework where each scenario consists of
//! ordered steps with dependency tracking, expected outcome assertions, and
//! artifact collection.  Scenarios are parsed from TOML, validated for structural
//! correctness, and executed in dependency order.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};

// ── Error types ─────────────────────────────────────────────────────────────

/// Errors that can occur during scenario parsing or execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScenarioError {
    /// The TOML input could not be parsed.
    ParseError { message: String },
    /// A required field is missing.
    MissingField { field: String },
    /// A step references a dependency that does not exist.
    MissingDependency { step_id: String, missing: String },
    /// A circular dependency was detected among steps.
    CircularDependency { cycle: Vec<String> },
    /// A step ID is duplicated.
    DuplicateStepId { step_id: String },
}

impl std::fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError { message } => write!(f, "scenario parse error: {message}"),
            Self::MissingField { field } => write!(f, "missing required field: {field}"),
            Self::MissingDependency { step_id, missing } => {
                write!(f, "step `{step_id}` depends on unknown step `{missing}`")
            }
            Self::CircularDependency { cycle } => {
                write!(f, "circular dependency: {}", cycle.join(" -> "))
            }
            Self::DuplicateStepId { step_id } => {
                write!(f, "duplicate step id: `{step_id}`")
            }
        }
    }
}

impl std::error::Error for ScenarioError {}

// ── Core types ──────────────────────────────────────────────────────────────

/// A single step within a scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioStep {
    /// Unique identifier for this step within the scenario.
    pub id: String,
    /// The command string to execute.
    pub command: String,
    /// Expected process exit code (default 0).
    #[serde(default)]
    pub expected_exit_code: i32,
    /// Strings that must appear in stdout.
    #[serde(default)]
    pub expected_output_contains: Vec<String>,
    /// Strings that must NOT appear in stdout.
    #[serde(default)]
    pub expected_output_not_contains: Vec<String>,
    /// IDs of steps that must complete before this one.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// If set, capture this step's stdout under this key in the artifact bundle.
    #[serde(default)]
    pub capture_as: Option<String>,
}

/// A complete test scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scenario {
    /// Human-readable scenario name.
    pub name: String,
    /// Description of what this scenario tests.
    #[serde(default)]
    pub description: String,
    /// Ordered list of steps.
    pub steps: Vec<ScenarioStep>,
    /// Expected final outcomes (freeform tags such as "connector listed").
    #[serde(default)]
    pub expected_outcomes: Vec<String>,
    /// Freeform tags for filtering (e.g. "smoke", "regression").
    #[serde(default)]
    pub tags: Vec<String>,
    /// Overall scenario timeout.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

const fn default_timeout_secs() -> u64 {
    300
}

impl Scenario {
    /// Get the timeout as a `Duration`.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Return the set of all step IDs.
    #[must_use]
    pub fn step_ids(&self) -> HashSet<String> {
        self.steps.iter().map(|s| s.id.clone()).collect()
    }
}

/// The outcome of executing a single step.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepOutcome {
    /// Which step produced this outcome.
    pub step_id: String,
    /// Actual exit code returned by the process.
    pub exit_code: i32,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// Wall-clock duration of the step.
    pub duration: Duration,
    /// Whether the step passed all assertions.
    pub passed: bool,
    /// If `passed` is false, a human-readable reason.
    pub failure_reason: Option<String>,
}

/// The result of running an entire scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Name of the scenario that was run.
    pub scenario_name: String,
    /// Whether the scenario passed overall.
    pub passed: bool,
    /// ID of the first step that failed (if any).
    pub failed_step: Option<String>,
    /// Total wall-clock duration.
    pub duration: Duration,
    /// Collected artifacts.
    pub artifacts: ArtifactBundle,
    /// Concatenated stdout from all steps.
    pub stdout_log: String,
    /// Concatenated stderr from all steps.
    pub stderr_log: String,
}

/// A bundle of artifacts collected during a scenario run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactBundle {
    /// Scenario that produced these artifacts.
    pub scenario_name: String,
    /// ISO-8601 timestamp of bundle creation.
    pub timestamp: String,
    /// Collected files (name -> content).
    pub files: HashMap<String, String>,
    /// Freeform metadata.
    pub metadata: HashMap<String, String>,
}

impl ArtifactBundle {
    /// Create a new empty bundle for the given scenario.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            scenario_name: name.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            files: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a file to the bundle.
    pub fn add_file(&mut self, name: &str, content: &str) {
        self.files.insert(name.to_string(), content.to_string());
    }

    /// Add a metadata entry.
    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Return the number of files in the bundle.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Format a manifest listing all files and metadata.
    #[must_use]
    pub fn format_manifest(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "Artifact Bundle: {}", self.scenario_name);
        let _ = writeln!(out, "Timestamp: {}", self.timestamp);
        let _ = writeln!(out, "Files ({}):", self.files.len());
        let mut names: Vec<&String> = self.files.keys().collect();
        names.sort();
        for name in names {
            let size = self.files[name].len();
            let _ = writeln!(out, "  {name} ({size} bytes)");
        }
        if !self.metadata.is_empty() {
            let _ = writeln!(out, "Metadata:");
            let mut keys: Vec<&String> = self.metadata.keys().collect();
            keys.sort();
            for key in keys {
                let _ = writeln!(out, "  {key}: {}", self.metadata[key]);
            }
        }
        out
    }
}

// ── Scenario Runner ─────────────────────────────────────────────────────────

/// Runs scenarios, collecting results and artifacts.
#[derive(Clone, Debug)]
pub struct ScenarioRunner {
    /// Registered scenarios.
    pub scenarios: Vec<Scenario>,
    /// Default timeout applied to scenarios that do not specify one.
    pub timeout: Duration,
    /// Whether to emit verbose step-by-step output.
    pub verbose: bool,
    /// Whether to collect artifacts from step outputs.
    pub capture_artifacts: bool,
}

impl ScenarioRunner {
    /// Create a new runner with the given default timeout.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self {
            scenarios: Vec::new(),
            timeout,
            verbose: false,
            capture_artifacts: true,
        }
    }

    /// Register a scenario for execution.
    pub fn add_scenario(&mut self, scenario: Scenario) {
        self.scenarios.push(scenario);
    }

    /// Return the number of registered scenarios.
    #[must_use]
    pub fn scenario_count(&self) -> usize {
        self.scenarios.len()
    }

    /// Compute the execution plan: for each scenario, return the ordered list of
    /// step IDs respecting dependency order.
    ///
    /// Returns `(scenario_name, ordered_step_ids)` pairs.
    #[must_use]
    pub fn plan(&self) -> Vec<(String, Vec<String>)> {
        self.scenarios
            .iter()
            .map(|s| {
                let ordered = topological_sort_steps(&s.steps);
                (s.name.clone(), ordered)
            })
            .collect()
    }

    /// Check whether a step outcome satisfies the step's assertions.
    #[must_use]
    pub fn check_step(step: &ScenarioStep, outcome: &StepOutcome) -> bool {
        if outcome.exit_code != step.expected_exit_code {
            return false;
        }
        for expected in &step.expected_output_contains {
            if !outcome.stdout.contains(expected.as_str()) {
                return false;
            }
        }
        for forbidden in &step.expected_output_not_contains {
            if outcome.stdout.contains(forbidden.as_str()) {
                return false;
            }
        }
        true
    }

    /// Produce a detailed failure reason for a step that did not pass.
    #[must_use]
    pub fn failure_reason(step: &ScenarioStep, outcome: &StepOutcome) -> Option<String> {
        let mut reasons = Vec::new();
        if outcome.exit_code != step.expected_exit_code {
            reasons.push(format!(
                "exit code: expected {}, got {}",
                step.expected_exit_code, outcome.exit_code
            ));
        }
        for expected in &step.expected_output_contains {
            if !outcome.stdout.contains(expected.as_str()) {
                reasons.push(format!("missing expected output: `{expected}`"));
            }
        }
        for forbidden in &step.expected_output_not_contains {
            if outcome.stdout.contains(forbidden.as_str()) {
                reasons.push(format!("found forbidden output: `{forbidden}`"));
            }
        }
        if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        }
    }
}

// ── Parsing ─────────────────────────────────────────────────────────────────

/// Parse a TOML string into a `Scenario`.
///
/// # Errors
///
/// Returns `ScenarioError::ParseError` if the TOML is malformed or missing
/// required fields.
pub fn parse_scenario(toml_str: &str) -> Result<Scenario, ScenarioError> {
    let scenario: Scenario = toml::from_str(toml_str).map_err(|e| ScenarioError::ParseError {
        message: e.to_string(),
    })?;
    if scenario.name.is_empty() {
        return Err(ScenarioError::MissingField {
            field: "name".to_string(),
        });
    }
    if scenario.steps.is_empty() {
        return Err(ScenarioError::MissingField {
            field: "steps".to_string(),
        });
    }
    for step in &scenario.steps {
        if step.id.is_empty() {
            return Err(ScenarioError::MissingField {
                field: "steps[].id".to_string(),
            });
        }
        if step.command.is_empty() {
            return Err(ScenarioError::MissingField {
                field: format!("steps[{}].command", step.id),
            });
        }
    }
    Ok(scenario)
}

// ── Validation ──────────────────────────────────────────────────────────────

/// Validate a parsed scenario for structural issues.
///
/// Returns a list of human-readable warnings/errors.  An empty list means the
/// scenario is fully valid.
#[must_use]
pub fn validate_scenario(scenario: &Scenario) -> Vec<String> {
    let mut issues = Vec::new();
    let ids = scenario.step_ids();

    // Check for duplicate step IDs.
    let mut seen = HashSet::new();
    for step in &scenario.steps {
        if !seen.insert(&step.id) {
            issues.push(format!("duplicate step id: `{}`", step.id));
        }
    }

    // Check for missing dependencies.
    for step in &scenario.steps {
        for dep in &step.depends_on {
            if !ids.contains(dep) {
                issues.push(format!(
                    "step `{}` depends on unknown step `{dep}`",
                    step.id
                ));
            }
        }
    }

    // Check for self-dependencies.
    for step in &scenario.steps {
        if step.depends_on.contains(&step.id) {
            issues.push(format!("step `{}` depends on itself", step.id));
        }
    }

    // Check for circular dependencies.
    if has_circular_dependency(&scenario.steps) {
        issues.push("circular dependency detected among steps".to_string());
    }

    // Warn about zero timeout.
    if scenario.timeout_secs == 0 {
        issues.push("scenario timeout is 0 seconds".to_string());
    }

    // Warn about empty description.
    if scenario.description.is_empty() {
        issues.push("scenario has no description".to_string());
    }

    issues
}

// ── Topological sort ────────────────────────────────────────────────────────

/// Perform a topological sort of steps respecting `depends_on`.
///
/// Steps with no dependencies come first.  If there is a cycle, the remaining
/// steps are appended in their original order.
#[must_use]
pub fn topological_sort_steps(steps: &[ScenarioStep]) -> Vec<String> {
    let n = steps.len();
    let id_to_idx: HashMap<&str, usize> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.as_str(), i))
        .collect();

    // Build adjacency: in_degree and outgoing edges.
    let mut in_degree = vec![0usize; n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (i, step) in steps.iter().enumerate() {
        for dep in &step.depends_on {
            if let Some(&dep_idx) = id_to_idx.get(dep.as_str()) {
                in_degree[i] += 1;
                dependents[dep_idx].push(i);
            }
        }
    }

    // Kahn's algorithm.
    let mut queue: Vec<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
    let mut order = Vec::with_capacity(n);

    while let Some(idx) = queue.pop() {
        order.push(steps[idx].id.clone());
        for &dep_idx in &dependents[idx] {
            in_degree[dep_idx] -= 1;
            if in_degree[dep_idx] == 0 {
                queue.push(dep_idx);
            }
        }
    }

    // If there was a cycle, append remaining steps in original order.
    if order.len() < n {
        let ordered_set: HashSet<String> = order.iter().cloned().collect();
        for step in steps {
            if !ordered_set.contains(&step.id) {
                order.push(step.id.clone());
            }
        }
    }

    order
}

/// Detect whether the step graph contains a cycle.
#[must_use]
pub fn has_circular_dependency(steps: &[ScenarioStep]) -> bool {
    let n = steps.len();
    let id_to_idx: HashMap<&str, usize> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.as_str(), i))
        .collect();

    let mut in_degree = vec![0usize; n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (i, step) in steps.iter().enumerate() {
        for dep in &step.depends_on {
            if let Some(&dep_idx) = id_to_idx.get(dep.as_str()) {
                in_degree[i] += 1;
                dependents[dep_idx].push(i);
            }
        }
    }

    let mut queue: Vec<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
    let mut visited = 0usize;

    while let Some(idx) = queue.pop() {
        visited += 1;
        for &dep_idx in &dependents[idx] {
            in_degree[dep_idx] -= 1;
            if in_degree[dep_idx] == 0 {
                queue.push(dep_idx);
            }
        }
    }

    visited < n
}

/// Detect and return a cycle path if one exists.
#[must_use]
pub fn find_cycle(steps: &[ScenarioStep]) -> Option<Vec<String>> {
    let n = steps.len();
    let id_to_idx: HashMap<&str, usize> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.as_str(), i))
        .collect();

    // Build adjacency (step -> its dependencies = outgoing edges for DFS).
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, step) in steps.iter().enumerate() {
        for dep in &step.depends_on {
            if let Some(&dep_idx) = id_to_idx.get(dep.as_str()) {
                adj[i].push(dep_idx);
            }
        }
    }

    // DFS with coloring: 0 = white, 1 = gray, 2 = black
    let mut color = vec![0u8; n];
    let mut parent = vec![usize::MAX; n];

    for start in 0..n {
        if color[start] != 0 {
            continue;
        }
        let mut stack = vec![(start, 0usize)];
        while let Some((node, edge_idx)) = stack.last_mut() {
            if *edge_idx == 0 {
                color[*node] = 1; // gray
            }
            if *edge_idx < adj[*node].len() {
                let next = adj[*node][*edge_idx];
                *edge_idx += 1;
                if color[next] == 1 {
                    // Found cycle: reconstruct.
                    let mut cycle = vec![steps[next].id.clone()];
                    let mut cur = *node;
                    while cur != next {
                        cycle.push(steps[cur].id.clone());
                        cur = parent[cur];
                    }
                    cycle.push(steps[next].id.clone());
                    cycle.reverse();
                    return Some(cycle);
                }
                if color[next] == 0 {
                    parent[next] = *node;
                    stack.push((next, 0));
                }
            } else {
                color[*node] = 2; // black
                stack.pop();
            }
        }
    }

    None
}

// ── Reporting ───────────────────────────────────────────────────────────────

/// Format a summary report from scenario results.
#[must_use]
pub fn format_scenario_report(results: &[ScenarioResult]) -> String {
    let mut out = String::new();
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    let _ = writeln!(out, "=== Scenario Report ===");
    let _ = writeln!(out, "Total: {total}  Passed: {passed}  Failed: {failed}");
    let _ = writeln!(out);

    for result in results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        let duration_ms = result.duration.as_millis();
        let _ = writeln!(out, "[{status}] {} ({duration_ms}ms)", result.scenario_name);
        if let Some(ref step) = result.failed_step {
            let _ = writeln!(out, "       failed at step: {step}");
        }
        let artifact_count = result.artifacts.file_count();
        if artifact_count > 0 {
            let _ = writeln!(out, "       artifacts: {artifact_count} files");
        }
    }

    if failed > 0 {
        let _ = writeln!(out);
        let _ = writeln!(out, "--- Failures ---");
        for result in results.iter().filter(|r| !r.passed) {
            let _ = writeln!(out, "  {}", result.scenario_name);
            if !result.stderr_log.is_empty() {
                let truncated: String = result.stderr_log.chars().take(200).collect();
                let _ = writeln!(out, "    stderr: {truncated}");
            }
        }
    }

    out
}

/// Format a single step outcome for display.
#[must_use]
pub fn format_step_outcome(outcome: &StepOutcome) -> String {
    let status = if outcome.passed { "PASS" } else { "FAIL" };
    let ms = outcome.duration.as_millis();
    let mut out = format!(
        "[{status}] step `{}` (exit={}, {ms}ms)",
        outcome.step_id, outcome.exit_code
    );
    if let Some(ref reason) = outcome.failure_reason {
        let _ = write!(out, " -- {reason}");
    }
    out
}

/// Format an execution plan for display.
#[must_use]
pub fn format_plan(plan: &[(String, Vec<String>)]) -> String {
    let mut out = String::new();
    for (name, steps) in plan {
        let _ = writeln!(out, "Scenario: {name}");
        for (i, step_id) in steps.iter().enumerate() {
            let _ = writeln!(out, "  {}: {step_id}", i + 1);
        }
    }
    out
}

// ── Helper: build a ScenarioResult from step outcomes ───────────────────────

/// Build a `ScenarioResult` from a scenario and its step outcomes.
#[must_use]
pub fn build_scenario_result(
    scenario: &Scenario,
    outcomes: &[StepOutcome],
    total_duration: Duration,
) -> ScenarioResult {
    let mut artifacts = ArtifactBundle::new(&scenario.name);
    let mut stdout_log = String::new();
    let mut stderr_log = String::new();
    let mut failed_step = None;
    let mut all_passed = true;

    for (i, step) in scenario.steps.iter().enumerate() {
        if let Some(outcome) = outcomes.get(i) {
            let _ = writeln!(stdout_log, "--- step: {} ---", step.id);
            stdout_log.push_str(&outcome.stdout);
            if !outcome.stderr.is_empty() {
                let _ = writeln!(stderr_log, "--- step: {} ---", step.id);
                stderr_log.push_str(&outcome.stderr);
            }
            if let Some(ref key) = step.capture_as {
                artifacts.add_file(key, &outcome.stdout);
            }
            if !outcome.passed && failed_step.is_none() {
                failed_step = Some(step.id.clone());
                all_passed = false;
            }
        }
    }

    artifacts.add_metadata("total_steps", &scenario.steps.len().to_string());
    artifacts.add_metadata("executed_steps", &outcomes.len().to_string());

    ScenarioResult {
        scenario_name: scenario.name.clone(),
        passed: all_passed,
        failed_step,
        duration: total_duration,
        artifacts,
        stdout_log,
        stderr_log,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper factories ────────────────────────────────────────────────

    fn step(id: &str, cmd: &str) -> ScenarioStep {
        ScenarioStep {
            id: id.to_string(),
            command: cmd.to_string(),
            expected_exit_code: 0,
            expected_output_contains: Vec::new(),
            expected_output_not_contains: Vec::new(),
            depends_on: Vec::new(),
            capture_as: None,
        }
    }

    fn step_with_deps(id: &str, cmd: &str, deps: &[&str]) -> ScenarioStep {
        ScenarioStep {
            depends_on: deps.iter().map(|d| d.to_string()).collect(),
            ..step(id, cmd)
        }
    }

    fn minimal_scenario(name: &str, steps: Vec<ScenarioStep>) -> Scenario {
        Scenario {
            name: name.to_string(),
            description: "test scenario".to_string(),
            steps,
            expected_outcomes: Vec::new(),
            tags: Vec::new(),
            timeout_secs: 60,
        }
    }

    fn passing_outcome(step_id: &str) -> StepOutcome {
        StepOutcome {
            step_id: step_id.to_string(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration: Duration::from_millis(10),
            passed: true,
            failure_reason: None,
        }
    }

    fn failing_outcome(step_id: &str, reason: &str) -> StepOutcome {
        StepOutcome {
            step_id: step_id.to_string(),
            exit_code: 1,
            stdout: String::new(),
            stderr: reason.to_string(),
            duration: Duration::from_millis(50),
            passed: false,
            failure_reason: Some(reason.to_string()),
        }
    }

    // ── Parsing tests ───────────────────────────────────────────────────

    #[test]
    fn parse_minimal_scenario() {
        let toml = r#"
name = "smoke"
description = "basic smoke test"

[[steps]]
id = "s1"
command = "fwc version"
"#;
        let s = parse_scenario(toml).unwrap();
        assert_eq!(s.name, "smoke");
        assert_eq!(s.steps.len(), 1);
        assert_eq!(s.steps[0].id, "s1");
        assert_eq!(s.steps[0].command, "fwc version");
        assert_eq!(s.timeout_secs, 300); // default
    }

    #[test]
    fn parse_full_scenario() {
        let toml = r#"
name = "full"
description = "fully specified scenario"
expected_outcomes = ["connector_listed", "version_printed"]
tags = ["smoke", "ci"]
timeout_secs = 120

[[steps]]
id = "version"
command = "fwc version"
expected_exit_code = 0
expected_output_contains = ["fwc"]

[[steps]]
id = "list"
command = "fwc catalog list"
depends_on = ["version"]
capture_as = "catalog_output"
"#;
        let s = parse_scenario(toml).unwrap();
        assert_eq!(s.name, "full");
        assert_eq!(s.expected_outcomes.len(), 2);
        assert_eq!(s.tags, vec!["smoke", "ci"]);
        assert_eq!(s.timeout_secs, 120);
        assert_eq!(s.steps.len(), 2);
        assert_eq!(s.steps[1].depends_on, vec!["version"]);
        assert_eq!(s.steps[1].capture_as.as_deref(), Some("catalog_output"));
    }

    #[test]
    fn parse_empty_name_is_error() {
        let toml = r#"
name = ""
[[steps]]
id = "s1"
command = "echo hello"
"#;
        let err = parse_scenario(toml).unwrap_err();
        assert!(matches!(err, ScenarioError::MissingField { ref field } if field == "name"));
    }

    #[test]
    fn parse_no_steps_is_error() {
        let toml = r#"
name = "no-steps"
steps = []
"#;
        let err = parse_scenario(toml).unwrap_err();
        assert!(matches!(err, ScenarioError::MissingField { ref field } if field == "steps"));
    }

    #[test]
    fn parse_empty_step_id_is_error() {
        let toml = r#"
name = "bad-step"
[[steps]]
id = ""
command = "echo hello"
"#;
        let err = parse_scenario(toml).unwrap_err();
        assert!(matches!(err, ScenarioError::MissingField { ref field } if field == "steps[].id"));
    }

    #[test]
    fn parse_empty_command_is_error() {
        let toml = r#"
name = "bad-cmd"
[[steps]]
id = "s1"
command = ""
"#;
        let err = parse_scenario(toml).unwrap_err();
        assert!(
            matches!(err, ScenarioError::MissingField { ref field } if field == "steps[s1].command")
        );
    }

    #[test]
    fn parse_invalid_toml() {
        let err = parse_scenario("not valid toml {{{").unwrap_err();
        assert!(matches!(err, ScenarioError::ParseError { .. }));
    }

    #[test]
    fn parse_missing_required_field() {
        let toml = r#"
description = "missing name"
[[steps]]
id = "s1"
command = "echo hello"
"#;
        let err = parse_scenario(toml).unwrap_err();
        assert!(matches!(err, ScenarioError::ParseError { .. }));
    }

    #[test]
    fn parse_step_with_expected_not_contains() {
        let toml = r#"
name = "negation"
[[steps]]
id = "s1"
command = "fwc version"
expected_output_not_contains = ["ERROR", "panic"]
"#;
        let s = parse_scenario(toml).unwrap();
        assert_eq!(
            s.steps[0].expected_output_not_contains,
            vec!["ERROR", "panic"]
        );
    }

    #[test]
    fn parse_multiple_steps_with_chain() {
        let toml = r#"
name = "chain"
[[steps]]
id = "a"
command = "echo a"
[[steps]]
id = "b"
command = "echo b"
depends_on = ["a"]
[[steps]]
id = "c"
command = "echo c"
depends_on = ["b"]
"#;
        let s = parse_scenario(toml).unwrap();
        assert_eq!(s.steps.len(), 3);
        assert_eq!(s.steps[2].depends_on, vec!["b"]);
    }

    #[test]
    fn parse_step_default_exit_code() {
        let toml = r#"
name = "defaults"
[[steps]]
id = "s1"
command = "echo hello"
"#;
        let s = parse_scenario(toml).unwrap();
        assert_eq!(s.steps[0].expected_exit_code, 0);
    }

    #[test]
    fn parse_step_custom_exit_code() {
        let toml = r#"
name = "custom-exit"
[[steps]]
id = "s1"
command = "false"
expected_exit_code = 1
"#;
        let s = parse_scenario(toml).unwrap();
        assert_eq!(s.steps[0].expected_exit_code, 1);
    }

    // ── Validation tests ────────────────────────────────────────────────

    #[test]
    fn validate_valid_scenario() {
        let s = minimal_scenario("ok", vec![step("s1", "echo hello")]);
        let issues = validate_scenario(&s);
        assert!(issues.is_empty(), "expected no issues, got: {issues:?}");
    }

    #[test]
    fn validate_duplicate_step_ids() {
        let s = minimal_scenario("dup", vec![step("s1", "echo a"), step("s1", "echo b")]);
        let issues = validate_scenario(&s);
        assert!(issues.iter().any(|i| i.contains("duplicate step id")));
    }

    #[test]
    fn validate_missing_dependency() {
        let s = minimal_scenario(
            "missing-dep",
            vec![step_with_deps("s1", "echo hello", &["nonexistent"])],
        );
        let issues = validate_scenario(&s);
        assert!(issues.iter().any(|i| i.contains("unknown step")));
    }

    #[test]
    fn validate_self_dependency() {
        let s = minimal_scenario(
            "self-dep",
            vec![step_with_deps("s1", "echo hello", &["s1"])],
        );
        let issues = validate_scenario(&s);
        assert!(issues.iter().any(|i| i.contains("depends on itself")));
    }

    #[test]
    fn validate_circular_dependency() {
        let s = minimal_scenario(
            "cycle",
            vec![
                step_with_deps("a", "echo a", &["b"]),
                step_with_deps("b", "echo b", &["a"]),
            ],
        );
        let issues = validate_scenario(&s);
        assert!(issues.iter().any(|i| i.contains("circular dependency")));
    }

    #[test]
    fn validate_zero_timeout() {
        let s = Scenario {
            timeout_secs: 0,
            ..minimal_scenario("zero", vec![step("s1", "echo hello")])
        };
        let issues = validate_scenario(&s);
        assert!(issues.iter().any(|i| i.contains("timeout is 0")));
    }

    #[test]
    fn validate_empty_description() {
        let s = Scenario {
            description: String::new(),
            ..minimal_scenario("no-desc", vec![step("s1", "echo hello")])
        };
        let issues = validate_scenario(&s);
        assert!(issues.iter().any(|i| i.contains("no description")));
    }

    #[test]
    fn validate_valid_complex_scenario() {
        let s = minimal_scenario(
            "complex",
            vec![
                step("a", "echo a"),
                step_with_deps("b", "echo b", &["a"]),
                step_with_deps("c", "echo c", &["a"]),
                step_with_deps("d", "echo d", &["b", "c"]),
            ],
        );
        let issues = validate_scenario(&s);
        assert!(issues.is_empty(), "expected no issues, got: {issues:?}");
    }

    // ── Topological sort tests ──────────────────────────────────────────

    #[test]
    fn topo_sort_no_deps() {
        let steps = vec![step("a", "x"), step("b", "y"), step("c", "z")];
        let order = topological_sort_steps(&steps);
        assert_eq!(order.len(), 3);
        // All steps should be present.
        assert!(order.contains(&"a".to_string()));
        assert!(order.contains(&"b".to_string()));
        assert!(order.contains(&"c".to_string()));
    }

    #[test]
    fn topo_sort_linear_chain() {
        let steps = vec![
            step("a", "x"),
            step_with_deps("b", "y", &["a"]),
            step_with_deps("c", "z", &["b"]),
        ];
        let order = topological_sort_steps(&steps);
        let pos = |id: &str| order.iter().position(|s| s == id).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("b") < pos("c"));
    }

    #[test]
    fn topo_sort_diamond() {
        let steps = vec![
            step("a", "x"),
            step_with_deps("b", "y", &["a"]),
            step_with_deps("c", "z", &["a"]),
            step_with_deps("d", "w", &["b", "c"]),
        ];
        let order = topological_sort_steps(&steps);
        let pos = |id: &str| order.iter().position(|s| s == id).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("a") < pos("c"));
        assert!(pos("b") < pos("d"));
        assert!(pos("c") < pos("d"));
    }

    #[test]
    fn topo_sort_with_cycle_includes_all_steps() {
        let steps = vec![
            step_with_deps("a", "x", &["b"]),
            step_with_deps("b", "y", &["a"]),
            step("c", "z"),
        ];
        let order = topological_sort_steps(&steps);
        // All 3 should still appear even though a<->b form a cycle.
        assert_eq!(order.len(), 3);
        assert!(order.contains(&"c".to_string()));
    }

    #[test]
    fn topo_sort_multiple_roots() {
        let steps = vec![
            step("r1", "x"),
            step("r2", "y"),
            step_with_deps("leaf", "z", &["r1", "r2"]),
        ];
        let order = topological_sort_steps(&steps);
        let pos = |id: &str| order.iter().position(|s| s == id).unwrap();
        assert!(pos("r1") < pos("leaf"));
        assert!(pos("r2") < pos("leaf"));
    }

    #[test]
    fn topo_sort_single_step() {
        let steps = vec![step("only", "echo only")];
        let order = topological_sort_steps(&steps);
        assert_eq!(order, vec!["only"]);
    }

    #[test]
    fn topo_sort_unknown_dep_ignored() {
        let steps = vec![step_with_deps("a", "x", &["nonexistent"])];
        let order = topological_sort_steps(&steps);
        assert_eq!(order, vec!["a"]);
    }

    // ── Cycle detection tests ───────────────────────────────────────────

    #[test]
    fn no_cycle_in_linear_chain() {
        let steps = vec![
            step("a", "x"),
            step_with_deps("b", "y", &["a"]),
            step_with_deps("c", "z", &["b"]),
        ];
        assert!(!has_circular_dependency(&steps));
    }

    #[test]
    fn cycle_detected_two_nodes() {
        let steps = vec![
            step_with_deps("a", "x", &["b"]),
            step_with_deps("b", "y", &["a"]),
        ];
        assert!(has_circular_dependency(&steps));
    }

    #[test]
    fn cycle_detected_three_nodes() {
        let steps = vec![
            step_with_deps("a", "x", &["c"]),
            step_with_deps("b", "y", &["a"]),
            step_with_deps("c", "z", &["b"]),
        ];
        assert!(has_circular_dependency(&steps));
    }

    #[test]
    fn no_cycle_diamond() {
        let steps = vec![
            step("root", "x"),
            step_with_deps("left", "y", &["root"]),
            step_with_deps("right", "z", &["root"]),
            step_with_deps("leaf", "w", &["left", "right"]),
        ];
        assert!(!has_circular_dependency(&steps));
    }

    #[test]
    fn no_cycle_empty() {
        let steps: Vec<ScenarioStep> = Vec::new();
        assert!(!has_circular_dependency(&steps));
    }

    #[test]
    fn find_cycle_returns_none_when_clean() {
        let steps = vec![step("a", "x"), step_with_deps("b", "y", &["a"])];
        assert!(find_cycle(&steps).is_none());
    }

    #[test]
    fn find_cycle_returns_path() {
        let steps = vec![
            step_with_deps("a", "x", &["b"]),
            step_with_deps("b", "y", &["a"]),
        ];
        let cycle = find_cycle(&steps).unwrap();
        assert!(cycle.len() >= 2);
        assert!(cycle.contains(&"a".to_string()));
        assert!(cycle.contains(&"b".to_string()));
    }

    #[test]
    fn find_cycle_three_node_ring() {
        let steps = vec![
            step_with_deps("a", "x", &["c"]),
            step_with_deps("b", "y", &["a"]),
            step_with_deps("c", "z", &["b"]),
        ];
        let cycle = find_cycle(&steps).unwrap();
        assert!(cycle.len() >= 3);
    }

    // ── ScenarioRunner tests ────────────────────────────────────────────

    #[test]
    fn runner_new_empty() {
        let r = ScenarioRunner::new(Duration::from_secs(60));
        assert_eq!(r.scenario_count(), 0);
        assert!(r.scenarios.is_empty());
    }

    #[test]
    fn runner_add_scenario() {
        let mut r = ScenarioRunner::new(Duration::from_secs(60));
        r.add_scenario(minimal_scenario("s1", vec![step("a", "echo a")]));
        r.add_scenario(minimal_scenario("s2", vec![step("b", "echo b")]));
        assert_eq!(r.scenario_count(), 2);
    }

    #[test]
    fn runner_plan_single_scenario() {
        let mut r = ScenarioRunner::new(Duration::from_secs(60));
        r.add_scenario(minimal_scenario(
            "test",
            vec![step("a", "echo a"), step_with_deps("b", "echo b", &["a"])],
        ));
        let plan = r.plan();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].0, "test");
        let pos = |id: &str| plan[0].1.iter().position(|s| s == id).unwrap();
        assert!(pos("a") < pos("b"));
    }

    #[test]
    fn runner_plan_multiple_scenarios() {
        let mut r = ScenarioRunner::new(Duration::from_secs(60));
        r.add_scenario(minimal_scenario("s1", vec![step("a", "x")]));
        r.add_scenario(minimal_scenario("s2", vec![step("b", "y")]));
        let plan = r.plan();
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn check_step_passing() {
        let s = step("s1", "echo hello");
        let o = StepOutcome {
            step_id: "s1".to_string(),
            exit_code: 0,
            stdout: "hello world".to_string(),
            stderr: String::new(),
            duration: Duration::from_millis(10),
            passed: true,
            failure_reason: None,
        };
        assert!(ScenarioRunner::check_step(&s, &o));
    }

    #[test]
    fn check_step_wrong_exit_code() {
        let s = step("s1", "echo hello");
        let o = StepOutcome {
            exit_code: 1,
            ..passing_outcome("s1")
        };
        assert!(!ScenarioRunner::check_step(&s, &o));
    }

    #[test]
    fn check_step_missing_expected_output() {
        let s = ScenarioStep {
            expected_output_contains: vec!["fwc version".to_string()],
            ..step("s1", "fwc version")
        };
        let o = StepOutcome {
            stdout: "some other output".to_string(),
            ..passing_outcome("s1")
        };
        assert!(!ScenarioRunner::check_step(&s, &o));
    }

    #[test]
    fn check_step_contains_forbidden_output() {
        let s = ScenarioStep {
            expected_output_not_contains: vec!["ERROR".to_string()],
            ..step("s1", "fwc version")
        };
        let o = StepOutcome {
            stdout: "something ERROR happened".to_string(),
            ..passing_outcome("s1")
        };
        assert!(!ScenarioRunner::check_step(&s, &o));
    }

    #[test]
    fn check_step_passes_with_expected_output() {
        let s = ScenarioStep {
            expected_output_contains: vec!["hello".to_string()],
            ..step("s1", "echo hello")
        };
        let o = StepOutcome {
            stdout: "hello world".to_string(),
            ..passing_outcome("s1")
        };
        assert!(ScenarioRunner::check_step(&s, &o));
    }

    #[test]
    fn check_step_passes_without_forbidden() {
        let s = ScenarioStep {
            expected_output_not_contains: vec!["ERROR".to_string()],
            ..step("s1", "echo hello")
        };
        let o = StepOutcome {
            stdout: "hello world".to_string(),
            ..passing_outcome("s1")
        };
        assert!(ScenarioRunner::check_step(&s, &o));
    }

    #[test]
    fn check_step_multiple_contains() {
        let s = ScenarioStep {
            expected_output_contains: vec!["foo".to_string(), "bar".to_string()],
            ..step("s1", "echo foobar")
        };
        let o = StepOutcome {
            stdout: "foo bar baz".to_string(),
            ..passing_outcome("s1")
        };
        assert!(ScenarioRunner::check_step(&s, &o));
    }

    #[test]
    fn check_step_one_of_multiple_contains_missing() {
        let s = ScenarioStep {
            expected_output_contains: vec!["foo".to_string(), "qux".to_string()],
            ..step("s1", "echo foobar")
        };
        let o = StepOutcome {
            stdout: "foo bar baz".to_string(),
            ..passing_outcome("s1")
        };
        assert!(!ScenarioRunner::check_step(&s, &o));
    }

    #[test]
    fn check_step_nonzero_expected_exit() {
        let s = ScenarioStep {
            expected_exit_code: 42,
            ..step("s1", "exit 42")
        };
        let o = StepOutcome {
            exit_code: 42,
            ..passing_outcome("s1")
        };
        assert!(ScenarioRunner::check_step(&s, &o));
    }

    // ── Failure reason tests ────────────────────────────────────────────

    #[test]
    fn failure_reason_none_when_passing() {
        let s = step("s1", "echo hello");
        let o = passing_outcome("s1");
        assert!(ScenarioRunner::failure_reason(&s, &o).is_none());
    }

    #[test]
    fn failure_reason_exit_code_mismatch() {
        let s = step("s1", "echo hello");
        let o = StepOutcome {
            exit_code: 1,
            ..passing_outcome("s1")
        };
        let reason = ScenarioRunner::failure_reason(&s, &o).unwrap();
        assert!(reason.contains("exit code"));
    }

    #[test]
    fn failure_reason_missing_output() {
        let s = ScenarioStep {
            expected_output_contains: vec!["expected_text".to_string()],
            ..step("s1", "echo hello")
        };
        let o = StepOutcome {
            stdout: "other text".to_string(),
            ..passing_outcome("s1")
        };
        let reason = ScenarioRunner::failure_reason(&s, &o).unwrap();
        assert!(reason.contains("missing expected output"));
    }

    #[test]
    fn failure_reason_forbidden_output() {
        let s = ScenarioStep {
            expected_output_not_contains: vec!["SECRET".to_string()],
            ..step("s1", "echo hello")
        };
        let o = StepOutcome {
            stdout: "contains SECRET data".to_string(),
            ..passing_outcome("s1")
        };
        let reason = ScenarioRunner::failure_reason(&s, &o).unwrap();
        assert!(reason.contains("forbidden output"));
    }

    #[test]
    fn failure_reason_multiple_issues() {
        let s = ScenarioStep {
            expected_output_contains: vec!["wanted".to_string()],
            expected_output_not_contains: vec!["bad".to_string()],
            ..step("s1", "echo hello")
        };
        let o = StepOutcome {
            exit_code: 1,
            stdout: "bad stuff".to_string(),
            ..passing_outcome("s1")
        };
        let reason = ScenarioRunner::failure_reason(&s, &o).unwrap();
        assert!(reason.contains("exit code"));
        assert!(reason.contains("missing expected output"));
        assert!(reason.contains("forbidden output"));
    }

    // ── ArtifactBundle tests ────────────────────────────────────────────

    #[test]
    fn artifact_bundle_new() {
        let b = ArtifactBundle::new("test-scenario");
        assert_eq!(b.scenario_name, "test-scenario");
        assert!(b.files.is_empty());
        assert!(b.metadata.is_empty());
    }

    #[test]
    fn artifact_bundle_add_file() {
        let mut b = ArtifactBundle::new("test");
        b.add_file("output.txt", "hello world");
        assert_eq!(b.file_count(), 1);
        assert_eq!(b.files.get("output.txt").unwrap(), "hello world");
    }

    #[test]
    fn artifact_bundle_add_multiple_files() {
        let mut b = ArtifactBundle::new("test");
        b.add_file("a.txt", "aaa");
        b.add_file("b.txt", "bbb");
        b.add_file("c.json", r#"{"key":"value"}"#);
        assert_eq!(b.file_count(), 3);
    }

    #[test]
    fn artifact_bundle_overwrite_file() {
        let mut b = ArtifactBundle::new("test");
        b.add_file("out.txt", "v1");
        b.add_file("out.txt", "v2");
        assert_eq!(b.file_count(), 1);
        assert_eq!(b.files.get("out.txt").unwrap(), "v2");
    }

    #[test]
    fn artifact_bundle_add_metadata() {
        let mut b = ArtifactBundle::new("test");
        b.add_metadata("version", "1.0.0");
        b.add_metadata("runner", "fwc");
        assert_eq!(b.metadata.len(), 2);
        assert_eq!(b.metadata.get("version").unwrap(), "1.0.0");
    }

    #[test]
    fn artifact_bundle_format_manifest_empty() {
        let b = ArtifactBundle::new("empty");
        let manifest = b.format_manifest();
        assert!(manifest.contains("Artifact Bundle: empty"));
        assert!(manifest.contains("Files (0):"));
    }

    #[test]
    fn artifact_bundle_format_manifest_with_files() {
        let mut b = ArtifactBundle::new("test");
        b.add_file("alpha.txt", "hello");
        b.add_file("beta.json", r#"{"a":1}"#);
        let manifest = b.format_manifest();
        assert!(manifest.contains("Files (2):"));
        assert!(manifest.contains("alpha.txt"));
        assert!(manifest.contains("beta.json"));
        assert!(manifest.contains("bytes"));
    }

    #[test]
    fn artifact_bundle_format_manifest_with_metadata() {
        let mut b = ArtifactBundle::new("test");
        b.add_metadata("env", "ci");
        let manifest = b.format_manifest();
        assert!(manifest.contains("Metadata:"));
        assert!(manifest.contains("env: ci"));
    }

    #[test]
    fn artifact_bundle_format_manifest_sorted_keys() {
        let mut b = ArtifactBundle::new("test");
        b.add_file("zeta.txt", "z");
        b.add_file("alpha.txt", "a");
        b.add_file("middle.txt", "m");
        let manifest = b.format_manifest();
        let alpha_pos = manifest.find("alpha.txt").unwrap();
        let middle_pos = manifest.find("middle.txt").unwrap();
        let zeta_pos = manifest.find("zeta.txt").unwrap();
        assert!(alpha_pos < middle_pos);
        assert!(middle_pos < zeta_pos);
    }

    // ── Reporting tests ─────────────────────────────────────────────────

    #[test]
    fn report_empty_results() {
        let report = format_scenario_report(&[]);
        assert!(report.contains("Total: 0"));
        assert!(report.contains("Passed: 0"));
        assert!(report.contains("Failed: 0"));
    }

    #[test]
    fn report_all_passing() {
        let results = vec![ScenarioResult {
            scenario_name: "smoke".to_string(),
            passed: true,
            failed_step: None,
            duration: Duration::from_millis(100),
            artifacts: ArtifactBundle::new("smoke"),
            stdout_log: String::new(),
            stderr_log: String::new(),
        }];
        let report = format_scenario_report(&results);
        assert!(report.contains("[PASS] smoke"));
        assert!(report.contains("Passed: 1"));
        assert!(!report.contains("Failures"));
    }

    #[test]
    fn report_with_failure() {
        let results = vec![ScenarioResult {
            scenario_name: "broken".to_string(),
            passed: false,
            failed_step: Some("step-3".to_string()),
            duration: Duration::from_millis(200),
            artifacts: ArtifactBundle::new("broken"),
            stdout_log: String::new(),
            stderr_log: "connection refused".to_string(),
        }];
        let report = format_scenario_report(&results);
        assert!(report.contains("[FAIL] broken"));
        assert!(report.contains("failed at step: step-3"));
        assert!(report.contains("Failures"));
        assert!(report.contains("connection refused"));
    }

    #[test]
    fn report_mixed_results() {
        let results = vec![
            ScenarioResult {
                scenario_name: "pass1".to_string(),
                passed: true,
                failed_step: None,
                duration: Duration::from_millis(50),
                artifacts: ArtifactBundle::new("pass1"),
                stdout_log: String::new(),
                stderr_log: String::new(),
            },
            ScenarioResult {
                scenario_name: "fail1".to_string(),
                passed: false,
                failed_step: Some("s2".to_string()),
                duration: Duration::from_millis(150),
                artifacts: ArtifactBundle::new("fail1"),
                stdout_log: String::new(),
                stderr_log: "err msg".to_string(),
            },
            ScenarioResult {
                scenario_name: "pass2".to_string(),
                passed: true,
                failed_step: None,
                duration: Duration::from_millis(75),
                artifacts: ArtifactBundle::new("pass2"),
                stdout_log: String::new(),
                stderr_log: String::new(),
            },
        ];
        let report = format_scenario_report(&results);
        assert!(report.contains("Total: 3"));
        assert!(report.contains("Passed: 2"));
        assert!(report.contains("Failed: 1"));
    }

    #[test]
    fn report_with_artifacts() {
        let mut artifacts = ArtifactBundle::new("test");
        artifacts.add_file("log.txt", "some log");
        artifacts.add_file("data.json", "{}");
        let results = vec![ScenarioResult {
            scenario_name: "with-artifacts".to_string(),
            passed: true,
            failed_step: None,
            duration: Duration::from_millis(100),
            artifacts,
            stdout_log: String::new(),
            stderr_log: String::new(),
        }];
        let report = format_scenario_report(&results);
        assert!(report.contains("artifacts: 2 files"));
    }

    #[test]
    fn format_step_outcome_passing() {
        let o = passing_outcome("step1");
        let formatted = format_step_outcome(&o);
        assert!(formatted.contains("[PASS]"));
        assert!(formatted.contains("step1"));
    }

    #[test]
    fn format_step_outcome_failing() {
        let o = failing_outcome("step2", "exit code mismatch");
        let formatted = format_step_outcome(&o);
        assert!(formatted.contains("[FAIL]"));
        assert!(formatted.contains("exit code mismatch"));
    }

    #[test]
    fn format_plan_output() {
        let plan = vec![
            (
                "scenario1".to_string(),
                vec!["a".to_string(), "b".to_string()],
            ),
            ("scenario2".to_string(), vec!["x".to_string()]),
        ];
        let formatted = format_plan(&plan);
        assert!(formatted.contains("Scenario: scenario1"));
        assert!(formatted.contains("1: a"));
        assert!(formatted.contains("2: b"));
        assert!(formatted.contains("Scenario: scenario2"));
    }

    // ── build_scenario_result tests ─────────────────────────────────────

    #[test]
    fn build_result_all_pass() {
        let s = minimal_scenario("test", vec![step("a", "echo a"), step("b", "echo b")]);
        let outcomes = vec![
            StepOutcome {
                stdout: "output-a".to_string(),
                ..passing_outcome("a")
            },
            StepOutcome {
                stdout: "output-b".to_string(),
                ..passing_outcome("b")
            },
        ];
        let result = build_scenario_result(&s, &outcomes, Duration::from_millis(100));
        assert!(result.passed);
        assert!(result.failed_step.is_none());
        assert!(result.stdout_log.contains("output-a"));
        assert!(result.stdout_log.contains("output-b"));
    }

    #[test]
    fn build_result_with_failure() {
        let s = minimal_scenario("test", vec![step("a", "echo a"), step("b", "echo b")]);
        let outcomes = vec![passing_outcome("a"), failing_outcome("b", "boom")];
        let result = build_scenario_result(&s, &outcomes, Duration::from_millis(100));
        assert!(!result.passed);
        assert_eq!(result.failed_step.as_deref(), Some("b"));
    }

    #[test]
    fn build_result_captures_artifacts() {
        let s = minimal_scenario(
            "test",
            vec![ScenarioStep {
                capture_as: Some("output".to_string()),
                ..step("a", "echo a")
            }],
        );
        let outcomes = vec![StepOutcome {
            stdout: "captured content".to_string(),
            ..passing_outcome("a")
        }];
        let result = build_scenario_result(&s, &outcomes, Duration::from_millis(50));
        assert_eq!(
            result.artifacts.files.get("output").unwrap(),
            "captured content"
        );
    }

    #[test]
    fn build_result_metadata() {
        let s = minimal_scenario("test", vec![step("a", "echo a"), step("b", "echo b")]);
        let outcomes = vec![passing_outcome("a"), passing_outcome("b")];
        let result = build_scenario_result(&s, &outcomes, Duration::from_millis(100));
        assert_eq!(result.artifacts.metadata.get("total_steps").unwrap(), "2");
        assert_eq!(
            result.artifacts.metadata.get("executed_steps").unwrap(),
            "2"
        );
    }

    #[test]
    fn build_result_partial_execution() {
        let s = minimal_scenario(
            "test",
            vec![
                step("a", "echo a"),
                step("b", "echo b"),
                step("c", "echo c"),
            ],
        );
        // Only one step executed (e.g., first step failed and runner stopped).
        let outcomes = vec![failing_outcome("a", "crash")];
        let result = build_scenario_result(&s, &outcomes, Duration::from_millis(30));
        assert!(!result.passed);
        assert_eq!(result.failed_step.as_deref(), Some("a"));
        assert_eq!(
            result.artifacts.metadata.get("executed_steps").unwrap(),
            "1"
        );
    }

    #[test]
    fn build_result_stderr_collected() {
        let s = minimal_scenario("test", vec![step("a", "echo a")]);
        let outcomes = vec![StepOutcome {
            stderr: "warning: something".to_string(),
            ..passing_outcome("a")
        }];
        let result = build_scenario_result(&s, &outcomes, Duration::from_millis(50));
        assert!(result.stderr_log.contains("warning: something"));
    }

    // ── Scenario model tests ────────────────────────────────────────────

    #[test]
    fn scenario_timeout_default() {
        let s = minimal_scenario("test", vec![step("a", "x")]);
        assert_eq!(s.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn scenario_step_ids() {
        let s = minimal_scenario("test", vec![step("a", "x"), step("b", "y"), step("c", "z")]);
        let ids = s.step_ids();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains("a"));
        assert!(ids.contains("b"));
        assert!(ids.contains("c"));
    }

    // ── ScenarioError Display tests ─────────────────────────────────────

    #[test]
    fn error_display_parse() {
        let e = ScenarioError::ParseError {
            message: "bad toml".to_string(),
        };
        assert_eq!(e.to_string(), "scenario parse error: bad toml");
    }

    #[test]
    fn error_display_missing_field() {
        let e = ScenarioError::MissingField {
            field: "name".to_string(),
        };
        assert_eq!(e.to_string(), "missing required field: name");
    }

    #[test]
    fn error_display_missing_dep() {
        let e = ScenarioError::MissingDependency {
            step_id: "s1".to_string(),
            missing: "s0".to_string(),
        };
        assert!(e.to_string().contains("s1"));
        assert!(e.to_string().contains("s0"));
    }

    #[test]
    fn error_display_circular() {
        let e = ScenarioError::CircularDependency {
            cycle: vec!["a".to_string(), "b".to_string(), "a".to_string()],
        };
        assert!(e.to_string().contains("a -> b -> a"));
    }

    #[test]
    fn error_display_duplicate() {
        let e = ScenarioError::DuplicateStepId {
            step_id: "dup".to_string(),
        };
        assert!(e.to_string().contains("dup"));
    }

    // ── Serialization roundtrip tests ───────────────────────────────────

    #[test]
    fn scenario_step_serde_roundtrip() {
        let s = step("test", "echo hello");
        let json = serde_json::to_string(&s).unwrap();
        let deserialized: ScenarioStep = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "test");
        assert_eq!(deserialized.command, "echo hello");
    }

    #[test]
    fn step_outcome_serde_roundtrip() {
        let o = passing_outcome("s1");
        let json = serde_json::to_string(&o).unwrap();
        let deserialized: StepOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.step_id, "s1");
        assert!(deserialized.passed);
    }

    #[test]
    fn artifact_bundle_serde_roundtrip() {
        let mut b = ArtifactBundle::new("test");
        b.add_file("f1.txt", "content");
        b.add_metadata("key", "value");
        let json = serde_json::to_string(&b).unwrap();
        let deserialized: ArtifactBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.scenario_name, "test");
        assert_eq!(deserialized.files.get("f1.txt").unwrap(), "content");
        assert_eq!(deserialized.metadata.get("key").unwrap(), "value");
    }

    #[test]
    fn scenario_error_serde_roundtrip() {
        let e = ScenarioError::ParseError {
            message: "bad".to_string(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let deserialized: ScenarioError = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, e);
    }

    #[test]
    fn scenario_result_serde_roundtrip() {
        let r = ScenarioResult {
            scenario_name: "test".to_string(),
            passed: true,
            failed_step: None,
            duration: Duration::from_millis(100),
            artifacts: ArtifactBundle::new("test"),
            stdout_log: "out".to_string(),
            stderr_log: "err".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let deserialized: ScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.scenario_name, "test");
        assert!(deserialized.passed);
    }

    // ── Edge case tests ─────────────────────────────────────────────────

    #[test]
    fn step_with_all_fields_populated() {
        let s = ScenarioStep {
            id: "full-step".to_string(),
            command: "fwc catalog list --format json".to_string(),
            expected_exit_code: 0,
            expected_output_contains: vec!["connector".to_string()],
            expected_output_not_contains: vec!["error".to_string()],
            depends_on: vec!["setup".to_string()],
            capture_as: Some("catalog_json".to_string()),
        };
        assert_eq!(s.id, "full-step");
        assert!(s.capture_as.is_some());
    }

    #[test]
    fn topo_sort_wide_fan_out() {
        let mut steps = vec![step("root", "echo root")];
        for i in 0..10 {
            steps.push(step_with_deps(
                &format!("leaf-{i}"),
                &format!("echo leaf-{i}"),
                &["root"],
            ));
        }
        let order = topological_sort_steps(&steps);
        assert_eq!(order.len(), 11);
        assert_eq!(order[0], "root");
    }

    #[test]
    fn topo_sort_wide_fan_in() {
        let mut steps = Vec::new();
        let dep_names: Vec<String> = (0..5).map(|i| format!("dep-{i}")).collect();
        for name in &dep_names {
            steps.push(step(name, &format!("echo {name}")));
        }
        let dep_refs: Vec<&str> = dep_names.iter().map(String::as_str).collect();
        steps.push(step_with_deps("sink", "echo sink", &dep_refs));
        let order = topological_sort_steps(&steps);
        let sink_pos = order.iter().position(|s| s == "sink").unwrap();
        assert_eq!(sink_pos, order.len() - 1);
    }

    #[test]
    fn validate_many_issues() {
        let s = Scenario {
            name: "bad".to_string(),
            description: String::new(),
            steps: vec![
                step_with_deps("a", "x", &["b"]),
                step_with_deps("b", "y", &["a"]),
                step_with_deps("c", "z", &["nonexistent"]),
                step("a", "dupe"), // duplicate ID
            ],
            expected_outcomes: Vec::new(),
            tags: Vec::new(),
            timeout_secs: 0,
        };
        let issues = validate_scenario(&s);
        assert!(
            issues.len() >= 3,
            "expected at least 3 issues, got: {issues:?}"
        );
    }

    #[test]
    fn runner_verbose_flag() {
        let mut r = ScenarioRunner::new(Duration::from_secs(60));
        assert!(!r.verbose);
        r.verbose = true;
        assert!(r.verbose);
    }

    #[test]
    fn runner_capture_artifacts_flag() {
        let r = ScenarioRunner::new(Duration::from_secs(60));
        assert!(r.capture_artifacts);
    }

    #[test]
    fn artifact_bundle_empty_file_content() {
        let mut b = ArtifactBundle::new("test");
        b.add_file("empty.txt", "");
        assert_eq!(b.file_count(), 1);
        let manifest = b.format_manifest();
        assert!(manifest.contains("0 bytes"));
    }

    #[test]
    fn scenario_with_many_tags() {
        let s = Scenario {
            tags: vec![
                "smoke".to_string(),
                "regression".to_string(),
                "ci".to_string(),
                "nightly".to_string(),
            ],
            ..minimal_scenario("tagged", vec![step("a", "x")])
        };
        assert_eq!(s.tags.len(), 4);
    }

    #[test]
    fn scenario_with_expected_outcomes() {
        let s = Scenario {
            expected_outcomes: vec!["connector_listed".to_string(), "no_errors".to_string()],
            ..minimal_scenario("outcomes", vec![step("a", "x")])
        };
        assert_eq!(s.expected_outcomes.len(), 2);
    }

    #[test]
    fn check_step_empty_stdout() {
        let s = step("s1", "echo");
        let o = StepOutcome {
            stdout: String::new(),
            ..passing_outcome("s1")
        };
        assert!(ScenarioRunner::check_step(&s, &o));
    }

    #[test]
    fn report_duration_shown() {
        let results = vec![ScenarioResult {
            scenario_name: "timed".to_string(),
            passed: true,
            failed_step: None,
            duration: Duration::from_millis(1234),
            artifacts: ArtifactBundle::new("timed"),
            stdout_log: String::new(),
            stderr_log: String::new(),
        }];
        let report = format_scenario_report(&results);
        assert!(report.contains("1234ms"));
    }

    #[test]
    fn topo_sort_preserves_independent_order() {
        // When there are no dependencies, steps should appear (some deterministic order).
        let steps = vec![step("x", "a"), step("y", "b"), step("z", "c")];
        let order = topological_sort_steps(&steps);
        assert_eq!(order.len(), 3);
        // All present.
        let set: HashSet<String> = order.into_iter().collect();
        assert!(set.contains("x"));
        assert!(set.contains("y"));
        assert!(set.contains("z"));
    }

    #[test]
    fn parse_scenario_with_no_description() {
        let toml = r#"
name = "no-desc"
[[steps]]
id = "s1"
command = "echo hello"
"#;
        let s = parse_scenario(toml).unwrap();
        assert!(s.description.is_empty());
    }

    #[test]
    fn build_result_empty_outcomes() {
        let s = minimal_scenario("test", vec![step("a", "x")]);
        let outcomes: Vec<StepOutcome> = Vec::new();
        let result = build_scenario_result(&s, &outcomes, Duration::from_millis(0));
        // No outcomes means all_passed stays true (no failure detected).
        assert!(result.passed);
        assert_eq!(
            result.artifacts.metadata.get("executed_steps").unwrap(),
            "0"
        );
    }

    #[test]
    fn format_plan_empty() {
        let formatted = format_plan(&[]);
        assert!(formatted.is_empty());
    }

    #[test]
    fn has_circular_dep_single_self_loop() {
        let steps = vec![step_with_deps("a", "x", &["a"])];
        assert!(has_circular_dependency(&steps));
    }

    #[test]
    fn find_cycle_self_loop() {
        let steps = vec![step_with_deps("a", "x", &["a"])];
        let cycle = find_cycle(&steps).unwrap();
        assert!(cycle.contains(&"a".to_string()));
    }
}
