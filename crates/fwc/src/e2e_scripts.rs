//! E2E scenario matrix and runner framework for FWC end-to-end testing.
//!
//! Provides a scenario matrix with category-based filtering, prerequisite-aware
//! wave planning, assertion checking, and detailed result formatting.  Each
//! scenario encodes a sequence of steps with output assertions, environment
//! variables, and variable capture for cross-step data flow.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Category / Level enums ──────────────────────────────────────────────

/// Category that classifies the purpose of a scenario.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioCategory {
    /// Fast sanity check — first things to run.
    Smoke,
    /// Guards against regressions in existing behavior.
    Regression,
    /// Measures latency, throughput, or resource consumption.
    Performance,
    /// Validates security invariants (redaction, approval, budget).
    Security,
}

impl std::fmt::Display for ScenarioCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Smoke => f.write_str("smoke"),
            Self::Regression => f.write_str("regression"),
            Self::Performance => f.write_str("performance"),
            Self::Security => f.write_str("security"),
        }
    }
}

/// Log level for `LogEntry`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debug => f.write_str("DEBUG"),
            Self::Info => f.write_str("INFO"),
            Self::Warn => f.write_str("WARN"),
            Self::Error => f.write_str("ERROR"),
        }
    }
}

/// Assertion condition kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionCondition {
    /// Exact equality with expected value.
    Equals,
    /// String contains expected substring.
    Contains,
    /// Value matches a regex pattern stored in `expected`.
    Matches,
    /// Numeric value falls within `[lo, hi]` stored as `"lo..hi"` in `expected`.
    Range,
    /// Value is present and non-empty (non-null, non-"", non-[]).
    NonEmpty,
}

// ── Core types ──────────────────────────────────────────────────────────

/// A single assertion to validate against a step's output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct E2EAssertion {
    /// JSON pointer or dot-separated path into the output value.
    pub field_path: String,
    /// What kind of check to perform.
    pub condition: AssertionCondition,
    /// Expected value (interpretation depends on `condition`).
    pub expected: Value,
    /// Human-readable failure message.
    pub message: String,
}

/// A single step in an E2E scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct E2EStep {
    /// Unique step identifier within the scenario.
    pub id: String,
    /// Human-readable description of what this step does.
    pub description: String,
    /// Command string to execute.
    pub command: String,
    /// Environment variables to set for this step.
    #[serde(default)]
    pub env_vars: HashMap<String, String>,
    /// Expected process exit code (0 by default).
    #[serde(default)]
    pub expected_exit_code: i32,
    /// Assertions to run against this step's output.
    #[serde(default)]
    pub output_assertions: Vec<E2EAssertion>,
    /// Capture variables from output (`capture_name` -> `json_pointer`).
    #[serde(default)]
    pub capture_vars: HashMap<String, String>,
    /// Number of times to retry on failure.
    #[serde(default)]
    pub retry_count: u32,
}

/// A complete E2E test scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct E2EScenario {
    /// Unique scenario identifier.
    pub id: String,
    /// Human-readable scenario name.
    pub name: String,
    /// Scenario category.
    pub category: ScenarioCategory,
    /// IDs of scenarios that must pass before this one runs.
    #[serde(default)]
    pub prerequisites: Vec<String>,
    /// Ordered list of steps.
    pub steps: Vec<E2EStep>,
    /// Post-step assertions on final output or captured variables.
    #[serde(default)]
    pub assertions: Vec<E2EAssertion>,
    /// Cleanup commands to run after the scenario (pass or fail).
    #[serde(default)]
    pub cleanup: Vec<String>,
    /// Maximum duration before the scenario is considered timed out.
    pub timeout: Duration,
    /// Free-form tags for filtering.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Result of executing a single step.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub passed: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub assertion_results: Vec<(String, bool)>,
}

/// A structured log entry produced during scenario execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    /// When the log was recorded.
    pub timestamp: DateTime<Utc>,
    /// Severity level.
    pub level: LogLevel,
    /// Which component produced this log.
    pub source: String,
    /// The log message.
    pub message: String,
    /// Arbitrary structured fields.
    #[serde(default)]
    pub fields: HashMap<String, String>,
}

/// Result of executing a complete scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct E2EResult {
    /// Which scenario was executed.
    pub scenario_id: String,
    /// Overall pass/fail.
    pub passed: bool,
    /// Per-step results.
    pub step_results: Vec<StepResult>,
    /// Total wall-clock duration.
    pub duration: Duration,
    /// Logs collected during execution.
    pub logs: Vec<LogEntry>,
    /// Artifact paths or inline data.
    #[serde(default)]
    pub artifacts: HashMap<String, String>,
}

/// Filter criteria for selecting scenarios from a matrix.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MatrixFilter {
    /// Include only these categories (empty = all).
    #[serde(default)]
    pub categories: Vec<ScenarioCategory>,
    /// Include only scenarios with at least one of these tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Exclude scenarios with any of these tags.
    #[serde(default)]
    pub exclude_tags: Vec<String>,
    /// Include only scenarios whose name contains this substring.
    #[serde(default)]
    pub name_pattern: Option<String>,
}

/// A complete scenario matrix with execution options.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioMatrix {
    /// All scenarios in the matrix.
    pub scenarios: Vec<E2EScenario>,
    /// Default filters applied before execution.
    #[serde(default)]
    pub filters: Vec<MatrixFilter>,
    /// Maximum number of concurrent scenario executions.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// Stop on first failure.
    #[serde(default)]
    pub fail_fast: bool,
}

const fn default_concurrency() -> usize {
    4
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn make_step(id: &str, desc: &str, cmd: &str) -> E2EStep {
    E2EStep {
        id: id.to_string(),
        description: desc.to_string(),
        command: cmd.to_string(),
        env_vars: HashMap::new(),
        expected_exit_code: 0,
        output_assertions: Vec::new(),
        capture_vars: HashMap::new(),
        retry_count: 0,
    }
}

fn make_scenario(
    id: &str,
    name: &str,
    cat: ScenarioCategory,
    tags: &[&str],
    steps: Vec<E2EStep>,
) -> E2EScenario {
    E2EScenario {
        id: id.to_string(),
        name: name.to_string(),
        category: cat,
        prerequisites: Vec::new(),
        steps,
        assertions: Vec::new(),
        cleanup: Vec::new(),
        timeout: Duration::from_secs(60),
        tags: tags.iter().map(|s| (*s).to_string()).collect(),
    }
}

// ── Builder: build_scenario_matrix ──────────────────────────────────────

/// Build a default scenario matrix with at least 20 scenarios covering all
/// four categories.
#[allow(clippy::too_many_lines)]
pub fn build_scenario_matrix() -> ScenarioMatrix {
    let mut scenarios = Vec::with_capacity(24);

    // ── Smoke (5) ──
    scenarios.push(make_scenario(
        "smoke-discover",
        "Connector discover returns valid introspection",
        ScenarioCategory::Smoke,
        &["connector", "discover"],
        vec![make_step(
            "discover",
            "Discover connector capabilities",
            "fwc discover --connector test",
        )],
    ));
    scenarios.push(make_scenario(
        "smoke-search",
        "Search returns results for known connector",
        ScenarioCategory::Smoke,
        &["search"],
        vec![make_step(
            "search",
            "Search for operations",
            "fwc search list",
        )],
    ));
    scenarios.push({
        let mut s = make_scenario(
            "smoke-invoke-basic",
            "Basic invoke completes without error",
            ScenarioCategory::Smoke,
            &["invoke", "basic"],
            vec![make_step(
                "invoke",
                "Invoke a safe operation",
                "fwc invoke test.list_items",
            )],
        );
        s.prerequisites.push("smoke-discover".to_string());
        s
    });
    scenarios.push(make_scenario(
        "smoke-validate",
        "Manifest validation passes for built-in connectors",
        ScenarioCategory::Smoke,
        &["validate", "manifest"],
        vec![make_step(
            "validate",
            "Validate manifests",
            "fwc validate --all",
        )],
    ));
    scenarios.push(make_scenario(
        "smoke-health",
        "Health check reports live status",
        ScenarioCategory::Smoke,
        &["health"],
        vec![make_step(
            "health",
            "Check connector health",
            "fwc health --connector test",
        )],
    ));

    // ── Regression (5) ──
    scenarios.push(make_scenario(
        "reg-auth-expiry",
        "Expired auth token triggers re-auth flow",
        ScenarioCategory::Regression,
        &["auth", "expiry"],
        vec![
            make_step(
                "set-expired",
                "Set expired token",
                "fwc auth set --token expired-test",
            ),
            make_step(
                "invoke",
                "Invoke should handle auth error",
                "fwc invoke test.list",
            ),
        ],
    ));
    scenarios.push(make_scenario(
        "reg-rate-limit",
        "Rate limit response triggers backoff and retry",
        ScenarioCategory::Regression,
        &["rate-limit", "retry"],
        vec![make_step(
            "invoke-rate",
            "Invoke with rate-limited endpoint",
            "fwc invoke test.rate_limited",
        )],
    ));
    scenarios.push(make_scenario(
        "reg-timeout",
        "Request timeout surfaces structured error",
        ScenarioCategory::Regression,
        &["timeout", "error"],
        vec![make_step(
            "invoke-slow",
            "Invoke slow endpoint",
            "fwc invoke test.slow_op --timeout 1",
        )],
    ));
    scenarios.push(make_scenario(
        "reg-error-recovery",
        "Transient error triggers recovery with partial results",
        ScenarioCategory::Regression,
        &["error", "recovery"],
        vec![
            make_step(
                "start-batch",
                "Start a batch with flaky items",
                "fwc batch run flaky.toml",
            ),
            make_step(
                "check-partial",
                "Verify partial results saved",
                "fwc batch status",
            ),
        ],
    ));
    scenarios.push(make_scenario(
        "reg-schema-mismatch",
        "Schema-violating input returns clear validation error",
        ScenarioCategory::Regression,
        &["schema", "validation"],
        vec![make_step(
            "bad-input",
            "Send invalid input",
            "fwc invoke test.create --input '{}'",
        )],
    ));

    // ── Performance (5) ──
    scenarios.push(make_scenario(
        "perf-batch-throughput",
        "Batch of 100 items completes within SLA",
        ScenarioCategory::Performance,
        &["batch", "throughput", "sla"],
        vec![make_step(
            "batch-100",
            "Run 100-item batch",
            "fwc batch run perf-100.toml",
        )],
    ));
    scenarios.push(make_scenario(
        "perf-search-latency",
        "Search response returns within 500ms",
        ScenarioCategory::Performance,
        &["search", "latency"],
        vec![make_step(
            "search-timed",
            "Search with timing",
            "fwc search list --timing",
        )],
    ));
    scenarios.push(make_scenario(
        "perf-pipeline-efficiency",
        "Multi-stage pipeline completes within 2x single invoke",
        ScenarioCategory::Performance,
        &["pipeline", "efficiency"],
        vec![
            make_step(
                "single",
                "Single invoke baseline",
                "fwc invoke test.transform",
            ),
            make_step(
                "pipeline",
                "Pipeline invoke",
                "fwc pipeline run transform-chain.toml",
            ),
        ],
    ));
    scenarios.push(make_scenario(
        "perf-concurrent-discover",
        "Concurrent discover for 10 connectors completes within SLA",
        ScenarioCategory::Performance,
        &["discover", "concurrency"],
        vec![make_step(
            "discover-10",
            "Discover 10 connectors",
            "fwc discover --all --limit 10",
        )],
    ));
    scenarios.push(make_scenario(
        "perf-large-payload",
        "Large payload (1MB) serializes and transmits within SLA",
        ScenarioCategory::Performance,
        &["payload", "large"],
        vec![make_step(
            "large-invoke",
            "Invoke with large input",
            "fwc invoke test.upload --input @large.json",
        )],
    ));

    // ── Security (5) ──
    scenarios.push(make_scenario(
        "sec-credential-redaction",
        "Credentials are redacted from logs and error output",
        ScenarioCategory::Security,
        &["credential", "redaction"],
        vec![
            make_step(
                "set-cred",
                "Set a credential",
                "fwc auth set --token secret123",
            ),
            make_step(
                "invoke-fail",
                "Invoke that fails — check no cred leak",
                "fwc invoke test.fail",
            ),
        ],
    ));
    scenarios.push(make_scenario(
        "sec-token-budget",
        "Token budget enforcement prevents over-spend",
        ScenarioCategory::Security,
        &["budget", "token"],
        vec![make_step(
            "budget-invoke",
            "Invoke with tight budget",
            "fwc invoke test.expensive --budget 10",
        )],
    ));
    scenarios.push(make_scenario(
        "sec-approval-flow",
        "High-risk operations require approval",
        ScenarioCategory::Security,
        &["approval", "risk"],
        vec![make_step(
            "risky-invoke",
            "Invoke risky operation without approval",
            "fwc invoke test.delete_all",
        )],
    ));
    scenarios.push(make_scenario(
        "sec-sandbox-escape",
        "Sandbox prevents filesystem access outside allowed paths",
        ScenarioCategory::Security,
        &["sandbox", "filesystem"],
        vec![make_step(
            "escape-attempt",
            "Try reading /etc/passwd via connector",
            "fwc invoke test.read_file --input '{\"path\":\"/etc/passwd\"}'",
        )],
    ));
    scenarios.push(make_scenario(
        "sec-tls-verification",
        "TLS certificate verification cannot be disabled by connector",
        ScenarioCategory::Security,
        &["tls", "certificate"],
        vec![make_step(
            "tls-check",
            "Invoke against self-signed endpoint",
            "fwc invoke test.https_self_signed",
        )],
    ));

    // Four more for good measure (24 total)
    scenarios.push(make_scenario(
        "smoke-version",
        "Version command returns semver string",
        ScenarioCategory::Smoke,
        &["version"],
        vec![make_step("version", "Check version", "fwc --version")],
    ));
    scenarios.push(make_scenario(
        "reg-concurrent-invoke",
        "Concurrent invokes to same connector serialize correctly",
        ScenarioCategory::Regression,
        &["concurrency", "invoke"],
        vec![make_step(
            "concurrent",
            "Run concurrent invokes",
            "fwc batch run concurrent.toml",
        )],
    ));
    scenarios.push(make_scenario(
        "perf-cache-hit",
        "Cached discover returns within 10ms",
        ScenarioCategory::Performance,
        &["cache", "discover"],
        vec![
            make_step("prime", "Prime the cache", "fwc discover --connector test"),
            make_step(
                "cached",
                "Discover again (cached)",
                "fwc discover --connector test",
            ),
        ],
    ));
    scenarios.push(make_scenario(
        "sec-input-injection",
        "SQL/command injection in input is safely escaped",
        ScenarioCategory::Security,
        &["injection", "input"],
        vec![make_step(
            "inject",
            "Try injection payload",
            "fwc invoke test.query --input '{\"q\":\"'; DROP TABLE x; --\"}'",
        )],
    ));

    ScenarioMatrix {
        scenarios,
        filters: Vec::new(),
        concurrency: 4,
        fail_fast: false,
    }
}

// ── Filtering ───────────────────────────────────────────────────────────

/// Filter scenarios from a matrix according to the given filter criteria.
pub fn filter_scenarios<'a>(
    matrix: &'a ScenarioMatrix,
    filter: &MatrixFilter,
) -> Vec<&'a E2EScenario> {
    matrix
        .scenarios
        .iter()
        .filter(|s| {
            // Category filter (empty = accept all).
            if !filter.categories.is_empty() && !filter.categories.contains(&s.category) {
                return false;
            }
            // Tag inclusion filter (empty = accept all).
            if !filter.tags.is_empty() && !filter.tags.iter().any(|t| s.tags.contains(t)) {
                return false;
            }
            // Tag exclusion filter.
            if filter.exclude_tags.iter().any(|t| s.tags.contains(t)) {
                return false;
            }
            // Name pattern filter.
            if let Some(ref pat) = filter.name_pattern {
                if !s.name.contains(pat.as_str()) {
                    return false;
                }
            }
            true
        })
        .collect()
}

// ── Validation ──────────────────────────────────────────────────────────

/// Validate a scenario for structural correctness.  Returns a list of
/// diagnostic messages (empty = valid).
pub fn validate_scenario(scenario: &E2EScenario) -> Vec<String> {
    let mut errors = Vec::new();

    if scenario.id.is_empty() {
        errors.push("scenario id must not be empty".to_string());
    }
    if scenario.name.is_empty() {
        errors.push("scenario name must not be empty".to_string());
    }
    if scenario.steps.is_empty() {
        errors.push("scenario must have at least one step".to_string());
    }
    if scenario.timeout.is_zero() {
        errors.push("scenario timeout must be > 0".to_string());
    }

    // Check step IDs unique.
    let mut seen_ids = HashSet::new();
    for step in &scenario.steps {
        if step.id.is_empty() {
            errors.push("step id must not be empty".to_string());
        }
        if !seen_ids.insert(&step.id) {
            errors.push(format!("duplicate step id: {}", step.id));
        }
        if step.command.is_empty() {
            errors.push(format!("step {} has empty command", step.id));
        }
    }

    // Check prerequisite references exist in matrix context (can't validate
    // cross-scenario here, but we can flag self-references).
    for prereq in &scenario.prerequisites {
        if prereq == &scenario.id {
            errors.push(format!("scenario cannot be its own prerequisite: {prereq}"));
        }
    }

    errors
}

// ── Assertion checking ──────────────────────────────────────────────────

/// Resolve a dot-separated or slash-separated field path against a JSON value.
fn resolve_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let parts: Vec<&str> = if path.starts_with('/') {
        path.split('/').skip(1).collect()
    } else {
        path.split('.').collect()
    };
    let mut current = value;
    for part in parts {
        match current {
            Value::Object(map) => {
                current = map.get(part)?;
            }
            Value::Array(arr) => {
                let idx: usize = part.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

/// Check whether a value satisfies an assertion.
pub fn check_assertion(value: &Value, assertion: &E2EAssertion) -> bool {
    let resolved = resolve_path(value, &assertion.field_path);

    match assertion.condition {
        AssertionCondition::NonEmpty => {
            match resolved {
                None | Some(Value::Null) => false,
                Some(Value::String(s)) => !s.is_empty(),
                Some(Value::Array(a)) => !a.is_empty(),
                Some(Value::Object(m)) => !m.is_empty(),
                Some(_) => true, // numbers and booleans are non-empty
            }
        }
        AssertionCondition::Equals => resolved == Some(&assertion.expected),
        AssertionCondition::Contains => {
            let Some(resolved_val) = resolved else {
                return false;
            };
            let haystack = match resolved_val {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let needle = match &assertion.expected {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            haystack.contains(&needle)
        }
        AssertionCondition::Matches => {
            let Some(Value::String(s)) = resolved else {
                return false;
            };
            let Value::String(pattern) = &assertion.expected else {
                return false;
            };
            // Simple glob-style match: * matches anything.
            if pattern == "*" {
                return true;
            }
            // Prefix match with trailing *.
            if let Some(prefix) = pattern.strip_suffix('*') {
                return s.starts_with(prefix);
            }
            // Suffix match with leading *.
            if let Some(suffix) = pattern.strip_prefix('*') {
                return s.ends_with(suffix);
            }
            s == pattern
        }
        AssertionCondition::Range => {
            let Some(resolved_val) = resolved else {
                return false;
            };
            let num = match resolved_val {
                Value::Number(n) => n.as_f64(),
                _ => None,
            };
            let Some(num) = num else {
                return false;
            };
            let Value::String(range_str) = &assertion.expected else {
                return false;
            };
            let Some((lo_s, hi_s)) = range_str.split_once("..") else {
                return false;
            };
            let Ok(lo) = lo_s.trim().parse::<f64>() else {
                return false;
            };
            let Ok(hi) = hi_s.trim().parse::<f64>() else {
                return false;
            };
            num >= lo && num <= hi
        }
    }
}

// ── Execution planning ──────────────────────────────────────────────────

/// Plan execution order by grouping scenarios into waves.  Scenarios with no
/// prerequisites (or whose prerequisites have already been scheduled) go into
/// earlier waves.  Returns a list of waves, each containing scenario indices.
pub fn plan_execution_order(scenarios: &[E2EScenario]) -> Vec<Vec<usize>> {
    let id_to_idx: HashMap<&str, usize> = scenarios
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.as_str(), i))
        .collect();

    let mut scheduled: HashSet<usize> = HashSet::new();
    let mut waves: Vec<Vec<usize>> = Vec::new();
    let total = scenarios.len();

    // Safeguard against infinite loops — at most `total` waves.
    for _ in 0..total {
        if scheduled.len() == total {
            break;
        }
        let mut wave = Vec::new();
        for (i, s) in scenarios.iter().enumerate() {
            if scheduled.contains(&i) {
                continue;
            }
            let prereqs_met = s.prerequisites.iter().all(|pid| {
                id_to_idx
                    .get(pid.as_str())
                    .is_none_or(|&idx| scheduled.contains(&idx))
            });
            if prereqs_met {
                wave.push(i);
            }
        }
        if wave.is_empty() {
            // Remaining scenarios have unsatisfiable prerequisites — push
            // them all into a final wave so nothing is silently dropped.
            let remaining: Vec<usize> = (0..total).filter(|i| !scheduled.contains(i)).collect();
            if !remaining.is_empty() {
                waves.push(remaining.clone());
                for i in &remaining {
                    scheduled.insert(*i);
                }
            }
            break;
        }
        for &i in &wave {
            scheduled.insert(i);
        }
        waves.push(wave);
    }

    waves
}

// ── Formatting ──────────────────────────────────────────────────────────

/// Format a human-readable summary of a scenario matrix.
pub fn format_matrix_summary(matrix: &ScenarioMatrix) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "E2E Scenario Matrix");
    let _ = writeln!(out, "===================");
    let _ = writeln!(out, "Total scenarios: {}", matrix.scenarios.len());
    let _ = writeln!(out, "Concurrency:     {}", matrix.concurrency);
    let _ = writeln!(out, "Fail-fast:       {}", matrix.fail_fast);
    let _ = writeln!(out);

    // Category breakdown.
    let mut by_cat: HashMap<&ScenarioCategory, usize> = HashMap::new();
    for s in &matrix.scenarios {
        *by_cat.entry(&s.category).or_default() += 1;
    }
    let _ = writeln!(out, "By category:");
    for (cat, count) in &by_cat {
        let _ = writeln!(out, "  {cat}: {count}");
    }
    let _ = writeln!(out);

    // List scenarios.
    let _ = writeln!(out, "Scenarios:");
    for s in &matrix.scenarios {
        let _ = writeln!(
            out,
            "  [{cat}] {id}: {name} ({n} steps, tags: {tags})",
            cat = s.category,
            id = s.id,
            name = s.name,
            n = s.steps.len(),
            tags = if s.tags.is_empty() {
                "none".to_string()
            } else {
                s.tags.join(", ")
            },
        );
    }

    out
}

/// Format a detailed result report.
pub fn format_result_detailed(result: &E2EResult) -> String {
    let mut out = String::new();
    let status = if result.passed { "PASSED" } else { "FAILED" };
    let _ = writeln!(out, "Scenario: {} — {status}", result.scenario_id);
    let _ = writeln!(out, "Duration: {:.2}s", result.duration.as_secs_f64());
    let _ = writeln!(out, "Steps: {}", result.step_results.len());
    let _ = writeln!(out);

    for sr in &result.step_results {
        let step_status = if sr.passed { "OK" } else { "FAIL" };
        let _ = writeln!(
            out,
            "  [{step_status}] {id} (exit={exit}, {dur:.2}s)",
            id = sr.step_id,
            exit = sr.exit_code,
            dur = sr.duration.as_secs_f64(),
        );
        for (name, ok) in &sr.assertion_results {
            let mark = if *ok { "+" } else { "-" };
            let _ = writeln!(out, "    [{mark}] {name}");
        }
    }

    if !result.logs.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Logs ({}):", result.logs.len());
        for entry in &result.logs {
            let _ = writeln!(
                out,
                "  {} [{level}] {src}: {msg}",
                entry.timestamp.format("%H:%M:%S"),
                level = entry.level,
                src = entry.source,
                msg = entry.message,
            );
        }
    }

    if !result.artifacts.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Artifacts:");
        for (k, v) in &result.artifacts {
            let _ = writeln!(out, "  {k}: {v}");
        }
    }

    out
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── build_scenario_matrix ───────────────────────────────────────────

    #[test]
    fn matrix_has_at_least_20_scenarios() {
        let m = build_scenario_matrix();
        assert!(m.scenarios.len() >= 20, "got {}", m.scenarios.len());
    }

    #[test]
    fn matrix_covers_all_categories() {
        let m = build_scenario_matrix();
        let cats: HashSet<_> = m.scenarios.iter().map(|s| &s.category).collect();
        assert!(cats.contains(&ScenarioCategory::Smoke));
        assert!(cats.contains(&ScenarioCategory::Regression));
        assert!(cats.contains(&ScenarioCategory::Performance));
        assert!(cats.contains(&ScenarioCategory::Security));
    }

    #[test]
    fn matrix_smoke_scenarios_count() {
        let m = build_scenario_matrix();
        let count = m
            .scenarios
            .iter()
            .filter(|s| s.category == ScenarioCategory::Smoke)
            .count();
        assert!(count >= 5, "smoke count: {count}");
    }

    #[test]
    fn matrix_regression_scenarios_count() {
        let m = build_scenario_matrix();
        let count = m
            .scenarios
            .iter()
            .filter(|s| s.category == ScenarioCategory::Regression)
            .count();
        assert!(count >= 5, "regression count: {count}");
    }

    #[test]
    fn matrix_performance_scenarios_count() {
        let m = build_scenario_matrix();
        let count = m
            .scenarios
            .iter()
            .filter(|s| s.category == ScenarioCategory::Performance)
            .count();
        assert!(count >= 5, "perf count: {count}");
    }

    #[test]
    fn matrix_security_scenarios_count() {
        let m = build_scenario_matrix();
        let count = m
            .scenarios
            .iter()
            .filter(|s| s.category == ScenarioCategory::Security)
            .count();
        assert!(count >= 5, "sec count: {count}");
    }

    #[test]
    fn matrix_ids_are_unique() {
        let m = build_scenario_matrix();
        let mut ids = HashSet::new();
        for s in &m.scenarios {
            assert!(ids.insert(&s.id), "duplicate id: {}", s.id);
        }
    }

    #[test]
    fn matrix_all_scenarios_have_steps() {
        let m = build_scenario_matrix();
        for s in &m.scenarios {
            assert!(!s.steps.is_empty(), "scenario {} has no steps", s.id);
        }
    }

    #[test]
    fn matrix_all_scenarios_have_timeout() {
        let m = build_scenario_matrix();
        for s in &m.scenarios {
            assert!(!s.timeout.is_zero(), "scenario {} has zero timeout", s.id);
        }
    }

    #[test]
    fn matrix_default_concurrency() {
        let m = build_scenario_matrix();
        assert_eq!(m.concurrency, 4);
    }

    #[test]
    fn matrix_default_fail_fast_off() {
        let m = build_scenario_matrix();
        assert!(!m.fail_fast);
    }

    #[test]
    fn matrix_scenario_names_non_empty() {
        let m = build_scenario_matrix();
        for s in &m.scenarios {
            assert!(!s.name.is_empty(), "scenario {} has empty name", s.id);
        }
    }

    #[test]
    fn matrix_tags_are_populated() {
        let m = build_scenario_matrix();
        let with_tags = m.scenarios.iter().filter(|s| !s.tags.is_empty()).count();
        assert_eq!(
            with_tags,
            m.scenarios.len(),
            "all scenarios should have tags"
        );
    }

    // ── filter_scenarios ────────────────────────────────────────────────

    #[test]
    fn filter_empty_returns_all() {
        let m = build_scenario_matrix();
        let f = MatrixFilter::default();
        let result = filter_scenarios(&m, &f);
        assert_eq!(result.len(), m.scenarios.len());
    }

    #[test]
    fn filter_by_single_category() {
        let m = build_scenario_matrix();
        let f = MatrixFilter {
            categories: vec![ScenarioCategory::Smoke],
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        assert!(result.iter().all(|s| s.category == ScenarioCategory::Smoke));
        assert!(!result.is_empty());
    }

    #[test]
    fn filter_by_multiple_categories() {
        let m = build_scenario_matrix();
        let f = MatrixFilter {
            categories: vec![ScenarioCategory::Smoke, ScenarioCategory::Security],
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        for s in &result {
            assert!(
                s.category == ScenarioCategory::Smoke || s.category == ScenarioCategory::Security
            );
        }
    }

    #[test]
    fn filter_by_tag_inclusion() {
        let m = build_scenario_matrix();
        let f = MatrixFilter {
            tags: vec!["invoke".to_string()],
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        assert!(
            result
                .iter()
                .all(|s| s.tags.contains(&"invoke".to_string()))
        );
    }

    #[test]
    fn filter_by_tag_exclusion() {
        let m = build_scenario_matrix();
        let f = MatrixFilter {
            exclude_tags: vec!["invoke".to_string()],
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        assert!(
            result
                .iter()
                .all(|s| !s.tags.contains(&"invoke".to_string()))
        );
    }

    #[test]
    fn filter_by_name_pattern() {
        let m = build_scenario_matrix();
        let f = MatrixFilter {
            name_pattern: Some("Connector".to_string()),
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        assert!(result.iter().all(|s| s.name.contains("Connector")));
    }

    #[test]
    fn filter_combined_category_and_tag() {
        let m = build_scenario_matrix();
        let f = MatrixFilter {
            categories: vec![ScenarioCategory::Security],
            tags: vec!["redaction".to_string()],
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        for s in &result {
            assert_eq!(s.category, ScenarioCategory::Security);
            assert!(s.tags.contains(&"redaction".to_string()));
        }
    }

    #[test]
    fn filter_nonexistent_tag_returns_empty() {
        let m = build_scenario_matrix();
        let f = MatrixFilter {
            tags: vec!["nonexistent_xyz".to_string()],
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_name_pattern_no_match() {
        let m = build_scenario_matrix();
        let f = MatrixFilter {
            name_pattern: Some("ZZZZNOTFOUNDZZZ".to_string()),
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_exclude_overrides_include() {
        let m = build_scenario_matrix();
        // Include "discover" tag but also exclude it — should be empty.
        let f = MatrixFilter {
            tags: vec!["discover".to_string()],
            exclude_tags: vec!["discover".to_string()],
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        assert!(result.is_empty());
    }

    // ── validate_scenario ───────────────────────────────────────────────

    #[test]
    fn validate_valid_scenario_no_errors() {
        let s = make_scenario(
            "t1",
            "Test",
            ScenarioCategory::Smoke,
            &["a"],
            vec![make_step("s1", "step1", "echo hello")],
        );
        assert!(validate_scenario(&s).is_empty());
    }

    #[test]
    fn validate_empty_id() {
        let mut s = make_scenario(
            "",
            "Test",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s1", "step", "cmd")],
        );
        s.id = String::new();
        let errs = validate_scenario(&s);
        assert!(errs.iter().any(|e| e.contains("id must not be empty")));
    }

    #[test]
    fn validate_empty_name() {
        let s = make_scenario(
            "t1",
            "",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s1", "step", "cmd")],
        );
        let errs = validate_scenario(&s);
        assert!(errs.iter().any(|e| e.contains("name must not be empty")));
    }

    #[test]
    fn validate_no_steps() {
        let s = make_scenario("t1", "Test", ScenarioCategory::Smoke, &[], vec![]);
        let errs = validate_scenario(&s);
        assert!(errs.iter().any(|e| e.contains("at least one step")));
    }

    #[test]
    fn validate_zero_timeout() {
        let mut s = make_scenario(
            "t1",
            "Test",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s1", "step", "cmd")],
        );
        s.timeout = Duration::ZERO;
        let errs = validate_scenario(&s);
        assert!(errs.iter().any(|e| e.contains("timeout")));
    }

    #[test]
    fn validate_duplicate_step_id() {
        let s = make_scenario(
            "t1",
            "Test",
            ScenarioCategory::Smoke,
            &[],
            vec![
                make_step("dup", "step1", "cmd1"),
                make_step("dup", "step2", "cmd2"),
            ],
        );
        let errs = validate_scenario(&s);
        assert!(errs.iter().any(|e| e.contains("duplicate step id")));
    }

    #[test]
    fn validate_empty_step_id() {
        let s = make_scenario(
            "t1",
            "Test",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("", "step", "cmd")],
        );
        let errs = validate_scenario(&s);
        assert!(errs.iter().any(|e| e.contains("step id must not be empty")));
    }

    #[test]
    fn validate_empty_step_command() {
        let s = make_scenario(
            "t1",
            "Test",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s1", "step", "")],
        );
        let errs = validate_scenario(&s);
        assert!(errs.iter().any(|e| e.contains("empty command")));
    }

    #[test]
    fn validate_self_prerequisite() {
        let mut s = make_scenario(
            "t1",
            "Test",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s1", "step", "cmd")],
        );
        s.prerequisites.push("t1".to_string());
        let errs = validate_scenario(&s);
        assert!(errs.iter().any(|e| e.contains("own prerequisite")));
    }

    #[test]
    fn validate_matrix_all_scenarios_valid() {
        let m = build_scenario_matrix();
        for s in &m.scenarios {
            let errs = validate_scenario(s);
            assert!(errs.is_empty(), "scenario {} invalid: {:?}", s.id, errs);
        }
    }

    #[test]
    fn validate_multiple_errors_collected() {
        let mut s = make_scenario("", "", ScenarioCategory::Smoke, &[], vec![]);
        s.timeout = Duration::ZERO;
        let errs = validate_scenario(&s);
        assert!(
            errs.len() >= 3,
            "expected >=3 errors, got {}: {:?}",
            errs.len(),
            errs
        );
    }

    // ── check_assertion ─────────────────────────────────────────────────

    fn assert_eq_assertion(path: &str, expected: Value) -> E2EAssertion {
        E2EAssertion {
            field_path: path.to_string(),
            condition: AssertionCondition::Equals,
            expected,
            message: "test".to_string(),
        }
    }

    #[test]
    fn assertion_equals_string() {
        let val = json!({"name": "hello"});
        let a = assert_eq_assertion("name", json!("hello"));
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_equals_number() {
        let val = json!({"count": 42});
        let a = assert_eq_assertion("count", json!(42));
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_equals_fails() {
        let val = json!({"name": "hello"});
        let a = assert_eq_assertion("name", json!("world"));
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_equals_nested() {
        let val = json!({"a": {"b": 1}});
        let a = assert_eq_assertion("a.b", json!(1));
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_equals_missing_path() {
        let val = json!({"a": 1});
        let a = assert_eq_assertion("b", json!(1));
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_contains_string() {
        let val = json!({"msg": "hello world"});
        let a = E2EAssertion {
            field_path: "msg".to_string(),
            condition: AssertionCondition::Contains,
            expected: json!("world"),
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_contains_fails() {
        let val = json!({"msg": "hello"});
        let a = E2EAssertion {
            field_path: "msg".to_string(),
            condition: AssertionCondition::Contains,
            expected: json!("xyz"),
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_contains_number_in_string() {
        let val = json!({"msg": "count is 42"});
        let a = E2EAssertion {
            field_path: "msg".to_string(),
            condition: AssertionCondition::Contains,
            expected: json!("42"),
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_non_empty_string() {
        let val = json!({"name": "hello"});
        let a = E2EAssertion {
            field_path: "name".to_string(),
            condition: AssertionCondition::NonEmpty,
            expected: Value::Null,
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_non_empty_empty_string() {
        let val = json!({"name": ""});
        let a = E2EAssertion {
            field_path: "name".to_string(),
            condition: AssertionCondition::NonEmpty,
            expected: Value::Null,
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_non_empty_null() {
        let val = json!({"name": null});
        let a = E2EAssertion {
            field_path: "name".to_string(),
            condition: AssertionCondition::NonEmpty,
            expected: Value::Null,
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_non_empty_missing() {
        let val = json!({"other": 1});
        let a = E2EAssertion {
            field_path: "name".to_string(),
            condition: AssertionCondition::NonEmpty,
            expected: Value::Null,
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_non_empty_array() {
        let val = json!({"items": [1, 2]});
        let a = E2EAssertion {
            field_path: "items".to_string(),
            condition: AssertionCondition::NonEmpty,
            expected: Value::Null,
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_non_empty_empty_array() {
        let val = json!({"items": []});
        let a = E2EAssertion {
            field_path: "items".to_string(),
            condition: AssertionCondition::NonEmpty,
            expected: Value::Null,
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_non_empty_number() {
        let val = json!({"n": 0});
        let a = E2EAssertion {
            field_path: "n".to_string(),
            condition: AssertionCondition::NonEmpty,
            expected: Value::Null,
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_non_empty_object_empty() {
        let val = json!({"obj": {}});
        let a = E2EAssertion {
            field_path: "obj".to_string(),
            condition: AssertionCondition::NonEmpty,
            expected: Value::Null,
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_non_empty_object_populated() {
        let val = json!({"obj": {"k": 1}});
        let a = E2EAssertion {
            field_path: "obj".to_string(),
            condition: AssertionCondition::NonEmpty,
            expected: Value::Null,
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_matches_wildcard() {
        let val = json!({"name": "anything"});
        let a = E2EAssertion {
            field_path: "name".to_string(),
            condition: AssertionCondition::Matches,
            expected: json!("*"),
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_matches_prefix() {
        let val = json!({"name": "fcp.github"});
        let a = E2EAssertion {
            field_path: "name".to_string(),
            condition: AssertionCondition::Matches,
            expected: json!("fcp.*"),
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_matches_suffix() {
        let val = json!({"name": "fcp.github"});
        let a = E2EAssertion {
            field_path: "name".to_string(),
            condition: AssertionCondition::Matches,
            expected: json!("*.github"),
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_matches_exact() {
        let val = json!({"name": "exact"});
        let a = E2EAssertion {
            field_path: "name".to_string(),
            condition: AssertionCondition::Matches,
            expected: json!("exact"),
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_matches_fails() {
        let val = json!({"name": "fcp.github"});
        let a = E2EAssertion {
            field_path: "name".to_string(),
            condition: AssertionCondition::Matches,
            expected: json!("xyz.*"),
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_range_in_range() {
        let val = json!({"latency": 250.0});
        let a = E2EAssertion {
            field_path: "latency".to_string(),
            condition: AssertionCondition::Range,
            expected: json!("0..500"),
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_range_below() {
        let val = json!({"latency": -1.0});
        let a = E2EAssertion {
            field_path: "latency".to_string(),
            condition: AssertionCondition::Range,
            expected: json!("0..500"),
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_range_above() {
        let val = json!({"latency": 501.0});
        let a = E2EAssertion {
            field_path: "latency".to_string(),
            condition: AssertionCondition::Range,
            expected: json!("0..500"),
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_range_boundary_lo() {
        let val = json!({"n": 0.0});
        let a = E2EAssertion {
            field_path: "n".to_string(),
            condition: AssertionCondition::Range,
            expected: json!("0..100"),
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_range_boundary_hi() {
        let val = json!({"n": 100.0});
        let a = E2EAssertion {
            field_path: "n".to_string(),
            condition: AssertionCondition::Range,
            expected: json!("0..100"),
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_range_non_numeric() {
        let val = json!({"n": "hello"});
        let a = E2EAssertion {
            field_path: "n".to_string(),
            condition: AssertionCondition::Range,
            expected: json!("0..100"),
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_range_bad_format() {
        let val = json!({"n": 50.0});
        let a = E2EAssertion {
            field_path: "n".to_string(),
            condition: AssertionCondition::Range,
            expected: json!("not-a-range"),
            message: "test".to_string(),
        };
        assert!(!check_assertion(&val, &a));
    }

    // ── resolve_path ────────────────────────────────────────────────────

    #[test]
    fn resolve_dot_path() {
        let val = json!({"a": {"b": {"c": 42}}});
        assert_eq!(resolve_path(&val, "a.b.c"), Some(&json!(42)));
    }

    #[test]
    fn resolve_slash_path() {
        let val = json!({"a": {"b": 1}});
        assert_eq!(resolve_path(&val, "/a/b"), Some(&json!(1)));
    }

    #[test]
    fn resolve_array_index() {
        let val = json!({"items": [10, 20, 30]});
        assert_eq!(resolve_path(&val, "items.1"), Some(&json!(20)));
    }

    #[test]
    fn resolve_missing() {
        let val = json!({"a": 1});
        assert_eq!(resolve_path(&val, "b"), None);
    }

    #[test]
    fn resolve_deep_missing() {
        let val = json!({"a": {"b": 1}});
        assert_eq!(resolve_path(&val, "a.c"), None);
    }

    #[test]
    fn resolve_root_key() {
        let val = json!({"x": "y"});
        assert_eq!(resolve_path(&val, "x"), Some(&json!("y")));
    }

    #[test]
    fn resolve_through_array_of_objects() {
        let val = json!({"items": [{"name": "a"}, {"name": "b"}]});
        assert_eq!(resolve_path(&val, "items.0.name"), Some(&json!("a")));
    }

    // ── plan_execution_order ────────────────────────────────────────────

    #[test]
    fn plan_no_prerequisites_single_wave() {
        let scenarios = vec![
            make_scenario(
                "a",
                "A",
                ScenarioCategory::Smoke,
                &[],
                vec![make_step("s", "s", "c")],
            ),
            make_scenario(
                "b",
                "B",
                ScenarioCategory::Smoke,
                &[],
                vec![make_step("s", "s", "c")],
            ),
        ];
        let waves = plan_execution_order(&scenarios);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].len(), 2);
    }

    #[test]
    fn plan_linear_chain() {
        let mut a = make_scenario(
            "a",
            "A",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        let mut b = make_scenario(
            "b",
            "B",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        let mut c_s = make_scenario(
            "c",
            "C",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        b.prerequisites.push("a".to_string());
        c_s.prerequisites.push("b".to_string());
        let scenarios = vec![a, b, c_s];
        let waves = plan_execution_order(&scenarios);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
        assert_eq!(waves[2], vec![2]);
    }

    #[test]
    fn plan_diamond_dependency() {
        // a -> b, a -> c, b+c -> d
        let a = make_scenario(
            "a",
            "A",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        let mut b = make_scenario(
            "b",
            "B",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        b.prerequisites.push("a".to_string());
        let mut c_s = make_scenario(
            "c",
            "C",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        c_s.prerequisites.push("a".to_string());
        let mut d = make_scenario(
            "d",
            "D",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        d.prerequisites.push("b".to_string());
        d.prerequisites.push("c".to_string());

        let scenarios = vec![a, b, c_s, d];
        let waves = plan_execution_order(&scenarios);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0], vec![0]); // a
        assert!(waves[1].contains(&1) && waves[1].contains(&2)); // b, c
        assert_eq!(waves[2], vec![3]); // d
    }

    #[test]
    fn plan_empty_scenarios() {
        let waves = plan_execution_order(&[]);
        assert!(waves.is_empty());
    }

    #[test]
    fn plan_unknown_prerequisite_treated_as_met() {
        let mut s = make_scenario(
            "a",
            "A",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        s.prerequisites.push("nonexistent".to_string());
        let scenarios = vec![s];
        let waves = plan_execution_order(&scenarios);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0], vec![0]);
    }

    #[test]
    fn plan_circular_dep_still_includes_all() {
        let mut a = make_scenario(
            "a",
            "A",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        a.prerequisites.push("b".to_string());
        let mut b = make_scenario(
            "b",
            "B",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        b.prerequisites.push("a".to_string());
        let scenarios = vec![a, b];
        let waves = plan_execution_order(&scenarios);
        let total: usize = waves.iter().map(|w| w.len()).sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn plan_matrix_all_covered() {
        let m = build_scenario_matrix();
        let waves = plan_execution_order(&m.scenarios);
        let total: usize = waves.iter().map(|w| w.len()).sum();
        assert_eq!(total, m.scenarios.len());
    }

    #[test]
    fn plan_two_independent_chains() {
        let a = make_scenario(
            "a",
            "A",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        let mut b = make_scenario(
            "b",
            "B",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        b.prerequisites.push("a".to_string());
        let c_s = make_scenario(
            "c",
            "C",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        let mut d = make_scenario(
            "d",
            "D",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        d.prerequisites.push("c".to_string());

        let scenarios = vec![a, b, c_s, d];
        let waves = plan_execution_order(&scenarios);
        assert_eq!(waves.len(), 2);
        // Wave 0: a and c (no prereqs)
        assert!(waves[0].contains(&0) && waves[0].contains(&2));
        // Wave 1: b and d (prereqs met)
        assert!(waves[1].contains(&1) && waves[1].contains(&3));
    }

    // ── format_matrix_summary ───────────────────────────────────────────

    #[test]
    fn format_summary_contains_title() {
        let m = build_scenario_matrix();
        let s = format_matrix_summary(&m);
        assert!(s.contains("E2E Scenario Matrix"));
    }

    #[test]
    fn format_summary_contains_total() {
        let m = build_scenario_matrix();
        let s = format_matrix_summary(&m);
        assert!(s.contains(&format!("Total scenarios: {}", m.scenarios.len())));
    }

    #[test]
    fn format_summary_contains_concurrency() {
        let m = build_scenario_matrix();
        let s = format_matrix_summary(&m);
        assert!(s.contains("Concurrency:"));
    }

    #[test]
    fn format_summary_contains_categories() {
        let m = build_scenario_matrix();
        let s = format_matrix_summary(&m);
        assert!(s.contains("smoke"));
        assert!(s.contains("regression"));
        assert!(s.contains("performance"));
        assert!(s.contains("security"));
    }

    #[test]
    fn format_summary_lists_scenario_ids() {
        let m = build_scenario_matrix();
        let s = format_matrix_summary(&m);
        for sc in &m.scenarios {
            assert!(s.contains(&sc.id), "missing scenario id: {}", sc.id);
        }
    }

    #[test]
    fn format_summary_empty_matrix() {
        let m = ScenarioMatrix {
            scenarios: vec![],
            filters: vec![],
            concurrency: 1,
            fail_fast: false,
        };
        let s = format_matrix_summary(&m);
        assert!(s.contains("Total scenarios: 0"));
    }

    // ── format_result_detailed ──────────────────────────────────────────

    fn make_result(passed: bool) -> E2EResult {
        E2EResult {
            scenario_id: "test-scenario".to_string(),
            passed,
            step_results: vec![
                StepResult {
                    step_id: "step1".to_string(),
                    passed: true,
                    exit_code: 0,
                    stdout: "ok".to_string(),
                    stderr: String::new(),
                    duration: Duration::from_millis(100),
                    assertion_results: vec![("check1".to_string(), true)],
                },
                StepResult {
                    step_id: "step2".to_string(),
                    passed: false,
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "err".to_string(),
                    duration: Duration::from_millis(200),
                    assertion_results: vec![("check2".to_string(), false)],
                },
            ],
            duration: Duration::from_millis(300),
            logs: vec![LogEntry {
                timestamp: Utc::now(),
                level: LogLevel::Info,
                source: "runner".to_string(),
                message: "started".to_string(),
                fields: HashMap::new(),
            }],
            artifacts: {
                let mut m = HashMap::new();
                m.insert("output".to_string(), "/tmp/out.json".to_string());
                m
            },
        }
    }

    #[test]
    fn format_result_shows_scenario_id() {
        let r = make_result(true);
        let s = format_result_detailed(&r);
        assert!(s.contains("test-scenario"));
    }

    #[test]
    fn format_result_shows_passed() {
        let s = format_result_detailed(&make_result(true));
        assert!(s.contains("PASSED"));
    }

    #[test]
    fn format_result_shows_failed() {
        let s = format_result_detailed(&make_result(false));
        assert!(s.contains("FAILED"));
    }

    #[test]
    fn format_result_shows_step_status() {
        let s = format_result_detailed(&make_result(false));
        assert!(s.contains("[OK]"));
        assert!(s.contains("[FAIL]"));
    }

    #[test]
    fn format_result_shows_duration() {
        let s = format_result_detailed(&make_result(true));
        assert!(s.contains("Duration:"));
    }

    #[test]
    fn format_result_shows_assertions() {
        let s = format_result_detailed(&make_result(false));
        assert!(s.contains("[+] check1"));
        assert!(s.contains("[-] check2"));
    }

    #[test]
    fn format_result_shows_logs() {
        let s = format_result_detailed(&make_result(true));
        assert!(s.contains("Logs"));
        assert!(s.contains("started"));
    }

    #[test]
    fn format_result_shows_artifacts() {
        let s = format_result_detailed(&make_result(true));
        assert!(s.contains("Artifacts"));
        assert!(s.contains("/tmp/out.json"));
    }

    #[test]
    fn format_result_no_logs() {
        let mut r = make_result(true);
        r.logs.clear();
        let s = format_result_detailed(&r);
        assert!(!s.contains("Logs"));
    }

    #[test]
    fn format_result_no_artifacts() {
        let mut r = make_result(true);
        r.artifacts.clear();
        let s = format_result_detailed(&r);
        assert!(!s.contains("Artifacts"));
    }

    // ── Serde roundtrip tests ───────────────────────────────────────────

    #[test]
    fn serde_roundtrip_scenario_category() {
        for cat in [
            ScenarioCategory::Smoke,
            ScenarioCategory::Regression,
            ScenarioCategory::Performance,
            ScenarioCategory::Security,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let back: ScenarioCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn serde_roundtrip_log_level() {
        for lvl in [
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ] {
            let json = serde_json::to_string(&lvl).unwrap();
            let back: LogLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(lvl, back);
        }
    }

    #[test]
    fn serde_roundtrip_assertion_condition() {
        for cond in [
            AssertionCondition::Equals,
            AssertionCondition::Contains,
            AssertionCondition::Matches,
            AssertionCondition::Range,
            AssertionCondition::NonEmpty,
        ] {
            let json = serde_json::to_string(&cond).unwrap();
            let back: AssertionCondition = serde_json::from_str(&json).unwrap();
            assert_eq!(cond, back);
        }
    }

    #[test]
    fn serde_roundtrip_scenario() {
        let s = make_scenario(
            "s1",
            "Test Scenario",
            ScenarioCategory::Smoke,
            &["tag1"],
            vec![make_step("step1", "first step", "echo hello")],
        );
        let json = serde_json::to_string(&s).unwrap();
        let back: E2EScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(s.id, back.id);
        assert_eq!(s.name, back.name);
        assert_eq!(s.category, back.category);
    }

    #[test]
    fn serde_roundtrip_matrix() {
        let m = build_scenario_matrix();
        let json = serde_json::to_string(&m).unwrap();
        let back: ScenarioMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m.scenarios.len(), back.scenarios.len());
    }

    #[test]
    fn serde_roundtrip_e2e_result() {
        let r = make_result(true);
        let json = serde_json::to_string(&r).unwrap();
        let back: E2EResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r.scenario_id, back.scenario_id);
        assert_eq!(r.passed, back.passed);
    }

    #[test]
    fn serde_roundtrip_step() {
        let mut s = make_step("s1", "desc", "cmd");
        s.env_vars.insert("KEY".to_string(), "VAL".to_string());
        s.capture_vars
            .insert("out".to_string(), "/result".to_string());
        s.retry_count = 3;
        let json = serde_json::to_string(&s).unwrap();
        let back: E2EStep = serde_json::from_str(&json).unwrap();
        assert_eq!(s.id, back.id);
        assert_eq!(s.env_vars, back.env_vars);
        assert_eq!(s.capture_vars, back.capture_vars);
        assert_eq!(s.retry_count, back.retry_count);
    }

    #[test]
    fn serde_roundtrip_assertion() {
        let a = E2EAssertion {
            field_path: "a.b".to_string(),
            condition: AssertionCondition::Range,
            expected: json!("0..100"),
            message: "in range".to_string(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: E2EAssertion = serde_json::from_str(&json).unwrap();
        assert_eq!(a.field_path, back.field_path);
        assert_eq!(a.condition, back.condition);
    }

    #[test]
    fn serde_roundtrip_log_entry() {
        let entry = LogEntry {
            timestamp: Utc::now(),
            level: LogLevel::Warn,
            source: "test".to_string(),
            message: "warning".to_string(),
            fields: {
                let mut m = HashMap::new();
                m.insert("key".to_string(), "val".to_string());
                m
            },
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.level, back.level);
        assert_eq!(entry.source, back.source);
    }

    #[test]
    fn serde_roundtrip_matrix_filter() {
        let f = MatrixFilter {
            categories: vec![ScenarioCategory::Performance],
            tags: vec!["fast".to_string()],
            exclude_tags: vec!["slow".to_string()],
            name_pattern: Some("batch".to_string()),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: MatrixFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(f.categories, back.categories);
        assert_eq!(f.tags, back.tags);
    }

    // ── Display impls ───────────────────────────────────────────────────

    #[test]
    fn display_scenario_category() {
        assert_eq!(format!("{}", ScenarioCategory::Smoke), "smoke");
        assert_eq!(format!("{}", ScenarioCategory::Regression), "regression");
        assert_eq!(format!("{}", ScenarioCategory::Performance), "performance");
        assert_eq!(format!("{}", ScenarioCategory::Security), "security");
    }

    #[test]
    fn display_log_level() {
        assert_eq!(format!("{}", LogLevel::Debug), "DEBUG");
        assert_eq!(format!("{}", LogLevel::Info), "INFO");
        assert_eq!(format!("{}", LogLevel::Warn), "WARN");
        assert_eq!(format!("{}", LogLevel::Error), "ERROR");
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn step_with_env_vars() {
        let mut s = make_step("s1", "desc", "cmd");
        s.env_vars
            .insert("API_KEY".to_string(), "secret".to_string());
        assert_eq!(s.env_vars.get("API_KEY").unwrap(), "secret");
    }

    #[test]
    fn step_with_capture_vars() {
        let mut s = make_step("s1", "desc", "cmd");
        s.capture_vars
            .insert("token".to_string(), "/auth/token".to_string());
        assert_eq!(s.capture_vars.get("token").unwrap(), "/auth/token");
    }

    #[test]
    fn step_default_retry_count() {
        let s = make_step("s1", "desc", "cmd");
        assert_eq!(s.retry_count, 0);
    }

    #[test]
    fn step_default_exit_code() {
        let s = make_step("s1", "desc", "cmd");
        assert_eq!(s.expected_exit_code, 0);
    }

    #[test]
    fn scenario_default_cleanup_empty() {
        let s = make_scenario(
            "t",
            "T",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        assert!(s.cleanup.is_empty());
    }

    #[test]
    fn scenario_default_prerequisites_empty() {
        let s = make_scenario(
            "t",
            "T",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        assert!(s.prerequisites.is_empty());
    }

    #[test]
    fn scenario_default_assertions_empty() {
        let s = make_scenario(
            "t",
            "T",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        assert!(s.assertions.is_empty());
    }

    #[test]
    fn assertion_contains_on_non_string() {
        let val = json!({"n": 42});
        let a = E2EAssertion {
            field_path: "n".to_string(),
            condition: AssertionCondition::Contains,
            expected: json!("42"),
            message: "test".to_string(),
        };
        // Numeric 42 serializes to "42", which contains "42".
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_matches_on_non_string() {
        let val = json!({"n": 42});
        let a = E2EAssertion {
            field_path: "n".to_string(),
            condition: AssertionCondition::Matches,
            expected: json!("*"),
            message: "test".to_string(),
        };
        // Matches requires string value.
        assert!(!check_assertion(&val, &a));
    }

    #[test]
    fn assertion_range_integer_value() {
        let val = json!({"n": 50});
        let a = E2EAssertion {
            field_path: "n".to_string(),
            condition: AssertionCondition::Range,
            expected: json!("0..100"),
            message: "test".to_string(),
        };
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_equals_bool() {
        let val = json!({"ok": true});
        let a = assert_eq_assertion("ok", json!(true));
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_equals_null() {
        let val = json!({"x": null});
        let a = assert_eq_assertion("x", Value::Null);
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_equals_array() {
        let val = json!({"items": [1, 2, 3]});
        let a = assert_eq_assertion("items", json!([1, 2, 3]));
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn assertion_equals_object() {
        let val = json!({"obj": {"k": "v"}});
        let a = assert_eq_assertion("obj", json!({"k": "v"}));
        assert!(check_assertion(&val, &a));
    }

    #[test]
    fn filter_performance_only() {
        let m = build_scenario_matrix();
        let f = MatrixFilter {
            categories: vec![ScenarioCategory::Performance],
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        assert!(result.len() >= 5);
        assert!(
            result
                .iter()
                .all(|s| s.category == ScenarioCategory::Performance)
        );
    }

    #[test]
    fn filter_regression_only() {
        let m = build_scenario_matrix();
        let f = MatrixFilter {
            categories: vec![ScenarioCategory::Regression],
            ..Default::default()
        };
        let result = filter_scenarios(&m, &f);
        assert!(result.len() >= 5);
    }

    #[test]
    fn plan_single_scenario() {
        let scenarios = vec![make_scenario(
            "only",
            "Only",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        )];
        let waves = plan_execution_order(&scenarios);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0], vec![0]);
    }

    #[test]
    fn plan_all_depend_on_first() {
        let a = make_scenario(
            "a",
            "A",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        let mut b = make_scenario(
            "b",
            "B",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        b.prerequisites.push("a".to_string());
        let mut c_s = make_scenario(
            "c",
            "C",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        c_s.prerequisites.push("a".to_string());
        let mut d = make_scenario(
            "d",
            "D",
            ScenarioCategory::Smoke,
            &[],
            vec![make_step("s", "s", "c")],
        );
        d.prerequisites.push("a".to_string());

        let scenarios = vec![a, b, c_s, d];
        let waves = plan_execution_order(&scenarios);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1].len(), 3);
    }

    #[test]
    fn log_entry_fields_accessible() {
        let mut fields = HashMap::new();
        fields.insert("connector".to_string(), "github".to_string());
        let entry = LogEntry {
            timestamp: Utc::now(),
            level: LogLevel::Debug,
            source: "test".to_string(),
            message: "msg".to_string(),
            fields,
        };
        assert_eq!(entry.fields.get("connector").unwrap(), "github");
    }

    #[test]
    fn step_result_assertion_results_empty_when_no_assertions() {
        let sr = StepResult {
            step_id: "s1".to_string(),
            passed: true,
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration: Duration::from_millis(10),
            assertion_results: vec![],
        };
        assert!(sr.assertion_results.is_empty());
    }

    #[test]
    fn result_artifacts_empty_by_default() {
        let r = E2EResult {
            scenario_id: "t".to_string(),
            passed: true,
            step_results: vec![],
            duration: Duration::from_millis(1),
            logs: vec![],
            artifacts: HashMap::new(),
        };
        assert!(r.artifacts.is_empty());
    }
}
