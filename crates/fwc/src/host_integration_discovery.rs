//! Host integration test matrix for discovery, configuration, and lifecycle.
//!
//! Provides a comprehensive matrix of test cases for exercising host-backed
//! discovery queries, configuration mutations, and lifecycle state transitions.
//! Each category builds a set of realistic test cases with expected outcomes,
//! and validators compare actual host output against expectations.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Discovery types ──────────────────────────────────────────────────

/// The kind of discovery query.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryType {
    /// Discover all connectors.
    All,
    /// Discover by specific connector ID.
    ByConnector,
    /// Discover by capability name.
    ByCapability,
    /// Discover by connector archetype.
    ByArchetype,
}

impl std::fmt::Display for DiscoveryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => f.write_str("all"),
            Self::ByConnector => f.write_str("by_connector"),
            Self::ByCapability => f.write_str("by_capability"),
            Self::ByArchetype => f.write_str("by_archetype"),
        }
    }
}

/// A single discovery test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryTestCase {
    /// Human-readable name for the test case.
    pub name: String,
    /// The type of discovery query.
    pub discovery_type: DiscoveryType,
    /// Expected number of results (or minimum count for open queries).
    pub expected_count: usize,
    /// Fields that must be present in each result.
    pub expected_fields: Vec<String>,
    /// Timeout in milliseconds for the discovery call.
    pub timeout_ms: u64,
}

impl DiscoveryTestCase {
    /// Create a new test case.
    pub fn new(
        name: impl Into<String>,
        discovery_type: DiscoveryType,
        expected_count: usize,
        expected_fields: Vec<String>,
        timeout_ms: u64,
    ) -> Self {
        Self {
            name: name.into(),
            discovery_type,
            expected_count,
            expected_fields,
            timeout_ms,
        }
    }
}

// ── Config types ─────────────────────────────────────────────────────

/// Configuration operation type.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigOperation {
    Get,
    Set,
    Reset,
    Import,
    Export,
    Diff,
}

impl std::fmt::Display for ConfigOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => f.write_str("get"),
            Self::Set => f.write_str("set"),
            Self::Reset => f.write_str("reset"),
            Self::Import => f.write_str("import"),
            Self::Export => f.write_str("export"),
            Self::Diff => f.write_str("diff"),
        }
    }
}

/// Expected outcome of a config operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigOutcome {
    /// Operation succeeds.
    Success,
    /// Operation fails with an expected error.
    Error,
    /// Operation returns no change (idempotent set).
    NoChange,
    /// Operation is rejected due to validation.
    ValidationError,
    /// Operation is rejected due to authorization.
    Unauthorized,
}

/// A single configuration test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigTestCase {
    /// Human-readable name.
    pub name: String,
    /// The config operation to perform.
    pub operation: ConfigOperation,
    /// Target connector ID.
    pub connector_id: String,
    /// Configuration key (for get/set/reset).
    pub key: String,
    /// Value to set (for set/import).
    pub value: Option<Value>,
    /// Expected outcome.
    pub expected_outcome: ConfigOutcome,
}

impl ConfigTestCase {
    /// Create a new config test case.
    pub fn new(
        name: impl Into<String>,
        operation: ConfigOperation,
        connector_id: impl Into<String>,
        key: impl Into<String>,
        value: Option<Value>,
        expected_outcome: ConfigOutcome,
    ) -> Self {
        Self {
            name: name.into(),
            operation,
            connector_id: connector_id.into(),
            key: key.into(),
            value,
            expected_outcome,
        }
    }

    /// Whether this test case mutates state.
    pub fn is_mutating(&self) -> bool {
        matches!(
            self.operation,
            ConfigOperation::Set | ConfigOperation::Reset | ConfigOperation::Import
        )
    }
}

// ── Lifecycle types ──────────────────────────────────────────────────

/// Lifecycle action to perform.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Enable,
    Disable,
    Start,
    Stop,
    Restart,
}

impl std::fmt::Display for LifecycleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enable => f.write_str("enable"),
            Self::Disable => f.write_str("disable"),
            Self::Start => f.write_str("start"),
            Self::Stop => f.write_str("stop"),
            Self::Restart => f.write_str("restart"),
        }
    }
}

/// Expected state after a lifecycle action.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedState {
    Enabled,
    Disabled,
    Running,
    Stopped,
    Starting,
    Stopping,
    Failed,
    Unknown,
}

impl std::fmt::Display for ExpectedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enabled => f.write_str("enabled"),
            Self::Disabled => f.write_str("disabled"),
            Self::Running => f.write_str("running"),
            Self::Stopped => f.write_str("stopped"),
            Self::Starting => f.write_str("starting"),
            Self::Stopping => f.write_str("stopping"),
            Self::Failed => f.write_str("failed"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

/// A single lifecycle test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LifecycleTestCase {
    /// Human-readable name.
    pub name: String,
    /// Target connector ID.
    pub connector_id: String,
    /// Lifecycle action to perform.
    pub action: LifecycleAction,
    /// Required precondition state (if any).
    pub precondition: Option<ExpectedState>,
    /// Expected state after the action.
    pub expected_state: ExpectedState,
    /// Expected exit code from the operation.
    pub expected_exit_code: i32,
}

impl LifecycleTestCase {
    /// Create a new lifecycle test case.
    pub fn new(
        name: impl Into<String>,
        connector_id: impl Into<String>,
        action: LifecycleAction,
        precondition: Option<ExpectedState>,
        expected_state: ExpectedState,
        expected_exit_code: i32,
    ) -> Self {
        Self {
            name: name.into(),
            connector_id: connector_id.into(),
            action,
            precondition,
            expected_state,
            expected_exit_code,
        }
    }

    /// Whether this test case is expected to succeed.
    pub fn expects_success(&self) -> bool {
        self.expected_exit_code == 0
    }

    /// Whether this action is destructive.
    pub fn is_destructive(&self) -> bool {
        matches!(
            self.action,
            LifecycleAction::Disable | LifecycleAction::Stop
        )
    }
}

// ── Integration matrix ───────────────────────────────────────────────

/// Full integration test matrix combining all three categories.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntegrationMatrix {
    /// Discovery test cases.
    pub discovery_cases: Vec<DiscoveryTestCase>,
    /// Configuration test cases.
    pub config_cases: Vec<ConfigTestCase>,
    /// Lifecycle test cases.
    pub lifecycle_cases: Vec<LifecycleTestCase>,
}

impl IntegrationMatrix {
    /// Build the complete integration matrix from the three category builders.
    pub fn build() -> Self {
        Self {
            discovery_cases: build_discovery_matrix(),
            config_cases: build_config_matrix(),
            lifecycle_cases: build_lifecycle_matrix(),
        }
    }

    /// Total number of test cases across all categories.
    pub fn total_cases(&self) -> usize {
        self.discovery_cases.len() + self.config_cases.len() + self.lifecycle_cases.len()
    }

    /// Count of discovery test cases.
    pub fn discovery_count(&self) -> usize {
        self.discovery_cases.len()
    }

    /// Count of config test cases.
    pub fn config_count(&self) -> usize {
        self.config_cases.len()
    }

    /// Count of lifecycle test cases.
    pub fn lifecycle_count(&self) -> usize {
        self.lifecycle_cases.len()
    }
}

/// Result of running the integration matrix.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixResult {
    /// Total test cases executed.
    pub total: usize,
    /// Number that passed.
    pub passed: usize,
    /// Number that failed.
    pub failed: usize,
    /// Number that were skipped.
    pub skipped: usize,
    /// Breakdown by category.
    pub by_category: std::collections::HashMap<String, CategoryResult>,
}

/// Result for a single category.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CategoryResult {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl CategoryResult {
    /// Create a new category result.
    pub fn new(total: usize, passed: usize, failed: usize, skipped: usize) -> Self {
        Self {
            total,
            passed,
            failed,
            skipped,
        }
    }

    /// Pass rate as a fraction (0.0–1.0).
    pub fn pass_rate(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.passed as f64 / self.total as f64
        }
    }
}

impl MatrixResult {
    /// Create a new result from category results.
    pub fn new(by_category: std::collections::HashMap<String, CategoryResult>) -> Self {
        let total = by_category.values().map(|c| c.total).sum();
        let passed = by_category.values().map(|c| c.passed).sum();
        let failed = by_category.values().map(|c| c.failed).sum();
        let skipped = by_category.values().map(|c| c.skipped).sum();
        Self {
            total,
            passed,
            failed,
            skipped,
            by_category,
        }
    }

    /// Overall pass rate as a fraction (0.0–1.0).
    pub fn pass_rate(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.passed as f64 / self.total as f64
        }
    }

    /// Whether all tests passed.
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.skipped == 0
    }
}

// ── Matrix builders ──────────────────────────────────────────────────

/// Build the discovery test matrix (at least 15 cases).
pub fn build_discovery_matrix() -> Vec<DiscoveryTestCase> {
    vec![
        DiscoveryTestCase::new(
            "discover_all_connectors",
            DiscoveryType::All,
            1,
            vec!["id".into(), "name".into(), "version".into()],
            5000,
        ),
        DiscoveryTestCase::new(
            "discover_all_with_capabilities",
            DiscoveryType::All,
            1,
            vec!["id".into(), "capabilities".into()],
            5000,
        ),
        DiscoveryTestCase::new(
            "discover_by_connector_github",
            DiscoveryType::ByConnector,
            1,
            vec!["id".into(), "operations".into()],
            3000,
        ),
        DiscoveryTestCase::new(
            "discover_by_connector_slack",
            DiscoveryType::ByConnector,
            1,
            vec!["id".into(), "name".into(), "operations".into()],
            3000,
        ),
        DiscoveryTestCase::new(
            "discover_by_connector_nonexistent",
            DiscoveryType::ByConnector,
            0,
            vec![],
            2000,
        ),
        DiscoveryTestCase::new(
            "discover_by_capability_read",
            DiscoveryType::ByCapability,
            1,
            vec!["id".into(), "capabilities".into()],
            3000,
        ),
        DiscoveryTestCase::new(
            "discover_by_capability_write",
            DiscoveryType::ByCapability,
            1,
            vec!["id".into(), "capabilities".into()],
            3000,
        ),
        DiscoveryTestCase::new(
            "discover_by_capability_admin",
            DiscoveryType::ByCapability,
            0,
            vec![],
            3000,
        ),
        DiscoveryTestCase::new(
            "discover_by_archetype_saas",
            DiscoveryType::ByArchetype,
            1,
            vec!["id".into(), "archetype".into()],
            3000,
        ),
        DiscoveryTestCase::new(
            "discover_by_archetype_database",
            DiscoveryType::ByArchetype,
            0,
            vec!["id".into(), "archetype".into()],
            3000,
        ),
        DiscoveryTestCase::new(
            "discover_by_archetype_messaging",
            DiscoveryType::ByArchetype,
            1,
            vec!["id".into(), "archetype".into()],
            3000,
        ),
        DiscoveryTestCase::new(
            "discover_all_includes_status",
            DiscoveryType::All,
            1,
            vec!["id".into(), "status".into()],
            5000,
        ),
        DiscoveryTestCase::new(
            "discover_all_includes_zone",
            DiscoveryType::All,
            1,
            vec!["id".into(), "zone".into()],
            5000,
        ),
        DiscoveryTestCase::new(
            "discover_by_connector_with_schema",
            DiscoveryType::ByConnector,
            1,
            vec!["id".into(), "input_schema".into()],
            4000,
        ),
        DiscoveryTestCase::new(
            "discover_by_capability_execute",
            DiscoveryType::ByCapability,
            1,
            vec!["id".into(), "capabilities".into()],
            3000,
        ),
        DiscoveryTestCase::new(
            "discover_all_timeout_boundary",
            DiscoveryType::All,
            0,
            vec![],
            100,
        ),
        DiscoveryTestCase::new(
            "discover_by_archetype_iot",
            DiscoveryType::ByArchetype,
            0,
            vec![],
            3000,
        ),
    ]
}

/// Build the config test matrix (at least 15 cases).
pub fn build_config_matrix() -> Vec<ConfigTestCase> {
    vec![
        ConfigTestCase::new(
            "get_existing_config_key",
            ConfigOperation::Get,
            "github",
            "api_base_url",
            None,
            ConfigOutcome::Success,
        ),
        ConfigTestCase::new(
            "get_nonexistent_config_key",
            ConfigOperation::Get,
            "github",
            "nonexistent_key",
            None,
            ConfigOutcome::Error,
        ),
        ConfigTestCase::new(
            "set_valid_string_config",
            ConfigOperation::Set,
            "slack",
            "default_channel",
            Some(serde_json::json!("#general")),
            ConfigOutcome::Success,
        ),
        ConfigTestCase::new(
            "set_valid_numeric_config",
            ConfigOperation::Set,
            "slack",
            "timeout_ms",
            Some(serde_json::json!(5000)),
            ConfigOutcome::Success,
        ),
        ConfigTestCase::new(
            "set_invalid_type_config",
            ConfigOperation::Set,
            "slack",
            "timeout_ms",
            Some(serde_json::json!("not_a_number")),
            ConfigOutcome::ValidationError,
        ),
        ConfigTestCase::new(
            "reset_existing_key_to_default",
            ConfigOperation::Reset,
            "github",
            "api_base_url",
            None,
            ConfigOutcome::Success,
        ),
        ConfigTestCase::new(
            "reset_nonexistent_key",
            ConfigOperation::Reset,
            "github",
            "nonexistent_key",
            None,
            ConfigOutcome::Error,
        ),
        ConfigTestCase::new(
            "export_connector_config",
            ConfigOperation::Export,
            "jira",
            "*",
            None,
            ConfigOutcome::Success,
        ),
        ConfigTestCase::new(
            "import_valid_config_bundle",
            ConfigOperation::Import,
            "jira",
            "*",
            Some(serde_json::json!({"api_url": "https://test.atlassian.net", "project": "TEST"})),
            ConfigOutcome::Success,
        ),
        ConfigTestCase::new(
            "import_invalid_config_bundle",
            ConfigOperation::Import,
            "jira",
            "*",
            Some(serde_json::json!({"unknown_field": true})),
            ConfigOutcome::ValidationError,
        ),
        ConfigTestCase::new(
            "diff_config_no_changes",
            ConfigOperation::Diff,
            "slack",
            "*",
            None,
            ConfigOutcome::NoChange,
        ),
        ConfigTestCase::new(
            "diff_config_with_changes",
            ConfigOperation::Diff,
            "slack",
            "default_channel",
            Some(serde_json::json!("#random")),
            ConfigOutcome::Success,
        ),
        ConfigTestCase::new(
            "set_config_nonexistent_connector",
            ConfigOperation::Set,
            "nonexistent_connector",
            "key",
            Some(serde_json::json!("value")),
            ConfigOutcome::Error,
        ),
        ConfigTestCase::new(
            "get_config_nonexistent_connector",
            ConfigOperation::Get,
            "nonexistent_connector",
            "key",
            None,
            ConfigOutcome::Error,
        ),
        ConfigTestCase::new(
            "set_config_idempotent_same_value",
            ConfigOperation::Set,
            "github",
            "api_base_url",
            Some(serde_json::json!("https://api.github.com")),
            ConfigOutcome::NoChange,
        ),
        ConfigTestCase::new(
            "export_all_connectors",
            ConfigOperation::Export,
            "*",
            "*",
            None,
            ConfigOutcome::Success,
        ),
        ConfigTestCase::new(
            "set_config_empty_value",
            ConfigOperation::Set,
            "slack",
            "default_channel",
            Some(serde_json::json!("")),
            ConfigOutcome::ValidationError,
        ),
    ]
}

/// Build the lifecycle test matrix (at least 15 cases).
pub fn build_lifecycle_matrix() -> Vec<LifecycleTestCase> {
    vec![
        LifecycleTestCase::new(
            "enable_disabled_connector",
            "github",
            LifecycleAction::Enable,
            Some(ExpectedState::Disabled),
            ExpectedState::Enabled,
            0,
        ),
        LifecycleTestCase::new(
            "start_enabled_connector",
            "github",
            LifecycleAction::Start,
            Some(ExpectedState::Enabled),
            ExpectedState::Running,
            0,
        ),
        LifecycleTestCase::new(
            "stop_running_connector",
            "slack",
            LifecycleAction::Stop,
            Some(ExpectedState::Running),
            ExpectedState::Stopped,
            0,
        ),
        LifecycleTestCase::new(
            "disable_stopped_connector",
            "slack",
            LifecycleAction::Disable,
            Some(ExpectedState::Stopped),
            ExpectedState::Disabled,
            0,
        ),
        LifecycleTestCase::new(
            "restart_running_connector",
            "jira",
            LifecycleAction::Restart,
            Some(ExpectedState::Running),
            ExpectedState::Running,
            0,
        ),
        LifecycleTestCase::new(
            "restart_stopped_connector",
            "jira",
            LifecycleAction::Restart,
            Some(ExpectedState::Stopped),
            ExpectedState::Running,
            0,
        ),
        LifecycleTestCase::new(
            "enable_already_enabled_connector",
            "github",
            LifecycleAction::Enable,
            Some(ExpectedState::Enabled),
            ExpectedState::Enabled,
            0,
        ),
        LifecycleTestCase::new(
            "stop_already_stopped_connector",
            "slack",
            LifecycleAction::Stop,
            Some(ExpectedState::Stopped),
            ExpectedState::Stopped,
            1,
        ),
        LifecycleTestCase::new(
            "start_running_connector_noop",
            "github",
            LifecycleAction::Start,
            Some(ExpectedState::Running),
            ExpectedState::Running,
            0,
        ),
        LifecycleTestCase::new(
            "disable_running_connector",
            "github",
            LifecycleAction::Disable,
            Some(ExpectedState::Running),
            ExpectedState::Disabled,
            0,
        ),
        LifecycleTestCase::new(
            "enable_nonexistent_connector",
            "nonexistent_connector",
            LifecycleAction::Enable,
            None,
            ExpectedState::Unknown,
            1,
        ),
        LifecycleTestCase::new(
            "stop_nonexistent_connector",
            "nonexistent_connector",
            LifecycleAction::Stop,
            None,
            ExpectedState::Unknown,
            1,
        ),
        LifecycleTestCase::new(
            "restart_failed_connector",
            "broken",
            LifecycleAction::Restart,
            Some(ExpectedState::Failed),
            ExpectedState::Running,
            0,
        ),
        LifecycleTestCase::new(
            "start_disabled_connector_error",
            "github",
            LifecycleAction::Start,
            Some(ExpectedState::Disabled),
            ExpectedState::Disabled,
            1,
        ),
        LifecycleTestCase::new(
            "enable_start_sequence",
            "telegram",
            LifecycleAction::Enable,
            Some(ExpectedState::Disabled),
            ExpectedState::Enabled,
            0,
        ),
        LifecycleTestCase::new(
            "restart_freshly_enabled",
            "telegram",
            LifecycleAction::Restart,
            Some(ExpectedState::Enabled),
            ExpectedState::Running,
            0,
        ),
        LifecycleTestCase::new(
            "disable_disable_idempotent",
            "slack",
            LifecycleAction::Disable,
            Some(ExpectedState::Disabled),
            ExpectedState::Disabled,
            0,
        ),
    ]
}

// ── Validators ───────────────────────────────────────────────────────

/// Validate a discovery result against a test case.
pub fn validate_discovery_result(case: &DiscoveryTestCase, output: &Value) -> bool {
    let results = match output.as_array() {
        Some(arr) => arr,
        None => return case.expected_count == 0,
    };

    // Check expected count (minimum).
    if results.len() < case.expected_count {
        return false;
    }

    // Check that each result has the expected fields.
    for result in results {
        for field in &case.expected_fields {
            if result.get(field.as_str()).is_none() {
                return false;
            }
        }
    }

    true
}

/// Validate a config result against a test case.
pub fn validate_config_result(case: &ConfigTestCase, output: &Value) -> bool {
    let status = output
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");

    match case.expected_outcome {
        ConfigOutcome::Success => status == "success" || status == "ok",
        ConfigOutcome::Error => status == "error",
        ConfigOutcome::NoChange => status == "no_change" || status == "unchanged",
        ConfigOutcome::ValidationError => status == "validation_error",
        ConfigOutcome::Unauthorized => status == "unauthorized",
    }
}

/// Validate a lifecycle result against a test case.
pub fn validate_lifecycle_result(case: &LifecycleTestCase, output: &Value) -> bool {
    let state = output
        .get("state")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");

    let exit_code = output
        .get("exit_code")
        .and_then(|c| c.as_i64())
        .unwrap_or(-1) as i32;

    state == case.expected_state.to_string() && exit_code == case.expected_exit_code
}

// ── Formatting ───────────────────────────────────────────────────────

/// Format the integration matrix as a human-readable table.
pub fn format_matrix_toon(matrix: &IntegrationMatrix) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== Host Integration Test Matrix ===");
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "--- Discovery ({} cases) ---",
        matrix.discovery_cases.len()
    );
    for (i, case) in matrix.discovery_cases.iter().enumerate() {
        let _ = writeln!(
            out,
            "  [{:>2}] {:<45} type={:<15} expected_count={} timeout={}ms",
            i + 1,
            case.name,
            case.discovery_type.to_string(),
            case.expected_count,
            case.timeout_ms,
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "--- Config ({} cases) ---", matrix.config_cases.len());
    for (i, case) in matrix.config_cases.iter().enumerate() {
        let _ = writeln!(
            out,
            "  [{:>2}] {:<45} op={:<8} connector={:<20} key={}",
            i + 1,
            case.name,
            case.operation.to_string(),
            case.connector_id,
            case.key,
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "--- Lifecycle ({} cases) ---",
        matrix.lifecycle_cases.len()
    );
    for (i, case) in matrix.lifecycle_cases.iter().enumerate() {
        let _ = writeln!(
            out,
            "  [{:>2}] {:<45} action={:<10} connector={:<20} exit={}",
            i + 1,
            case.name,
            case.action.to_string(),
            case.connector_id,
            case.expected_exit_code,
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "Total: {} cases", matrix.total_cases());
    out
}

/// Format a matrix result as a human-readable summary.
pub fn format_matrix_result_toon(result: &MatrixResult) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== Matrix Result ===");
    let _ = writeln!(
        out,
        "Total: {} | Passed: {} | Failed: {} | Skipped: {} | Rate: {:.1}%",
        result.total,
        result.passed,
        result.failed,
        result.skipped,
        result.pass_rate() * 100.0,
    );
    let _ = writeln!(out);

    let mut categories: Vec<_> = result.by_category.iter().collect();
    categories.sort_by_key(|(k, _)| (*k).clone());

    for (name, cat) in &categories {
        let _ = writeln!(
            out,
            "  {:<15} total={:<4} passed={:<4} failed={:<4} skipped={:<4} rate={:.1}%",
            name,
            cat.total,
            cat.passed,
            cat.failed,
            cat.skipped,
            cat.pass_rate() * 100.0,
        );
    }

    out
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── DiscoveryType ─────────────────────────────────────────────

    #[test]
    fn discovery_type_display_all() {
        assert_eq!(DiscoveryType::All.to_string(), "all");
    }

    #[test]
    fn discovery_type_display_by_connector() {
        assert_eq!(DiscoveryType::ByConnector.to_string(), "by_connector");
    }

    #[test]
    fn discovery_type_display_by_capability() {
        assert_eq!(DiscoveryType::ByCapability.to_string(), "by_capability");
    }

    #[test]
    fn discovery_type_display_by_archetype() {
        assert_eq!(DiscoveryType::ByArchetype.to_string(), "by_archetype");
    }

    #[test]
    fn discovery_type_serde_roundtrip() {
        let dt = DiscoveryType::ByCapability;
        let json = serde_json::to_string(&dt).unwrap();
        let back: DiscoveryType = serde_json::from_str(&json).unwrap();
        assert_eq!(dt, back);
    }

    #[test]
    fn discovery_type_clone() {
        let dt = DiscoveryType::All;
        let cloned = dt.clone();
        assert_eq!(dt, cloned);
    }

    // ── DiscoveryTestCase ────────────────────────────────────────

    #[test]
    fn discovery_test_case_new() {
        let tc = DiscoveryTestCase::new("test", DiscoveryType::All, 5, vec!["id".into()], 3000);
        assert_eq!(tc.name, "test");
        assert_eq!(tc.expected_count, 5);
        assert_eq!(tc.timeout_ms, 3000);
    }

    #[test]
    fn discovery_test_case_serde_roundtrip() {
        let tc = DiscoveryTestCase::new(
            "round",
            DiscoveryType::ByConnector,
            1,
            vec!["id".into(), "name".into()],
            2000,
        );
        let json = serde_json::to_string(&tc).unwrap();
        let back: DiscoveryTestCase = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "round");
        assert_eq!(back.expected_count, 1);
    }

    #[test]
    fn discovery_test_case_empty_fields() {
        let tc = DiscoveryTestCase::new("empty", DiscoveryType::All, 0, vec![], 1000);
        assert!(tc.expected_fields.is_empty());
    }

    #[test]
    fn discovery_test_case_clone() {
        let tc = DiscoveryTestCase::new(
            "clone_me",
            DiscoveryType::ByArchetype,
            2,
            vec!["x".into()],
            500,
        );
        let cloned = tc.clone();
        assert_eq!(cloned.name, "clone_me");
    }

    // ── ConfigOperation ──────────────────────────────────────────

    #[test]
    fn config_operation_display_get() {
        assert_eq!(ConfigOperation::Get.to_string(), "get");
    }

    #[test]
    fn config_operation_display_set() {
        assert_eq!(ConfigOperation::Set.to_string(), "set");
    }

    #[test]
    fn config_operation_display_reset() {
        assert_eq!(ConfigOperation::Reset.to_string(), "reset");
    }

    #[test]
    fn config_operation_display_import() {
        assert_eq!(ConfigOperation::Import.to_string(), "import");
    }

    #[test]
    fn config_operation_display_export() {
        assert_eq!(ConfigOperation::Export.to_string(), "export");
    }

    #[test]
    fn config_operation_display_diff() {
        assert_eq!(ConfigOperation::Diff.to_string(), "diff");
    }

    #[test]
    fn config_operation_serde_roundtrip() {
        let op = ConfigOperation::Import;
        let json = serde_json::to_string(&op).unwrap();
        let back: ConfigOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(op, back);
    }

    // ── ConfigOutcome ────────────────────────────────────────────

    #[test]
    fn config_outcome_serde_roundtrip_success() {
        let o = ConfigOutcome::Success;
        let json = serde_json::to_string(&o).unwrap();
        let back: ConfigOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn config_outcome_serde_roundtrip_error() {
        let o = ConfigOutcome::Error;
        let json = serde_json::to_string(&o).unwrap();
        let back: ConfigOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn config_outcome_serde_roundtrip_no_change() {
        let o = ConfigOutcome::NoChange;
        let json = serde_json::to_string(&o).unwrap();
        let back: ConfigOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn config_outcome_serde_roundtrip_validation() {
        let o = ConfigOutcome::ValidationError;
        let json = serde_json::to_string(&o).unwrap();
        let back: ConfigOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn config_outcome_serde_roundtrip_unauthorized() {
        let o = ConfigOutcome::Unauthorized;
        let json = serde_json::to_string(&o).unwrap();
        let back: ConfigOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    // ── ConfigTestCase ───────────────────────────────────────────

    #[test]
    fn config_test_case_new_with_value() {
        let tc = ConfigTestCase::new(
            "test_set",
            ConfigOperation::Set,
            "github",
            "url",
            Some(json!("https://api.github.com")),
            ConfigOutcome::Success,
        );
        assert_eq!(tc.name, "test_set");
        assert!(tc.value.is_some());
    }

    #[test]
    fn config_test_case_new_without_value() {
        let tc = ConfigTestCase::new(
            "test_get",
            ConfigOperation::Get,
            "slack",
            "channel",
            None,
            ConfigOutcome::Success,
        );
        assert!(tc.value.is_none());
    }

    #[test]
    fn config_test_case_is_mutating_set() {
        let tc = ConfigTestCase::new(
            "m",
            ConfigOperation::Set,
            "c",
            "k",
            None,
            ConfigOutcome::Success,
        );
        assert!(tc.is_mutating());
    }

    #[test]
    fn config_test_case_is_mutating_reset() {
        let tc = ConfigTestCase::new(
            "m",
            ConfigOperation::Reset,
            "c",
            "k",
            None,
            ConfigOutcome::Success,
        );
        assert!(tc.is_mutating());
    }

    #[test]
    fn config_test_case_is_mutating_import() {
        let tc = ConfigTestCase::new(
            "m",
            ConfigOperation::Import,
            "c",
            "k",
            None,
            ConfigOutcome::Success,
        );
        assert!(tc.is_mutating());
    }

    #[test]
    fn config_test_case_not_mutating_get() {
        let tc = ConfigTestCase::new(
            "m",
            ConfigOperation::Get,
            "c",
            "k",
            None,
            ConfigOutcome::Success,
        );
        assert!(!tc.is_mutating());
    }

    #[test]
    fn config_test_case_not_mutating_export() {
        let tc = ConfigTestCase::new(
            "m",
            ConfigOperation::Export,
            "c",
            "k",
            None,
            ConfigOutcome::Success,
        );
        assert!(!tc.is_mutating());
    }

    #[test]
    fn config_test_case_not_mutating_diff() {
        let tc = ConfigTestCase::new(
            "m",
            ConfigOperation::Diff,
            "c",
            "k",
            None,
            ConfigOutcome::Success,
        );
        assert!(!tc.is_mutating());
    }

    #[test]
    fn config_test_case_serde_roundtrip() {
        let tc = ConfigTestCase::new(
            "round",
            ConfigOperation::Set,
            "gh",
            "url",
            Some(json!(42)),
            ConfigOutcome::Success,
        );
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: ConfigTestCase = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "round");
        assert_eq!(back.connector_id, "gh");
    }

    #[test]
    fn config_test_case_clone() {
        let tc = ConfigTestCase::new(
            "cl",
            ConfigOperation::Get,
            "c",
            "k",
            None,
            ConfigOutcome::Error,
        );
        let cloned = tc.clone();
        assert_eq!(cloned.name, "cl");
    }

    // ── LifecycleAction ──────────────────────────────────────────

    #[test]
    fn lifecycle_action_display_enable() {
        assert_eq!(LifecycleAction::Enable.to_string(), "enable");
    }

    #[test]
    fn lifecycle_action_display_disable() {
        assert_eq!(LifecycleAction::Disable.to_string(), "disable");
    }

    #[test]
    fn lifecycle_action_display_start() {
        assert_eq!(LifecycleAction::Start.to_string(), "start");
    }

    #[test]
    fn lifecycle_action_display_stop() {
        assert_eq!(LifecycleAction::Stop.to_string(), "stop");
    }

    #[test]
    fn lifecycle_action_display_restart() {
        assert_eq!(LifecycleAction::Restart.to_string(), "restart");
    }

    #[test]
    fn lifecycle_action_serde_roundtrip() {
        let a = LifecycleAction::Restart;
        let json = serde_json::to_string(&a).unwrap();
        let back: LifecycleAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // ── ExpectedState ────────────────────────────────────────────

    #[test]
    fn expected_state_display_enabled() {
        assert_eq!(ExpectedState::Enabled.to_string(), "enabled");
    }

    #[test]
    fn expected_state_display_disabled() {
        assert_eq!(ExpectedState::Disabled.to_string(), "disabled");
    }

    #[test]
    fn expected_state_display_running() {
        assert_eq!(ExpectedState::Running.to_string(), "running");
    }

    #[test]
    fn expected_state_display_stopped() {
        assert_eq!(ExpectedState::Stopped.to_string(), "stopped");
    }

    #[test]
    fn expected_state_display_starting() {
        assert_eq!(ExpectedState::Starting.to_string(), "starting");
    }

    #[test]
    fn expected_state_display_stopping() {
        assert_eq!(ExpectedState::Stopping.to_string(), "stopping");
    }

    #[test]
    fn expected_state_display_failed() {
        assert_eq!(ExpectedState::Failed.to_string(), "failed");
    }

    #[test]
    fn expected_state_display_unknown() {
        assert_eq!(ExpectedState::Unknown.to_string(), "unknown");
    }

    #[test]
    fn expected_state_serde_roundtrip() {
        let s = ExpectedState::Running;
        let json = serde_json::to_string(&s).unwrap();
        let back: ExpectedState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // ── LifecycleTestCase ────────────────────────────────────────

    #[test]
    fn lifecycle_test_case_new() {
        let tc = LifecycleTestCase::new(
            "test",
            "github",
            LifecycleAction::Start,
            Some(ExpectedState::Enabled),
            ExpectedState::Running,
            0,
        );
        assert_eq!(tc.name, "test");
        assert_eq!(tc.connector_id, "github");
    }

    #[test]
    fn lifecycle_test_case_expects_success() {
        let tc = LifecycleTestCase::new(
            "ok",
            "c",
            LifecycleAction::Start,
            None,
            ExpectedState::Running,
            0,
        );
        assert!(tc.expects_success());
    }

    #[test]
    fn lifecycle_test_case_expects_failure() {
        let tc = LifecycleTestCase::new(
            "fail",
            "c",
            LifecycleAction::Start,
            None,
            ExpectedState::Unknown,
            1,
        );
        assert!(!tc.expects_success());
    }

    #[test]
    fn lifecycle_test_case_is_destructive_disable() {
        let tc = LifecycleTestCase::new(
            "d",
            "c",
            LifecycleAction::Disable,
            None,
            ExpectedState::Disabled,
            0,
        );
        assert!(tc.is_destructive());
    }

    #[test]
    fn lifecycle_test_case_is_destructive_stop() {
        let tc = LifecycleTestCase::new(
            "d",
            "c",
            LifecycleAction::Stop,
            None,
            ExpectedState::Stopped,
            0,
        );
        assert!(tc.is_destructive());
    }

    #[test]
    fn lifecycle_test_case_not_destructive_enable() {
        let tc = LifecycleTestCase::new(
            "d",
            "c",
            LifecycleAction::Enable,
            None,
            ExpectedState::Enabled,
            0,
        );
        assert!(!tc.is_destructive());
    }

    #[test]
    fn lifecycle_test_case_not_destructive_start() {
        let tc = LifecycleTestCase::new(
            "d",
            "c",
            LifecycleAction::Start,
            None,
            ExpectedState::Running,
            0,
        );
        assert!(!tc.is_destructive());
    }

    #[test]
    fn lifecycle_test_case_not_destructive_restart() {
        let tc = LifecycleTestCase::new(
            "d",
            "c",
            LifecycleAction::Restart,
            None,
            ExpectedState::Running,
            0,
        );
        assert!(!tc.is_destructive());
    }

    #[test]
    fn lifecycle_test_case_serde_roundtrip() {
        let tc = LifecycleTestCase::new(
            "r",
            "gh",
            LifecycleAction::Enable,
            None,
            ExpectedState::Enabled,
            0,
        );
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: LifecycleTestCase = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "r");
        assert_eq!(back.connector_id, "gh");
    }

    #[test]
    fn lifecycle_test_case_clone() {
        let tc = LifecycleTestCase::new(
            "cl",
            "c",
            LifecycleAction::Stop,
            None,
            ExpectedState::Stopped,
            0,
        );
        let cloned = tc.clone();
        assert_eq!(cloned.name, "cl");
    }

    #[test]
    fn lifecycle_test_case_with_precondition() {
        let tc = LifecycleTestCase::new(
            "pre",
            "c",
            LifecycleAction::Start,
            Some(ExpectedState::Enabled),
            ExpectedState::Running,
            0,
        );
        assert_eq!(tc.precondition, Some(ExpectedState::Enabled));
    }

    #[test]
    fn lifecycle_test_case_without_precondition() {
        let tc = LifecycleTestCase::new(
            "nopre",
            "c",
            LifecycleAction::Enable,
            None,
            ExpectedState::Enabled,
            0,
        );
        assert!(tc.precondition.is_none());
    }

    // ── IntegrationMatrix ────────────────────────────────────────

    #[test]
    fn integration_matrix_build() {
        let matrix = IntegrationMatrix::build();
        assert!(matrix.discovery_cases.len() >= 15);
        assert!(matrix.config_cases.len() >= 15);
        assert!(matrix.lifecycle_cases.len() >= 15);
    }

    #[test]
    fn integration_matrix_total_cases() {
        let matrix = IntegrationMatrix::build();
        assert_eq!(
            matrix.total_cases(),
            matrix.discovery_cases.len() + matrix.config_cases.len() + matrix.lifecycle_cases.len()
        );
    }

    #[test]
    fn integration_matrix_discovery_count() {
        let matrix = IntegrationMatrix::build();
        assert_eq!(matrix.discovery_count(), matrix.discovery_cases.len());
    }

    #[test]
    fn integration_matrix_config_count() {
        let matrix = IntegrationMatrix::build();
        assert_eq!(matrix.config_count(), matrix.config_cases.len());
    }

    #[test]
    fn integration_matrix_lifecycle_count() {
        let matrix = IntegrationMatrix::build();
        assert_eq!(matrix.lifecycle_count(), matrix.lifecycle_cases.len());
    }

    #[test]
    fn integration_matrix_serde_roundtrip() {
        let matrix = IntegrationMatrix::build();
        let json_str = serde_json::to_string(&matrix).unwrap();
        let back: IntegrationMatrix = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.total_cases(), matrix.total_cases());
    }

    #[test]
    fn integration_matrix_clone() {
        let matrix = IntegrationMatrix::build();
        let cloned = matrix.clone();
        assert_eq!(cloned.total_cases(), matrix.total_cases());
    }

    // ── CategoryResult ───────────────────────────────────────────

    #[test]
    fn category_result_pass_rate_all_pass() {
        let cr = CategoryResult::new(10, 10, 0, 0);
        assert!((cr.pass_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn category_result_pass_rate_all_fail() {
        let cr = CategoryResult::new(10, 0, 10, 0);
        assert!((cr.pass_rate()).abs() < f64::EPSILON);
    }

    #[test]
    fn category_result_pass_rate_half() {
        let cr = CategoryResult::new(10, 5, 5, 0);
        assert!((cr.pass_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn category_result_pass_rate_empty() {
        let cr = CategoryResult::new(0, 0, 0, 0);
        assert!((cr.pass_rate() - 1.0).abs() < f64::EPSILON);
    }

    // ── MatrixResult ─────────────────────────────────────────────

    #[test]
    fn matrix_result_new_sums_categories() {
        let mut cats = std::collections::HashMap::new();
        cats.insert("discovery".into(), CategoryResult::new(10, 8, 2, 0));
        cats.insert("config".into(), CategoryResult::new(15, 14, 1, 0));
        let result = MatrixResult::new(cats);
        assert_eq!(result.total, 25);
        assert_eq!(result.passed, 22);
        assert_eq!(result.failed, 3);
    }

    #[test]
    fn matrix_result_pass_rate() {
        let mut cats = std::collections::HashMap::new();
        cats.insert("a".into(), CategoryResult::new(10, 10, 0, 0));
        let result = MatrixResult::new(cats);
        assert!((result.pass_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn matrix_result_all_passed_true() {
        let mut cats = std::collections::HashMap::new();
        cats.insert("a".into(), CategoryResult::new(5, 5, 0, 0));
        let result = MatrixResult::new(cats);
        assert!(result.all_passed());
    }

    #[test]
    fn matrix_result_all_passed_false_failure() {
        let mut cats = std::collections::HashMap::new();
        cats.insert("a".into(), CategoryResult::new(5, 4, 1, 0));
        let result = MatrixResult::new(cats);
        assert!(!result.all_passed());
    }

    #[test]
    fn matrix_result_all_passed_false_skip() {
        let mut cats = std::collections::HashMap::new();
        cats.insert("a".into(), CategoryResult::new(5, 4, 0, 1));
        let result = MatrixResult::new(cats);
        assert!(!result.all_passed());
    }

    #[test]
    fn matrix_result_serde_roundtrip() {
        let mut cats = std::collections::HashMap::new();
        cats.insert("discovery".into(), CategoryResult::new(3, 2, 1, 0));
        let result = MatrixResult::new(cats);
        let json_str = serde_json::to_string(&result).unwrap();
        let back: MatrixResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.total, result.total);
    }

    #[test]
    fn matrix_result_empty() {
        let result = MatrixResult::new(std::collections::HashMap::new());
        assert_eq!(result.total, 0);
        assert!(result.all_passed());
    }

    // ── Matrix builders ──────────────────────────────────────────

    #[test]
    fn build_discovery_matrix_has_at_least_15() {
        let cases = build_discovery_matrix();
        assert!(cases.len() >= 15, "got {}", cases.len());
    }

    #[test]
    fn build_discovery_matrix_unique_names() {
        let cases = build_discovery_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_discovery_matrix_covers_all_types() {
        let cases = build_discovery_matrix();
        let types: std::collections::HashSet<_> = cases.iter().map(|c| &c.discovery_type).collect();
        assert!(types.contains(&DiscoveryType::All));
        assert!(types.contains(&DiscoveryType::ByConnector));
        assert!(types.contains(&DiscoveryType::ByCapability));
        assert!(types.contains(&DiscoveryType::ByArchetype));
    }

    #[test]
    fn build_discovery_matrix_all_have_timeouts() {
        let cases = build_discovery_matrix();
        for case in &cases {
            assert!(case.timeout_ms > 0, "case {} has zero timeout", case.name);
        }
    }

    #[test]
    fn build_config_matrix_has_at_least_15() {
        let cases = build_config_matrix();
        assert!(cases.len() >= 15, "got {}", cases.len());
    }

    #[test]
    fn build_config_matrix_unique_names() {
        let cases = build_config_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_config_matrix_covers_all_operations() {
        let cases = build_config_matrix();
        let ops: std::collections::HashSet<_> = cases.iter().map(|c| &c.operation).collect();
        assert!(ops.contains(&ConfigOperation::Get));
        assert!(ops.contains(&ConfigOperation::Set));
        assert!(ops.contains(&ConfigOperation::Reset));
        assert!(ops.contains(&ConfigOperation::Import));
        assert!(ops.contains(&ConfigOperation::Export));
        assert!(ops.contains(&ConfigOperation::Diff));
    }

    #[test]
    fn build_config_matrix_has_error_cases() {
        let cases = build_config_matrix();
        let error_cases: Vec<_> = cases
            .iter()
            .filter(|c| {
                matches!(
                    c.expected_outcome,
                    ConfigOutcome::Error | ConfigOutcome::ValidationError
                )
            })
            .collect();
        assert!(!error_cases.is_empty());
    }

    #[test]
    fn build_lifecycle_matrix_has_at_least_15() {
        let cases = build_lifecycle_matrix();
        assert!(cases.len() >= 15, "got {}", cases.len());
    }

    #[test]
    fn build_lifecycle_matrix_unique_names() {
        let cases = build_lifecycle_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_lifecycle_matrix_covers_all_actions() {
        let cases = build_lifecycle_matrix();
        let actions: std::collections::HashSet<_> = cases.iter().map(|c| &c.action).collect();
        assert!(actions.contains(&LifecycleAction::Enable));
        assert!(actions.contains(&LifecycleAction::Disable));
        assert!(actions.contains(&LifecycleAction::Start));
        assert!(actions.contains(&LifecycleAction::Stop));
        assert!(actions.contains(&LifecycleAction::Restart));
    }

    #[test]
    fn build_lifecycle_matrix_has_failure_cases() {
        let cases = build_lifecycle_matrix();
        let failures: Vec<_> = cases.iter().filter(|c| c.expected_exit_code != 0).collect();
        assert!(!failures.is_empty());
    }

    #[test]
    fn build_lifecycle_matrix_has_success_cases() {
        let cases = build_lifecycle_matrix();
        let successes: Vec<_> = cases.iter().filter(|c| c.expected_exit_code == 0).collect();
        assert!(!successes.is_empty());
    }

    // ── Validators ───────────────────────────────────────────────

    #[test]
    fn validate_discovery_result_matching_array() {
        let case = DiscoveryTestCase::new(
            "test",
            DiscoveryType::All,
            1,
            vec!["id".into(), "name".into()],
            3000,
        );
        let output = json!([{"id": "gh", "name": "GitHub"}]);
        assert!(validate_discovery_result(&case, &output));
    }

    #[test]
    fn validate_discovery_result_empty_array_zero_count() {
        let case = DiscoveryTestCase::new("test", DiscoveryType::ByConnector, 0, vec![], 3000);
        let output = json!([]);
        assert!(validate_discovery_result(&case, &output));
    }

    #[test]
    fn validate_discovery_result_not_enough_results() {
        let case = DiscoveryTestCase::new("test", DiscoveryType::All, 5, vec![], 3000);
        let output = json!([{"id": "a"}, {"id": "b"}]);
        assert!(!validate_discovery_result(&case, &output));
    }

    #[test]
    fn validate_discovery_result_missing_field() {
        let case = DiscoveryTestCase::new(
            "test",
            DiscoveryType::All,
            1,
            vec!["id".into(), "missing_field".into()],
            3000,
        );
        let output = json!([{"id": "gh"}]);
        assert!(!validate_discovery_result(&case, &output));
    }

    #[test]
    fn validate_discovery_result_null_returns_zero_count() {
        let case = DiscoveryTestCase::new("test", DiscoveryType::ByConnector, 0, vec![], 3000);
        let output = json!(null);
        assert!(validate_discovery_result(&case, &output));
    }

    #[test]
    fn validate_discovery_result_null_nonzero_count_fails() {
        let case = DiscoveryTestCase::new("test", DiscoveryType::All, 1, vec![], 3000);
        let output = json!(null);
        assert!(!validate_discovery_result(&case, &output));
    }

    #[test]
    fn validate_config_result_success() {
        let case = ConfigTestCase::new(
            "t",
            ConfigOperation::Get,
            "c",
            "k",
            None,
            ConfigOutcome::Success,
        );
        let output = json!({"status": "success"});
        assert!(validate_config_result(&case, &output));
    }

    #[test]
    fn validate_config_result_success_ok() {
        let case = ConfigTestCase::new(
            "t",
            ConfigOperation::Get,
            "c",
            "k",
            None,
            ConfigOutcome::Success,
        );
        let output = json!({"status": "ok"});
        assert!(validate_config_result(&case, &output));
    }

    #[test]
    fn validate_config_result_error() {
        let case = ConfigTestCase::new(
            "t",
            ConfigOperation::Get,
            "c",
            "k",
            None,
            ConfigOutcome::Error,
        );
        let output = json!({"status": "error"});
        assert!(validate_config_result(&case, &output));
    }

    #[test]
    fn validate_config_result_no_change() {
        let case = ConfigTestCase::new(
            "t",
            ConfigOperation::Set,
            "c",
            "k",
            None,
            ConfigOutcome::NoChange,
        );
        let output = json!({"status": "no_change"});
        assert!(validate_config_result(&case, &output));
    }

    #[test]
    fn validate_config_result_no_change_unchanged() {
        let case = ConfigTestCase::new(
            "t",
            ConfigOperation::Set,
            "c",
            "k",
            None,
            ConfigOutcome::NoChange,
        );
        let output = json!({"status": "unchanged"});
        assert!(validate_config_result(&case, &output));
    }

    #[test]
    fn validate_config_result_validation_error() {
        let case = ConfigTestCase::new(
            "t",
            ConfigOperation::Set,
            "c",
            "k",
            None,
            ConfigOutcome::ValidationError,
        );
        let output = json!({"status": "validation_error"});
        assert!(validate_config_result(&case, &output));
    }

    #[test]
    fn validate_config_result_unauthorized() {
        let case = ConfigTestCase::new(
            "t",
            ConfigOperation::Get,
            "c",
            "k",
            None,
            ConfigOutcome::Unauthorized,
        );
        let output = json!({"status": "unauthorized"});
        assert!(validate_config_result(&case, &output));
    }

    #[test]
    fn validate_config_result_mismatch() {
        let case = ConfigTestCase::new(
            "t",
            ConfigOperation::Get,
            "c",
            "k",
            None,
            ConfigOutcome::Success,
        );
        let output = json!({"status": "error"});
        assert!(!validate_config_result(&case, &output));
    }

    #[test]
    fn validate_config_result_missing_status() {
        let case = ConfigTestCase::new(
            "t",
            ConfigOperation::Get,
            "c",
            "k",
            None,
            ConfigOutcome::Success,
        );
        let output = json!({"result": "done"});
        assert!(!validate_config_result(&case, &output));
    }

    #[test]
    fn validate_lifecycle_result_match() {
        let case = LifecycleTestCase::new(
            "t",
            "c",
            LifecycleAction::Start,
            None,
            ExpectedState::Running,
            0,
        );
        let output = json!({"state": "running", "exit_code": 0});
        assert!(validate_lifecycle_result(&case, &output));
    }

    #[test]
    fn validate_lifecycle_result_wrong_state() {
        let case = LifecycleTestCase::new(
            "t",
            "c",
            LifecycleAction::Start,
            None,
            ExpectedState::Running,
            0,
        );
        let output = json!({"state": "stopped", "exit_code": 0});
        assert!(!validate_lifecycle_result(&case, &output));
    }

    #[test]
    fn validate_lifecycle_result_wrong_exit_code() {
        let case = LifecycleTestCase::new(
            "t",
            "c",
            LifecycleAction::Start,
            None,
            ExpectedState::Running,
            0,
        );
        let output = json!({"state": "running", "exit_code": 1});
        assert!(!validate_lifecycle_result(&case, &output));
    }

    #[test]
    fn validate_lifecycle_result_missing_state() {
        let case = LifecycleTestCase::new(
            "t",
            "c",
            LifecycleAction::Start,
            None,
            ExpectedState::Running,
            0,
        );
        let output = json!({"exit_code": 0});
        assert!(!validate_lifecycle_result(&case, &output));
    }

    #[test]
    fn validate_lifecycle_result_missing_exit_code() {
        let case = LifecycleTestCase::new(
            "t",
            "c",
            LifecycleAction::Start,
            None,
            ExpectedState::Running,
            0,
        );
        let output = json!({"state": "running"});
        assert!(!validate_lifecycle_result(&case, &output));
    }

    // ── Formatting ───────────────────────────────────────────────

    #[test]
    fn format_matrix_toon_contains_header() {
        let matrix = IntegrationMatrix::build();
        let toon = format_matrix_toon(&matrix);
        assert!(toon.contains("Host Integration Test Matrix"));
    }

    #[test]
    fn format_matrix_toon_contains_discovery_section() {
        let matrix = IntegrationMatrix::build();
        let toon = format_matrix_toon(&matrix);
        assert!(toon.contains("Discovery"));
    }

    #[test]
    fn format_matrix_toon_contains_config_section() {
        let matrix = IntegrationMatrix::build();
        let toon = format_matrix_toon(&matrix);
        assert!(toon.contains("Config"));
    }

    #[test]
    fn format_matrix_toon_contains_lifecycle_section() {
        let matrix = IntegrationMatrix::build();
        let toon = format_matrix_toon(&matrix);
        assert!(toon.contains("Lifecycle"));
    }

    #[test]
    fn format_matrix_toon_contains_total() {
        let matrix = IntegrationMatrix::build();
        let toon = format_matrix_toon(&matrix);
        assert!(toon.contains(&format!("Total: {} cases", matrix.total_cases())));
    }

    #[test]
    fn format_matrix_toon_not_empty() {
        let matrix = IntegrationMatrix::build();
        let toon = format_matrix_toon(&matrix);
        assert!(!toon.is_empty());
    }

    #[test]
    fn format_matrix_result_toon_contains_header() {
        let mut cats = std::collections::HashMap::new();
        cats.insert("discovery".into(), CategoryResult::new(5, 5, 0, 0));
        let result = MatrixResult::new(cats);
        let toon = format_matrix_result_toon(&result);
        assert!(toon.contains("Matrix Result"));
    }

    #[test]
    fn format_matrix_result_toon_contains_totals() {
        let mut cats = std::collections::HashMap::new();
        cats.insert("a".into(), CategoryResult::new(10, 8, 2, 0));
        let result = MatrixResult::new(cats);
        let toon = format_matrix_result_toon(&result);
        assert!(toon.contains("Total: 10"));
        assert!(toon.contains("Passed: 8"));
        assert!(toon.contains("Failed: 2"));
    }

    #[test]
    fn format_matrix_result_toon_contains_rate() {
        let mut cats = std::collections::HashMap::new();
        cats.insert("a".into(), CategoryResult::new(10, 10, 0, 0));
        let result = MatrixResult::new(cats);
        let toon = format_matrix_result_toon(&result);
        assert!(toon.contains("100.0%"));
    }

    #[test]
    fn format_matrix_result_toon_contains_category() {
        let mut cats = std::collections::HashMap::new();
        cats.insert("discovery".into(), CategoryResult::new(5, 5, 0, 0));
        let result = MatrixResult::new(cats);
        let toon = format_matrix_result_toon(&result);
        assert!(toon.contains("discovery"));
    }

    // ── Discovery matrix content ─────────────────────────────────

    #[test]
    fn discovery_matrix_has_all_type_case() {
        let cases = build_discovery_matrix();
        assert!(cases.iter().any(|c| c.discovery_type == DiscoveryType::All));
    }

    #[test]
    fn discovery_matrix_has_by_connector_case() {
        let cases = build_discovery_matrix();
        assert!(
            cases
                .iter()
                .any(|c| c.discovery_type == DiscoveryType::ByConnector)
        );
    }

    #[test]
    fn discovery_matrix_has_zero_count_case() {
        let cases = build_discovery_matrix();
        assert!(cases.iter().any(|c| c.expected_count == 0));
    }

    #[test]
    fn discovery_matrix_has_nonzero_count_case() {
        let cases = build_discovery_matrix();
        assert!(cases.iter().any(|c| c.expected_count > 0));
    }

    // ── Config matrix content ────────────────────────────────────

    #[test]
    fn config_matrix_has_get_operation() {
        let cases = build_config_matrix();
        assert!(cases.iter().any(|c| c.operation == ConfigOperation::Get));
    }

    #[test]
    fn config_matrix_has_set_operation() {
        let cases = build_config_matrix();
        assert!(cases.iter().any(|c| c.operation == ConfigOperation::Set));
    }

    #[test]
    fn config_matrix_has_cases_with_values() {
        let cases = build_config_matrix();
        assert!(cases.iter().any(|c| c.value.is_some()));
    }

    #[test]
    fn config_matrix_has_cases_without_values() {
        let cases = build_config_matrix();
        assert!(cases.iter().any(|c| c.value.is_none()));
    }

    // ── Lifecycle matrix content ─────────────────────────────────

    #[test]
    fn lifecycle_matrix_has_enable_action() {
        let cases = build_lifecycle_matrix();
        assert!(cases.iter().any(|c| c.action == LifecycleAction::Enable));
    }

    #[test]
    fn lifecycle_matrix_has_restart_action() {
        let cases = build_lifecycle_matrix();
        assert!(cases.iter().any(|c| c.action == LifecycleAction::Restart));
    }

    #[test]
    fn lifecycle_matrix_has_precondition_cases() {
        let cases = build_lifecycle_matrix();
        assert!(cases.iter().any(|c| c.precondition.is_some()));
    }

    #[test]
    fn lifecycle_matrix_has_no_precondition_cases() {
        let cases = build_lifecycle_matrix();
        assert!(cases.iter().any(|c| c.precondition.is_none()));
    }

    #[test]
    fn lifecycle_matrix_has_nonzero_exit_code() {
        let cases = build_lifecycle_matrix();
        assert!(cases.iter().any(|c| c.expected_exit_code != 0));
    }
}
