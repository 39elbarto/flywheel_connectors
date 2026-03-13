//! Host integration test matrix for invoke, simulate, batch, and result handling.
//!
//! Provides a comprehensive matrix of test cases for exercising host-backed
//! invoke calls, dry-run simulation, batch execution with dependency ordering,
//! and result type handling (scalar, array, stream, paginated).

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Invoke types ─────────────────────────────────────────────────────

/// Expected status of an invoke operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvokeExpectedStatus {
    /// Operation succeeds.
    Success,
    /// Operation fails with an error.
    Error,
    /// Operation times out.
    Timeout,
}

impl std::fmt::Display for InvokeExpectedStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => f.write_str("success"),
            Self::Error => f.write_str("error"),
            Self::Timeout => f.write_str("timeout"),
        }
    }
}

/// A single invoke test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvokeTestCase {
    /// Human-readable name.
    pub name: String,
    /// Target connector.
    pub connector: String,
    /// Operation to invoke.
    pub operation: String,
    /// Input payload.
    pub input: Value,
    /// Expected outcome status.
    pub expected_status: InvokeExpectedStatus,
    /// Fields expected in the output on success.
    pub expected_output_fields: Vec<String>,
    /// Error code expected on failure.
    pub expected_error_code: Option<String>,
}

impl InvokeTestCase {
    /// Create a new invoke test case.
    pub fn new(
        name: impl Into<String>,
        connector: impl Into<String>,
        operation: impl Into<String>,
        input: Value,
        expected_status: InvokeExpectedStatus,
        expected_output_fields: Vec<String>,
        expected_error_code: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            connector: connector.into(),
            operation: operation.into(),
            input,
            expected_status,
            expected_output_fields,
            expected_error_code,
        }
    }

    /// Whether this test expects a successful outcome.
    pub fn expects_success(&self) -> bool {
        matches!(self.expected_status, InvokeExpectedStatus::Success)
    }

    /// Whether this test expects an error code.
    pub fn expects_error(&self) -> bool {
        matches!(
            self.expected_status,
            InvokeExpectedStatus::Error | InvokeExpectedStatus::Timeout
        )
    }

    /// Whether this test has an explicit error code expectation.
    pub fn has_error_code(&self) -> bool {
        self.expected_error_code.is_some()
    }
}

// ── Simulate types ───────────────────────────────────────────────────

/// A single simulate (dry-run) test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimulateTestCase {
    /// Human-readable name.
    pub name: String,
    /// Target connector.
    pub connector: String,
    /// Operation to simulate.
    pub operation: String,
    /// Input payload.
    pub input: Value,
    /// Expected fields in the dry-run output.
    pub expected_dry_run_output: Vec<String>,
    /// Whether side effects should be absent.
    pub expected_side_effects_none: bool,
}

impl SimulateTestCase {
    /// Create a new simulate test case.
    pub fn new(
        name: impl Into<String>,
        connector: impl Into<String>,
        operation: impl Into<String>,
        input: Value,
        expected_dry_run_output: Vec<String>,
        expected_side_effects_none: bool,
    ) -> Self {
        Self {
            name: name.into(),
            connector: connector.into(),
            operation: operation.into(),
            input,
            expected_dry_run_output,
            expected_side_effects_none,
        }
    }

    /// Whether this test expects no side effects.
    pub fn is_side_effect_free(&self) -> bool {
        self.expected_side_effects_none
    }
}

// ── Batch types ──────────────────────────────────────────────────────

/// A single operation within a batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchOp {
    /// Target connector.
    pub connector: String,
    /// Operation to invoke.
    pub operation: String,
    /// Input payload.
    pub input: Value,
    /// Optional dependency on another op (by index).
    pub depends_on: Option<usize>,
}

impl BatchOp {
    /// Create a new batch operation.
    pub fn new(
        connector: impl Into<String>,
        operation: impl Into<String>,
        input: Value,
        depends_on: Option<usize>,
    ) -> Self {
        Self {
            connector: connector.into(),
            operation: operation.into(),
            input,
            depends_on,
        }
    }

    /// Whether this op has a dependency.
    pub fn has_dependency(&self) -> bool {
        self.depends_on.is_some()
    }
}

/// Error handling strategy for batch operations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnBatchError {
    /// Stop all remaining operations.
    Stop,
    /// Continue with remaining operations.
    Continue,
    /// Skip dependent operations only.
    SkipDependents,
}

impl std::fmt::Display for OnBatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stop => f.write_str("stop"),
            Self::Continue => f.write_str("continue"),
            Self::SkipDependents => f.write_str("skip_dependents"),
        }
    }
}

/// Expected result status for a batch operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchExpectedResult {
    AllSuccess,
    PartialSuccess,
    AllFail,
}

impl std::fmt::Display for BatchExpectedResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllSuccess => f.write_str("all_success"),
            Self::PartialSuccess => f.write_str("partial_success"),
            Self::AllFail => f.write_str("all_fail"),
        }
    }
}

/// A single batch test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchTestCase {
    /// Human-readable name.
    pub name: String,
    /// Operations in this batch.
    pub operations: Vec<BatchOp>,
    /// Concurrency level.
    pub concurrency: usize,
    /// Error handling strategy.
    pub on_error: OnBatchError,
    /// Expected overall result.
    pub expected_results: BatchExpectedResult,
}

impl BatchTestCase {
    /// Create a new batch test case.
    pub fn new(
        name: impl Into<String>,
        operations: Vec<BatchOp>,
        concurrency: usize,
        on_error: OnBatchError,
        expected_results: BatchExpectedResult,
    ) -> Self {
        Self {
            name: name.into(),
            operations,
            concurrency,
            on_error,
            expected_results,
        }
    }

    /// Number of operations in this batch.
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Whether any operations have dependencies.
    pub fn has_dependencies(&self) -> bool {
        self.operations.iter().any(|op| op.has_dependency())
    }
}

// ── Result handle types ──────────────────────────────────────────────

/// Type of result from an invoke operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultType {
    /// A single scalar value.
    Scalar,
    /// An array of values.
    Array,
    /// A streaming sequence of events.
    Stream,
    /// A paginated result set.
    Paginated,
}

impl std::fmt::Display for ResultType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scalar => f.write_str("scalar"),
            Self::Array => f.write_str("array"),
            Self::Stream => f.write_str("stream"),
            Self::Paginated => f.write_str("paginated"),
        }
    }
}

/// A single result-handling test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultHandleTestCase {
    /// Human-readable name.
    pub name: String,
    /// Type of result expected.
    pub result_type: ResultType,
    /// Expected format of the result (e.g., "json", "csv", "table").
    pub expected_format: String,
}

impl ResultHandleTestCase {
    /// Create a new result handle test case.
    pub fn new(
        name: impl Into<String>,
        result_type: ResultType,
        expected_format: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            result_type,
            expected_format: expected_format.into(),
        }
    }

    /// Whether this is a streaming result.
    pub fn is_streaming(&self) -> bool {
        matches!(self.result_type, ResultType::Stream)
    }

    /// Whether this is a paginated result.
    pub fn is_paginated(&self) -> bool {
        matches!(self.result_type, ResultType::Paginated)
    }
}

// ── Matrix builders ──────────────────────────────────────────────────

/// Build the invoke test matrix (at least 20 cases).
pub fn build_invoke_matrix() -> Vec<InvokeTestCase> {
    vec![
        // ── Success cases ──
        InvokeTestCase::new(
            "invoke_github_list_repos_success",
            "github",
            "list_repos",
            serde_json::json!({"org": "test-org"}),
            InvokeExpectedStatus::Success,
            vec!["repos".into(), "total_count".into()],
            None,
        ),
        InvokeTestCase::new(
            "invoke_slack_send_message_success",
            "slack",
            "send_message",
            serde_json::json!({"channel": "#general", "text": "hello"}),
            InvokeExpectedStatus::Success,
            vec!["ok".into(), "ts".into()],
            None,
        ),
        InvokeTestCase::new(
            "invoke_jira_create_issue_success",
            "jira",
            "create_issue",
            serde_json::json!({"project": "TEST", "summary": "A test issue", "type": "Task"}),
            InvokeExpectedStatus::Success,
            vec!["key".into(), "id".into()],
            None,
        ),
        InvokeTestCase::new(
            "invoke_github_get_repo_success",
            "github",
            "get_repo",
            serde_json::json!({"owner": "test", "repo": "test-repo"}),
            InvokeExpectedStatus::Success,
            vec!["full_name".into(), "default_branch".into()],
            None,
        ),
        InvokeTestCase::new(
            "invoke_slack_list_channels_success",
            "slack",
            "list_channels",
            serde_json::json!({}),
            InvokeExpectedStatus::Success,
            vec!["channels".into()],
            None,
        ),
        InvokeTestCase::new(
            "invoke_discord_send_message_success",
            "discord",
            "send_message",
            serde_json::json!({"channel_id": "123456", "content": "test"}),
            InvokeExpectedStatus::Success,
            vec!["id".into(), "content".into()],
            None,
        ),
        InvokeTestCase::new(
            "invoke_telegram_send_message_success",
            "telegram",
            "send_message",
            serde_json::json!({"chat_id": 12345, "text": "test message"}),
            InvokeExpectedStatus::Success,
            vec!["message_id".into()],
            None,
        ),
        // ── Error cases ──
        InvokeTestCase::new(
            "invoke_github_missing_required_field",
            "github",
            "list_repos",
            serde_json::json!({}),
            InvokeExpectedStatus::Error,
            vec![],
            Some("missing_field".into()),
        ),
        InvokeTestCase::new(
            "invoke_slack_invalid_channel",
            "slack",
            "send_message",
            serde_json::json!({"channel": "nonexistent", "text": "hello"}),
            InvokeExpectedStatus::Error,
            vec![],
            Some("channel_not_found".into()),
        ),
        InvokeTestCase::new(
            "invoke_jira_invalid_project",
            "jira",
            "create_issue",
            serde_json::json!({"project": "INVALID", "summary": "test"}),
            InvokeExpectedStatus::Error,
            vec![],
            Some("project_not_found".into()),
        ),
        InvokeTestCase::new(
            "invoke_nonexistent_connector",
            "nonexistent_connector",
            "list",
            serde_json::json!({}),
            InvokeExpectedStatus::Error,
            vec![],
            Some("connector_not_found".into()),
        ),
        InvokeTestCase::new(
            "invoke_nonexistent_operation",
            "github",
            "nonexistent_operation",
            serde_json::json!({}),
            InvokeExpectedStatus::Error,
            vec![],
            Some("operation_not_found".into()),
        ),
        // ── Auth error cases ──
        InvokeTestCase::new(
            "invoke_github_auth_expired",
            "github",
            "list_repos",
            serde_json::json!({"org": "test-org", "_auth": "expired_token"}),
            InvokeExpectedStatus::Error,
            vec![],
            Some("auth_expired".into()),
        ),
        InvokeTestCase::new(
            "invoke_slack_auth_revoked",
            "slack",
            "send_message",
            serde_json::json!({"channel": "#general", "text": "hello", "_auth": "revoked"}),
            InvokeExpectedStatus::Error,
            vec![],
            Some("auth_revoked".into()),
        ),
        InvokeTestCase::new(
            "invoke_jira_auth_insufficient_scope",
            "jira",
            "delete_issue",
            serde_json::json!({"issue_key": "TEST-1", "_auth": "read_only"}),
            InvokeExpectedStatus::Error,
            vec![],
            Some("insufficient_scope".into()),
        ),
        // ── Rate limit cases ──
        InvokeTestCase::new(
            "invoke_github_rate_limited",
            "github",
            "search_code",
            serde_json::json!({"query": "test", "_simulate_rate_limit": true}),
            InvokeExpectedStatus::Error,
            vec![],
            Some("rate_limited".into()),
        ),
        InvokeTestCase::new(
            "invoke_slack_rate_limited",
            "slack",
            "list_users",
            serde_json::json!({"_simulate_rate_limit": true}),
            InvokeExpectedStatus::Error,
            vec![],
            Some("rate_limited".into()),
        ),
        // ── Timeout cases ──
        InvokeTestCase::new(
            "invoke_github_timeout",
            "github",
            "list_repos",
            serde_json::json!({"org": "huge-org", "_simulate_timeout": true}),
            InvokeExpectedStatus::Timeout,
            vec![],
            Some("timeout".into()),
        ),
        InvokeTestCase::new(
            "invoke_jira_timeout_large_query",
            "jira",
            "search_issues",
            serde_json::json!({"jql": "project = HUGE", "_simulate_timeout": true}),
            InvokeExpectedStatus::Timeout,
            vec![],
            Some("timeout".into()),
        ),
        // ── Edge cases ──
        InvokeTestCase::new(
            "invoke_github_empty_result",
            "github",
            "list_repos",
            serde_json::json!({"org": "empty-org"}),
            InvokeExpectedStatus::Success,
            vec!["repos".into()],
            None,
        ),
        InvokeTestCase::new(
            "invoke_slack_unicode_content",
            "slack",
            "send_message",
            serde_json::json!({"channel": "#general", "text": "Hello \u{1F600} world"}),
            InvokeExpectedStatus::Success,
            vec!["ok".into()],
            None,
        ),
        InvokeTestCase::new(
            "invoke_github_large_payload",
            "github",
            "create_issue",
            serde_json::json!({"owner": "test", "repo": "test-repo", "title": "Large", "body": "x".repeat(10000)}),
            InvokeExpectedStatus::Success,
            vec!["number".into()],
            None,
        ),
    ]
}

/// Build the simulate test matrix (at least 10 cases).
pub fn build_simulate_matrix() -> Vec<SimulateTestCase> {
    vec![
        SimulateTestCase::new(
            "simulate_github_create_issue",
            "github",
            "create_issue",
            serde_json::json!({"owner": "test", "repo": "test-repo", "title": "Sim issue"}),
            vec!["would_create".into(), "resource_type".into()],
            true,
        ),
        SimulateTestCase::new(
            "simulate_slack_send_message",
            "slack",
            "send_message",
            serde_json::json!({"channel": "#general", "text": "dry run"}),
            vec!["would_send".into(), "channel".into()],
            true,
        ),
        SimulateTestCase::new(
            "simulate_jira_update_issue",
            "jira",
            "update_issue",
            serde_json::json!({"issue_key": "TEST-1", "fields": {"summary": "Updated"}}),
            vec!["would_update".into(), "fields_changed".into()],
            true,
        ),
        SimulateTestCase::new(
            "simulate_github_delete_repo",
            "github",
            "delete_repo",
            serde_json::json!({"owner": "test", "repo": "to-delete"}),
            vec!["would_delete".into(), "destructive".into()],
            true,
        ),
        SimulateTestCase::new(
            "simulate_discord_create_channel",
            "discord",
            "create_channel",
            serde_json::json!({"guild_id": "123", "name": "new-channel"}),
            vec!["would_create".into(), "resource_type".into()],
            true,
        ),
        SimulateTestCase::new(
            "simulate_telegram_send_photo",
            "telegram",
            "send_photo",
            serde_json::json!({"chat_id": 12345, "photo": "https://example.com/photo.jpg"}),
            vec!["would_send".into(), "media_type".into()],
            true,
        ),
        SimulateTestCase::new(
            "simulate_github_list_repos_readonly",
            "github",
            "list_repos",
            serde_json::json!({"org": "test-org"}),
            vec!["read_only".into()],
            true,
        ),
        SimulateTestCase::new(
            "simulate_jira_delete_issue",
            "jira",
            "delete_issue",
            serde_json::json!({"issue_key": "TEST-99"}),
            vec!["would_delete".into(), "destructive".into(), "irreversible".into()],
            true,
        ),
        SimulateTestCase::new(
            "simulate_slack_archive_channel",
            "slack",
            "archive_channel",
            serde_json::json!({"channel": "C123"}),
            vec!["would_archive".into()],
            true,
        ),
        SimulateTestCase::new(
            "simulate_github_merge_pr",
            "github",
            "merge_pull_request",
            serde_json::json!({"owner": "test", "repo": "test-repo", "pull_number": 42}),
            vec!["would_merge".into(), "merge_method".into()],
            true,
        ),
        SimulateTestCase::new(
            "simulate_nonexistent_operation",
            "github",
            "nonexistent_op",
            serde_json::json!({}),
            vec!["error".into()],
            true,
        ),
    ]
}

/// Build the batch test matrix (at least 10 cases).
pub fn build_batch_matrix() -> Vec<BatchTestCase> {
    vec![
        BatchTestCase::new(
            "batch_sequential_two_ops",
            vec![
                BatchOp::new("github", "list_repos", serde_json::json!({"org": "test"}), None),
                BatchOp::new("github", "get_repo", serde_json::json!({"owner": "test", "repo": "a"}), Some(0)),
            ],
            1,
            OnBatchError::Stop,
            BatchExpectedResult::AllSuccess,
        ),
        BatchTestCase::new(
            "batch_parallel_two_ops",
            vec![
                BatchOp::new("github", "list_repos", serde_json::json!({"org": "a"}), None),
                BatchOp::new("slack", "list_channels", serde_json::json!({}), None),
            ],
            2,
            OnBatchError::Continue,
            BatchExpectedResult::AllSuccess,
        ),
        BatchTestCase::new(
            "batch_three_ops_with_chain",
            vec![
                BatchOp::new("github", "list_repos", serde_json::json!({"org": "test"}), None),
                BatchOp::new("github", "get_repo", serde_json::json!({"owner": "test", "repo": "a"}), Some(0)),
                BatchOp::new("github", "list_issues", serde_json::json!({"owner": "test", "repo": "a"}), Some(1)),
            ],
            1,
            OnBatchError::Stop,
            BatchExpectedResult::AllSuccess,
        ),
        BatchTestCase::new(
            "batch_fail_first_stop",
            vec![
                BatchOp::new("nonexistent", "op", serde_json::json!({}), None),
                BatchOp::new("github", "list_repos", serde_json::json!({"org": "test"}), None),
            ],
            1,
            OnBatchError::Stop,
            BatchExpectedResult::AllFail,
        ),
        BatchTestCase::new(
            "batch_fail_first_continue",
            vec![
                BatchOp::new("nonexistent", "op", serde_json::json!({}), None),
                BatchOp::new("github", "list_repos", serde_json::json!({"org": "test"}), None),
            ],
            1,
            OnBatchError::Continue,
            BatchExpectedResult::PartialSuccess,
        ),
        BatchTestCase::new(
            "batch_fail_skip_dependents",
            vec![
                BatchOp::new("nonexistent", "op", serde_json::json!({}), None),
                BatchOp::new("github", "get_repo", serde_json::json!({}), Some(0)),
                BatchOp::new("slack", "list_channels", serde_json::json!({}), None),
            ],
            2,
            OnBatchError::SkipDependents,
            BatchExpectedResult::PartialSuccess,
        ),
        BatchTestCase::new(
            "batch_high_concurrency",
            vec![
                BatchOp::new("github", "list_repos", serde_json::json!({"org": "a"}), None),
                BatchOp::new("slack", "list_channels", serde_json::json!({}), None),
                BatchOp::new("jira", "search_issues", serde_json::json!({"jql": "project=TEST"}), None),
                BatchOp::new("discord", "list_guilds", serde_json::json!({}), None),
            ],
            4,
            OnBatchError::Continue,
            BatchExpectedResult::AllSuccess,
        ),
        BatchTestCase::new(
            "batch_single_op",
            vec![
                BatchOp::new("github", "list_repos", serde_json::json!({"org": "test"}), None),
            ],
            1,
            OnBatchError::Stop,
            BatchExpectedResult::AllSuccess,
        ),
        BatchTestCase::new(
            "batch_diamond_dependency",
            vec![
                BatchOp::new("github", "list_repos", serde_json::json!({"org": "test"}), None),
                BatchOp::new("github", "get_repo", serde_json::json!({}), Some(0)),
                BatchOp::new("github", "list_issues", serde_json::json!({}), Some(0)),
                BatchOp::new("github", "create_issue", serde_json::json!({}), Some(1)),
            ],
            2,
            OnBatchError::Stop,
            BatchExpectedResult::AllSuccess,
        ),
        BatchTestCase::new(
            "batch_empty_operations",
            vec![],
            1,
            OnBatchError::Stop,
            BatchExpectedResult::AllSuccess,
        ),
        BatchTestCase::new(
            "batch_all_fail",
            vec![
                BatchOp::new("nonexistent1", "op", serde_json::json!({}), None),
                BatchOp::new("nonexistent2", "op", serde_json::json!({}), None),
            ],
            2,
            OnBatchError::Continue,
            BatchExpectedResult::AllFail,
        ),
    ]
}

/// Build the result-handle test matrix (at least 8 cases).
pub fn build_result_handle_matrix() -> Vec<ResultHandleTestCase> {
    vec![
        ResultHandleTestCase::new(
            "result_scalar_json",
            ResultType::Scalar,
            "json",
        ),
        ResultHandleTestCase::new(
            "result_scalar_text",
            ResultType::Scalar,
            "text",
        ),
        ResultHandleTestCase::new(
            "result_array_json",
            ResultType::Array,
            "json",
        ),
        ResultHandleTestCase::new(
            "result_array_csv",
            ResultType::Array,
            "csv",
        ),
        ResultHandleTestCase::new(
            "result_array_table",
            ResultType::Array,
            "table",
        ),
        ResultHandleTestCase::new(
            "result_stream_ndjson",
            ResultType::Stream,
            "ndjson",
        ),
        ResultHandleTestCase::new(
            "result_stream_sse",
            ResultType::Stream,
            "sse",
        ),
        ResultHandleTestCase::new(
            "result_paginated_json",
            ResultType::Paginated,
            "json",
        ),
        ResultHandleTestCase::new(
            "result_paginated_table",
            ResultType::Paginated,
            "table",
        ),
        ResultHandleTestCase::new(
            "result_scalar_yaml",
            ResultType::Scalar,
            "yaml",
        ),
    ]
}

// ── Validators ───────────────────────────────────────────────────────

/// Validate an invoke result against a test case.
pub fn validate_invoke_result(case: &InvokeTestCase, output: &Value) -> bool {
    let status = output
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");

    match case.expected_status {
        InvokeExpectedStatus::Success => {
            if status != "success" && status != "ok" {
                return false;
            }
            // Check expected output fields.
            for field in &case.expected_output_fields {
                if output.get(field.as_str()).is_none()
                    && output
                        .get("data")
                        .and_then(|d| d.get(field.as_str()))
                        .is_none()
                {
                    return false;
                }
            }
            true
        }
        InvokeExpectedStatus::Error => {
            if status != "error" {
                return false;
            }
            if let Some(expected_code) = &case.expected_error_code {
                let actual_code = output
                    .get("error_code")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                actual_code == expected_code.as_str()
            } else {
                true
            }
        }
        InvokeExpectedStatus::Timeout => {
            status == "timeout" || status == "error"
        }
    }
}

/// Validate a simulate result against a test case.
pub fn validate_simulate_result(case: &SimulateTestCase, output: &Value) -> bool {
    // Check expected dry-run output fields.
    for field in &case.expected_dry_run_output {
        if output.get(field.as_str()).is_none() {
            return false;
        }
    }

    // Check side-effect-free marker.
    if case.expected_side_effects_none {
        let has_side_effects = output
            .get("side_effects")
            .and_then(|s| s.as_bool())
            .unwrap_or(false);
        if has_side_effects {
            return false;
        }
    }

    true
}

/// Validate a batch result against a test case.
pub fn validate_batch_result(case: &BatchTestCase, output: &Value) -> bool {
    let results = output.get("results").and_then(|r| r.as_array());

    match case.expected_results {
        BatchExpectedResult::AllSuccess => {
            if let Some(results) = results {
                results.iter().all(|r| {
                    r.get("status")
                        .and_then(|s| s.as_str())
                        .is_some_and(|s| s == "success" || s == "ok")
                })
            } else {
                case.operations.is_empty()
            }
        }
        BatchExpectedResult::PartialSuccess => {
            if let Some(results) = results {
                let has_success = results.iter().any(|r| {
                    r.get("status")
                        .and_then(|s| s.as_str())
                        .is_some_and(|s| s == "success" || s == "ok")
                });
                let has_failure = results.iter().any(|r| {
                    r.get("status")
                        .and_then(|s| s.as_str())
                        .is_some_and(|s| s == "error")
                });
                has_success && has_failure
            } else {
                false
            }
        }
        BatchExpectedResult::AllFail => {
            if let Some(results) = results {
                results.iter().all(|r| {
                    r.get("status")
                        .and_then(|s| s.as_str())
                        .is_some_and(|s| s == "error")
                })
            } else {
                false
            }
        }
    }
}

// ── Formatting ───────────────────────────────────────────────────────

/// Format the invoke matrix as a human-readable table.
pub fn format_invoke_matrix_toon(cases: &[InvokeTestCase]) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== Invoke Test Matrix ({} cases) ===", cases.len());
    let _ = writeln!(out);

    for (i, case) in cases.iter().enumerate() {
        let _ = writeln!(
            out,
            "  [{:>2}] {:<45} connector={:<15} op={:<25} status={}",
            i + 1,
            case.name,
            case.connector,
            case.operation,
            case.expected_status,
        );
    }

    out
}

/// Format the simulate matrix as a human-readable table.
pub fn format_simulate_matrix_toon(cases: &[SimulateTestCase]) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== Simulate Test Matrix ({} cases) ===", cases.len());
    let _ = writeln!(out);

    for (i, case) in cases.iter().enumerate() {
        let _ = writeln!(
            out,
            "  [{:>2}] {:<45} connector={:<15} op={:<25} side_effects_none={}",
            i + 1,
            case.name,
            case.connector,
            case.operation,
            case.expected_side_effects_none,
        );
    }

    out
}

/// Format the batch matrix as a human-readable table.
pub fn format_batch_matrix_toon(cases: &[BatchTestCase]) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== Batch Test Matrix ({} cases) ===", cases.len());
    let _ = writeln!(out);

    for (i, case) in cases.iter().enumerate() {
        let _ = writeln!(
            out,
            "  [{:>2}] {:<45} ops={:<3} concurrency={:<3} on_error={:<16} expected={}",
            i + 1,
            case.name,
            case.operation_count(),
            case.concurrency,
            case.on_error.to_string(),
            case.expected_results,
        );
    }

    out
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── InvokeExpectedStatus ─────────────────────────────────────

    #[test]
    fn invoke_status_display_success() {
        assert_eq!(InvokeExpectedStatus::Success.to_string(), "success");
    }

    #[test]
    fn invoke_status_display_error() {
        assert_eq!(InvokeExpectedStatus::Error.to_string(), "error");
    }

    #[test]
    fn invoke_status_display_timeout() {
        assert_eq!(InvokeExpectedStatus::Timeout.to_string(), "timeout");
    }

    #[test]
    fn invoke_status_serde_roundtrip() {
        let s = InvokeExpectedStatus::Timeout;
        let json_str = serde_json::to_string(&s).unwrap();
        let back: InvokeExpectedStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn invoke_status_clone() {
        let s = InvokeExpectedStatus::Success;
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    // ── InvokeTestCase ───────────────────────────────────────────

    #[test]
    fn invoke_test_case_new() {
        let tc = InvokeTestCase::new(
            "test",
            "github",
            "list_repos",
            json!({}),
            InvokeExpectedStatus::Success,
            vec!["repos".into()],
            None,
        );
        assert_eq!(tc.name, "test");
        assert_eq!(tc.connector, "github");
    }

    #[test]
    fn invoke_test_case_expects_success() {
        let tc = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Success, vec![], None);
        assert!(tc.expects_success());
        assert!(!tc.expects_error());
    }

    #[test]
    fn invoke_test_case_expects_error() {
        let tc = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Error, vec![], Some("e".into()));
        assert!(!tc.expects_success());
        assert!(tc.expects_error());
    }

    #[test]
    fn invoke_test_case_expects_timeout() {
        let tc = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Timeout, vec![], None);
        assert!(!tc.expects_success());
        assert!(tc.expects_error());
    }

    #[test]
    fn invoke_test_case_has_error_code() {
        let tc = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Error, vec![], Some("e".into()));
        assert!(tc.has_error_code());
    }

    #[test]
    fn invoke_test_case_no_error_code() {
        let tc = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Success, vec![], None);
        assert!(!tc.has_error_code());
    }

    #[test]
    fn invoke_test_case_serde_roundtrip() {
        let tc = InvokeTestCase::new("r", "gh", "list", json!({"a": 1}), InvokeExpectedStatus::Success, vec!["x".into()], None);
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: InvokeTestCase = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "r");
        assert_eq!(back.connector, "gh");
    }

    #[test]
    fn invoke_test_case_clone() {
        let tc = InvokeTestCase::new("cl", "c", "o", json!({}), InvokeExpectedStatus::Success, vec![], None);
        let cloned = tc.clone();
        assert_eq!(cloned.name, "cl");
    }

    // ── SimulateTestCase ─────────────────────────────────────────

    #[test]
    fn simulate_test_case_new() {
        let tc = SimulateTestCase::new("sim", "github", "create_issue", json!({}), vec!["would_create".into()], true);
        assert_eq!(tc.name, "sim");
        assert!(tc.expected_side_effects_none);
    }

    #[test]
    fn simulate_test_case_side_effect_free() {
        let tc = SimulateTestCase::new("t", "c", "o", json!({}), vec![], true);
        assert!(tc.is_side_effect_free());
    }

    #[test]
    fn simulate_test_case_not_side_effect_free() {
        let tc = SimulateTestCase::new("t", "c", "o", json!({}), vec![], false);
        assert!(!tc.is_side_effect_free());
    }

    #[test]
    fn simulate_test_case_serde_roundtrip() {
        let tc = SimulateTestCase::new("r", "gh", "op", json!({}), vec!["x".into()], true);
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: SimulateTestCase = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "r");
    }

    #[test]
    fn simulate_test_case_clone() {
        let tc = SimulateTestCase::new("cl", "c", "o", json!({}), vec![], false);
        let cloned = tc.clone();
        assert_eq!(cloned.name, "cl");
    }

    // ── BatchOp ──────────────────────────────────────────────────

    #[test]
    fn batch_op_new() {
        let op = BatchOp::new("github", "list_repos", json!({}), None);
        assert_eq!(op.connector, "github");
        assert!(!op.has_dependency());
    }

    #[test]
    fn batch_op_with_dependency() {
        let op = BatchOp::new("github", "get_repo", json!({}), Some(0));
        assert!(op.has_dependency());
        assert_eq!(op.depends_on, Some(0));
    }

    #[test]
    fn batch_op_serde_roundtrip() {
        let op = BatchOp::new("gh", "list", json!({"a": 1}), Some(2));
        let json_str = serde_json::to_string(&op).unwrap();
        let back: BatchOp = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.connector, "gh");
        assert_eq!(back.depends_on, Some(2));
    }

    #[test]
    fn batch_op_clone() {
        let op = BatchOp::new("c", "o", json!({}), None);
        let cloned = op.clone();
        assert_eq!(cloned.connector, "c");
    }

    // ── OnBatchError ─────────────────────────────────────────────

    #[test]
    fn on_batch_error_display_stop() {
        assert_eq!(OnBatchError::Stop.to_string(), "stop");
    }

    #[test]
    fn on_batch_error_display_continue() {
        assert_eq!(OnBatchError::Continue.to_string(), "continue");
    }

    #[test]
    fn on_batch_error_display_skip_dependents() {
        assert_eq!(OnBatchError::SkipDependents.to_string(), "skip_dependents");
    }

    #[test]
    fn on_batch_error_serde_roundtrip() {
        let e = OnBatchError::SkipDependents;
        let json_str = serde_json::to_string(&e).unwrap();
        let back: OnBatchError = serde_json::from_str(&json_str).unwrap();
        assert_eq!(e, back);
    }

    // ── BatchExpectedResult ──────────────────────────────────────

    #[test]
    fn batch_expected_result_display_all_success() {
        assert_eq!(BatchExpectedResult::AllSuccess.to_string(), "all_success");
    }

    #[test]
    fn batch_expected_result_display_partial() {
        assert_eq!(BatchExpectedResult::PartialSuccess.to_string(), "partial_success");
    }

    #[test]
    fn batch_expected_result_display_all_fail() {
        assert_eq!(BatchExpectedResult::AllFail.to_string(), "all_fail");
    }

    #[test]
    fn batch_expected_result_serde_roundtrip() {
        let r = BatchExpectedResult::PartialSuccess;
        let json_str = serde_json::to_string(&r).unwrap();
        let back: BatchExpectedResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(r, back);
    }

    // ── BatchTestCase ────────────────────────────────────────────

    #[test]
    fn batch_test_case_new() {
        let tc = BatchTestCase::new(
            "test",
            vec![BatchOp::new("gh", "list", json!({}), None)],
            1,
            OnBatchError::Stop,
            BatchExpectedResult::AllSuccess,
        );
        assert_eq!(tc.name, "test");
        assert_eq!(tc.operation_count(), 1);
    }

    #[test]
    fn batch_test_case_operation_count() {
        let tc = BatchTestCase::new(
            "t",
            vec![
                BatchOp::new("a", "o1", json!({}), None),
                BatchOp::new("b", "o2", json!({}), None),
            ],
            2,
            OnBatchError::Continue,
            BatchExpectedResult::AllSuccess,
        );
        assert_eq!(tc.operation_count(), 2);
    }

    #[test]
    fn batch_test_case_has_dependencies() {
        let tc = BatchTestCase::new(
            "t",
            vec![
                BatchOp::new("a", "o1", json!({}), None),
                BatchOp::new("b", "o2", json!({}), Some(0)),
            ],
            1,
            OnBatchError::Stop,
            BatchExpectedResult::AllSuccess,
        );
        assert!(tc.has_dependencies());
    }

    #[test]
    fn batch_test_case_no_dependencies() {
        let tc = BatchTestCase::new(
            "t",
            vec![
                BatchOp::new("a", "o1", json!({}), None),
                BatchOp::new("b", "o2", json!({}), None),
            ],
            2,
            OnBatchError::Continue,
            BatchExpectedResult::AllSuccess,
        );
        assert!(!tc.has_dependencies());
    }

    #[test]
    fn batch_test_case_empty_ops() {
        let tc = BatchTestCase::new("e", vec![], 1, OnBatchError::Stop, BatchExpectedResult::AllSuccess);
        assert_eq!(tc.operation_count(), 0);
        assert!(!tc.has_dependencies());
    }

    #[test]
    fn batch_test_case_serde_roundtrip() {
        let tc = BatchTestCase::new("r", vec![], 1, OnBatchError::Continue, BatchExpectedResult::AllFail);
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: BatchTestCase = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "r");
    }

    #[test]
    fn batch_test_case_clone() {
        let tc = BatchTestCase::new("cl", vec![], 1, OnBatchError::Stop, BatchExpectedResult::AllSuccess);
        let cloned = tc.clone();
        assert_eq!(cloned.name, "cl");
    }

    // ── ResultType ───────────────────────────────────────────────

    #[test]
    fn result_type_display_scalar() {
        assert_eq!(ResultType::Scalar.to_string(), "scalar");
    }

    #[test]
    fn result_type_display_array() {
        assert_eq!(ResultType::Array.to_string(), "array");
    }

    #[test]
    fn result_type_display_stream() {
        assert_eq!(ResultType::Stream.to_string(), "stream");
    }

    #[test]
    fn result_type_display_paginated() {
        assert_eq!(ResultType::Paginated.to_string(), "paginated");
    }

    #[test]
    fn result_type_serde_roundtrip() {
        let r = ResultType::Paginated;
        let json_str = serde_json::to_string(&r).unwrap();
        let back: ResultType = serde_json::from_str(&json_str).unwrap();
        assert_eq!(r, back);
    }

    // ── ResultHandleTestCase ─────────────────────────────────────

    #[test]
    fn result_handle_test_case_new() {
        let tc = ResultHandleTestCase::new("test", ResultType::Scalar, "json");
        assert_eq!(tc.name, "test");
        assert_eq!(tc.expected_format, "json");
    }

    #[test]
    fn result_handle_test_case_is_streaming() {
        let tc = ResultHandleTestCase::new("t", ResultType::Stream, "ndjson");
        assert!(tc.is_streaming());
        assert!(!tc.is_paginated());
    }

    #[test]
    fn result_handle_test_case_is_paginated() {
        let tc = ResultHandleTestCase::new("t", ResultType::Paginated, "json");
        assert!(tc.is_paginated());
        assert!(!tc.is_streaming());
    }

    #[test]
    fn result_handle_test_case_scalar_not_streaming() {
        let tc = ResultHandleTestCase::new("t", ResultType::Scalar, "json");
        assert!(!tc.is_streaming());
        assert!(!tc.is_paginated());
    }

    #[test]
    fn result_handle_test_case_serde_roundtrip() {
        let tc = ResultHandleTestCase::new("r", ResultType::Array, "csv");
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: ResultHandleTestCase = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "r");
        assert_eq!(back.expected_format, "csv");
    }

    #[test]
    fn result_handle_test_case_clone() {
        let tc = ResultHandleTestCase::new("cl", ResultType::Scalar, "text");
        let cloned = tc.clone();
        assert_eq!(cloned.name, "cl");
    }

    // ── Matrix builders ──────────────────────────────────────────

    #[test]
    fn build_invoke_matrix_has_at_least_20() {
        let cases = build_invoke_matrix();
        assert!(cases.len() >= 20, "got {}", cases.len());
    }

    #[test]
    fn build_invoke_matrix_unique_names() {
        let cases = build_invoke_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_invoke_matrix_has_success_cases() {
        let cases = build_invoke_matrix();
        assert!(cases.iter().any(|c| c.expected_status == InvokeExpectedStatus::Success));
    }

    #[test]
    fn build_invoke_matrix_has_error_cases() {
        let cases = build_invoke_matrix();
        assert!(cases.iter().any(|c| c.expected_status == InvokeExpectedStatus::Error));
    }

    #[test]
    fn build_invoke_matrix_has_timeout_cases() {
        let cases = build_invoke_matrix();
        assert!(cases.iter().any(|c| c.expected_status == InvokeExpectedStatus::Timeout));
    }

    #[test]
    fn build_invoke_matrix_has_auth_error_cases() {
        let cases = build_invoke_matrix();
        assert!(cases.iter().any(|c| c.name.contains("auth")));
    }

    #[test]
    fn build_invoke_matrix_has_rate_limit_cases() {
        let cases = build_invoke_matrix();
        assert!(cases.iter().any(|c| c.name.contains("rate_limit")));
    }

    #[test]
    fn build_simulate_matrix_has_at_least_10() {
        let cases = build_simulate_matrix();
        assert!(cases.len() >= 10, "got {}", cases.len());
    }

    #[test]
    fn build_simulate_matrix_unique_names() {
        let cases = build_simulate_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_simulate_matrix_all_side_effect_free() {
        let cases = build_simulate_matrix();
        assert!(cases.iter().all(|c| c.expected_side_effects_none));
    }

    #[test]
    fn build_batch_matrix_has_at_least_10() {
        let cases = build_batch_matrix();
        assert!(cases.len() >= 10, "got {}", cases.len());
    }

    #[test]
    fn build_batch_matrix_unique_names() {
        let cases = build_batch_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_batch_matrix_covers_all_error_strategies() {
        let cases = build_batch_matrix();
        let strategies: std::collections::HashSet<_> = cases.iter().map(|c| &c.on_error).collect();
        assert!(strategies.contains(&OnBatchError::Stop));
        assert!(strategies.contains(&OnBatchError::Continue));
        assert!(strategies.contains(&OnBatchError::SkipDependents));
    }

    #[test]
    fn build_batch_matrix_covers_all_expected_results() {
        let cases = build_batch_matrix();
        let results: std::collections::HashSet<_> = cases.iter().map(|c| &c.expected_results).collect();
        assert!(results.contains(&BatchExpectedResult::AllSuccess));
        assert!(results.contains(&BatchExpectedResult::PartialSuccess));
        assert!(results.contains(&BatchExpectedResult::AllFail));
    }

    #[test]
    fn build_batch_matrix_has_dependency_cases() {
        let cases = build_batch_matrix();
        assert!(cases.iter().any(|c| c.has_dependencies()));
    }

    #[test]
    fn build_batch_matrix_has_no_dependency_cases() {
        let cases = build_batch_matrix();
        assert!(cases.iter().any(|c| !c.has_dependencies()));
    }

    #[test]
    fn build_result_handle_matrix_has_at_least_8() {
        let cases = build_result_handle_matrix();
        assert!(cases.len() >= 8, "got {}", cases.len());
    }

    #[test]
    fn build_result_handle_matrix_unique_names() {
        let cases = build_result_handle_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_result_handle_matrix_covers_all_types() {
        let cases = build_result_handle_matrix();
        let types: std::collections::HashSet<_> = cases.iter().map(|c| &c.result_type).collect();
        assert!(types.contains(&ResultType::Scalar));
        assert!(types.contains(&ResultType::Array));
        assert!(types.contains(&ResultType::Stream));
        assert!(types.contains(&ResultType::Paginated));
    }

    // ── Validators ───────────────────────────────────────────────

    #[test]
    fn validate_invoke_result_success_with_fields() {
        let case = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Success, vec!["repos".into()], None);
        let output = json!({"status": "success", "repos": [1, 2, 3]});
        assert!(validate_invoke_result(&case, &output));
    }

    #[test]
    fn validate_invoke_result_success_ok_status() {
        let case = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Success, vec![], None);
        let output = json!({"status": "ok"});
        assert!(validate_invoke_result(&case, &output));
    }

    #[test]
    fn validate_invoke_result_success_missing_field() {
        let case = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Success, vec!["missing".into()], None);
        let output = json!({"status": "success"});
        assert!(!validate_invoke_result(&case, &output));
    }

    #[test]
    fn validate_invoke_result_success_field_in_data() {
        let case = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Success, vec!["repos".into()], None);
        let output = json!({"status": "success", "data": {"repos": []}});
        assert!(validate_invoke_result(&case, &output));
    }

    #[test]
    fn validate_invoke_result_error_with_code() {
        let case = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Error, vec![], Some("not_found".into()));
        let output = json!({"status": "error", "error_code": "not_found"});
        assert!(validate_invoke_result(&case, &output));
    }

    #[test]
    fn validate_invoke_result_error_wrong_code() {
        let case = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Error, vec![], Some("not_found".into()));
        let output = json!({"status": "error", "error_code": "other"});
        assert!(!validate_invoke_result(&case, &output));
    }

    #[test]
    fn validate_invoke_result_error_no_code_expected() {
        let case = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Error, vec![], None);
        let output = json!({"status": "error"});
        assert!(validate_invoke_result(&case, &output));
    }

    #[test]
    fn validate_invoke_result_timeout() {
        let case = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Timeout, vec![], None);
        let output = json!({"status": "timeout"});
        assert!(validate_invoke_result(&case, &output));
    }

    #[test]
    fn validate_invoke_result_timeout_as_error() {
        let case = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Timeout, vec![], None);
        let output = json!({"status": "error"});
        assert!(validate_invoke_result(&case, &output));
    }

    #[test]
    fn validate_invoke_result_wrong_status() {
        let case = InvokeTestCase::new("t", "c", "o", json!({}), InvokeExpectedStatus::Success, vec![], None);
        let output = json!({"status": "error"});
        assert!(!validate_invoke_result(&case, &output));
    }

    #[test]
    fn validate_simulate_result_with_fields() {
        let case = SimulateTestCase::new("t", "c", "o", json!({}), vec!["would_create".into()], true);
        let output = json!({"would_create": true, "side_effects": false});
        assert!(validate_simulate_result(&case, &output));
    }

    #[test]
    fn validate_simulate_result_missing_field() {
        let case = SimulateTestCase::new("t", "c", "o", json!({}), vec!["missing".into()], true);
        let output = json!({"side_effects": false});
        assert!(!validate_simulate_result(&case, &output));
    }

    #[test]
    fn validate_simulate_result_side_effects_present() {
        let case = SimulateTestCase::new("t", "c", "o", json!({}), vec![], true);
        let output = json!({"side_effects": true});
        assert!(!validate_simulate_result(&case, &output));
    }

    #[test]
    fn validate_simulate_result_side_effects_allowed() {
        let case = SimulateTestCase::new("t", "c", "o", json!({}), vec![], false);
        let output = json!({"side_effects": true});
        assert!(validate_simulate_result(&case, &output));
    }

    #[test]
    fn validate_batch_result_all_success() {
        let case = BatchTestCase::new("t", vec![BatchOp::new("c", "o", json!({}), None)], 1, OnBatchError::Stop, BatchExpectedResult::AllSuccess);
        let output = json!({"results": [{"status": "success"}]});
        assert!(validate_batch_result(&case, &output));
    }

    #[test]
    fn validate_batch_result_all_success_ok_status() {
        let case = BatchTestCase::new("t", vec![BatchOp::new("c", "o", json!({}), None)], 1, OnBatchError::Stop, BatchExpectedResult::AllSuccess);
        let output = json!({"results": [{"status": "ok"}]});
        assert!(validate_batch_result(&case, &output));
    }

    #[test]
    fn validate_batch_result_all_success_but_has_error() {
        let case = BatchTestCase::new("t", vec![], 1, OnBatchError::Stop, BatchExpectedResult::AllSuccess);
        let output = json!({"results": [{"status": "success"}, {"status": "error"}]});
        assert!(!validate_batch_result(&case, &output));
    }

    #[test]
    fn validate_batch_result_partial_success() {
        let case = BatchTestCase::new("t", vec![], 1, OnBatchError::Continue, BatchExpectedResult::PartialSuccess);
        let output = json!({"results": [{"status": "success"}, {"status": "error"}]});
        assert!(validate_batch_result(&case, &output));
    }

    #[test]
    fn validate_batch_result_all_fail() {
        let case = BatchTestCase::new("t", vec![], 1, OnBatchError::Stop, BatchExpectedResult::AllFail);
        let output = json!({"results": [{"status": "error"}, {"status": "error"}]});
        assert!(validate_batch_result(&case, &output));
    }

    #[test]
    fn validate_batch_result_empty_all_success() {
        let case = BatchTestCase::new("t", vec![], 1, OnBatchError::Stop, BatchExpectedResult::AllSuccess);
        let output = json!({"results": null});
        assert!(validate_batch_result(&case, &output));
    }

    #[test]
    fn validate_batch_result_empty_no_results_field() {
        let case = BatchTestCase::new("t", vec![], 1, OnBatchError::Stop, BatchExpectedResult::AllSuccess);
        let output = json!({});
        assert!(validate_batch_result(&case, &output));
    }

    // ── Formatting ───────────────────────────────────────────────

    #[test]
    fn format_invoke_matrix_toon_contains_header() {
        let cases = build_invoke_matrix();
        let toon = format_invoke_matrix_toon(&cases);
        assert!(toon.contains("Invoke Test Matrix"));
    }

    #[test]
    fn format_invoke_matrix_toon_contains_case_names() {
        let cases = build_invoke_matrix();
        let toon = format_invoke_matrix_toon(&cases);
        for case in &cases {
            assert!(toon.contains(&case.name), "missing case: {}", case.name);
        }
    }

    #[test]
    fn format_invoke_matrix_toon_not_empty() {
        let cases = build_invoke_matrix();
        let toon = format_invoke_matrix_toon(&cases);
        assert!(!toon.is_empty());
    }

    #[test]
    fn format_simulate_matrix_toon_contains_header() {
        let cases = build_simulate_matrix();
        let toon = format_simulate_matrix_toon(&cases);
        assert!(toon.contains("Simulate Test Matrix"));
    }

    #[test]
    fn format_simulate_matrix_toon_not_empty() {
        let cases = build_simulate_matrix();
        let toon = format_simulate_matrix_toon(&cases);
        assert!(!toon.is_empty());
    }

    #[test]
    fn format_batch_matrix_toon_contains_header() {
        let cases = build_batch_matrix();
        let toon = format_batch_matrix_toon(&cases);
        assert!(toon.contains("Batch Test Matrix"));
    }

    #[test]
    fn format_batch_matrix_toon_not_empty() {
        let cases = build_batch_matrix();
        let toon = format_batch_matrix_toon(&cases);
        assert!(!toon.is_empty());
    }

    // ── Cross-module consistency ─────────────────────────────────

    #[test]
    fn invoke_matrix_connectors_not_empty() {
        let cases = build_invoke_matrix();
        for case in &cases {
            assert!(!case.connector.is_empty(), "case {} has empty connector", case.name);
        }
    }

    #[test]
    fn invoke_matrix_operations_not_empty() {
        let cases = build_invoke_matrix();
        for case in &cases {
            assert!(!case.operation.is_empty(), "case {} has empty operation", case.name);
        }
    }

    #[test]
    fn simulate_matrix_connectors_not_empty() {
        let cases = build_simulate_matrix();
        for case in &cases {
            assert!(!case.connector.is_empty(), "case {} has empty connector", case.name);
        }
    }

    #[test]
    fn batch_matrix_ops_connectors_not_empty() {
        let cases = build_batch_matrix();
        for case in &cases {
            for op in &case.operations {
                assert!(!op.connector.is_empty(), "case {} has op with empty connector", case.name);
            }
        }
    }

    #[test]
    fn result_handle_matrix_formats_not_empty() {
        let cases = build_result_handle_matrix();
        for case in &cases {
            assert!(!case.expected_format.is_empty(), "case {} has empty format", case.name);
        }
    }
}
