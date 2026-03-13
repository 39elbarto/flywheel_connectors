//! Agent playbooks for plan/task/session/pipeline documentation contract (bead 21.3).
//!
//! Encodes agent-focused workflows as testable structures so that agent
//! integration documentation stays in sync with FWC capabilities.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

/// A single step in an agent workflow.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Human-readable description of this step.
    pub description: String,
    /// The FWC command template (may contain `{placeholders}`).
    pub command_template: String,
    /// Shape of the expected output (e.g. "JSON array of operation names").
    pub expected_output_shape: String,
    /// What to do if this step fails.
    pub fallback: String,
}

/// Complexity classification for agent playbooks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookComplexity {
    /// Simple, single-connector operations.
    Simple,
    /// Moderate, may involve multiple operations or connectors.
    Moderate,
    /// Advanced, involves pipelines, error handling, and recovery.
    Advanced,
}

impl PlaybookComplexity {
    /// Short lowercase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Moderate => "moderate",
            Self::Advanced => "advanced",
        }
    }

    /// Parse from lowercase label.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "simple" => Some(Self::Simple),
            "moderate" => Some(Self::Moderate),
            "advanced" => Some(Self::Advanced),
            _ => None,
        }
    }
}

impl std::fmt::Display for PlaybookComplexity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A playbook describing a complete agent workflow with FWC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentPlaybook {
    /// Unique identifier.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// What the agent is trying to accomplish.
    pub goal: String,
    /// Ordered workflow steps.
    pub workflow_steps: Vec<WorkflowStep>,
    /// Approximate token budget hint for an LLM agent.
    pub token_budget_hint: u32,
    /// Complexity classification.
    pub complexity: PlaybookComplexity,
}

/// A reusable agent pattern with best practices.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentPattern {
    /// Name of the pattern.
    pub name: String,
    /// What this pattern is for.
    pub description: String,
    /// When to use this pattern.
    pub when_to_use: String,
    /// Example step sequence.
    pub example_flow: Vec<String>,
    /// Common mistakes to avoid.
    pub anti_patterns: Vec<String>,
}

// ── Playbook Data ────────────────────────────────────────────────────────────

/// Returns at least 10 agent playbooks.
#[must_use]
pub fn get_agent_playbooks() -> Vec<AgentPlaybook> {
    vec![
        AgentPlaybook {
            id: "agent-001".into(),
            title: "Discover and Invoke".into(),
            goal: "Find a relevant connector and invoke an operation".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Search for connectors matching the user's intent".into(),
                    command_template: "fwc search {query} --format json".into(),
                    expected_output_shape: "JSON array with connector_id, operation, score".into(),
                    fallback: "Broaden the search query or try catalog browsing".into(),
                },
                WorkflowStep {
                    description: "Get the operation schema to understand required inputs".into(),
                    command_template: "fwc schema {connector} {operation} --format json".into(),
                    expected_output_shape: "JSON object with input_schema and output_schema".into(),
                    fallback: "Use introspect to see all available operations".into(),
                },
                WorkflowStep {
                    description: "Invoke the operation with constructed input".into(),
                    command_template: "fwc invoke {connector} {operation} --input '{input_json}'".into(),
                    expected_output_shape: "JSON response with status and output payload".into(),
                    fallback: "Check error message, fix input, and retry".into(),
                },
            ],
            token_budget_hint: 2000,
            complexity: PlaybookComplexity::Simple,
        },
        AgentPlaybook {
            id: "agent-002".into(),
            title: "Batch Data Collection".into(),
            goal: "Collect data from multiple operations in parallel".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Introspect the connector for available list operations".into(),
                    command_template: "fwc introspect {connector} --format json".into(),
                    expected_output_shape: "JSON array of OperationInfo entries".into(),
                    fallback: "Search for the connector if name is uncertain".into(),
                },
                WorkflowStep {
                    description: "Prepare a batch file with all desired operations".into(),
                    command_template: "fwc batch {batch_file} --parallel 4 --format json".into(),
                    expected_output_shape: "JSON array of invocation results".into(),
                    fallback: "Reduce parallelism if rate-limited".into(),
                },
                WorkflowStep {
                    description: "Extract key fields from results".into(),
                    command_template: "fwc extract '.results[] | .output.items' --input '{batch_output}'".into(),
                    expected_output_shape: "Filtered JSON array".into(),
                    fallback: "Adjust jq expression for the actual output shape".into(),
                },
            ],
            token_budget_hint: 3000,
            complexity: PlaybookComplexity::Moderate,
        },
        AgentPlaybook {
            id: "agent-003".into(),
            title: "Pipeline Chain".into(),
            goal: "Execute a multi-step pipeline across connectors".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Validate the pipeline definition".into(),
                    command_template: "fwc pipeline validate {pipeline_file}".into(),
                    expected_output_shape: "Validation result: ok or error list".into(),
                    fallback: "Fix pipeline syntax errors".into(),
                },
                WorkflowStep {
                    description: "Dry-run the pipeline".into(),
                    command_template: "fwc pipeline run {pipeline_file} --dry-run --format json".into(),
                    expected_output_shape: "Simulated pipeline execution plan".into(),
                    fallback: "Fix step errors in dry-run output".into(),
                },
                WorkflowStep {
                    description: "Execute the pipeline".into(),
                    command_template: "fwc pipeline run {pipeline_file} --format json".into(),
                    expected_output_shape: "Pipeline execution results with per-step outputs".into(),
                    fallback: "Check failed step index, fix, and re-run".into(),
                },
                WorkflowStep {
                    description: "Format results with a template".into(),
                    command_template: "fwc template apply {template_file} --data '{pipeline_output}'".into(),
                    expected_output_shape: "Formatted human-readable output".into(),
                    fallback: "Use raw JSON output if template fails".into(),
                },
            ],
            token_budget_hint: 4000,
            complexity: PlaybookComplexity::Advanced,
        },
        AgentPlaybook {
            id: "agent-004".into(),
            title: "Error Recovery Workflow".into(),
            goal: "Detect, diagnose, and recover from operation failures".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Check recent invocation history for failures".into(),
                    command_template: "fwc history --connector {connector} --limit 20 --format json".into(),
                    expected_output_shape: "JSON array with status field per entry".into(),
                    fallback: "Broaden time window if no results".into(),
                },
                WorkflowStep {
                    description: "Get detailed trace for the failing request".into(),
                    command_template: "fwc trace {request_id} --format json".into(),
                    expected_output_shape: "Distributed trace with timing and error details".into(),
                    fallback: "Check events if trace is unavailable".into(),
                },
                WorkflowStep {
                    description: "Check connector health".into(),
                    command_template: "fwc health --connector {connector} --format json".into(),
                    expected_output_shape: "Health status with checks and latency".into(),
                    fallback: "Run fwc doctor for broader diagnostics".into(),
                },
                WorkflowStep {
                    description: "Replay the failed operation".into(),
                    command_template: "fwc replay {entry_id} --format json".into(),
                    expected_output_shape: "New invocation result".into(),
                    fallback: "If replay also fails, the issue is persistent".into(),
                },
            ],
            token_budget_hint: 3000,
            complexity: PlaybookComplexity::Moderate,
        },
        AgentPlaybook {
            id: "agent-005".into(),
            title: "Schema-Driven Input Construction".into(),
            goal: "Construct valid operation input from schema inspection".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Get the input schema".into(),
                    command_template: "fwc schema {connector} {operation} --format json".into(),
                    expected_output_shape: "JSON Schema for input".into(),
                    fallback: "Try introspect if schema is not available".into(),
                },
                WorkflowStep {
                    description: "Identify required fields from the schema".into(),
                    command_template: "fwc extract '.input_schema.required' --input '{schema_output}'".into(),
                    expected_output_shape: "Array of required field names".into(),
                    fallback: "Parse schema manually for required fields".into(),
                },
                WorkflowStep {
                    description: "Construct and invoke with minimal valid input".into(),
                    command_template: "fwc invoke {connector} {operation} --input '{constructed_input}'".into(),
                    expected_output_shape: "Successful invocation result".into(),
                    fallback: "Examine error for missing or invalid fields, fix and retry".into(),
                },
            ],
            token_budget_hint: 2500,
            complexity: PlaybookComplexity::Simple,
        },
        AgentPlaybook {
            id: "agent-006".into(),
            title: "Cross-Connector Data Sync".into(),
            goal: "Read from one connector and write to another".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Read data from source connector".into(),
                    command_template: "fwc invoke {source_connector} {list_op} --input '{}' --format json".into(),
                    expected_output_shape: "JSON array of source records".into(),
                    fallback: "Check source connector health and credentials".into(),
                },
                WorkflowStep {
                    description: "Get target operation schema".into(),
                    command_template: "fwc schema {target_connector} {create_op} --format json".into(),
                    expected_output_shape: "JSON Schema for create input".into(),
                    fallback: "Introspect target connector for available write ops".into(),
                },
                WorkflowStep {
                    description: "Transform and write each record".into(),
                    command_template: "fwc invoke {target_connector} {create_op} --input '{transformed_record}'".into(),
                    expected_output_shape: "Created record confirmation".into(),
                    fallback: "Log failed records and continue with remaining".into(),
                },
                WorkflowStep {
                    description: "Verify sync by comparing counts".into(),
                    command_template: "fwc invoke {target_connector} {count_op} --input '{}' --format json".into(),
                    expected_output_shape: "Count matching source records".into(),
                    fallback: "Manually compare source and target lists".into(),
                },
            ],
            token_budget_hint: 5000,
            complexity: PlaybookComplexity::Advanced,
        },
        AgentPlaybook {
            id: "agent-007".into(),
            title: "Progressive Discovery".into(),
            goal: "Systematically explore available connectors and capabilities".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "List all available connectors".into(),
                    command_template: "fwc catalog --format json".into(),
                    expected_output_shape: "JSON array of connector summaries".into(),
                    fallback: "Search with a broad query".into(),
                },
                WorkflowStep {
                    description: "Introspect a specific connector".into(),
                    command_template: "fwc introspect {connector} --format json".into(),
                    expected_output_shape: "JSON array of operations with metadata".into(),
                    fallback: "Try a different connector if introspection fails".into(),
                },
                WorkflowStep {
                    description: "Get schema for interesting operations".into(),
                    command_template: "fwc schema {connector} {operation} --format json".into(),
                    expected_output_shape: "Detailed input/output schema".into(),
                    fallback: "Some operations may not have detailed schemas".into(),
                },
            ],
            token_budget_hint: 1500,
            complexity: PlaybookComplexity::Simple,
        },
        AgentPlaybook {
            id: "agent-008".into(),
            title: "Credential Setup and Validation".into(),
            goal: "Set up credentials for a connector and validate they work".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Store the API credential".into(),
                    command_template: "fwc credential set {connector} --token {token}".into(),
                    expected_output_shape: "Success confirmation".into(),
                    fallback: "Run fwc doctor --fix if credential store is broken".into(),
                },
                WorkflowStep {
                    description: "Verify the credential is accepted".into(),
                    command_template: "fwc credential verify {connector}".into(),
                    expected_output_shape: "Verification result: valid or invalid".into(),
                    fallback: "Re-check token scopes and expiration".into(),
                },
                WorkflowStep {
                    description: "Test with a read-only operation".into(),
                    command_template: "fwc invoke {connector} {safe_read_op} --input '{}' --format json".into(),
                    expected_output_shape: "Successful response with data".into(),
                    fallback: "Check connector health and network connectivity".into(),
                },
            ],
            token_budget_hint: 1500,
            complexity: PlaybookComplexity::Simple,
        },
        AgentPlaybook {
            id: "agent-009".into(),
            title: "Undo and Rollback".into(),
            goal: "Reverse a previous operation using the undo capability".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Find the invocation to undo in history".into(),
                    command_template: "fwc history --connector {connector} --limit 10 --format json".into(),
                    expected_output_shape: "Recent invocations with entry IDs".into(),
                    fallback: "Broaden search or check different connector".into(),
                },
                WorkflowStep {
                    description: "Check if the operation supports undo".into(),
                    command_template: "fwc schema {connector} {operation} --format json".into(),
                    expected_output_shape: "Schema with idempotency and undo metadata".into(),
                    fallback: "Not all operations support undo; manual reversal may be needed".into(),
                },
                WorkflowStep {
                    description: "Execute the undo".into(),
                    command_template: "fwc undo {entry_id}".into(),
                    expected_output_shape: "Undo confirmation with reversal details".into(),
                    fallback: "If undo fails, use the original operation to manually revert".into(),
                },
            ],
            token_budget_hint: 2000,
            complexity: PlaybookComplexity::Moderate,
        },
        AgentPlaybook {
            id: "agent-010".into(),
            title: "Health-Gated Invocation".into(),
            goal: "Check connector health before invoking, with fallback routing".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Check target connector health".into(),
                    command_template: "fwc health --connector {connector} --format json".into(),
                    expected_output_shape: "Health status: healthy, degraded, or unhealthy".into(),
                    fallback: "If health check itself fails, assume unhealthy".into(),
                },
                WorkflowStep {
                    description: "If healthy, invoke the operation".into(),
                    command_template: "fwc invoke {connector} {operation} --input '{input}' --format json".into(),
                    expected_output_shape: "Operation result".into(),
                    fallback: "If unhealthy, search for alternative connectors".into(),
                },
                WorkflowStep {
                    description: "Search for fallback connectors if primary is unhealthy".into(),
                    command_template: "fwc search {operation_name} --format json".into(),
                    expected_output_shape: "Alternative connectors offering the same operation".into(),
                    fallback: "Report failure if no alternatives found".into(),
                },
                WorkflowStep {
                    description: "Invoke on fallback connector".into(),
                    command_template: "fwc invoke {fallback_connector} {operation} --input '{input}' --format json".into(),
                    expected_output_shape: "Operation result from fallback".into(),
                    fallback: "Report that all connectors are unavailable".into(),
                },
            ],
            token_budget_hint: 3000,
            complexity: PlaybookComplexity::Moderate,
        },
        AgentPlaybook {
            id: "agent-011".into(),
            title: "Template-Based Reporting".into(),
            goal: "Generate a formatted report from operation output".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Invoke the data-gathering operation".into(),
                    command_template: "fwc invoke {connector} {operation} --input '{input}' --format json".into(),
                    expected_output_shape: "Raw operation output".into(),
                    fallback: "Check connector health and retry".into(),
                },
                WorkflowStep {
                    description: "Apply a report template".into(),
                    command_template: "fwc template apply {template} --data '{data}'".into(),
                    expected_output_shape: "Formatted report text".into(),
                    fallback: "Use extract for simpler formatting".into(),
                },
            ],
            token_budget_hint: 2000,
            complexity: PlaybookComplexity::Simple,
        },
        AgentPlaybook {
            id: "agent-012".into(),
            title: "Plan: Natural-Language Goal to Workflow".into(),
            goal: "Convert a high-level goal into concrete fwc steps".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Compile the goal into a plan".into(),
                    command_template: "fwc plan '{goal}' --format json".into(),
                    expected_output_shape: "JSON array of planned steps with connectors and operations".into(),
                    fallback: "If plan fails, use search to find relevant operations manually".into(),
                },
                WorkflowStep {
                    description: "Review the plan before execution".into(),
                    command_template: "fwc explain '{goal}' --format json".into(),
                    expected_output_shape: "Explanation of why each step was chosen".into(),
                    fallback: "Manually inspect each operation's schema".into(),
                },
                WorkflowStep {
                    description: "Execute the plan with simulation first".into(),
                    command_template: "fwc do '{goal}' --dry-run --format json".into(),
                    expected_output_shape: "Simulated results for each step".into(),
                    fallback: "Execute steps individually with fwc invoke".into(),
                },
                WorkflowStep {
                    description: "Execute the plan for real".into(),
                    command_template: "fwc do '{goal}' --format json".into(),
                    expected_output_shape: "Actual execution results with history entries".into(),
                    fallback: "Fall back to individual invocations for failed steps".into(),
                },
            ],
            token_budget_hint: 4000,
            complexity: PlaybookComplexity::Advanced,
        },
        AgentPlaybook {
            id: "agent-013".into(),
            title: "Task: Durable Workflow Capsule".into(),
            goal: "Create and manage a resumable multi-step task".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Create a task capsule from a goal".into(),
                    command_template: "fwc task create --goal '{goal}' --format json".into(),
                    expected_output_shape: "Task handle and initial step list".into(),
                    fallback: "Break goal into individual operations manually".into(),
                },
                WorkflowStep {
                    description: "Check task status".into(),
                    command_template: "fwc task show {task_handle} --format json".into(),
                    expected_output_shape: "Current step, completed steps, pending steps".into(),
                    fallback: "Use fwc task list to find the handle".into(),
                },
                WorkflowStep {
                    description: "Advance the task to the next step".into(),
                    command_template: "fwc task advance {task_handle} --format json".into(),
                    expected_output_shape: "Result of the current step and next action".into(),
                    fallback: "If step needs approval, use fwc task approve".into(),
                },
                WorkflowStep {
                    description: "Resume a paused task".into(),
                    command_template: "fwc task run {task_handle} --format json".into(),
                    expected_output_shape: "Execution results and completion status".into(),
                    fallback: "Resolve any blockers shown in task show output".into(),
                },
            ],
            token_budget_hint: 3500,
            complexity: PlaybookComplexity::Advanced,
        },
        AgentPlaybook {
            id: "agent-014".into(),
            title: "Session: Persistent Agent Context".into(),
            goal: "Track work across multiple operations in a session".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "Start a new session".into(),
                    command_template: "fwc session start --name '{session_name}' --format json".into(),
                    expected_output_shape: "Session handle and context snapshot".into(),
                    fallback: "Continue without session tracking".into(),
                },
                WorkflowStep {
                    description: "Perform operations within the session".into(),
                    command_template: "fwc invoke {connector} {operation} --input '{input}' --format json".into(),
                    expected_output_shape: "Operation result, automatically linked to session".into(),
                    fallback: "Each invocation is recorded in history with session context".into(),
                },
                WorkflowStep {
                    description: "Review session history".into(),
                    command_template: "fwc session show {session_handle} --format json".into(),
                    expected_output_shape: "All operations performed in this session".into(),
                    fallback: "Use fwc history with time range matching session start".into(),
                },
                WorkflowStep {
                    description: "End or resume the session".into(),
                    command_template: "fwc session end {session_handle} --format json".into(),
                    expected_output_shape: "Session summary with operation count and outcomes".into(),
                    fallback: "Session can be resumed later with fwc session resume".into(),
                },
            ],
            token_budget_hint: 2500,
            complexity: PlaybookComplexity::Moderate,
        },
        AgentPlaybook {
            id: "agent-015".into(),
            title: "Pipeline: Multi-Step Workflow from TOML".into(),
            goal: "Define and execute a reusable multi-step pipeline".into(),
            workflow_steps: vec![
                WorkflowStep {
                    description: "List available pipeline definitions".into(),
                    command_template: "fwc pipeline list --format json".into(),
                    expected_output_shape: "JSON array of pipeline names and descriptions".into(),
                    fallback: "Check the pipelines/ directory for .toml files".into(),
                },
                WorkflowStep {
                    description: "Validate the pipeline before running".into(),
                    command_template: "fwc pipeline validate {pipeline_file} --format json".into(),
                    expected_output_shape: "Validation result with any errors or warnings".into(),
                    fallback: "Fix TOML syntax or schema errors in the pipeline file".into(),
                },
                WorkflowStep {
                    description: "Preview the pipeline without executing".into(),
                    command_template: "fwc pipeline dry-run {pipeline_file} --format json".into(),
                    expected_output_shape: "Simulated results for each pipeline step".into(),
                    fallback: "Check individual operations with fwc simulate".into(),
                },
                WorkflowStep {
                    description: "Execute the pipeline".into(),
                    command_template: "fwc pipeline run {pipeline_file} --format json".into(),
                    expected_output_shape: "Step-by-step results with receipt handles".into(),
                    fallback: "If a step fails, check fwc history for the failing operation".into(),
                },
            ],
            token_budget_hint: 3000,
            complexity: PlaybookComplexity::Moderate,
        },
    ]
}

/// Returns at least 8 agent patterns with best practices.
#[must_use]
pub fn get_agent_patterns() -> Vec<AgentPattern> {
    vec![
        AgentPattern {
            name: "Progressive Discovery".into(),
            description: "Start broad, narrow down to specific operations".into(),
            when_to_use: "When you don't know which connector or operation to use".into(),
            example_flow: vec![
                "fwc catalog --format json".into(),
                "fwc search 'user management' --format json".into(),
                "fwc introspect okta --format json".into(),
                "fwc schema okta list_users --format json".into(),
            ],
            anti_patterns: vec![
                "Trying to invoke without checking the schema first".into(),
                "Hardcoding connector names without searching".into(),
            ],
        },
        AgentPattern {
            name: "Fail-Fast Validation".into(),
            description: "Validate inputs and preconditions before executing".into(),
            when_to_use: "Before any mutating operation or pipeline execution".into(),
            example_flow: vec![
                "fwc schema connector op --format json".into(),
                "Validate input matches schema".into(),
                "fwc health --connector connector --format json".into(),
                "fwc invoke connector op --input '...'".into(),
            ],
            anti_patterns: vec![
                "Invoking without checking schema or health first".into(),
                "Ignoring validation errors and hoping for the best".into(),
            ],
        },
        AgentPattern {
            name: "Token Budget Management".into(),
            description: "Plan workflow steps to stay within token limits".into(),
            when_to_use: "When operating under LLM context window constraints".into(),
            example_flow: vec![
                "Use --format json for machine-parseable output".into(),
                "Use extract to select only needed fields".into(),
                "Limit history queries with --limit".into(),
                "Avoid requesting full schemas when only names are needed".into(),
            ],
            anti_patterns: vec![
                "Requesting full catalog when a targeted search suffices".into(),
                "Not using --limit on history and event queries".into(),
                "Requesting table format when JSON would be more compact".into(),
            ],
        },
        AgentPattern {
            name: "Idempotent Retry".into(),
            description: "Safely retry operations that are marked idempotent".into(),
            when_to_use: "When an invocation fails with a transient error".into(),
            example_flow: vec![
                "Check operation's idempotency_class from schema".into(),
                "If idempotent, retry with same input".into(),
                "If at-most-once, check history before retrying".into(),
                "Use exponential backoff between retries".into(),
            ],
            anti_patterns: vec![
                "Retrying at-most-once operations without checking history".into(),
                "Retrying immediately without backoff".into(),
                "Retrying indefinitely without a max attempt limit".into(),
            ],
        },
        AgentPattern {
            name: "Structured Error Handling".into(),
            description: "Parse and handle errors based on their category".into(),
            when_to_use: "When an invocation returns an error response".into(),
            example_flow: vec![
                "Parse error response JSON for error_code and message".into(),
                "If auth error: re-check credentials".into(),
                "If rate limit: wait and retry".into(),
                "If input error: fix input and retry".into(),
                "If server error: check health and try fallback".into(),
            ],
            anti_patterns: vec![
                "Treating all errors the same way".into(),
                "Not parsing the error response for details".into(),
                "Giving up on the first error without diagnosis".into(),
            ],
        },
        AgentPattern {
            name: "Pipeline Composition".into(),
            description: "Build multi-step workflows from validated components".into(),
            when_to_use: "When a task requires multiple sequential operations".into(),
            example_flow: vec![
                "fwc pipeline validate pipeline.json".into(),
                "fwc pipeline run pipeline.json --dry-run".into(),
                "Review dry-run output for expected behavior".into(),
                "fwc pipeline run pipeline.json".into(),
            ],
            anti_patterns: vec![
                "Running pipelines without validation or dry-run".into(),
                "Building very long pipelines without intermediate checkpoints".into(),
                "Not handling partial pipeline failures".into(),
            ],
        },
        AgentPattern {
            name: "Least Privilege".into(),
            description: "Use the minimum required permissions and scope".into(),
            when_to_use: "Always, especially for write and destructive operations".into(),
            example_flow: vec![
                "Prefer read-only operations when possible".into(),
                "Check safety_tier before invoking".into(),
                "Use --dry-run for destructive operations first".into(),
                "Scope operations to specific zones when available".into(),
            ],
            anti_patterns: vec![
                "Using admin-level operations when user-level suffices".into(),
                "Not checking safety_tier before destructive operations".into(),
                "Operating on all zones when only one is needed".into(),
            ],
        },
        AgentPattern {
            name: "Output Chaining".into(),
            description: "Feed output from one command as input to the next".into(),
            when_to_use: "When building ad-hoc multi-step workflows without a pipeline file".into(),
            example_flow: vec![
                "fwc invoke source list_items --format json > items.json".into(),
                "fwc extract '.items[0].id' --input @items.json".into(),
                "fwc invoke target get_item --input '{\"id\": \"extracted_id\"}'".into(),
            ],
            anti_patterns: vec![
                "Trying to chain commands without JSON format".into(),
                "Not handling empty or null results in the chain".into(),
            ],
        },
        AgentPattern {
            name: "Health-Gated Execution".into(),
            description: "Check connector health before attempting operations".into(),
            when_to_use: "Before critical operations or when reliability matters".into(),
            example_flow: vec![
                "fwc health --connector target --format json".into(),
                "If healthy: proceed with invocation".into(),
                "If degraded: proceed with caution, set shorter timeout".into(),
                "If unhealthy: search for alternative connectors".into(),
            ],
            anti_patterns: vec![
                "Skipping health checks for critical operations".into(),
                "Not having a fallback plan for unhealthy connectors".into(),
            ],
        },
    ]
}

// ── Formatting ───────────────────────────────────────────────────────────────

/// Format an agent playbook as a human-readable string.
#[must_use]
pub fn format_agent_playbook_toon(playbook: &AgentPlaybook) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Agent Playbook: {} ({})", playbook.title, playbook.id);
    let _ = writeln!(out, "Goal: {}", playbook.goal);
    let _ = writeln!(out, "Complexity: {}", playbook.complexity);
    let _ = writeln!(out, "Token budget hint: {}", playbook.token_budget_hint);
    let _ = writeln!(out, "\nWorkflow:");
    for (i, step) in playbook.workflow_steps.iter().enumerate() {
        let _ = writeln!(out, "  {}. {}", i + 1, step.description);
        let _ = writeln!(out, "     $ {}", step.command_template);
        let _ = writeln!(out, "     Expected: {}", step.expected_output_shape);
        let _ = writeln!(out, "     Fallback: {}", step.fallback);
    }
    out
}

/// Format an agent pattern as a human-readable string.
#[must_use]
pub fn format_pattern_toon(pattern: &AgentPattern) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Pattern: {}", pattern.name);
    let _ = writeln!(out, "{}", pattern.description);
    let _ = writeln!(out, "When to use: {}", pattern.when_to_use);

    let _ = writeln!(out, "\nExample flow:");
    for (i, step) in pattern.example_flow.iter().enumerate() {
        let _ = writeln!(out, "  {}. {step}", i + 1);
    }

    if !pattern.anti_patterns.is_empty() {
        let _ = writeln!(out, "\nAnti-patterns:");
        for ap in &pattern.anti_patterns {
            let _ = writeln!(out, "  - {ap}");
        }
    }

    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;

    // ── Playbook count and structure ─────────────────────────────────────

    #[test]
    fn playbooks_has_at_least_10() {
        let pbs = get_agent_playbooks();
        assert!(pbs.len() >= 10, "Only {} playbooks", pbs.len());
    }

    #[test]
    fn playbooks_have_unique_ids() {
        let pbs = get_agent_playbooks();
        let mut ids = std::collections::BTreeSet::new();
        for pb in &pbs {
            assert!(ids.insert(&pb.id), "Duplicate id: {}", pb.id);
        }
    }

    #[test]
    fn playbooks_have_titles() {
        for pb in &get_agent_playbooks() {
            assert!(!pb.title.is_empty(), "Playbook {} missing title", pb.id);
        }
    }

    #[test]
    fn playbooks_have_goals() {
        for pb in &get_agent_playbooks() {
            assert!(!pb.goal.is_empty(), "Playbook {} missing goal", pb.id);
        }
    }

    #[test]
    fn playbooks_have_workflow_steps() {
        for pb in &get_agent_playbooks() {
            assert!(
                !pb.workflow_steps.is_empty(),
                "Playbook {} has no steps",
                pb.id
            );
        }
    }

    #[test]
    fn playbooks_have_positive_token_budget() {
        for pb in &get_agent_playbooks() {
            assert!(
                pb.token_budget_hint > 0,
                "Playbook {} has zero token budget",
                pb.id
            );
        }
    }

    #[test]
    fn playbooks_steps_have_descriptions() {
        for pb in &get_agent_playbooks() {
            for step in &pb.workflow_steps {
                assert!(
                    !step.description.is_empty(),
                    "Step in {} has empty description",
                    pb.id
                );
            }
        }
    }

    #[test]
    fn playbooks_steps_have_command_templates() {
        for pb in &get_agent_playbooks() {
            for step in &pb.workflow_steps {
                assert!(
                    !step.command_template.is_empty(),
                    "Step in {} has empty command",
                    pb.id
                );
            }
        }
    }

    #[test]
    fn playbooks_steps_have_expected_output() {
        for pb in &get_agent_playbooks() {
            for step in &pb.workflow_steps {
                assert!(
                    !step.expected_output_shape.is_empty(),
                    "Step in {} has empty output shape",
                    pb.id
                );
            }
        }
    }

    #[test]
    fn playbooks_steps_have_fallbacks() {
        for pb in &get_agent_playbooks() {
            for step in &pb.workflow_steps {
                assert!(
                    !step.fallback.is_empty(),
                    "Step in {} has empty fallback",
                    pb.id
                );
            }
        }
    }

    #[test]
    fn playbooks_commands_reference_fwc() {
        for pb in &get_agent_playbooks() {
            for step in &pb.workflow_steps {
                assert!(
                    step.command_template.starts_with("fwc"),
                    "Command in {} doesn't start with fwc: {}",
                    pb.id,
                    step.command_template
                );
            }
        }
    }

    #[test]
    fn playbooks_have_at_least_2_steps() {
        for pb in &get_agent_playbooks() {
            assert!(
                pb.workflow_steps.len() >= 2,
                "Playbook {} has only {} steps",
                pb.id,
                pb.workflow_steps.len()
            );
        }
    }

    // ── Complexity enum tests ────────────────────────────────────────────

    #[test]
    fn complexity_as_str_roundtrips() {
        for c in [
            PlaybookComplexity::Simple,
            PlaybookComplexity::Moderate,
            PlaybookComplexity::Advanced,
        ] {
            let s = c.as_str();
            let parsed = PlaybookComplexity::parse(s).unwrap();
            assert_eq!(c, parsed);
        }
    }

    #[test]
    fn complexity_parse_unknown_returns_none() {
        assert!(PlaybookComplexity::parse("unknown").is_none());
        assert!(PlaybookComplexity::parse("").is_none());
    }

    #[test]
    fn complexity_display() {
        assert_eq!(format!("{}", PlaybookComplexity::Simple), "simple");
        assert_eq!(format!("{}", PlaybookComplexity::Advanced), "advanced");
    }

    #[test]
    fn complexity_serialize_deserialize() {
        for c in [
            PlaybookComplexity::Simple,
            PlaybookComplexity::Moderate,
            PlaybookComplexity::Advanced,
        ] {
            let json = serde_json::to_string(&c).unwrap();
            let back: PlaybookComplexity = serde_json::from_str(&json).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn complexity_debug() {
        let dbg = format!("{:?}", PlaybookComplexity::Moderate);
        assert!(dbg.contains("Moderate"));
    }

    #[test]
    fn complexity_clone_eq() {
        let a = PlaybookComplexity::Advanced;
        let b = a;
        assert_eq!(a, b);
    }

    // ── Playbook complexity distribution ─────────────────────────────────

    #[test]
    fn playbooks_have_simple_complexity() {
        let pbs = get_agent_playbooks();
        assert!(
            pbs.iter()
                .any(|pb| pb.complexity == PlaybookComplexity::Simple)
        );
    }

    #[test]
    fn playbooks_have_moderate_complexity() {
        let pbs = get_agent_playbooks();
        assert!(
            pbs.iter()
                .any(|pb| pb.complexity == PlaybookComplexity::Moderate)
        );
    }

    #[test]
    fn playbooks_have_advanced_complexity() {
        let pbs = get_agent_playbooks();
        assert!(
            pbs.iter()
                .any(|pb| pb.complexity == PlaybookComplexity::Advanced)
        );
    }

    // ── Pattern tests ────────────────────────────────────────────────────

    #[test]
    fn patterns_has_at_least_8() {
        let patterns = get_agent_patterns();
        assert!(patterns.len() >= 8, "Only {} patterns", patterns.len());
    }

    #[test]
    fn patterns_have_unique_names() {
        let patterns = get_agent_patterns();
        let mut names = std::collections::BTreeSet::new();
        for p in &patterns {
            assert!(names.insert(&p.name), "Duplicate name: {}", p.name);
        }
    }

    #[test]
    fn patterns_have_descriptions() {
        for p in &get_agent_patterns() {
            assert!(
                !p.description.is_empty(),
                "Pattern {} missing description",
                p.name
            );
        }
    }

    #[test]
    fn patterns_have_when_to_use() {
        for p in &get_agent_patterns() {
            assert!(
                !p.when_to_use.is_empty(),
                "Pattern {} missing when_to_use",
                p.name
            );
        }
    }

    #[test]
    fn patterns_have_example_flows() {
        for p in &get_agent_patterns() {
            assert!(
                !p.example_flow.is_empty(),
                "Pattern {} has no example flow",
                p.name
            );
        }
    }

    #[test]
    fn patterns_have_anti_patterns() {
        for p in &get_agent_patterns() {
            assert!(
                !p.anti_patterns.is_empty(),
                "Pattern {} has no anti-patterns",
                p.name
            );
        }
    }

    #[test]
    fn patterns_example_flows_non_empty_strings() {
        for p in &get_agent_patterns() {
            for s in &p.example_flow {
                assert!(!s.is_empty(), "Empty example in {}", p.name);
            }
        }
    }

    #[test]
    fn patterns_anti_patterns_non_empty_strings() {
        for p in &get_agent_patterns() {
            for ap in &p.anti_patterns {
                assert!(!ap.is_empty(), "Empty anti-pattern in {}", p.name);
            }
        }
    }

    // ── Specific pattern existence ───────────────────────────────────────

    #[test]
    fn pattern_progressive_discovery_exists() {
        let patterns = get_agent_patterns();
        assert!(
            patterns
                .iter()
                .any(|p| p.name.contains("Progressive Discovery"))
        );
    }

    #[test]
    fn pattern_fail_fast_exists() {
        let patterns = get_agent_patterns();
        assert!(patterns.iter().any(|p| p.name.contains("Fail-Fast")));
    }

    #[test]
    fn pattern_token_budget_exists() {
        let patterns = get_agent_patterns();
        assert!(patterns.iter().any(|p| p.name.contains("Token Budget")));
    }

    #[test]
    fn pattern_retry_exists() {
        let patterns = get_agent_patterns();
        assert!(patterns.iter().any(|p| p.name.contains("Retry")));
    }

    #[test]
    fn pattern_error_handling_exists() {
        let patterns = get_agent_patterns();
        assert!(patterns.iter().any(|p| p.name.contains("Error")));
    }

    // ── Serialization ────────────────────────────────────────────────────

    #[test]
    fn playbook_serializes() {
        let pb = &get_agent_playbooks()[0];
        let json = serde_json::to_string(pb).unwrap();
        assert!(json.contains(&pb.id));
    }

    #[test]
    fn playbook_deserializes_roundtrip() {
        let pb = &get_agent_playbooks()[0];
        let json = serde_json::to_string(pb).unwrap();
        let back: AgentPlaybook = serde_json::from_str(&json).unwrap();
        assert_eq!(pb.id, back.id);
        assert_eq!(pb.title, back.title);
    }

    #[test]
    fn pattern_serializes() {
        let p = &get_agent_patterns()[0];
        let json = serde_json::to_string(p).unwrap();
        assert!(json.contains(&p.name));
    }

    #[test]
    fn pattern_deserializes_roundtrip() {
        let p = &get_agent_patterns()[0];
        let json = serde_json::to_string(p).unwrap();
        let back: AgentPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(p.name, back.name);
    }

    #[test]
    fn workflow_step_serializes() {
        let step = &get_agent_playbooks()[0].workflow_steps[0];
        let json = serde_json::to_string(step).unwrap();
        assert!(json.contains("description"));
    }

    #[test]
    fn workflow_step_deserializes_roundtrip() {
        let step = &get_agent_playbooks()[0].workflow_steps[0];
        let json = serde_json::to_string(step).unwrap();
        let back: WorkflowStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step.description, back.description);
    }

    // ── Clone and Debug ──────────────────────────────────────────────────

    #[test]
    fn playbook_clone() {
        let pb = &get_agent_playbooks()[0];
        let cloned = pb.clone();
        assert_eq!(pb.id, cloned.id);
    }

    #[test]
    fn playbook_debug() {
        let pb = &get_agent_playbooks()[0];
        let dbg = format!("{pb:?}");
        assert!(dbg.contains("AgentPlaybook"));
    }

    #[test]
    fn pattern_clone() {
        let p = &get_agent_patterns()[0];
        let cloned = p.clone();
        assert_eq!(p.name, cloned.name);
    }

    #[test]
    fn pattern_debug() {
        let p = &get_agent_patterns()[0];
        let dbg = format!("{p:?}");
        assert!(dbg.contains("AgentPattern"));
    }

    #[test]
    fn workflow_step_clone() {
        let step = &get_agent_playbooks()[0].workflow_steps[0];
        let cloned = step.clone();
        assert_eq!(step.description, cloned.description);
    }

    #[test]
    fn workflow_step_debug() {
        let step = &get_agent_playbooks()[0].workflow_steps[0];
        let dbg = format!("{step:?}");
        assert!(dbg.contains("WorkflowStep"));
    }

    // ── Format tests ─────────────────────────────────────────────────────

    #[test]
    fn format_playbook_toon_contains_title() {
        let pb = &get_agent_playbooks()[0];
        let out = format_agent_playbook_toon(pb);
        assert!(out.contains(&pb.title));
    }

    #[test]
    fn format_playbook_toon_contains_goal() {
        let pb = &get_agent_playbooks()[0];
        let out = format_agent_playbook_toon(pb);
        assert!(out.contains(&pb.goal));
    }

    #[test]
    fn format_playbook_toon_contains_complexity() {
        let pb = &get_agent_playbooks()[0];
        let out = format_agent_playbook_toon(pb);
        assert!(out.contains(pb.complexity.as_str()));
    }

    #[test]
    fn format_playbook_toon_contains_token_budget() {
        let pb = &get_agent_playbooks()[0];
        let out = format_agent_playbook_toon(pb);
        assert!(out.contains(&pb.token_budget_hint.to_string()));
    }

    #[test]
    fn format_playbook_toon_contains_steps() {
        let pb = &get_agent_playbooks()[0];
        let out = format_agent_playbook_toon(pb);
        assert!(out.contains("Workflow:"));
        assert!(out.contains("1."));
    }

    #[test]
    fn format_pattern_toon_contains_name() {
        let p = &get_agent_patterns()[0];
        let out = format_pattern_toon(p);
        assert!(out.contains(&p.name));
    }

    #[test]
    fn format_pattern_toon_contains_when_to_use() {
        let p = &get_agent_patterns()[0];
        let out = format_pattern_toon(p);
        assert!(out.contains("When to use"));
    }

    #[test]
    fn format_pattern_toon_contains_anti_patterns() {
        let p = &get_agent_patterns()[0];
        let out = format_pattern_toon(p);
        assert!(out.contains("Anti-patterns"));
    }

    #[test]
    fn format_pattern_toon_contains_example_flow() {
        let p = &get_agent_patterns()[0];
        let out = format_pattern_toon(p);
        assert!(out.contains("Example flow"));
    }

    // ── All format without panic ─────────────────────────────────────────

    #[test]
    fn all_playbooks_format_without_panic() {
        for pb in &get_agent_playbooks() {
            let out = format_agent_playbook_toon(pb);
            assert!(!out.is_empty());
        }
    }

    #[test]
    fn all_patterns_format_without_panic() {
        for p in &get_agent_patterns() {
            let out = format_pattern_toon(p);
            assert!(!out.is_empty());
        }
    }

    // ── Specific playbook existence ──────────────────────────────────────

    #[test]
    fn playbook_discover_invoke_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Discover")));
    }

    #[test]
    fn playbook_batch_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Batch")));
    }

    #[test]
    fn playbook_pipeline_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Pipeline")));
    }

    #[test]
    fn playbook_error_recovery_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Error Recovery")));
    }

    #[test]
    fn playbook_undo_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Undo")));
    }

    // ── Additional coverage ──────────────────────────────────────────────

    #[test]
    fn playbook_credential_setup_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Credential")));
    }

    #[test]
    fn playbook_health_gated_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Health")));
    }

    #[test]
    fn playbook_cross_connector_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Cross-Connector")));
    }

    #[test]
    fn playbook_schema_driven_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Schema")));
    }

    #[test]
    fn pattern_pipeline_composition_exists() {
        let patterns = get_agent_patterns();
        assert!(patterns.iter().any(|p| p.name.contains("Pipeline")));
    }

    #[test]
    fn pattern_least_privilege_exists() {
        let patterns = get_agent_patterns();
        assert!(patterns.iter().any(|p| p.name.contains("Least Privilege")));
    }

    #[test]
    fn pattern_output_chaining_exists() {
        let patterns = get_agent_patterns();
        assert!(patterns.iter().any(|p| p.name.contains("Output Chaining")));
    }

    #[test]
    fn pattern_health_gated_exists() {
        let patterns = get_agent_patterns();
        assert!(patterns.iter().any(|p| p.name.contains("Health")));
    }

    #[test]
    fn playbook_template_reporting_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Template")));
    }

    #[test]
    fn playbook_progressive_discovery_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.title.contains("Progressive")));
    }

    // ── New agent playbooks (012–015) ────────────────────────────────────

    #[test]
    fn playbook_plan_natural_language_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.id == "agent-012"));
    }

    #[test]
    fn playbook_plan_has_correct_title() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-012").unwrap();
        assert!(pb.title.contains("Plan"));
        assert!(pb.title.contains("Natural-Language"));
    }

    #[test]
    fn playbook_plan_has_four_steps() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-012").unwrap();
        assert_eq!(pb.workflow_steps.len(), 4);
    }

    #[test]
    fn playbook_plan_steps_reference_plan_and_do() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-012").unwrap();
        let cmds: Vec<&str> = pb
            .workflow_steps
            .iter()
            .map(|s| s.command_template.as_str())
            .collect();
        assert!(cmds.iter().any(|c| c.contains("plan")));
        assert!(cmds.iter().any(|c| c.contains("do")));
    }

    #[test]
    fn playbook_task_durable_capsule_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.id == "agent-013"));
    }

    #[test]
    fn playbook_task_has_correct_title() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-013").unwrap();
        assert!(pb.title.contains("Task"));
        assert!(pb.title.contains("Durable"));
    }

    #[test]
    fn playbook_task_has_four_steps() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-013").unwrap();
        assert_eq!(pb.workflow_steps.len(), 4);
    }

    #[test]
    fn playbook_task_steps_reference_create_and_advance() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-013").unwrap();
        let cmds: Vec<&str> = pb
            .workflow_steps
            .iter()
            .map(|s| s.command_template.as_str())
            .collect();
        assert!(cmds.iter().any(|c| c.contains("create")));
        assert!(cmds.iter().any(|c| c.contains("advance")));
    }

    #[test]
    fn playbook_session_persistent_context_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.id == "agent-014"));
    }

    #[test]
    fn playbook_session_has_correct_title() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-014").unwrap();
        assert!(pb.title.contains("Session"));
        assert!(pb.title.contains("Persistent"));
    }

    #[test]
    fn playbook_session_has_four_steps() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-014").unwrap();
        assert_eq!(pb.workflow_steps.len(), 4);
    }

    #[test]
    fn playbook_session_steps_reference_start_and_end() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-014").unwrap();
        let cmds: Vec<&str> = pb
            .workflow_steps
            .iter()
            .map(|s| s.command_template.as_str())
            .collect();
        assert!(cmds.iter().any(|c| c.contains("start")));
        assert!(cmds.iter().any(|c| c.contains("end")));
    }

    #[test]
    fn playbook_pipeline_multi_step_exists() {
        let pbs = get_agent_playbooks();
        assert!(pbs.iter().any(|pb| pb.id == "agent-015"));
    }

    #[test]
    fn playbook_pipeline_has_correct_title() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-015").unwrap();
        assert!(pb.title.contains("Pipeline"));
        assert!(pb.title.contains("TOML"));
    }

    #[test]
    fn playbook_pipeline_has_four_steps() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-015").unwrap();
        assert_eq!(pb.workflow_steps.len(), 4);
    }

    #[test]
    fn playbook_pipeline_steps_reference_validate_and_run() {
        let pbs = get_agent_playbooks();
        let pb = pbs.iter().find(|pb| pb.id == "agent-015").unwrap();
        let cmds: Vec<&str> = pb
            .workflow_steps
            .iter()
            .map(|s| s.command_template.as_str())
            .collect();
        assert!(cmds.iter().any(|c| c.contains("validate")));
        assert!(cmds.iter().any(|c| c.contains("run")));
    }

    #[test]
    fn playbook_count_at_least_fifteen() {
        let pbs = get_agent_playbooks();
        assert!(
            pbs.len() >= 15,
            "Expected at least 15 playbooks, got {}",
            pbs.len()
        );
    }

    #[test]
    fn new_playbooks_all_serialize() {
        for id in &["agent-012", "agent-013", "agent-014", "agent-015"] {
            let pbs = get_agent_playbooks();
            let pb = pbs.iter().find(|pb| pb.id == *id).unwrap();
            let json = serde_json::to_string(pb).unwrap();
            assert!(json.contains(id));
        }
    }

    #[test]
    fn new_playbooks_all_format_toon() {
        for id in &["agent-012", "agent-013", "agent-014", "agent-015"] {
            let pbs = get_agent_playbooks();
            let pb = pbs.iter().find(|pb| pb.id == *id).unwrap();
            let out = format_agent_playbook_toon(pb);
            assert!(out.contains("Workflow:"));
            assert!(out.contains(&pb.title));
        }
    }
}
