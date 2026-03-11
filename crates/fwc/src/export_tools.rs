//! Tool schema export for MCP, Claude, and `OpenAI` formats.
//!
//! Converts [`DiscoveredOperation`] data from the discovery catalog into
//! tool schemas consumable by external AI agent runtimes.

use fcp_core::{OperationInfo, tool_schema::ExportOptions as SharedExportOptions};
use serde::Serialize;
use serde_json::{Value, json};

use crate::readiness::DiscoveredOperation;

/// Target format for tool schema export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize)]
pub enum ToolSchemaFormat {
    /// Model Context Protocol (MCP) tool format.
    Mcp,
    /// Anthropic Claude tool-use format.
    Claude,
    /// `OpenAI` function-calling format.
    #[value(name = "openai")]
    OpenAi,
}

impl std::fmt::Display for ToolSchemaFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mcp => write!(f, "mcp"),
            Self::Claude => write!(f, "claude"),
            Self::OpenAi => write!(f, "openai"),
        }
    }
}

/// Options controlling tool schema generation.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ExportOptions {
    /// Whether to include safety metadata in the description.
    pub include_safety_metadata: bool,
    /// Whether to include `ai_hints` in the description.
    pub include_ai_hints: bool,
    /// Whether to include examples in the description.
    pub include_examples: bool,
    /// Optional connector prefix to strip from operation IDs.
    pub strip_prefix: Option<String>,
    /// Maximum risk level to include (operations above this are filtered out).
    pub risk_max: Option<String>,
    /// Filter to only include operations with this capability prefix.
    pub capability_filter: Option<String>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            include_safety_metadata: true,
            include_ai_hints: true,
            include_examples: true,
            strip_prefix: None,
            risk_max: None,
            capability_filter: None,
        }
    }
}

// ── MCP Tool Schema ──────────────────────────────────────────────────────

/// MCP tool definition.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<McpToolAnnotations>,
}

/// MCP tool annotations for risk and behavior metadata.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct McpToolAnnotations {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive: Option<bool>,
}

// ── Claude Tool Schema ───────────────────────────────────────────────────

/// Anthropic Claude tool-use definition.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ClaudeTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

// ── OpenAI Function Schema ───────────────────────────────────────────────

/// `OpenAI` function-calling tool definition.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OpenAiTool {
    #[serde(rename = "type")]
    pub tool_type: String,
    pub function: OpenAiFunction,
}

/// `OpenAI` function definition (nested inside tool).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OpenAiFunction {
    pub name: String,
    pub description: String,
    pub parameters: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

// ── Codec ────────────────────────────────────────────────────────────────

#[cfg(test)]
fn make_tool_name(op_id: &str, opts: &ExportOptions, sanitize: bool) -> String {
    let mut name = opts.strip_prefix.as_ref().map_or_else(
        || op_id.to_string(),
        |prefix| {
            op_id
                .strip_prefix(prefix.as_str())
                .unwrap_or(op_id)
                .to_string()
        },
    );
    if sanitize {
        name = name.replace('.', "_");
    }
    name
}

fn shared_export_options(opts: &ExportOptions, sanitize_name: bool) -> SharedExportOptions {
    SharedExportOptions {
        include_safety_metadata: opts.include_safety_metadata,
        include_ai_hints: opts.include_ai_hints,
        include_examples: opts.include_examples,
        strip_prefix: opts.strip_prefix.clone(),
        sanitize_name,
    }
}

#[cfg(test)]
fn build_description(op: &DiscoveredOperation, opts: &ExportOptions) -> String {
    let mut parts: Vec<String> = Vec::new();

    parts.push(op.description.clone());

    if opts.include_ai_hints && !op.when_to_use.is_empty() {
        parts.push(format!("When to use: {}", op.when_to_use));
    }

    if opts.include_ai_hints && !op.common_mistakes.is_empty() {
        let mistakes = op.common_mistakes.join("; ");
        parts.push(format!("Common mistakes: {mistakes}"));
    }

    if opts.include_examples && !op.examples.is_empty() {
        let examples = op.examples.join("; ");
        parts.push(format!("Examples: {examples}"));
    }

    if opts.include_safety_metadata {
        let mut meta: Vec<String> = Vec::new();
        meta.push(format!("Risk: {}", op.summary.risk_level));
        meta.push(format!("Safety: {}", op.summary.safety_tier));
        if op.summary.idempotency != "none" {
            meta.push(format!("Idempotency: {}", op.summary.idempotency));
        }
        if op.approval_mode != "none" {
            meta.push(format!("Approval: {}", op.approval_mode));
        }
        parts.push(format!("[{}]", meta.join(" | ")));
    }

    parts.join("\n\n")
}

#[cfg(test)]
fn is_read_only(op: &DiscoveredOperation) -> bool {
    op.summary.safety_tier == "safe" && op.summary.idempotency == "strict"
}

#[cfg(test)]
fn is_destructive(op: &DiscoveredOperation) -> bool {
    op.summary.safety_tier == "dangerous" || op.summary.safety_tier == "critical"
}

/// Convert canonical `OperationInfo` metadata to an MCP tool.
pub fn to_mcp_tool_info(op: &OperationInfo, opts: &ExportOptions) -> McpTool {
    let tool = fcp_core::tool_schema::to_mcp_tool(op, &shared_export_options(opts, false));
    McpTool {
        name: tool.name,
        description: tool.description,
        input_schema: tool.input_schema,
        annotations: tool.annotations.map(|annotations| McpToolAnnotations {
            risk_level: annotations.risk_level,
            safety_tier: annotations.safety_tier,
            idempotency: annotations.idempotency,
            capability: annotations.capability,
            read_only: annotations.read_only,
            destructive: annotations.destructive,
        }),
    }
}

/// Convert a discovered operation to an MCP tool.
pub fn to_mcp_tool(op: &DiscoveredOperation, opts: &ExportOptions) -> McpTool {
    to_mcp_tool_info(&op.operation_info(), opts)
}

/// Convert canonical `OperationInfo` metadata to a Claude tool.
pub fn to_claude_tool_info(op: &OperationInfo, opts: &ExportOptions) -> ClaudeTool {
    let tool = fcp_core::tool_schema::to_claude_tool(op, &shared_export_options(opts, false));
    ClaudeTool {
        name: tool.name,
        description: tool.description,
        input_schema: tool.input_schema,
    }
}

/// Convert a discovered operation to a Claude tool.
pub fn to_claude_tool(op: &DiscoveredOperation, opts: &ExportOptions) -> ClaudeTool {
    to_claude_tool_info(&op.operation_info(), opts)
}

/// Convert canonical `OperationInfo` metadata to an `OpenAI` tool.
pub fn to_openai_tool_info(op: &OperationInfo, opts: &ExportOptions) -> OpenAiTool {
    let tool = fcp_core::tool_schema::to_openai_tool(op, &shared_export_options(opts, true));
    OpenAiTool {
        tool_type: tool.tool_type,
        function: OpenAiFunction {
            name: tool.function.name,
            description: tool.function.description,
            parameters: tool.function.parameters,
            strict: tool.function.strict,
        },
    }
}

/// Convert a discovered operation to an `OpenAI` tool.
pub fn to_openai_tool(op: &DiscoveredOperation, opts: &ExportOptions) -> OpenAiTool {
    to_openai_tool_info(&op.operation_info(), opts)
}

/// Export canonical `OperationInfo` values as tool schemas in the specified format.
pub fn export_operation_infos(
    operations: &[OperationInfo],
    format: ToolSchemaFormat,
    options: &ExportOptions,
) -> Value {
    match format {
        ToolSchemaFormat::Mcp => {
            let tools: Vec<_> = operations
                .iter()
                .map(|op| to_mcp_tool_info(op, options))
                .collect();
            json!(tools)
        }
        ToolSchemaFormat::Claude => {
            let tools: Vec<_> = operations
                .iter()
                .map(|op| to_claude_tool_info(op, options))
                .collect();
            json!(tools)
        }
        ToolSchemaFormat::OpenAi => {
            let tools: Vec<_> = operations
                .iter()
                .map(|op| to_openai_tool_info(op, options))
                .collect();
            json!(tools)
        }
    }
}

/// Check if an operation passes the risk filter.
pub fn passes_risk_filter(op: &DiscoveredOperation, risk_max: Option<&str>) -> bool {
    let Some(max) = risk_max else {
        return true;
    };
    let rank = |level: &str| -> u8 {
        match level {
            "low" => 0,
            "medium" => 1,
            "high" => 2,
            "critical" => 3,
            _ => 4,
        }
    };
    rank(&op.summary.risk_level) <= rank(max)
}

/// Check if an operation passes the capability filter.
pub fn passes_capability_filter(op: &DiscoveredOperation, capability: Option<&str>) -> bool {
    let Some(filter) = capability else {
        return true;
    };
    op.summary.capability.starts_with(filter)
}

/// Export all matching operations as tool schemas in the specified format.
pub fn export_tools(
    operations: &[&DiscoveredOperation],
    format: ToolSchemaFormat,
    options: &ExportOptions,
) -> Value {
    let operation_infos = operations
        .iter()
        .map(|op| op.operation_info())
        .collect::<Vec<_>>();
    export_operation_infos(&operation_infos, format, options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readiness::OperationSummary;

    fn sample_op() -> DiscoveredOperation {
        DiscoveredOperation {
            actual_id: "github.list_issues".to_string(),
            local_id: "list_issues".to_string(),
            preferred_selector: "list_issues".to_string(),
            aliases: vec!["issues.list".to_string()],
            description: "List issues in a repository".to_string(),
            summary: OperationSummary {
                id: "github.list_issues".to_string(),
                summary: "List issues in a repository".to_string(),
                capability: "github.read".to_string(),
                risk_level: "low".to_string(),
                safety_tier: "safe".to_string(),
                idempotency: "strict".to_string(),
                requires_approval: false,
                supports_simulate: true,
            },
            input_schema: json!({
                "type": "object",
                "required": ["owner", "repo"],
                "properties": {
                    "owner": { "type": "string" },
                    "repo": { "type": "string" }
                }
            }),
            output_schema: json!({"type": "object"}),
            approval_mode: "none".to_string(),
            when_to_use: "When you need to list issues".to_string(),
            common_mistakes: vec!["Forgetting pagination".to_string()],
            examples: vec![r#"{"owner":"a","repo":"b"}"#.to_string()],
            related: vec!["github.get_issue".to_string()],
            network_constraints: None,
            rate_limits: Some(vec![]),
        }
    }

    fn sample_write_op() -> DiscoveredOperation {
        DiscoveredOperation {
            actual_id: "twilio.create_call".to_string(),
            local_id: "create_call".to_string(),
            preferred_selector: "create_call".to_string(),
            aliases: vec![],
            description: "Initiate an outbound voice call".to_string(),
            summary: OperationSummary {
                id: "twilio.create_call".to_string(),
                summary: "Initiate an outbound voice call".to_string(),
                capability: "twilio.voice".to_string(),
                risk_level: "high".to_string(),
                safety_tier: "dangerous".to_string(),
                idempotency: "none".to_string(),
                requires_approval: true,
                supports_simulate: true,
            },
            input_schema: json!({"type": "object", "required": ["to", "from"]}),
            output_schema: json!({"type": "object"}),
            approval_mode: "interactive".to_string(),
            when_to_use: "When you need to place a phone call".to_string(),
            common_mistakes: vec![],
            examples: vec![],
            related: vec![],
            network_constraints: None,
            rate_limits: Some(vec![]),
        }
    }

    // ── MCP format tests ─────────────────────────────────────────────

    #[test]
    fn mcp_tool_has_correct_name() {
        let tool = to_mcp_tool(&sample_op(), &ExportOptions::default());
        assert_eq!(tool.name, "github.list_issues");
    }

    #[test]
    fn mcp_tool_has_annotations() {
        let tool = to_mcp_tool(&sample_op(), &ExportOptions::default());
        let ann = tool.annotations.as_ref().unwrap();
        assert_eq!(ann.risk_level.as_deref(), Some("low"));
        assert_eq!(ann.safety_tier.as_deref(), Some("safe"));
        assert_eq!(ann.read_only, Some(true));
        assert_eq!(ann.destructive, Some(false));
    }

    #[test]
    fn mcp_dangerous_op_annotations() {
        let tool = to_mcp_tool(&sample_write_op(), &ExportOptions::default());
        let ann = tool.annotations.as_ref().unwrap();
        assert_eq!(ann.risk_level.as_deref(), Some("high"));
        assert_eq!(ann.destructive, Some(true));
        assert_eq!(ann.read_only, Some(false));
    }

    #[test]
    fn mcp_no_annotations_when_disabled() {
        let opts = ExportOptions {
            include_safety_metadata: false,
            ..ExportOptions::default()
        };
        let tool = to_mcp_tool(&sample_op(), &opts);
        assert!(tool.annotations.is_none());
    }

    #[test]
    fn mcp_serializes_input_schema_key() {
        let tool = to_mcp_tool(&sample_op(), &ExportOptions::default());
        let json = serde_json::to_value(&tool).unwrap();
        assert!(json["inputSchema"].is_object());
        assert!(json.get("input_schema").is_none());
    }

    // ── Claude format tests ──────────────────────────────────────────

    #[test]
    fn claude_tool_structure() {
        let tool = to_claude_tool(&sample_op(), &ExportOptions::default());
        assert_eq!(tool.name, "github.list_issues");
        assert!(tool.description.contains("List issues"));
        let json = serde_json::to_value(&tool).unwrap();
        assert!(json.get("input_schema").is_some());
    }

    #[test]
    fn claude_includes_ai_hints() {
        let tool = to_claude_tool(&sample_op(), &ExportOptions::default());
        assert!(tool.description.contains("When to use:"));
        assert!(tool.description.contains("Common mistakes:"));
    }

    // ── OpenAI format tests ──────────────────────────────────────────

    #[test]
    fn openai_tool_type_is_function() {
        let tool = to_openai_tool(&sample_op(), &ExportOptions::default());
        assert_eq!(tool.tool_type, "function");
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["type"], "function");
    }

    #[test]
    fn openai_sanitizes_dots() {
        let tool = to_openai_tool(&sample_op(), &ExportOptions::default());
        assert_eq!(tool.function.name, "github_list_issues");
        assert!(!tool.function.name.contains('.'));
    }

    // ── Description tests ────────────────────────────────────────────

    #[test]
    fn description_includes_safety_metadata() {
        let desc = build_description(&sample_write_op(), &ExportOptions::default());
        assert!(desc.contains("Risk: high"));
        assert!(desc.contains("Safety: dangerous"));
        assert!(desc.contains("Approval: interactive"));
    }

    #[test]
    fn description_skips_hints_when_disabled() {
        let opts = ExportOptions {
            include_ai_hints: false,
            include_examples: false,
            ..ExportOptions::default()
        };
        let desc = build_description(&sample_op(), &opts);
        assert!(!desc.contains("When to use:"));
    }

    // ── Name transformation tests ────────────────────────────────────

    #[test]
    fn strip_prefix_removes_namespace() {
        let opts = ExportOptions {
            strip_prefix: Some("github.".to_string()),
            ..ExportOptions::default()
        };
        assert_eq!(
            make_tool_name("github.list_issues", &opts, false),
            "list_issues"
        );
    }

    #[test]
    fn strip_prefix_no_match_preserves() {
        let opts = ExportOptions {
            strip_prefix: Some("slack.".to_string()),
            ..ExportOptions::default()
        };
        assert_eq!(
            make_tool_name("github.list_issues", &opts, false),
            "github.list_issues"
        );
    }

    // ── Filter tests ─────────────────────────────────────────────────

    #[test]
    fn risk_filter_allows_low_when_max_medium() {
        assert!(passes_risk_filter(&sample_op(), Some("medium")));
    }

    #[test]
    fn risk_filter_blocks_high_when_max_medium() {
        assert!(!passes_risk_filter(&sample_write_op(), Some("medium")));
    }

    #[test]
    fn risk_filter_allows_all_when_none() {
        assert!(passes_risk_filter(&sample_write_op(), None));
    }

    #[test]
    fn capability_filter_matches_prefix() {
        assert!(passes_capability_filter(&sample_op(), Some("github")));
        assert!(!passes_capability_filter(&sample_op(), Some("twilio")));
    }

    #[test]
    fn capability_filter_allows_all_when_none() {
        assert!(passes_capability_filter(&sample_op(), None));
    }

    // ── Batch export tests ───────────────────────────────────────────

    #[test]
    fn export_mcp_array() {
        let op = sample_op();
        let ops: Vec<&DiscoveredOperation> = vec![&op];
        let result = export_tools(&ops, ToolSchemaFormat::Mcp, &ExportOptions::default());
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 1);
    }

    #[test]
    fn export_claude_array() {
        let op = sample_op();
        let ops: Vec<&DiscoveredOperation> = vec![&op];
        let result = export_tools(&ops, ToolSchemaFormat::Claude, &ExportOptions::default());
        assert!(result.is_array());
    }

    #[test]
    fn export_openai_array() {
        let op = sample_op();
        let ops: Vec<&DiscoveredOperation> = vec![&op];
        let result = export_tools(&ops, ToolSchemaFormat::OpenAi, &ExportOptions::default());
        assert!(result.is_array());
        assert_eq!(result[0]["type"], "function");
    }

    #[test]
    fn export_empty_operations() {
        let ops: Vec<&DiscoveredOperation> = vec![];
        let result = export_tools(&ops, ToolSchemaFormat::Mcp, &ExportOptions::default());
        assert_eq!(result, json!([]));
    }

    // ── Determinism ──────────────────────────────────────────────────

    #[test]
    fn output_is_deterministic() {
        let op = sample_op();
        let opts = ExportOptions::default();
        let a = serde_json::to_string(&to_mcp_tool(&op, &opts)).unwrap();
        let b = serde_json::to_string(&to_mcp_tool(&op, &opts)).unwrap();
        assert_eq!(a, b);
    }

    // ── ToolSchemaFormat Display tests ───────────────────────────────

    #[test]
    fn format_display_mcp() {
        assert_eq!(ToolSchemaFormat::Mcp.to_string(), "mcp");
    }

    #[test]
    fn format_display_claude() {
        assert_eq!(ToolSchemaFormat::Claude.to_string(), "claude");
    }

    #[test]
    fn format_display_openai() {
        assert_eq!(ToolSchemaFormat::OpenAi.to_string(), "openai");
    }

    #[test]
    fn format_eq_same() {
        assert_eq!(ToolSchemaFormat::Mcp, ToolSchemaFormat::Mcp);
        assert_eq!(ToolSchemaFormat::Claude, ToolSchemaFormat::Claude);
        assert_eq!(ToolSchemaFormat::OpenAi, ToolSchemaFormat::OpenAi);
    }

    #[test]
    fn format_ne_different() {
        assert_ne!(ToolSchemaFormat::Mcp, ToolSchemaFormat::Claude);
        assert_ne!(ToolSchemaFormat::Claude, ToolSchemaFormat::OpenAi);
    }

    // ── ExportOptions defaults ──────────────────────────────────────

    #[test]
    fn export_options_defaults() {
        let opts = ExportOptions::default();
        assert!(opts.include_safety_metadata);
        assert!(opts.include_ai_hints);
        assert!(opts.include_examples);
        assert!(opts.strip_prefix.is_none());
        assert!(opts.risk_max.is_none());
        assert!(opts.capability_filter.is_none());
    }

    // ── Description building edge cases ─────────────────────────────

    #[test]
    fn description_with_no_common_mistakes() {
        let op = sample_op_no_hints();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(!desc.contains("Common mistakes:"));
    }

    #[test]
    fn description_with_no_examples() {
        let op = sample_op_no_hints();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(!desc.contains("Examples:"));
    }

    #[test]
    fn description_with_no_when_to_use() {
        let op = sample_op_no_hints();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(!desc.contains("When to use:"));
    }

    #[test]
    fn description_includes_examples_when_present() {
        let op = sample_op();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(desc.contains("Examples:"));
    }

    #[test]
    fn description_includes_idempotency_when_not_none() {
        let op = sample_op();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(desc.contains("Idempotency: strict"));
    }

    #[test]
    fn description_omits_approval_when_none() {
        let op = sample_op();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(!desc.contains("Approval:"));
    }

    #[test]
    fn description_no_safety_when_disabled() {
        let opts = ExportOptions {
            include_safety_metadata: false,
            ..ExportOptions::default()
        };
        let desc = build_description(&sample_op(), &opts);
        assert!(!desc.contains("Risk:"));
        assert!(!desc.contains("Safety:"));
    }

    #[test]
    fn description_multiple_common_mistakes_joined() {
        let mut op = sample_op();
        op.common_mistakes = vec!["Mistake A".to_string(), "Mistake B".to_string()];
        let desc = build_description(&op, &ExportOptions::default());
        assert!(desc.contains("Mistake A; Mistake B"));
    }

    // ── is_read_only / is_destructive ───────────────────────────────

    #[test]
    fn read_only_for_safe_strict() {
        assert!(is_read_only(&sample_op()));
    }

    #[test]
    fn not_read_only_for_risky() {
        assert!(!is_read_only(&sample_write_op()));
    }

    #[test]
    fn destructive_for_dangerous() {
        assert!(is_destructive(&sample_write_op()));
    }

    #[test]
    fn not_destructive_for_safe() {
        assert!(!is_destructive(&sample_op()));
    }

    #[test]
    fn destructive_for_critical() {
        let mut op = sample_write_op();
        op.summary.safety_tier = "critical".to_string();
        assert!(is_destructive(&op));
    }

    #[test]
    fn not_destructive_for_risky() {
        let mut op = sample_write_op();
        op.summary.safety_tier = "risky".to_string();
        assert!(!is_destructive(&op));
    }

    // ── Name transformation edge cases ──────────────────────────────

    #[test]
    fn make_tool_name_no_prefix() {
        let opts = ExportOptions::default();
        assert_eq!(make_tool_name("op.id", &opts, false), "op.id");
    }

    #[test]
    fn make_tool_name_sanitize_dots() {
        let opts = ExportOptions::default();
        assert_eq!(make_tool_name("a.b.c", &opts, true), "a_b_c");
    }

    #[test]
    fn make_tool_name_no_sanitize() {
        let opts = ExportOptions::default();
        assert_eq!(make_tool_name("a.b.c", &opts, false), "a.b.c");
    }

    #[test]
    fn make_tool_name_strip_and_sanitize() {
        let opts = ExportOptions {
            strip_prefix: Some("ns.".to_string()),
            ..ExportOptions::default()
        };
        assert_eq!(make_tool_name("ns.op.sub", &opts, true), "op_sub");
    }

    #[test]
    fn make_tool_name_empty_after_strip() {
        let opts = ExportOptions {
            strip_prefix: Some("full_id".to_string()),
            ..ExportOptions::default()
        };
        assert_eq!(make_tool_name("full_id", &opts, false), "");
    }

    // ── Filter edge cases ───────────────────────────────────────────

    #[test]
    fn risk_filter_allows_low_when_max_low() {
        assert!(passes_risk_filter(&sample_op(), Some("low")));
    }

    #[test]
    fn risk_filter_blocks_low_for_unknown_level() {
        let mut op = sample_op();
        op.summary.risk_level = "unknown".to_string();
        assert!(!passes_risk_filter(&op, Some("high")));
    }

    #[test]
    fn risk_filter_allows_critical_when_max_critical() {
        let mut op = sample_write_op();
        op.summary.risk_level = "critical".to_string();
        assert!(passes_risk_filter(&op, Some("critical")));
    }

    #[test]
    fn capability_filter_exact_match() {
        assert!(passes_capability_filter(&sample_op(), Some("github.read")));
    }

    #[test]
    fn capability_filter_partial_prefix() {
        assert!(passes_capability_filter(&sample_op(), Some("git")));
    }

    #[test]
    fn capability_filter_no_match_different_prefix() {
        assert!(!passes_capability_filter(&sample_op(), Some("slack")));
    }

    // ── MCP tool serialization ──────────────────────────────────────

    #[test]
    fn mcp_tool_equality() {
        let a = to_mcp_tool(&sample_op(), &ExportOptions::default());
        let b = to_mcp_tool(&sample_op(), &ExportOptions::default());
        assert_eq!(a, b);
    }

    #[test]
    fn mcp_tool_clone() {
        let tool = to_mcp_tool(&sample_op(), &ExportOptions::default());
        let cloned = tool.clone();
        assert_eq!(tool, cloned);
    }

    #[test]
    fn mcp_annotations_serializes_skipping_none() {
        let ann = McpToolAnnotations {
            risk_level: Some("low".to_string()),
            safety_tier: None,
            idempotency: None,
            capability: None,
            read_only: None,
            destructive: None,
        };
        let json = serde_json::to_value(&ann).unwrap();
        assert_eq!(json["risk_level"], "low");
        assert!(json.get("safety_tier").is_none());
    }

    // ── Claude tool tests ───────────────────────────────────────────

    #[test]
    fn claude_tool_preserves_input_schema() {
        let op = sample_op();
        let tool = to_claude_tool(&op, &ExportOptions::default());
        assert_eq!(tool.input_schema, op.input_schema);
    }

    #[test]
    fn claude_tool_with_strip_prefix() {
        let opts = ExportOptions {
            strip_prefix: Some("github.".to_string()),
            ..ExportOptions::default()
        };
        let tool = to_claude_tool(&sample_op(), &opts);
        assert_eq!(tool.name, "list_issues");
    }

    #[test]
    fn claude_tool_equality() {
        let a = to_claude_tool(&sample_op(), &ExportOptions::default());
        let b = to_claude_tool(&sample_op(), &ExportOptions::default());
        assert_eq!(a, b);
    }

    // ── OpenAI tool tests ───────────────────────────────────────────

    #[test]
    fn openai_tool_preserves_parameters() {
        let op = sample_op();
        let tool = to_openai_tool(&op, &ExportOptions::default());
        assert_eq!(tool.function.parameters, op.input_schema);
    }

    #[test]
    fn openai_tool_strict_is_none() {
        let tool = to_openai_tool(&sample_op(), &ExportOptions::default());
        assert!(tool.function.strict.is_none());
    }

    #[test]
    fn openai_tool_with_strip_prefix() {
        let opts = ExportOptions {
            strip_prefix: Some("github.".to_string()),
            ..ExportOptions::default()
        };
        let tool = to_openai_tool(&sample_op(), &opts);
        assert_eq!(tool.function.name, "list_issues");
    }

    #[test]
    fn openai_tool_serializes_type_field() {
        let tool = to_openai_tool(&sample_op(), &ExportOptions::default());
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["type"], "function");
        assert!(json.get("tool_type").is_none());
    }

    // ── Batch export edge cases ─────────────────────────────────────

    #[test]
    fn export_multiple_operations() {
        let op1 = sample_op();
        let op2 = sample_write_op();
        let ops: Vec<&DiscoveredOperation> = vec![&op1, &op2];
        let result = export_tools(&ops, ToolSchemaFormat::Mcp, &ExportOptions::default());
        assert_eq!(result.as_array().unwrap().len(), 2);
    }

    #[test]
    fn export_openai_multiple_all_function_type() {
        let op1 = sample_op();
        let op2 = sample_write_op();
        let ops: Vec<&DiscoveredOperation> = vec![&op1, &op2];
        let result = export_tools(&ops, ToolSchemaFormat::OpenAi, &ExportOptions::default());
        for item in result.as_array().unwrap() {
            assert_eq!(item["type"], "function");
        }
    }

    #[test]
    fn export_claude_has_input_schema_field() {
        let op = sample_op();
        let ops: Vec<&DiscoveredOperation> = vec![&op];
        let result = export_tools(&ops, ToolSchemaFormat::Claude, &ExportOptions::default());
        assert!(result[0].get("input_schema").is_some());
    }

    /// Helper: operation with no hints/examples/mistakes.
    fn sample_op_no_hints() -> DiscoveredOperation {
        DiscoveredOperation {
            actual_id: "test.op".to_string(),
            local_id: "op".to_string(),
            preferred_selector: "op".to_string(),
            aliases: vec![],
            description: "A test operation".to_string(),
            summary: OperationSummary {
                id: "test.op".to_string(),
                summary: "A test operation".to_string(),
                capability: "test.read".to_string(),
                risk_level: "low".to_string(),
                safety_tier: "safe".to_string(),
                idempotency: "none".to_string(),
                requires_approval: false,
                supports_simulate: false,
            },
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
            approval_mode: "none".to_string(),
            when_to_use: String::new(),
            common_mistakes: vec![],
            examples: vec![],
            related: vec![],
            network_constraints: None,
            rate_limits: Some(vec![]),
        }
    }
}
