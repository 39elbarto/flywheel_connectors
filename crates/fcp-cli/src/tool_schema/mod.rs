//! `OperationInfo`-to-tool-schema codec for MCP, Claude, and `OpenAI` formats.
//!
//! Translates FCP [`OperationInfo`] structs into tool schemas consumable by
//! external AI agent runtimes:
//!
//! - **MCP**: Model Context Protocol tools (`{ name, description, inputSchema }`)
//! - **Claude**: Anthropic tool-use format (`{ name, description, input_schema }`)
//! - **`OpenAI`**: Function-calling format (`{ type: "function", function: { name, description, parameters } }`)
//!
//! The codec preserves safety metadata (risk level, safety tier, approval requirements)
//! as structured annotations and description suffixes so agents can make informed decisions.

use fcp_core::{IdempotencyClass, OperationInfo, RiskLevel, SafetyTier};
use serde::{Deserialize, Serialize};

/// Target format for tool schema export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolSchemaFormat {
    /// Model Context Protocol (MCP) tool format.
    Mcp,
    /// Anthropic Claude tool-use format.
    Claude,
    /// `OpenAI` function-calling format.
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

/// Options controlling how tool schemas are generated.
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
    /// E.g., stripping "github." from `github.create_issue` yields `create_issue`.
    pub strip_prefix: Option<String>,
    /// Whether to replace dots with underscores in tool names
    /// (required for `OpenAI` which doesn't allow dots in function names).
    pub sanitize_name: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            include_safety_metadata: true,
            include_ai_hints: true,
            include_examples: true,
            strip_prefix: None,
            sanitize_name: false,
        }
    }
}

// ── MCP Tool Schema ──────────────────────────────────────────────────────

/// MCP tool definition (Model Context Protocol).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpTool {
    /// Tool name (operation ID).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the tool's input parameters.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
    /// Optional annotations for safety/risk metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<McpToolAnnotations>,
}

/// MCP tool annotations for risk and behavior metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolAnnotations {
    /// Risk level: low, medium, high, critical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    /// Safety tier: safe, risky, dangerous, critical, forbidden.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_tier: Option<String>,
    /// Idempotency class: none, `best_effort`, strict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency: Option<String>,
    /// Required capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// Whether this tool is read-only (no side effects).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    /// Whether this tool is destructive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive: Option<bool>,
}

// ── Claude Tool Schema ───────────────────────────────────────────────────

/// Anthropic Claude tool-use definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaudeTool {
    /// Tool name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the tool's input parameters.
    pub input_schema: serde_json::Value,
}

// ── OpenAI Function Schema ───────────────────────────────────────────────

/// `OpenAI` function-calling tool definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenAiTool {
    /// Always "function".
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function definition.
    pub function: OpenAiFunction,
}

/// `OpenAI` function definition (nested inside tool).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenAiFunction {
    /// Function name (no dots allowed, use underscores).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the function's parameters.
    pub parameters: serde_json::Value,
    /// Whether to enable strict mode for function calling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

// ── Codec Implementation ─────────────────────────────────────────────────

/// Convert an operation ID to a tool name based on options.
fn make_tool_name(op_id: &str, opts: &ExportOptions) -> String {
    let mut name = opts.strip_prefix.as_ref().map_or_else(
        || op_id.to_string(),
        |prefix| {
            op_id
                .strip_prefix(prefix.as_str())
                .unwrap_or(op_id)
                .to_string()
        },
    );

    if opts.sanitize_name {
        name = name.replace('.', "_");
    }

    name
}

/// Build a rich description from `OperationInfo` fields.
fn build_description(op: &OperationInfo, opts: &ExportOptions) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Primary description
    parts.push(op.summary.clone());

    if let Some(desc) = &op.description {
        if !desc.is_empty() && desc != &op.summary {
            parts.push(desc.clone());
        }
    }

    // AI hints
    if opts.include_ai_hints && !op.ai_hints.when_to_use.is_empty() {
        parts.push(format!("When to use: {}", op.ai_hints.when_to_use));
    }

    if opts.include_ai_hints && !op.ai_hints.common_mistakes.is_empty() {
        let mistakes = op.ai_hints.common_mistakes.join("; ");
        parts.push(format!("Common mistakes: {mistakes}"));
    }

    if opts.include_examples && !op.ai_hints.examples.is_empty() {
        let examples = op.ai_hints.examples.join("; ");
        parts.push(format!("Examples: {examples}"));
    }

    // Safety metadata
    if opts.include_safety_metadata {
        let mut meta_parts: Vec<String> = Vec::new();

        meta_parts.push(format!("Risk: {}", risk_level_str(op.risk_level)));
        meta_parts.push(format!("Safety: {}", safety_tier_str(op.safety_tier)));

        if op.idempotency != IdempotencyClass::None {
            meta_parts.push(format!(
                "Idempotency: {}",
                idempotency_str(op.idempotency)
            ));
        }

        if let Some(approval) = &op.requires_approval {
            let approval_str = serde_json::to_value(approval)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| format!("{approval:?}"));
            if approval_str != "none" {
                meta_parts.push(format!("Approval: {approval_str}"));
            }
        }

        parts.push(format!("[{}]", meta_parts.join(" | ")));
    }

    parts.join("\n\n")
}

const fn risk_level_str(r: RiskLevel) -> &'static str {
    match r {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

const fn safety_tier_str(s: SafetyTier) -> &'static str {
    match s {
        SafetyTier::Safe => "safe",
        SafetyTier::Risky => "risky",
        SafetyTier::Dangerous => "dangerous",
        SafetyTier::Critical => "critical",
        SafetyTier::Forbidden => "forbidden",
    }
}

const fn idempotency_str(i: IdempotencyClass) -> &'static str {
    match i {
        IdempotencyClass::None => "none",
        IdempotencyClass::BestEffort => "best_effort",
        IdempotencyClass::Strict => "strict",
    }
}

/// Determine if an operation is read-only based on its safety tier and idempotency.
const fn is_read_only(op: &OperationInfo) -> bool {
    matches!(
        (&op.safety_tier, &op.idempotency),
        (SafetyTier::Safe, IdempotencyClass::Strict)
    )
}

/// Determine if an operation is destructive.
const fn is_destructive(op: &OperationInfo) -> bool {
    match op.safety_tier {
        SafetyTier::Dangerous | SafetyTier::Critical => true,
        SafetyTier::Safe | SafetyTier::Risky | SafetyTier::Forbidden => false,
    }
}

// ── Public API ───────────────────────────────────────────────────────────

/// Convert an `OperationInfo` to an MCP tool definition.
#[must_use]
pub fn to_mcp_tool(op: &OperationInfo, opts: &ExportOptions) -> McpTool {
    let name = make_tool_name(op.id.as_str(), opts);
    let description = build_description(op, opts);

    let annotations = if opts.include_safety_metadata {
        Some(McpToolAnnotations {
            risk_level: Some(risk_level_str(op.risk_level).to_string()),
            safety_tier: Some(safety_tier_str(op.safety_tier).to_string()),
            idempotency: Some(idempotency_str(op.idempotency).to_string()),
            capability: Some(op.capability.as_str().to_string()),
            read_only: Some(is_read_only(op)),
            destructive: Some(is_destructive(op)),
        })
    } else {
        None
    };

    McpTool {
        name,
        description,
        input_schema: op.input_schema.clone(),
        annotations,
    }
}

/// Convert an `OperationInfo` to a Claude tool-use definition.
#[must_use]
pub fn to_claude_tool(op: &OperationInfo, opts: &ExportOptions) -> ClaudeTool {
    let name = make_tool_name(op.id.as_str(), opts);
    let description = build_description(op, opts);

    ClaudeTool {
        name,
        description,
        input_schema: op.input_schema.clone(),
    }
}

/// Convert an `OperationInfo` to an `OpenAI` function-calling tool definition.
#[must_use]
pub fn to_openai_tool(op: &OperationInfo, opts: &ExportOptions) -> OpenAiTool {
    let mut openai_opts = opts.clone();
    // OpenAI function names must match ^[a-zA-Z0-9_-]+$
    openai_opts.sanitize_name = true;

    let name = make_tool_name(op.id.as_str(), &openai_opts);
    let description = build_description(op, opts);

    OpenAiTool {
        tool_type: "function".to_string(),
        function: OpenAiFunction {
            name,
            description,
            parameters: op.input_schema.clone(),
            strict: None,
        },
    }
}

/// Convert a slice of `OperationInfo` to MCP tools.
#[must_use]
pub fn to_mcp_tools(operations: &[OperationInfo], options: &ExportOptions) -> Vec<McpTool> {
    operations
        .iter()
        .map(|op| to_mcp_tool(op, options))
        .collect()
}

/// Convert a slice of `OperationInfo` to Claude tools.
#[must_use]
pub fn to_claude_tools(operations: &[OperationInfo], options: &ExportOptions) -> Vec<ClaudeTool> {
    operations
        .iter()
        .map(|op| to_claude_tool(op, options))
        .collect()
}

/// Convert a slice of `OperationInfo` to `OpenAI` tools.
#[must_use]
pub fn to_openai_tools(operations: &[OperationInfo], options: &ExportOptions) -> Vec<OpenAiTool> {
    operations
        .iter()
        .map(|op| to_openai_tool(op, options))
        .collect()
}

/// Convert a slice of `OperationInfo` to JSON in the specified format.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn export_tools_json(
    operations: &[OperationInfo],
    format: ToolSchemaFormat,
    options: &ExportOptions,
) -> Result<serde_json::Value, serde_json::Error> {
    match format {
        ToolSchemaFormat::Mcp => serde_json::to_value(to_mcp_tools(operations, options)),
        ToolSchemaFormat::Claude => serde_json::to_value(to_claude_tools(operations, options)),
        ToolSchemaFormat::OpenAi => serde_json::to_value(to_openai_tools(operations, options)),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{AgentHint, CapabilityId, OperationId};
    use serde_json::json;

    fn sample_read_op() -> OperationInfo {
        OperationInfo {
            id: OperationId::from_static("github.list_issues"),
            summary: "List issues in a repository".to_string(),
            description: Some("Returns paginated list of issues with filtering support".to_string()),
            input_schema: json!({
                "type": "object",
                "required": ["owner", "repo"],
                "properties": {
                    "owner": { "type": "string", "description": "Repository owner" },
                    "repo": { "type": "string", "description": "Repository name" },
                    "state": { "type": "string", "enum": ["open", "closed", "all"] },
                    "page": { "type": "integer", "minimum": 1 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "issues": { "type": "array" },
                    "total_count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("github.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to find or list issues in a GitHub repository".to_string(),
                common_mistakes: vec![
                    "Forgetting to paginate large result sets".to_string(),
                    "Not specifying state filter (defaults to open)".to_string(),
                ],
                examples: vec![
                    r#"{"owner": "anthropics", "repo": "claude-code", "state": "open"}"#.to_string(),
                ],
                related: vec![
                    CapabilityId::from_static("github.get_issue"),
                    CapabilityId::from_static("github.create_issue"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        }
    }

    fn sample_write_op() -> OperationInfo {
        OperationInfo {
            id: OperationId::from_static("twilio.create_call"),
            summary: "Initiate an outbound voice call".to_string(),
            description: None,
            input_schema: json!({
                "type": "object",
                "required": ["to", "from", "url"],
                "properties": {
                    "to": { "type": "string", "description": "Destination phone number" },
                    "from": { "type": "string", "description": "Caller ID" },
                    "url": { "type": "string", "description": "TwiML URL for call instructions" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "sid": { "type": "string" },
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static("twilio.voice"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to place an outbound phone call".to_string(),
                common_mistakes: vec![
                    "Using E.164 format for phone numbers".to_string(),
                ],
                examples: vec![],
                related: vec![CapabilityId::from_static("twilio.hangup_call")],
            },
            rate_limit: None,
            requires_approval: Some(fcp_core::ApprovalMode::Interactive),
        }
    }

    // ── MCP format tests ─────────────────────────────────────────────

    #[test]
    fn mcp_tool_has_correct_name() {
        let op = sample_read_op();
        let tool = to_mcp_tool(&op, &ExportOptions::default());
        assert_eq!(tool.name, "github.list_issues");
    }

    #[test]
    fn mcp_tool_has_input_schema() {
        let op = sample_read_op();
        let tool = to_mcp_tool(&op, &ExportOptions::default());
        assert!(tool.input_schema.is_object());
        assert_eq!(tool.input_schema["type"], "object");
        assert!(tool.input_schema["properties"]["owner"].is_object());
    }

    #[test]
    fn mcp_tool_includes_annotations() {
        let op = sample_read_op();
        let tool = to_mcp_tool(&op, &ExportOptions::default());
        let ann = tool.annotations.as_ref().unwrap();
        assert_eq!(ann.risk_level.as_deref(), Some("low"));
        assert_eq!(ann.safety_tier.as_deref(), Some("safe"));
        assert_eq!(ann.idempotency.as_deref(), Some("strict"));
        assert_eq!(ann.read_only, Some(true));
        assert_eq!(ann.destructive, Some(false));
    }

    #[test]
    fn mcp_tool_dangerous_op_annotations() {
        let op = sample_write_op();
        let tool = to_mcp_tool(&op, &ExportOptions::default());
        let ann = tool.annotations.as_ref().unwrap();
        assert_eq!(ann.risk_level.as_deref(), Some("high"));
        assert_eq!(ann.safety_tier.as_deref(), Some("dangerous"));
        assert_eq!(ann.read_only, Some(false));
        assert_eq!(ann.destructive, Some(true));
    }

    #[test]
    fn mcp_tool_no_annotations_when_disabled() {
        let op = sample_read_op();
        let opts = ExportOptions {
            include_safety_metadata: false,
            ..ExportOptions::default()
        };
        let tool = to_mcp_tool(&op, &opts);
        assert!(tool.annotations.is_none());
    }

    #[test]
    fn mcp_tool_serializes_to_valid_json() {
        let op = sample_read_op();
        let tool = to_mcp_tool(&op, &ExportOptions::default());
        let json = serde_json::to_value(&tool).unwrap();
        assert!(json["name"].is_string());
        assert!(json["description"].is_string());
        assert!(json["inputSchema"].is_object());
    }

    // ── Claude format tests ──────────────────────────────────────────

    #[test]
    fn claude_tool_has_correct_structure() {
        let op = sample_read_op();
        let tool = to_claude_tool(&op, &ExportOptions::default());
        assert_eq!(tool.name, "github.list_issues");
        assert!(tool.description.contains("List issues"));
        assert!(tool.input_schema.is_object());
    }

    #[test]
    fn claude_tool_includes_ai_hints() {
        let op = sample_read_op();
        let tool = to_claude_tool(&op, &ExportOptions::default());
        assert!(tool.description.contains("When to use:"));
        assert!(tool.description.contains("Common mistakes:"));
    }

    #[test]
    fn claude_tool_serializes_with_snake_case_key() {
        let op = sample_read_op();
        let tool = to_claude_tool(&op, &ExportOptions::default());
        let json = serde_json::to_value(&tool).unwrap();
        assert!(json.get("input_schema").is_some());
        assert!(json.get("inputSchema").is_none());
    }

    // ── OpenAI format tests ──────────────────────────────────────────

    #[test]
    fn openai_tool_has_function_type() {
        let op = sample_read_op();
        let tool = to_openai_tool(&op, &ExportOptions::default());
        assert_eq!(tool.tool_type, "function");
    }

    #[test]
    fn openai_tool_sanitizes_name() {
        let op = sample_read_op();
        let tool = to_openai_tool(&op, &ExportOptions::default());
        assert_eq!(tool.function.name, "github_list_issues");
        assert!(!tool.function.name.contains('.'));
    }

    #[test]
    fn openai_tool_has_parameters_field() {
        let op = sample_read_op();
        let tool = to_openai_tool(&op, &ExportOptions::default());
        assert!(tool.function.parameters.is_object());
        assert_eq!(tool.function.parameters["type"], "object");
    }

    #[test]
    fn openai_tool_serializes_correctly() {
        let op = sample_read_op();
        let tool = to_openai_tool(&op, &ExportOptions::default());
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["type"], "function");
        assert!(json["function"]["name"].is_string());
        assert!(json["function"]["parameters"].is_object());
    }

    // ── Description building tests ───────────────────────────────────

    #[test]
    fn description_includes_summary() {
        let op = sample_read_op();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(desc.starts_with("List issues in a repository"));
    }

    #[test]
    fn description_includes_detailed_description() {
        let op = sample_read_op();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(desc.contains("paginated list"));
    }

    #[test]
    fn description_includes_when_to_use() {
        let op = sample_read_op();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(desc.contains("When to use:"));
    }

    #[test]
    fn description_includes_common_mistakes() {
        let op = sample_read_op();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(desc.contains("Common mistakes:"));
        assert!(desc.contains("paginate"));
    }

    #[test]
    fn description_includes_safety_metadata() {
        let op = sample_write_op();
        let desc = build_description(&op, &ExportOptions::default());
        assert!(desc.contains("Risk: high"));
        assert!(desc.contains("Safety: dangerous"));
        assert!(desc.contains("Approval: interactive"));
    }

    #[test]
    fn description_skips_hints_when_disabled() {
        let op = sample_read_op();
        let opts = ExportOptions {
            include_ai_hints: false,
            include_examples: false,
            ..ExportOptions::default()
        };
        let desc = build_description(&op, &opts);
        assert!(!desc.contains("When to use:"));
        assert!(!desc.contains("Common mistakes:"));
    }

    #[test]
    fn description_skips_safety_when_disabled() {
        let op = sample_write_op();
        let opts = ExportOptions {
            include_safety_metadata: false,
            ..ExportOptions::default()
        };
        let desc = build_description(&op, &opts);
        assert!(!desc.contains("Risk:"));
        assert!(!desc.contains("Safety:"));
    }

    // ── Name transformation tests ────────────────────────────────────

    #[test]
    fn strip_prefix_removes_connector_namespace() {
        let opts = ExportOptions {
            strip_prefix: Some("github.".to_string()),
            ..ExportOptions::default()
        };
        assert_eq!(make_tool_name("github.list_issues", &opts), "list_issues");
    }

    #[test]
    fn strip_prefix_no_match_preserves_name() {
        let opts = ExportOptions {
            strip_prefix: Some("slack.".to_string()),
            ..ExportOptions::default()
        };
        assert_eq!(
            make_tool_name("github.list_issues", &opts),
            "github.list_issues"
        );
    }

    #[test]
    fn sanitize_replaces_dots() {
        let opts = ExportOptions {
            sanitize_name: true,
            ..ExportOptions::default()
        };
        assert_eq!(
            make_tool_name("github.list_issues", &opts),
            "github_list_issues"
        );
    }

    #[test]
    fn strip_and_sanitize_combined() {
        let opts = ExportOptions {
            strip_prefix: Some("twilio.".to_string()),
            sanitize_name: true,
            ..ExportOptions::default()
        };
        assert_eq!(make_tool_name("twilio.create_call", &opts), "create_call");
    }

    // ── Batch conversion tests ───────────────────────────────────────

    #[test]
    fn batch_mcp_converts_all_ops() {
        let ops = vec![sample_read_op(), sample_write_op()];
        let tools = to_mcp_tools(&ops, &ExportOptions::default());
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "github.list_issues");
        assert_eq!(tools[1].name, "twilio.create_call");
    }

    #[test]
    fn batch_claude_converts_all_ops() {
        let ops = vec![sample_read_op(), sample_write_op()];
        let tools = to_claude_tools(&ops, &ExportOptions::default());
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn batch_openai_converts_all_ops() {
        let ops = vec![sample_read_op(), sample_write_op()];
        let tools = to_openai_tools(&ops, &ExportOptions::default());
        assert_eq!(tools.len(), 2);
        assert!(tools.iter().all(|t| t.tool_type == "function"));
    }

    // ── Determinism tests ────────────────────────────────────────────

    #[test]
    fn mcp_output_is_deterministic() {
        let op = sample_read_op();
        let opts = ExportOptions::default();
        let a = serde_json::to_string(&to_mcp_tool(&op, &opts)).unwrap();
        let b = serde_json::to_string(&to_mcp_tool(&op, &opts)).unwrap();
        assert_eq!(a, b, "MCP output must be deterministic");
    }

    #[test]
    fn claude_output_is_deterministic() {
        let op = sample_read_op();
        let opts = ExportOptions::default();
        let a = serde_json::to_string(&to_claude_tool(&op, &opts)).unwrap();
        let b = serde_json::to_string(&to_claude_tool(&op, &opts)).unwrap();
        assert_eq!(a, b, "Claude output must be deterministic");
    }

    #[test]
    fn openai_output_is_deterministic() {
        let op = sample_read_op();
        let opts = ExportOptions::default();
        let a = serde_json::to_string(&to_openai_tool(&op, &opts)).unwrap();
        let b = serde_json::to_string(&to_openai_tool(&op, &opts)).unwrap();
        assert_eq!(a, b, "OpenAI output must be deterministic");
    }

    // ── export_tools_json tests ──────────────────────────────────────

    #[test]
    fn export_json_mcp_is_array() {
        let ops = vec![sample_read_op()];
        let json = export_tools_json(&ops, ToolSchemaFormat::Mcp, &ExportOptions::default()).unwrap();
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 1);
    }

    #[test]
    fn export_json_claude_is_array() {
        let ops = vec![sample_read_op()];
        let json =
            export_tools_json(&ops, ToolSchemaFormat::Claude, &ExportOptions::default()).unwrap();
        assert!(json.is_array());
    }

    #[test]
    fn export_json_openai_is_array() {
        let ops = vec![sample_read_op()];
        let json =
            export_tools_json(&ops, ToolSchemaFormat::OpenAi, &ExportOptions::default()).unwrap();
        assert!(json.is_array());
        assert_eq!(json[0]["type"], "function");
    }

    #[test]
    fn export_json_empty_input() {
        let ops: Vec<OperationInfo> = vec![];
        let json = export_tools_json(&ops, ToolSchemaFormat::Mcp, &ExportOptions::default()).unwrap();
        assert_eq!(json, json!([]));
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn op_with_no_description_uses_summary() {
        let op = sample_write_op();
        assert!(op.description.is_none());
        let desc = build_description(&op, &ExportOptions::default());
        assert!(desc.starts_with("Initiate an outbound voice call"));
    }

    #[test]
    fn op_with_empty_hints() {
        let mut op = sample_read_op();
        op.ai_hints = AgentHint::default();
        let tool = to_claude_tool(&op, &ExportOptions::default());
        assert!(!tool.description.contains("When to use:"));
    }

    #[test]
    fn op_with_no_approval_requirement() {
        let op = sample_read_op();
        assert!(op.requires_approval.is_none());
        let desc = build_description(&op, &ExportOptions::default());
        assert!(!desc.contains("Approval:"));
    }

    #[test]
    fn format_display_strings() {
        assert_eq!(ToolSchemaFormat::Mcp.to_string(), "mcp");
        assert_eq!(ToolSchemaFormat::Claude.to_string(), "claude");
        assert_eq!(ToolSchemaFormat::OpenAi.to_string(), "openai");
    }

    // ── Read-only / destructive classification ───────────────────────

    #[test]
    fn safe_strict_op_is_read_only() {
        let op = sample_read_op();
        assert!(is_read_only(&op));
        assert!(!is_destructive(&op));
    }

    #[test]
    fn dangerous_op_is_destructive() {
        let op = sample_write_op();
        assert!(!is_read_only(&op));
        assert!(is_destructive(&op));
    }

    #[test]
    fn risky_op_is_neither_read_only_nor_destructive() {
        let mut op = sample_read_op();
        op.safety_tier = SafetyTier::Risky;
        op.idempotency = IdempotencyClass::None;
        assert!(!is_read_only(&op));
        assert!(!is_destructive(&op));
    }
}
