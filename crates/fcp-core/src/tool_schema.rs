//! `OperationInfo`-to-tool-schema codec for MCP, Claude, and `OpenAI` formats.
//!
//! This keeps tool export logic anchored on the canonical `OperationInfo`
//! contract instead of letting each CLI invent its own metadata transform.

use crate::{IdempotencyClass, OperationInfo, RiskLevel, SafetyTier};
use serde::{Deserialize, Serialize};

/// Target format for tool schema export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
    pub strip_prefix: Option<String>,
    /// Whether to replace dots with underscores in tool names.
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

/// MCP tool definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpTool {
    /// Tool name.
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
    /// Whether this tool is read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    /// Whether this tool is destructive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive: Option<bool>,
}

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

/// `OpenAI` function-calling tool definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenAiTool {
    /// Always `function`.
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Function definition.
    pub function: OpenAiFunction,
}

/// `OpenAI` function definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenAiFunction {
    /// Function name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the function's parameters.
    pub parameters: serde_json::Value,
    /// Whether to enable strict mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

fn make_tool_name(op_id: &str, opts: &ExportOptions) -> String {
    let mut name = opts.strip_prefix.as_ref().map_or_else(
        || op_id.to_owned(),
        |prefix| {
            op_id
                .strip_prefix(prefix.as_str())
                .unwrap_or(op_id)
                .to_owned()
        },
    );

    if opts.sanitize_name {
        name = name.replace('.', "_");
    }

    name
}

fn build_description(op: &OperationInfo, opts: &ExportOptions) -> String {
    let mut parts = vec![op.summary.clone()];

    if let Some(description) = &op.description {
        if !description.is_empty() && description != &op.summary {
            parts.push(description.clone());
        }
    }

    if opts.include_ai_hints && !op.ai_hints.when_to_use.is_empty() {
        parts.push(format!("When to use: {}", op.ai_hints.when_to_use));
    }

    if opts.include_ai_hints && !op.ai_hints.common_mistakes.is_empty() {
        parts.push(format!(
            "Common mistakes: {}",
            op.ai_hints.common_mistakes.join("; ")
        ));
    }

    if opts.include_examples && !op.ai_hints.examples.is_empty() {
        parts.push(format!("Examples: {}", op.ai_hints.examples.join("; ")));
    }

    if opts.include_safety_metadata {
        let mut meta_parts = vec![
            format!("Risk: {}", risk_level_str(op.risk_level)),
            format!("Safety: {}", safety_tier_str(op.safety_tier)),
        ];

        if op.idempotency != IdempotencyClass::None {
            meta_parts.push(format!("Idempotency: {}", idempotency_str(op.idempotency)));
        }

        if let Some(approval) = op.requires_approval {
            let approval_str = serde_json::to_value(approval)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| format!("{approval:?}"));
            if approval_str != "none" {
                meta_parts.push(format!("Approval: {approval_str}"));
            }
        }

        parts.push(format!("[{}]", meta_parts.join(" | ")));
    }

    parts.join("\n\n")
}

const fn risk_level_str(risk_level: RiskLevel) -> &'static str {
    match risk_level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

const fn safety_tier_str(safety_tier: SafetyTier) -> &'static str {
    match safety_tier {
        SafetyTier::Safe => "safe",
        SafetyTier::Risky => "risky",
        SafetyTier::Dangerous => "dangerous",
        SafetyTier::Critical => "critical",
        SafetyTier::Forbidden => "forbidden",
    }
}

const fn idempotency_str(idempotency: IdempotencyClass) -> &'static str {
    match idempotency {
        IdempotencyClass::None => "none",
        IdempotencyClass::BestEffort => "best_effort",
        IdempotencyClass::Strict => "strict",
    }
}

const fn is_read_only(op: &OperationInfo) -> bool {
    matches!(
        (&op.safety_tier, &op.idempotency),
        (SafetyTier::Safe, IdempotencyClass::Strict)
    )
}

const fn is_destructive(op: &OperationInfo) -> bool {
    match op.safety_tier {
        SafetyTier::Dangerous | SafetyTier::Critical => true,
        SafetyTier::Safe | SafetyTier::Risky | SafetyTier::Forbidden => false,
    }
}

/// Convert an `OperationInfo` to an MCP tool.
#[must_use]
pub fn to_mcp_tool(op: &OperationInfo, opts: &ExportOptions) -> McpTool {
    let annotations = opts.include_safety_metadata.then(|| McpToolAnnotations {
        risk_level: Some(risk_level_str(op.risk_level).to_owned()),
        safety_tier: Some(safety_tier_str(op.safety_tier).to_owned()),
        idempotency: Some(idempotency_str(op.idempotency).to_owned()),
        capability: Some(op.capability.as_str().to_owned()),
        read_only: Some(is_read_only(op)),
        destructive: Some(is_destructive(op)),
    });

    McpTool {
        name: make_tool_name(op.id.as_str(), opts),
        description: build_description(op, opts),
        input_schema: op.input_schema.clone(),
        annotations,
    }
}

/// Convert an `OperationInfo` to a Claude tool.
#[must_use]
pub fn to_claude_tool(op: &OperationInfo, opts: &ExportOptions) -> ClaudeTool {
    ClaudeTool {
        name: make_tool_name(op.id.as_str(), opts),
        description: build_description(op, opts),
        input_schema: op.input_schema.clone(),
    }
}

/// Convert an `OperationInfo` to an `OpenAI` tool.
#[must_use]
pub fn to_openai_tool(op: &OperationInfo, opts: &ExportOptions) -> OpenAiTool {
    let mut openai_opts = opts.clone();
    openai_opts.sanitize_name = true;

    OpenAiTool {
        tool_type: "function".to_owned(),
        function: OpenAiFunction {
            name: make_tool_name(op.id.as_str(), &openai_opts),
            description: build_description(op, opts),
            parameters: op.input_schema.clone(),
            strict: None,
        },
    }
}

/// Convert multiple operations to MCP tools.
#[must_use]
pub fn to_mcp_tools(operations: &[OperationInfo], options: &ExportOptions) -> Vec<McpTool> {
    operations
        .iter()
        .map(|operation| to_mcp_tool(operation, options))
        .collect()
}

/// Convert multiple operations to Claude tools.
#[must_use]
pub fn to_claude_tools(operations: &[OperationInfo], options: &ExportOptions) -> Vec<ClaudeTool> {
    operations
        .iter()
        .map(|operation| to_claude_tool(operation, options))
        .collect()
}

/// Convert multiple operations to `OpenAI` tools.
#[must_use]
pub fn to_openai_tools(operations: &[OperationInfo], options: &ExportOptions) -> Vec<OpenAiTool> {
    operations
        .iter()
        .map(|operation| to_openai_tool(operation, options))
        .collect()
}

/// Convert multiple operations to the requested JSON tool schema format.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentHint, ApprovalMode, CapabilityId, OperationId};
    use serde_json::json;

    fn sample_operation() -> OperationInfo {
        OperationInfo {
            id: OperationId::from_static("github.list_issues"),
            summary: "List issues in a repository".to_owned(),
            description: Some("Returns paginated list of issues.".to_owned()),
            input_schema: json!({
                "type": "object",
                "required": ["owner", "repo"],
                "properties": {
                    "owner": { "type": "string" },
                    "repo": { "type": "string" }
                }
            }),
            output_schema: json!({"type": "object"}),
            capability: CapabilityId::from_static("github.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to inspect repository issues".to_owned(),
                common_mistakes: vec!["Forgetting pagination".to_owned()],
                examples: vec![r#"{"owner":"openai","repo":"gpt"}"#.to_owned()],
                related: vec![CapabilityId::from_static("github.get_issue")],
            },
            rate_limit: None,
            requires_approval: None,
        }
    }

    fn dangerous_operation() -> OperationInfo {
        OperationInfo {
            id: OperationId::from_static("twilio.create_call"),
            summary: "Initiate an outbound voice call".to_owned(),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
            capability: CapabilityId::from_static("twilio.voice"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint::default(),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        }
    }

    #[test]
    fn mcp_export_includes_annotations() {
        let tool = to_mcp_tool(&sample_operation(), &ExportOptions::default());
        let annotations = tool.annotations.expect("annotations present");
        assert_eq!(annotations.risk_level.as_deref(), Some("low"));
        assert_eq!(annotations.safety_tier.as_deref(), Some("safe"));
        assert_eq!(annotations.idempotency.as_deref(), Some("strict"));
        assert_eq!(annotations.read_only, Some(true));
        assert_eq!(annotations.destructive, Some(false));
    }

    #[test]
    fn openai_export_sanitizes_names() {
        let tool = to_openai_tool(&sample_operation(), &ExportOptions::default());
        assert_eq!(tool.function.name, "github_list_issues");
    }

    #[test]
    fn description_includes_approval_for_dangerous_operations() {
        let tool = to_claude_tool(&dangerous_operation(), &ExportOptions::default());
        assert!(tool.description.contains("Approval: interactive"));
        assert!(tool.description.contains("Risk: high"));
    }

    #[test]
    fn export_tools_json_emits_requested_format() {
        let operations = vec![sample_operation()];
        let json = export_tools_json(
            &operations,
            ToolSchemaFormat::Mcp,
            &ExportOptions::default(),
        )
        .expect("serialize mcp tools");
        assert!(json.is_array());
        assert_eq!(json[0]["name"], "github.list_issues");
        assert!(json[0]["inputSchema"].is_object());
    }
}
