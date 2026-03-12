//! MCP resource and prompt exposure for connector state and documentation.
//!
//! Defines the resource and prompt URIs that the MCP server exposes to agents,
//! providing access to connector health, rate limits, operations, history,
//! and documentation.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Resource URIs ─────────────────────────────────────────────────

/// A registered MCP resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpResource {
    /// Resource URI (e.g., `"resource://connector/github/health"`).
    pub uri: String,
    /// Human-readable name.
    pub name: String,
    /// MIME type of the resource content.
    pub mime_type: String,
    /// Description of what this resource provides.
    pub description: String,
}

impl McpResource {
    /// Create a new resource.
    pub fn new(
        uri: impl Into<String>,
        name: impl Into<String>,
        mime_type: impl Into<String>,
    ) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            mime_type: mime_type.into(),
            description: String::new(),
        }
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// Resource URI pattern for parameterized resources.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePattern {
    /// Per-connector health snapshot.
    ConnectorHealth,
    /// Per-connector rate limit status.
    ConnectorRateLimits,
    /// Per-connector operation list.
    ConnectorOperations,
    /// Per-connector recent operation history.
    ConnectorHistory,
    /// Cross-connector health dashboard.
    ConnectorsStatus,
}

impl ResourcePattern {
    /// Generate the URI for this pattern, given a connector ID.
    pub fn uri(&self, connector_id: Option<&str>) -> String {
        match self {
            Self::ConnectorHealth => format!(
                "resource://connector/{}/health",
                connector_id.unwrap_or("{id}")
            ),
            Self::ConnectorRateLimits => format!(
                "resource://connector/{}/rate-limits",
                connector_id.unwrap_or("{id}")
            ),
            Self::ConnectorOperations => format!(
                "resource://connector/{}/operations",
                connector_id.unwrap_or("{id}")
            ),
            Self::ConnectorHistory => format!(
                "resource://connector/{}/history",
                connector_id.unwrap_or("{id}")
            ),
            Self::ConnectorsStatus => "resource://connectors/status".to_string(),
        }
    }

    /// Human-readable name for this resource type.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ConnectorHealth => "Connector Health",
            Self::ConnectorRateLimits => "Rate Limit Status",
            Self::ConnectorOperations => "Operations List",
            Self::ConnectorHistory => "Operation History",
            Self::ConnectorsStatus => "All Connectors Status",
        }
    }

    /// Description.
    pub const fn description(&self) -> &'static str {
        match self {
            Self::ConnectorHealth => "Current health snapshot for a connector",
            Self::ConnectorRateLimits => "Rate limit pool usage and remaining quota",
            Self::ConnectorOperations => "List of available operations with metadata",
            Self::ConnectorHistory => "Recent operation audit log entries",
            Self::ConnectorsStatus => "Cross-connector health dashboard overview",
        }
    }

    /// MIME type.
    pub const fn mime_type() -> &'static str {
        "application/json"
    }

    /// Build an `McpResource` from this pattern.
    pub fn to_resource(&self, connector_id: Option<&str>) -> McpResource {
        McpResource::new(self.uri(connector_id), self.name(), Self::mime_type())
            .with_description(self.description())
    }
}

impl fmt::Display for ResourcePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── Prompt URIs ───────────────────────────────────────────────────

/// An MCP prompt template.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpPrompt {
    /// Prompt URI (e.g., `"prompt://connector/github/how-to-use"`).
    pub uri: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what this prompt provides.
    pub description: String,
    /// Arguments the prompt accepts.
    pub arguments: Vec<PromptArgument>,
}

impl McpPrompt {
    /// Create a new prompt.
    pub fn new(uri: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            description: String::new(),
            arguments: Vec::new(),
        }
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: add an argument.
    pub fn with_argument(mut self, arg: PromptArgument) -> Self {
        self.arguments.push(arg);
        self
    }
}

/// An argument for a prompt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptArgument {
    /// Argument name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Whether required.
    pub required: bool,
}

impl PromptArgument {
    /// Create a required argument.
    pub fn required(name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: desc.into(),
            required: true,
        }
    }

    /// Create an optional argument.
    pub fn optional(name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: desc.into(),
            required: false,
        }
    }
}

/// Prompt pattern for parameterized prompts.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptPattern {
    /// Usage guide for a connector.
    HowToUse,
    /// Example for a specific operation.
    OperationExample,
    /// Troubleshooting guide.
    Troubleshoot,
}

impl PromptPattern {
    /// Generate the URI for this pattern.
    pub fn uri(&self, connector_id: &str, operation: Option<&str>) -> String {
        match self {
            Self::HowToUse => format!("prompt://connector/{connector_id}/how-to-use"),
            Self::OperationExample => format!(
                "prompt://connector/{connector_id}/op/{}/example",
                operation.unwrap_or("{op}")
            ),
            Self::Troubleshoot => format!("prompt://connector/{connector_id}/troubleshoot"),
        }
    }

    /// Human-readable name.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::HowToUse => "How to Use",
            Self::OperationExample => "Operation Example",
            Self::Troubleshoot => "Troubleshooting Guide",
        }
    }

    /// Description.
    pub const fn description(&self) -> &'static str {
        match self {
            Self::HowToUse => "Usage guide with examples for this connector",
            Self::OperationExample => "Specific operation example with inputs and expected output",
            Self::Troubleshoot => "Troubleshooting guide for common issues with this connector",
        }
    }

    /// Build an `McpPrompt` from this pattern.
    pub fn to_prompt(&self, connector_id: &str, operation: Option<&str>) -> McpPrompt {
        let mut prompt = McpPrompt::new(self.uri(connector_id, operation), self.name())
            .with_description(self.description());

        // Add pattern-specific arguments
        match self {
            Self::HowToUse => {
                prompt = prompt.with_argument(PromptArgument::optional(
                    "focus",
                    "Focus area (auth, operations, errors)",
                ));
            }
            Self::OperationExample => {
                prompt = prompt.with_argument(PromptArgument::optional(
                    "format",
                    "Output format (json, toml, cli)",
                ));
            }
            Self::Troubleshoot => {
                prompt = prompt.with_argument(PromptArgument::optional(
                    "symptom",
                    "Specific symptom or error to troubleshoot",
                ));
            }
        }

        prompt
    }
}

impl fmt::Display for PromptPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── Resource Content ──────────────────────────────────────────────

/// Content of a resolved resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceContent {
    /// The resource URI that was resolved.
    pub uri: String,
    /// MIME type.
    pub mime_type: String,
    /// The actual content (JSON value).
    pub content: serde_json::Value,
}

impl ResourceContent {
    /// Create resource content.
    pub fn new(uri: impl Into<String>, content: serde_json::Value) -> Self {
        Self {
            uri: uri.into(),
            mime_type: "application/json".to_string(),
            content,
        }
    }
}

/// Content of a resolved prompt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptContent {
    /// The prompt URI that was resolved.
    pub uri: String,
    /// Rendered prompt messages.
    pub messages: Vec<PromptMessage>,
}

/// A single message in a prompt response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptMessage {
    /// Role (user/assistant).
    pub role: String,
    /// Content text.
    pub content: String,
}

impl PromptMessage {
    /// Create a user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
        }
    }

    /// Create an assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.into(),
        }
    }
}

impl PromptContent {
    /// Create prompt content.
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            messages: Vec::new(),
        }
    }

    /// Add a message.
    pub fn with_message(mut self, msg: PromptMessage) -> Self {
        self.messages.push(msg);
        self
    }
}

// ── Registry ──────────────────────────────────────────────────────

/// Registry of MCP resources and prompts for a server.
#[derive(Clone, Debug, Default)]
pub struct McpResourceRegistry {
    /// Registered resources.
    pub resources: Vec<McpResource>,
    /// Registered prompts.
    pub prompts: Vec<McpPrompt>,
}

impl McpResourceRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            resources: Vec::new(),
            prompts: Vec::new(),
        }
    }

    /// Register resources and prompts for a connector.
    pub fn register_connector(&mut self, connector_id: &str) {
        // Add all resource patterns
        for pattern in &[
            ResourcePattern::ConnectorHealth,
            ResourcePattern::ConnectorRateLimits,
            ResourcePattern::ConnectorOperations,
            ResourcePattern::ConnectorHistory,
        ] {
            self.resources.push(pattern.to_resource(Some(connector_id)));
        }

        // Add prompt patterns
        for pattern in &[PromptPattern::HowToUse, PromptPattern::Troubleshoot] {
            self.prompts.push(pattern.to_prompt(connector_id, None));
        }
    }

    /// Register the cross-connector status resource.
    pub fn register_global_resources(&mut self) {
        self.resources
            .push(ResourcePattern::ConnectorsStatus.to_resource(None));
    }

    /// Register an operation-specific example prompt.
    pub fn register_operation_prompt(&mut self, connector_id: &str, operation: &str) {
        self.prompts
            .push(PromptPattern::OperationExample.to_prompt(connector_id, Some(operation)));
    }

    /// List all resources.
    pub fn list_resources(&self) -> &[McpResource] {
        &self.resources
    }

    /// List all prompts.
    pub fn list_prompts(&self) -> &[McpPrompt] {
        &self.prompts
    }

    /// Find a resource by URI.
    pub fn find_resource(&self, uri: &str) -> Option<&McpResource> {
        self.resources.iter().find(|r| r.uri == uri)
    }

    /// Find a prompt by URI.
    pub fn find_prompt(&self, uri: &str) -> Option<&McpPrompt> {
        self.prompts.iter().find(|p| p.uri == uri)
    }

    /// Total resource count.
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    /// Total prompt count.
    pub fn prompt_count(&self) -> usize {
        self.prompts.len()
    }
}

// ── URI Resolution ────────────────────────────────────────────────

/// Parsed resource URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedUri {
    /// Per-connector resource: `resource://connector/{id}/{type}`.
    ConnectorResource {
        /// Connector ID.
        connector_id: String,
        /// Resource type (health, rate-limits, operations, history).
        resource_type: String,
    },
    /// Global resource: `resource://connectors/status`.
    GlobalStatus,
    /// Per-connector prompt: `prompt://connector/{id}/{type}`.
    ConnectorPrompt {
        /// Connector ID.
        connector_id: String,
        /// Prompt type.
        prompt_type: String,
        /// Operation (for operation-specific prompts).
        operation: Option<String>,
    },
    /// Unknown URI.
    Unknown(String),
}

/// Parse an MCP resource or prompt URI.
pub fn parse_uri(uri: &str) -> ParsedUri {
    if uri == "resource://connectors/status" {
        return ParsedUri::GlobalStatus;
    }

    if let Some(rest) = uri.strip_prefix("resource://connector/") {
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        if parts.len() == 2 {
            return ParsedUri::ConnectorResource {
                connector_id: parts[0].to_string(),
                resource_type: parts[1].to_string(),
            };
        }
    }

    if let Some(rest) = uri.strip_prefix("prompt://connector/") {
        let parts: Vec<&str> = rest.split('/').collect();
        match parts.len() {
            2 => {
                return ParsedUri::ConnectorPrompt {
                    connector_id: parts[0].to_string(),
                    prompt_type: parts[1].to_string(),
                    operation: None,
                };
            }
            4 if parts[1] == "op" && parts[3] == "example" => {
                return ParsedUri::ConnectorPrompt {
                    connector_id: parts[0].to_string(),
                    prompt_type: "operation-example".to_string(),
                    operation: Some(parts[2].to_string()),
                };
            }
            _ => {}
        }
    }

    ParsedUri::Unknown(uri.to_string())
}

// ── Display helpers ───────────────────────────────────────────────

/// Format the resource list for TOON display.
pub fn format_resource_list(resources: &[McpResource]) -> String {
    let mut lines = vec![format!("Resources ({}):", resources.len())];
    for r in resources {
        lines.push(format!("  {} — {}", r.uri, r.description));
    }
    lines.join("\n")
}

/// Format the prompt list for TOON display.
pub fn format_prompt_list(prompts: &[McpPrompt]) -> String {
    let mut lines = vec![format!("Prompts ({}):", prompts.len())];
    for p in prompts {
        let args: Vec<&str> = p.arguments.iter().map(|a| a.name.as_str()).collect();
        let args_str = if args.is_empty() {
            String::new()
        } else {
            format!(" [args: {}]", args.join(", "))
        };
        lines.push(format!("  {} — {}{}", p.uri, p.description, args_str));
    }
    lines.join("\n")
}

/// Generate a usage guide prompt for a connector.
pub fn generate_usage_guide(
    connector_id: &str,
    operations: &[String],
    _args: &BTreeMap<String, String>,
) -> PromptContent {
    let ops_list = operations
        .iter()
        .map(|o| format!("- {o}"))
        .collect::<Vec<_>>()
        .join("\n");

    PromptContent::new(format!("prompt://connector/{connector_id}/how-to-use"))
        .with_message(PromptMessage::user(format!(
            "How do I use the {connector_id} connector?"
        )))
        .with_message(PromptMessage::assistant(format!(
            "The {connector_id} connector provides the following operations:\n\n{ops_list}\n\n\
             Use `fwc invoke {connector_id} <operation>` to run an operation.\n\
             Use `fwc describe {connector_id} <operation>` for input/output details."
        )))
}

/// Generate a troubleshooting guide prompt.
pub fn generate_troubleshoot_guide(
    connector_id: &str,
    _args: &BTreeMap<String, String>,
) -> PromptContent {
    PromptContent::new(format!("prompt://connector/{connector_id}/troubleshoot"))
        .with_message(PromptMessage::user(format!(
            "Troubleshoot issues with the {connector_id} connector"
        )))
        .with_message(PromptMessage::assistant(format!(
            "Common troubleshooting steps for {connector_id}:\n\n\
             1. Check auth: `fwc auth status {connector_id}`\n\
             2. Check health: `fwc doctor {connector_id}`\n\
             3. Check rate limits: `fwc rate-limit {connector_id}`\n\
             4. Test connectivity: `fwc invoke {connector_id} <read-op> --dry-run`\n\n\
             If issues persist, check the connector logs with `fwc logs {connector_id}`."
        )))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── McpResource ───────────────────────────────────────────────

    #[test]
    fn resource_basic() {
        let r = McpResource::new("resource://test", "Test", "application/json");
        assert_eq!(r.uri, "resource://test");
        assert_eq!(r.name, "Test");
        assert_eq!(r.mime_type, "application/json");
    }

    #[test]
    fn resource_with_description() {
        let r = McpResource::new("resource://test", "Test", "application/json")
            .with_description("A test resource");
        assert_eq!(r.description, "A test resource");
    }

    #[test]
    fn resource_serializes() {
        let r = McpResource::new("resource://test", "Test", "application/json");
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["uri"], "resource://test");
    }

    // ── ResourcePattern ───────────────────────────────────────────

    #[test]
    fn resource_pattern_uri() {
        assert_eq!(
            ResourcePattern::ConnectorHealth.uri(Some("github")),
            "resource://connector/github/health"
        );
        assert_eq!(
            ResourcePattern::ConnectorRateLimits.uri(Some("slack")),
            "resource://connector/slack/rate-limits"
        );
        assert_eq!(
            ResourcePattern::ConnectorOperations.uri(Some("github")),
            "resource://connector/github/operations"
        );
        assert_eq!(
            ResourcePattern::ConnectorHistory.uri(Some("github")),
            "resource://connector/github/history"
        );
        assert_eq!(
            ResourcePattern::ConnectorsStatus.uri(None),
            "resource://connectors/status"
        );
    }

    #[test]
    fn resource_pattern_template_uri() {
        let uri = ResourcePattern::ConnectorHealth.uri(None);
        assert!(uri.contains("{id}"));
    }

    #[test]
    fn resource_pattern_names() {
        assert_eq!(ResourcePattern::ConnectorHealth.name(), "Connector Health");
        assert_eq!(
            ResourcePattern::ConnectorsStatus.name(),
            "All Connectors Status"
        );
    }

    #[test]
    fn resource_pattern_to_resource() {
        let r = ResourcePattern::ConnectorHealth.to_resource(Some("github"));
        assert_eq!(r.uri, "resource://connector/github/health");
        assert_eq!(r.mime_type, "application/json");
        assert!(!r.description.is_empty());
    }

    #[test]
    fn resource_pattern_display() {
        assert_eq!(
            ResourcePattern::ConnectorHealth.to_string(),
            "Connector Health"
        );
    }

    // ── McpPrompt ─────────────────────────────────────────────────

    #[test]
    fn prompt_basic() {
        let p = McpPrompt::new("prompt://test", "Test");
        assert_eq!(p.uri, "prompt://test");
        assert_eq!(p.name, "Test");
        assert!(p.arguments.is_empty());
    }

    #[test]
    fn prompt_with_arguments() {
        let p = McpPrompt::new("prompt://test", "Test")
            .with_argument(PromptArgument::required("x", "X"))
            .with_argument(PromptArgument::optional("y", "Y"));
        assert_eq!(p.arguments.len(), 2);
        assert!(p.arguments[0].required);
        assert!(!p.arguments[1].required);
    }

    // ── PromptPattern ─────────────────────────────────────────────

    #[test]
    fn prompt_pattern_uri() {
        assert_eq!(
            PromptPattern::HowToUse.uri("github", None),
            "prompt://connector/github/how-to-use"
        );
        assert_eq!(
            PromptPattern::OperationExample.uri("github", Some("create_issue")),
            "prompt://connector/github/op/create_issue/example"
        );
        assert_eq!(
            PromptPattern::Troubleshoot.uri("slack", None),
            "prompt://connector/slack/troubleshoot"
        );
    }

    #[test]
    fn prompt_pattern_to_prompt() {
        let p = PromptPattern::HowToUse.to_prompt("github", None);
        assert!(p.uri.contains("github/how-to-use"));
        assert!(!p.arguments.is_empty());
    }

    #[test]
    fn prompt_pattern_display() {
        assert_eq!(PromptPattern::HowToUse.to_string(), "How to Use");
    }

    // ── ResourceContent ───────────────────────────────────────────

    #[test]
    fn resource_content_basic() {
        let c = ResourceContent::new("resource://test", serde_json::json!({"status": "ok"}));
        assert_eq!(c.uri, "resource://test");
        assert_eq!(c.content["status"], "ok");
    }

    // ── PromptContent ─────────────────────────────────────────────

    #[test]
    fn prompt_content_basic() {
        let c = PromptContent::new("prompt://test")
            .with_message(PromptMessage::user("Hello"))
            .with_message(PromptMessage::assistant("Hi there"));
        assert_eq!(c.messages.len(), 2);
        assert_eq!(c.messages[0].role, "user");
        assert_eq!(c.messages[1].role, "assistant");
    }

    #[test]
    fn prompt_message_user() {
        let m = PromptMessage::user("test");
        assert_eq!(m.role, "user");
        assert_eq!(m.content, "test");
    }

    #[test]
    fn prompt_message_assistant() {
        let m = PromptMessage::assistant("response");
        assert_eq!(m.role, "assistant");
    }

    // ── McpResourceRegistry ───────────────────────────────────────

    #[test]
    fn registry_empty() {
        let reg = McpResourceRegistry::new();
        assert_eq!(reg.resource_count(), 0);
        assert_eq!(reg.prompt_count(), 0);
    }

    #[test]
    fn registry_register_connector() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        assert_eq!(reg.resource_count(), 4); // health, rate-limits, operations, history
        assert_eq!(reg.prompt_count(), 2); // how-to-use, troubleshoot
    }

    #[test]
    fn registry_register_multiple() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        reg.register_connector("slack");
        assert_eq!(reg.resource_count(), 8);
        assert_eq!(reg.prompt_count(), 4);
    }

    #[test]
    fn registry_global_resources() {
        let mut reg = McpResourceRegistry::new();
        reg.register_global_resources();
        assert_eq!(reg.resource_count(), 1);
        assert!(reg.find_resource("resource://connectors/status").is_some());
    }

    #[test]
    fn registry_operation_prompt() {
        let mut reg = McpResourceRegistry::new();
        reg.register_operation_prompt("github", "create_issue");
        assert_eq!(reg.prompt_count(), 1);
        assert!(
            reg.find_prompt("prompt://connector/github/op/create_issue/example")
                .is_some()
        );
    }

    #[test]
    fn registry_find_resource() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        assert!(
            reg.find_resource("resource://connector/github/health")
                .is_some()
        );
        assert!(
            reg.find_resource("resource://connector/slack/health")
                .is_none()
        );
    }

    #[test]
    fn registry_find_prompt() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        assert!(
            reg.find_prompt("prompt://connector/github/how-to-use")
                .is_some()
        );
    }

    // ── parse_uri ─────────────────────────────────────────────────

    #[test]
    fn parse_global_status() {
        let parsed = parse_uri("resource://connectors/status");
        assert_eq!(parsed, ParsedUri::GlobalStatus);
    }

    #[test]
    fn parse_connector_resource() {
        let parsed = parse_uri("resource://connector/github/health");
        assert_eq!(
            parsed,
            ParsedUri::ConnectorResource {
                connector_id: "github".to_string(),
                resource_type: "health".to_string(),
            }
        );
    }

    #[test]
    fn parse_connector_rate_limits() {
        let parsed = parse_uri("resource://connector/slack/rate-limits");
        assert_eq!(
            parsed,
            ParsedUri::ConnectorResource {
                connector_id: "slack".to_string(),
                resource_type: "rate-limits".to_string(),
            }
        );
    }

    #[test]
    fn parse_prompt_how_to_use() {
        let parsed = parse_uri("prompt://connector/github/how-to-use");
        assert_eq!(
            parsed,
            ParsedUri::ConnectorPrompt {
                connector_id: "github".to_string(),
                prompt_type: "how-to-use".to_string(),
                operation: None,
            }
        );
    }

    #[test]
    fn parse_prompt_operation_example() {
        let parsed = parse_uri("prompt://connector/github/op/create_issue/example");
        assert_eq!(
            parsed,
            ParsedUri::ConnectorPrompt {
                connector_id: "github".to_string(),
                prompt_type: "operation-example".to_string(),
                operation: Some("create_issue".to_string()),
            }
        );
    }

    #[test]
    fn parse_unknown_uri() {
        let parsed = parse_uri("http://example.com");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    // ── generate helpers ──────────────────────────────────────────

    #[test]
    fn usage_guide() {
        let ops = vec!["create_issue".to_string(), "list_repos".to_string()];
        let args = BTreeMap::new();
        let content = generate_usage_guide("github", &ops, &args);
        assert_eq!(content.messages.len(), 2);
        assert!(content.messages[1].content.contains("create_issue"));
    }

    #[test]
    fn troubleshoot_guide() {
        let args = BTreeMap::new();
        let content = generate_troubleshoot_guide("github", &args);
        assert_eq!(content.messages.len(), 2);
        assert!(content.messages[1].content.contains("auth status"));
    }

    // ── format helpers ────────────────────────────────────────────

    #[test]
    fn format_resources() {
        let resources = vec![
            McpResource::new("resource://test", "Test", "application/json")
                .with_description("A test"),
        ];
        let s = format_resource_list(&resources);
        assert!(s.contains("Resources (1)"));
        assert!(s.contains("resource://test"));
    }

    #[test]
    fn format_prompts() {
        let prompts = vec![
            McpPrompt::new("prompt://test", "Test")
                .with_description("A test prompt")
                .with_argument(PromptArgument::optional("x", "X")),
        ];
        let s = format_prompt_list(&prompts);
        assert!(s.contains("Prompts (1)"));
        assert!(s.contains("prompt://test"));
        assert!(s.contains("[args: x]"));
    }

    #[test]
    fn format_prompts_no_args() {
        let prompts =
            vec![McpPrompt::new("prompt://test", "Test").with_description("A test prompt")];
        let s = format_prompt_list(&prompts);
        assert!(!s.contains("args"));
    }

    // ── McpResource serde roundtrip ──────────────────────────────

    #[test]
    fn resource_serde_roundtrip() {
        let r = McpResource::new(
            "resource://connector/github/health",
            "Health",
            "application/json",
        )
        .with_description("Health check");
        let json = serde_json::to_string(&r).unwrap();
        let r2: McpResource = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.uri, "resource://connector/github/health");
        assert_eq!(r2.name, "Health");
        assert_eq!(r2.description, "Health check");
    }

    #[test]
    fn resource_empty_description() {
        let r = McpResource::new("resource://test", "T", "text/plain");
        assert!(r.description.is_empty());
    }

    #[test]
    fn resource_clone() {
        let r =
            McpResource::new("resource://test", "T", "application/json").with_description("desc");
        let r2 = r.clone();
        assert_eq!(r.uri, r2.uri);
        assert_eq!(r.description, r2.description);
    }

    // ── ResourcePattern exhaustive ───────────────────────────────

    #[test]
    fn resource_pattern_all_descriptions_non_empty() {
        for p in &[
            ResourcePattern::ConnectorHealth,
            ResourcePattern::ConnectorRateLimits,
            ResourcePattern::ConnectorOperations,
            ResourcePattern::ConnectorHistory,
            ResourcePattern::ConnectorsStatus,
        ] {
            assert!(!p.description().is_empty());
            assert!(!p.name().is_empty());
        }
    }

    #[test]
    fn resource_pattern_all_uris_with_connector() {
        let patterns = [
            ResourcePattern::ConnectorHealth,
            ResourcePattern::ConnectorRateLimits,
            ResourcePattern::ConnectorOperations,
            ResourcePattern::ConnectorHistory,
        ];
        for p in &patterns {
            let uri = p.uri(Some("slack"));
            assert!(uri.starts_with("resource://connector/slack/"));
        }
    }

    #[test]
    fn resource_pattern_mime_type() {
        assert_eq!(ResourcePattern::mime_type(), "application/json");
    }

    #[test]
    fn resource_pattern_serde_roundtrip() {
        for p in &[
            ResourcePattern::ConnectorHealth,
            ResourcePattern::ConnectorRateLimits,
            ResourcePattern::ConnectorOperations,
            ResourcePattern::ConnectorHistory,
            ResourcePattern::ConnectorsStatus,
        ] {
            let json = serde_json::to_string(p).unwrap();
            let p2: ResourcePattern = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, p2);
        }
    }

    #[test]
    fn resource_pattern_display_all() {
        assert_eq!(
            ResourcePattern::ConnectorRateLimits.to_string(),
            "Rate Limit Status"
        );
        assert_eq!(
            ResourcePattern::ConnectorOperations.to_string(),
            "Operations List"
        );
        assert_eq!(
            ResourcePattern::ConnectorHistory.to_string(),
            "Operation History"
        );
    }

    #[test]
    fn resource_pattern_connectors_status_ignores_id() {
        let uri1 = ResourcePattern::ConnectorsStatus.uri(None);
        let uri2 = ResourcePattern::ConnectorsStatus.uri(Some("github"));
        assert_eq!(uri1, uri2);
    }

    // ── McpPrompt additional ─────────────────────────────────────

    #[test]
    fn prompt_serde_roundtrip() {
        let p = McpPrompt::new("prompt://test", "Test")
            .with_description("A prompt")
            .with_argument(PromptArgument::required("x", "X arg"));
        let json = serde_json::to_string(&p).unwrap();
        let p2: McpPrompt = serde_json::from_str(&json).unwrap();
        assert_eq!(p2.uri, "prompt://test");
        assert_eq!(p2.arguments.len(), 1);
        assert!(p2.arguments[0].required);
    }

    #[test]
    fn prompt_empty_description() {
        let p = McpPrompt::new("prompt://test", "T");
        assert!(p.description.is_empty());
    }

    #[test]
    fn prompt_multiple_arguments() {
        let p = McpPrompt::new("prompt://test", "T")
            .with_argument(PromptArgument::required("a", "A"))
            .with_argument(PromptArgument::required("b", "B"))
            .with_argument(PromptArgument::optional("c", "C"));
        assert_eq!(p.arguments.len(), 3);
        assert!(p.arguments[0].required);
        assert!(!p.arguments[2].required);
    }

    // ── PromptPattern additional ─────────────────────────────────

    #[test]
    fn prompt_pattern_operation_example_template() {
        let uri = PromptPattern::OperationExample.uri("github", None);
        assert!(uri.contains("{op}"));
    }

    #[test]
    fn prompt_pattern_all_descriptions_non_empty() {
        for p in &[
            PromptPattern::HowToUse,
            PromptPattern::OperationExample,
            PromptPattern::Troubleshoot,
        ] {
            assert!(!p.description().is_empty());
            assert!(!p.name().is_empty());
        }
    }

    #[test]
    fn prompt_pattern_to_prompt_operation_example() {
        let p = PromptPattern::OperationExample.to_prompt("github", Some("create_issue"));
        assert!(p.uri.contains("create_issue"));
        assert!(!p.arguments.is_empty());
    }

    #[test]
    fn prompt_pattern_to_prompt_troubleshoot() {
        let p = PromptPattern::Troubleshoot.to_prompt("slack", None);
        assert!(p.uri.contains("slack/troubleshoot"));
        assert!(!p.arguments.is_empty());
    }

    #[test]
    fn prompt_pattern_display_all() {
        assert_eq!(
            PromptPattern::OperationExample.to_string(),
            "Operation Example"
        );
        assert_eq!(
            PromptPattern::Troubleshoot.to_string(),
            "Troubleshooting Guide"
        );
    }

    #[test]
    fn prompt_pattern_serde_roundtrip() {
        for p in &[
            PromptPattern::HowToUse,
            PromptPattern::OperationExample,
            PromptPattern::Troubleshoot,
        ] {
            let json = serde_json::to_string(p).unwrap();
            let p2: PromptPattern = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, p2);
        }
    }

    // ── PromptArgument ───────────────────────────────────────────

    #[test]
    fn prompt_argument_serde() {
        let arg = PromptArgument::required("focus", "Focus area");
        let json = serde_json::to_value(&arg).unwrap();
        assert_eq!(json["name"], "focus");
        assert!(json["required"].as_bool().unwrap());
    }

    #[test]
    fn prompt_argument_optional_serde() {
        let arg = PromptArgument::optional("format", "Output format");
        let json = serde_json::to_value(&arg).unwrap();
        assert!(!json["required"].as_bool().unwrap());
    }

    // ── ResourceContent additional ───────────────────────────────

    #[test]
    fn resource_content_serde_roundtrip() {
        let c = ResourceContent::new("resource://test", serde_json::json!({"data": [1, 2, 3]}));
        let json = serde_json::to_string(&c).unwrap();
        let c2: ResourceContent = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.uri, "resource://test");
        assert_eq!(c2.mime_type, "application/json");
        assert_eq!(c2.content["data"][0], 1);
    }

    #[test]
    fn resource_content_null_value() {
        let c = ResourceContent::new("resource://empty", serde_json::Value::Null);
        assert!(c.content.is_null());
    }

    // ── PromptContent additional ─────────────────────────────────

    #[test]
    fn prompt_content_serde_roundtrip() {
        let c = PromptContent::new("prompt://test")
            .with_message(PromptMessage::user("Q"))
            .with_message(PromptMessage::assistant("A"));
        let json = serde_json::to_string(&c).unwrap();
        let c2: PromptContent = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.uri, "prompt://test");
        assert_eq!(c2.messages.len(), 2);
    }

    #[test]
    fn prompt_content_empty() {
        let c = PromptContent::new("prompt://empty");
        assert!(c.messages.is_empty());
    }

    // ── McpResourceRegistry additional ───────────────────────────

    #[test]
    fn registry_list_resources() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        let list = reg.list_resources();
        assert_eq!(list.len(), 4);
    }

    #[test]
    fn registry_list_prompts() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        let list = reg.list_prompts();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn registry_find_resource_not_found() {
        let reg = McpResourceRegistry::new();
        assert!(reg.find_resource("resource://nonexistent").is_none());
    }

    #[test]
    fn registry_find_prompt_not_found() {
        let reg = McpResourceRegistry::new();
        assert!(reg.find_prompt("prompt://nonexistent").is_none());
    }

    #[test]
    fn registry_register_many_connectors() {
        let mut reg = McpResourceRegistry::new();
        for name in &["github", "slack", "jira", "linear", "notion"] {
            reg.register_connector(name);
        }
        assert_eq!(reg.resource_count(), 20); // 4 per connector * 5
        assert_eq!(reg.prompt_count(), 10); // 2 per connector * 5
    }

    #[test]
    fn registry_global_plus_connector() {
        let mut reg = McpResourceRegistry::new();
        reg.register_global_resources();
        reg.register_connector("github");
        assert_eq!(reg.resource_count(), 5); // 1 global + 4 connector
    }

    #[test]
    fn registry_multiple_operation_prompts() {
        let mut reg = McpResourceRegistry::new();
        reg.register_operation_prompt("github", "create_issue");
        reg.register_operation_prompt("github", "list_repos");
        assert_eq!(reg.prompt_count(), 2);
        assert!(
            reg.find_prompt("prompt://connector/github/op/list_repos/example")
                .is_some()
        );
    }

    // ── parse_uri edge cases ─────────────────────────────────────

    #[test]
    fn parse_resource_only_connector_no_type() {
        let parsed = parse_uri("resource://connector/github");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_prompt_only_connector() {
        let parsed = parse_uri("prompt://connector/github");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_empty_string() {
        let parsed = parse_uri("");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_resource_with_nested_path() {
        let parsed = parse_uri("resource://connector/github/nested/path");
        // splitn(2, '/') → ["github", "nested/path"]
        assert_eq!(
            parsed,
            ParsedUri::ConnectorResource {
                connector_id: "github".to_string(),
                resource_type: "nested/path".to_string(),
            }
        );
    }

    #[test]
    fn parse_prompt_three_segments() {
        // 3 segments but not matching op/X/example
        let parsed = parse_uri("prompt://connector/github/extra/segment");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_prompt_four_segments_wrong_pattern() {
        let parsed = parse_uri("prompt://connector/github/notop/create_issue/example");
        // parts[1] != "op" → doesn't match
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_prompt_four_segments_wrong_suffix() {
        let parsed = parse_uri("prompt://connector/github/op/create_issue/notexample");
        // parts[3] != "example" → doesn't match
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_uri_special_chars_in_connector() {
        let parsed = parse_uri("resource://connector/my-connector_v2/health");
        assert_eq!(
            parsed,
            ParsedUri::ConnectorResource {
                connector_id: "my-connector_v2".to_string(),
                resource_type: "health".to_string(),
            }
        );
    }

    // ── generate helpers additional ──────────────────────────────

    #[test]
    fn usage_guide_empty_ops() {
        let ops: Vec<String> = vec![];
        let args = BTreeMap::new();
        let content = generate_usage_guide("test", &ops, &args);
        assert_eq!(content.messages.len(), 2);
        assert!(content.messages[1].content.contains("test"));
    }

    #[test]
    fn usage_guide_many_ops() {
        let ops: Vec<String> = (0..20).map(|i| format!("op_{i}")).collect();
        let args = BTreeMap::new();
        let content = generate_usage_guide("connector", &ops, &args);
        assert!(content.messages[1].content.contains("op_0"));
        assert!(content.messages[1].content.contains("op_19"));
    }

    #[test]
    fn troubleshoot_guide_contains_all_steps() {
        let args = BTreeMap::new();
        let content = generate_troubleshoot_guide("slack", &args);
        let text = &content.messages[1].content;
        assert!(text.contains("auth status slack"));
        assert!(text.contains("doctor slack"));
        assert!(text.contains("rate-limit slack"));
        assert!(text.contains("logs slack"));
    }

    // ── format helpers additional ────────────────────────────────

    #[test]
    fn format_resources_empty() {
        let s = format_resource_list(&[]);
        assert!(s.contains("Resources (0)"));
    }

    #[test]
    fn format_prompts_empty() {
        let s = format_prompt_list(&[]);
        assert!(s.contains("Prompts (0)"));
    }

    #[test]
    fn format_prompts_multiple_args() {
        let prompts = vec![
            McpPrompt::new("prompt://test", "Test")
                .with_description("desc")
                .with_argument(PromptArgument::required("a", "A"))
                .with_argument(PromptArgument::optional("b", "B")),
        ];
        let s = format_prompt_list(&prompts);
        assert!(s.contains("[args: a, b]"));
    }

    #[test]
    fn format_resources_multiple() {
        let resources = vec![
            McpResource::new("resource://a", "A", "application/json").with_description("First"),
            McpResource::new("resource://b", "B", "application/json").with_description("Second"),
        ];
        let s = format_resource_list(&resources);
        assert!(s.contains("Resources (2)"));
        assert!(s.contains("resource://a"));
        assert!(s.contains("resource://b"));
    }

    // ── McpResource extended ────────────────────────────────────

    #[test]
    fn resource_debug_contains_fields() {
        let r = McpResource::new("resource://x", "X", "text/plain").with_description("desc");
        let dbg = format!("{r:?}");
        assert!(dbg.contains("resource://x"));
        assert!(dbg.contains("text/plain"));
        assert!(dbg.contains("desc"));
    }

    #[test]
    fn resource_clone_independence() {
        let r =
            McpResource::new("resource://a", "A", "application/json").with_description("original");
        let mut r2 = r.clone();
        r2.description = "modified".to_string();
        assert_eq!(r.description, "original");
        assert_eq!(r2.description, "modified");
    }

    #[test]
    fn resource_text_mime_type() {
        let r = McpResource::new("resource://t", "T", "text/plain");
        assert_eq!(r.mime_type, "text/plain");
    }

    #[test]
    fn resource_with_description_chaining() {
        let r = McpResource::new("resource://a", "A", "application/json")
            .with_description("first")
            .with_description("second");
        assert_eq!(r.description, "second");
    }

    #[test]
    fn resource_from_string_types() {
        let uri = String::from("resource://s");
        let name = String::from("S");
        let mime = String::from("text/html");
        let r = McpResource::new(uri, name, mime);
        assert_eq!(r.uri, "resource://s");
        assert_eq!(r.name, "S");
        assert_eq!(r.mime_type, "text/html");
    }

    #[test]
    fn resource_serialize_all_fields() {
        let r = McpResource::new("resource://f", "Full", "application/json")
            .with_description("all fields");
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["uri"], "resource://f");
        assert_eq!(json["name"], "Full");
        assert_eq!(json["mime_type"], "application/json");
        assert_eq!(json["description"], "all fields");
    }

    #[test]
    fn resource_deserialize_from_json() {
        let json = serde_json::json!({
            "uri": "resource://d",
            "name": "Deser",
            "mime_type": "text/csv",
            "description": "deserialized"
        });
        let r: McpResource = serde_json::from_value(json).unwrap();
        assert_eq!(r.uri, "resource://d");
        assert_eq!(r.mime_type, "text/csv");
    }

    // ── ResourcePattern extended ────────────────────────────────

    #[test]
    fn resource_pattern_template_uris_all() {
        let patterns = [
            ResourcePattern::ConnectorRateLimits,
            ResourcePattern::ConnectorOperations,
            ResourcePattern::ConnectorHistory,
        ];
        for p in &patterns {
            let uri = p.uri(None);
            assert!(
                uri.contains("{id}"),
                "Pattern {p:?} should contain template"
            );
        }
    }

    #[test]
    fn resource_pattern_to_resource_all_variants() {
        let patterns = [
            ResourcePattern::ConnectorHealth,
            ResourcePattern::ConnectorRateLimits,
            ResourcePattern::ConnectorOperations,
            ResourcePattern::ConnectorHistory,
            ResourcePattern::ConnectorsStatus,
        ];
        for p in &patterns {
            let r = p.to_resource(Some("test"));
            assert_eq!(r.mime_type, "application/json");
            assert!(!r.name.is_empty());
            assert!(!r.description.is_empty());
        }
    }

    #[test]
    fn resource_pattern_to_resource_global_no_id() {
        let r = ResourcePattern::ConnectorsStatus.to_resource(None);
        assert_eq!(r.uri, "resource://connectors/status");
        assert_eq!(r.name, "All Connectors Status");
    }

    #[test]
    fn resource_pattern_names_all() {
        assert_eq!(
            ResourcePattern::ConnectorRateLimits.name(),
            "Rate Limit Status"
        );
        assert_eq!(
            ResourcePattern::ConnectorOperations.name(),
            "Operations List"
        );
        assert_eq!(
            ResourcePattern::ConnectorHistory.name(),
            "Operation History"
        );
    }

    #[test]
    fn resource_pattern_descriptions_all() {
        assert!(
            ResourcePattern::ConnectorHealth
                .description()
                .contains("health")
        );
        assert!(
            ResourcePattern::ConnectorRateLimits
                .description()
                .contains("rate limit")
                || ResourcePattern::ConnectorRateLimits
                    .description()
                    .contains("Rate limit")
        );
        assert!(
            ResourcePattern::ConnectorOperations
                .description()
                .contains("operation")
        );
        assert!(
            ResourcePattern::ConnectorHistory
                .description()
                .contains("audit")
                || ResourcePattern::ConnectorHistory
                    .description()
                    .contains("log")
                || ResourcePattern::ConnectorHistory
                    .description()
                    .contains("history")
                || ResourcePattern::ConnectorHistory
                    .description()
                    .contains("Recent")
        );
        assert!(
            ResourcePattern::ConnectorsStatus
                .description()
                .contains("dashboard")
                || ResourcePattern::ConnectorsStatus
                    .description()
                    .contains("overview")
                || ResourcePattern::ConnectorsStatus
                    .description()
                    .contains("Cross")
        );
    }

    #[test]
    fn resource_pattern_hash_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ResourcePattern::ConnectorHealth);
        set.insert(ResourcePattern::ConnectorRateLimits);
        set.insert(ResourcePattern::ConnectorOperations);
        set.insert(ResourcePattern::ConnectorHistory);
        set.insert(ResourcePattern::ConnectorsStatus);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn resource_pattern_serde_snake_case_values() {
        let json = serde_json::to_string(&ResourcePattern::ConnectorHealth).unwrap();
        assert!(json.contains("connector_health"));
        let json = serde_json::to_string(&ResourcePattern::ConnectorRateLimits).unwrap();
        assert!(json.contains("connector_rate_limits"));
        let json = serde_json::to_string(&ResourcePattern::ConnectorsStatus).unwrap();
        assert!(json.contains("connectors_status"));
    }

    // ── McpPrompt extended ──────────────────────────────────────

    #[test]
    fn prompt_clone_independence() {
        let p = McpPrompt::new("prompt://a", "A")
            .with_description("orig")
            .with_argument(PromptArgument::required("x", "X"));
        let mut p2 = p.clone();
        p2.description = "modified".to_string();
        assert_eq!(p.description, "orig");
        assert_eq!(p2.description, "modified");
    }

    #[test]
    fn prompt_debug_output() {
        let p = McpPrompt::new("prompt://d", "Debug").with_description("debug test");
        let dbg = format!("{p:?}");
        assert!(dbg.contains("prompt://d"));
        assert!(dbg.contains("Debug"));
    }

    #[test]
    fn prompt_from_string_types() {
        let uri = String::from("prompt://s");
        let name = String::from("S");
        let p = McpPrompt::new(uri, name).with_description(String::from("desc"));
        assert_eq!(p.uri, "prompt://s");
        assert_eq!(p.name, "S");
        assert_eq!(p.description, "desc");
    }

    #[test]
    fn prompt_serialize_with_arguments() {
        let p = McpPrompt::new("prompt://ser", "Ser")
            .with_description("serial")
            .with_argument(PromptArgument::required("a", "A"))
            .with_argument(PromptArgument::optional("b", "B"));
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["arguments"].as_array().unwrap().len(), 2);
        assert_eq!(json["arguments"][0]["name"], "a");
        assert!(json["arguments"][0]["required"].as_bool().unwrap());
        assert!(!json["arguments"][1]["required"].as_bool().unwrap());
    }

    #[test]
    fn prompt_deserialize_from_json() {
        let json = serde_json::json!({
            "uri": "prompt://des",
            "name": "Des",
            "description": "deser",
            "arguments": [
                {"name": "x", "description": "X", "required": true}
            ]
        });
        let p: McpPrompt = serde_json::from_value(json).unwrap();
        assert_eq!(p.uri, "prompt://des");
        assert_eq!(p.arguments.len(), 1);
        assert!(p.arguments[0].required);
    }

    // ── PromptArgument extended ─────────────────────────────────

    #[test]
    fn prompt_argument_required_fields() {
        let arg = PromptArgument::required("key", "A key param");
        assert_eq!(arg.name, "key");
        assert_eq!(arg.description, "A key param");
        assert!(arg.required);
    }

    #[test]
    fn prompt_argument_optional_fields() {
        let arg = PromptArgument::optional("opt", "Optional param");
        assert_eq!(arg.name, "opt");
        assert_eq!(arg.description, "Optional param");
        assert!(!arg.required);
    }

    #[test]
    fn prompt_argument_clone() {
        let arg = PromptArgument::required("c", "Clone test");
        let arg2 = arg.clone();
        assert_eq!(arg.name, arg2.name);
        assert_eq!(arg.required, arg2.required);
    }

    #[test]
    fn prompt_argument_debug() {
        let arg = PromptArgument::optional("dbg", "debug");
        let dbg = format!("{arg:?}");
        assert!(dbg.contains("dbg"));
        assert!(dbg.contains("false"));
    }

    #[test]
    fn prompt_argument_serde_roundtrip() {
        let arg = PromptArgument::required("rt", "roundtrip");
        let json = serde_json::to_string(&arg).unwrap();
        let arg2: PromptArgument = serde_json::from_str(&json).unwrap();
        assert_eq!(arg2.name, "rt");
        assert_eq!(arg2.description, "roundtrip");
        assert!(arg2.required);
    }

    #[test]
    fn prompt_argument_from_string_types() {
        let name = String::from("str");
        let desc = String::from("string types");
        let arg = PromptArgument::required(name, desc);
        assert_eq!(arg.name, "str");
    }

    // ── PromptPattern extended ──────────────────────────────────

    #[test]
    fn prompt_pattern_hash_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PromptPattern::HowToUse);
        set.insert(PromptPattern::OperationExample);
        set.insert(PromptPattern::Troubleshoot);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn prompt_pattern_serde_snake_case_values() {
        let json = serde_json::to_string(&PromptPattern::HowToUse).unwrap();
        assert!(json.contains("how_to_use"));
        let json = serde_json::to_string(&PromptPattern::OperationExample).unwrap();
        assert!(json.contains("operation_example"));
        let json = serde_json::to_string(&PromptPattern::Troubleshoot).unwrap();
        assert!(json.contains("troubleshoot"));
    }

    #[test]
    fn prompt_pattern_to_prompt_how_to_use_has_focus_arg() {
        let p = PromptPattern::HowToUse.to_prompt("github", None);
        assert_eq!(p.arguments.len(), 1);
        assert_eq!(p.arguments[0].name, "focus");
        assert!(!p.arguments[0].required);
    }

    #[test]
    fn prompt_pattern_to_prompt_op_example_has_format_arg() {
        let p = PromptPattern::OperationExample.to_prompt("github", Some("list_repos"));
        assert_eq!(p.arguments.len(), 1);
        assert_eq!(p.arguments[0].name, "format");
        assert!(!p.arguments[0].required);
    }

    #[test]
    fn prompt_pattern_to_prompt_troubleshoot_has_symptom_arg() {
        let p = PromptPattern::Troubleshoot.to_prompt("slack", None);
        assert_eq!(p.arguments.len(), 1);
        assert_eq!(p.arguments[0].name, "symptom");
        assert!(!p.arguments[0].required);
    }

    #[test]
    fn prompt_pattern_to_prompt_sets_description() {
        let p = PromptPattern::HowToUse.to_prompt("github", None);
        assert!(!p.description.is_empty());
        assert!(
            p.description.contains("Usage")
                || p.description.contains("usage")
                || p.description.contains("guide")
        );
    }

    #[test]
    fn prompt_pattern_to_prompt_sets_name() {
        let p = PromptPattern::OperationExample.to_prompt("github", Some("create"));
        assert_eq!(p.name, "Operation Example");
    }

    // ── ResourceContent extended ────────────────────────────────

    #[test]
    fn resource_content_default_mime() {
        let c = ResourceContent::new("resource://m", serde_json::json!({}));
        assert_eq!(c.mime_type, "application/json");
    }

    #[test]
    fn resource_content_complex_json() {
        let val = serde_json::json!({
            "connectors": [
                {"id": "github", "status": "healthy"},
                {"id": "slack", "status": "degraded"}
            ],
            "count": 2
        });
        let c = ResourceContent::new("resource://complex", val);
        assert_eq!(c.content["connectors"].as_array().unwrap().len(), 2);
        assert_eq!(c.content["count"], 2);
    }

    #[test]
    fn resource_content_clone() {
        let c = ResourceContent::new("resource://cl", serde_json::json!({"a": 1}));
        let c2 = c.clone();
        assert_eq!(c.uri, c2.uri);
        assert_eq!(c.content, c2.content);
    }

    #[test]
    fn resource_content_debug() {
        let c = ResourceContent::new("resource://dbg", serde_json::json!(null));
        let dbg = format!("{c:?}");
        assert!(dbg.contains("resource://dbg"));
    }

    #[test]
    fn resource_content_string_value() {
        let c = ResourceContent::new("resource://sv", serde_json::json!("hello"));
        assert_eq!(c.content.as_str().unwrap(), "hello");
    }

    #[test]
    fn resource_content_array_value() {
        let c = ResourceContent::new("resource://arr", serde_json::json!([1, 2, 3]));
        assert_eq!(c.content.as_array().unwrap().len(), 3);
    }

    // ── PromptMessage extended ──────────────────────────────────

    #[test]
    fn prompt_message_clone() {
        let m = PromptMessage::user("clone me");
        let m2 = m.clone();
        assert_eq!(m.role, m2.role);
        assert_eq!(m.content, m2.content);
    }

    #[test]
    fn prompt_message_debug() {
        let m = PromptMessage::assistant("debug test");
        let dbg = format!("{m:?}");
        assert!(dbg.contains("assistant"));
        assert!(dbg.contains("debug test"));
    }

    #[test]
    fn prompt_message_serde_roundtrip() {
        let m = PromptMessage::user("serde test");
        let json = serde_json::to_string(&m).unwrap();
        let m2: PromptMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.role, "user");
        assert_eq!(m2.content, "serde test");
    }

    #[test]
    fn prompt_message_user_from_string() {
        let content = String::from("string content");
        let m = PromptMessage::user(content);
        assert_eq!(m.content, "string content");
    }

    #[test]
    fn prompt_message_assistant_from_string() {
        let content = String::from("assistant string");
        let m = PromptMessage::assistant(content);
        assert_eq!(m.content, "assistant string");
    }

    // ── PromptContent extended ──────────────────────────────────

    #[test]
    fn prompt_content_many_messages() {
        let mut c = PromptContent::new("prompt://many");
        for i in 0..10 {
            c = c.with_message(PromptMessage::user(format!("Q{i}")));
            c = c.with_message(PromptMessage::assistant(format!("A{i}")));
        }
        assert_eq!(c.messages.len(), 20);
        assert_eq!(c.messages[0].content, "Q0");
        assert_eq!(c.messages[19].content, "A9");
    }

    #[test]
    fn prompt_content_clone() {
        let c = PromptContent::new("prompt://cl")
            .with_message(PromptMessage::user("Q"))
            .with_message(PromptMessage::assistant("A"));
        let c2 = c.clone();
        assert_eq!(c.uri, c2.uri);
        assert_eq!(c.messages.len(), c2.messages.len());
    }

    #[test]
    fn prompt_content_debug() {
        let c = PromptContent::new("prompt://dbg");
        let dbg = format!("{c:?}");
        assert!(dbg.contains("prompt://dbg"));
    }

    #[test]
    fn prompt_content_from_string_uri() {
        let uri = String::from("prompt://string_uri");
        let c = PromptContent::new(uri);
        assert_eq!(c.uri, "prompt://string_uri");
    }

    // ── McpResourceRegistry extended ────────────────────────────

    #[test]
    fn registry_default_is_empty() {
        let reg = McpResourceRegistry::default();
        assert_eq!(reg.resource_count(), 0);
        assert_eq!(reg.prompt_count(), 0);
    }

    #[test]
    fn registry_clone() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        let reg2 = reg.clone();
        assert_eq!(reg.resource_count(), reg2.resource_count());
        assert_eq!(reg.prompt_count(), reg2.prompt_count());
    }

    #[test]
    fn registry_debug() {
        let reg = McpResourceRegistry::new();
        let dbg = format!("{reg:?}");
        assert!(dbg.contains("McpResourceRegistry"));
    }

    #[test]
    fn registry_connector_resources_have_correct_uris() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("jira");
        assert!(
            reg.find_resource("resource://connector/jira/health")
                .is_some()
        );
        assert!(
            reg.find_resource("resource://connector/jira/rate-limits")
                .is_some()
        );
        assert!(
            reg.find_resource("resource://connector/jira/operations")
                .is_some()
        );
        assert!(
            reg.find_resource("resource://connector/jira/history")
                .is_some()
        );
    }

    #[test]
    fn registry_connector_prompts_have_correct_uris() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("jira");
        assert!(
            reg.find_prompt("prompt://connector/jira/how-to-use")
                .is_some()
        );
        assert!(
            reg.find_prompt("prompt://connector/jira/troubleshoot")
                .is_some()
        );
    }

    #[test]
    fn registry_find_resource_returns_correct_data() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        let r = reg
            .find_resource("resource://connector/github/health")
            .unwrap();
        assert_eq!(r.name, "Connector Health");
        assert_eq!(r.mime_type, "application/json");
        assert!(!r.description.is_empty());
    }

    #[test]
    fn registry_find_prompt_returns_correct_data() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        let p = reg
            .find_prompt("prompt://connector/github/how-to-use")
            .unwrap();
        assert_eq!(p.name, "How to Use");
        assert!(!p.description.is_empty());
    }

    #[test]
    fn registry_operation_prompt_has_arguments() {
        let mut reg = McpResourceRegistry::new();
        reg.register_operation_prompt("github", "create_issue");
        let p = reg
            .find_prompt("prompt://connector/github/op/create_issue/example")
            .unwrap();
        assert!(!p.arguments.is_empty());
        assert_eq!(p.arguments[0].name, "format");
    }

    #[test]
    fn registry_combined_full_setup() {
        let mut reg = McpResourceRegistry::new();
        reg.register_global_resources();
        reg.register_connector("github");
        reg.register_connector("slack");
        reg.register_operation_prompt("github", "create_issue");
        reg.register_operation_prompt("slack", "send_message");
        assert_eq!(reg.resource_count(), 9); // 1 global + 4*2 connector
        assert_eq!(reg.prompt_count(), 6); // 2*2 connector + 2 operation
    }

    #[test]
    fn registry_list_resources_matches_count() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("a");
        reg.register_connector("b");
        assert_eq!(reg.list_resources().len(), reg.resource_count());
    }

    #[test]
    fn registry_list_prompts_matches_count() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("a");
        reg.register_operation_prompt("a", "op1");
        assert_eq!(reg.list_prompts().len(), reg.prompt_count());
    }

    // ── parse_uri extended ──────────────────────────────────────

    #[test]
    fn parse_connector_operations() {
        let parsed = parse_uri("resource://connector/github/operations");
        assert_eq!(
            parsed,
            ParsedUri::ConnectorResource {
                connector_id: "github".to_string(),
                resource_type: "operations".to_string(),
            }
        );
    }

    #[test]
    fn parse_connector_history() {
        let parsed = parse_uri("resource://connector/slack/history");
        assert_eq!(
            parsed,
            ParsedUri::ConnectorResource {
                connector_id: "slack".to_string(),
                resource_type: "history".to_string(),
            }
        );
    }

    #[test]
    fn parse_prompt_troubleshoot() {
        let parsed = parse_uri("prompt://connector/jira/troubleshoot");
        assert_eq!(
            parsed,
            ParsedUri::ConnectorPrompt {
                connector_id: "jira".to_string(),
                prompt_type: "troubleshoot".to_string(),
                operation: None,
            }
        );
    }

    #[test]
    fn parse_uri_wrong_scheme() {
        let parsed = parse_uri("https://connector/github/health");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_uri_partial_resource_prefix() {
        let parsed = parse_uri("resource://connect/github/health");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_uri_partial_prompt_prefix() {
        let parsed = parse_uri("prompt://connect/github/how-to-use");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_uri_resource_trailing_slash() {
        // "resource://connector/" → rest = "", splitn(2, '/') → [""], len == 1
        let parsed = parse_uri("resource://connector/");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_uri_just_resource_prefix() {
        let parsed = parse_uri("resource://connector");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_uri_prompt_five_segments() {
        // 5 segments in the path after connector/
        let parsed = parse_uri("prompt://connector/github/a/b/c/d");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_uri_global_status_exact_match() {
        // Slight variation should NOT match GlobalStatus — "connectors" != "connector"
        let parsed = parse_uri("resource://connectors/status/extra");
        assert!(matches!(parsed, ParsedUri::Unknown(_)));
    }

    #[test]
    fn parse_uri_unknown_preserves_input() {
        let input = "ftp://some/random/uri";
        let parsed = parse_uri(input);
        match parsed {
            ParsedUri::Unknown(s) => assert_eq!(s, input),
            _ => panic!("Expected Unknown"),
        }
    }

    #[test]
    fn parse_uri_operation_example_different_connector() {
        let parsed = parse_uri("prompt://connector/linear/op/create_task/example");
        assert_eq!(
            parsed,
            ParsedUri::ConnectorPrompt {
                connector_id: "linear".to_string(),
                prompt_type: "operation-example".to_string(),
                operation: Some("create_task".to_string()),
            }
        );
    }

    #[test]
    fn parsed_uri_eq_reflexive() {
        let a = ParsedUri::GlobalStatus;
        assert_eq!(a, a.clone());
    }

    #[test]
    fn parsed_uri_ne_different_variants() {
        let a = ParsedUri::GlobalStatus;
        let b = ParsedUri::Unknown("x".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn parsed_uri_clone() {
        let p = ParsedUri::ConnectorResource {
            connector_id: "g".to_string(),
            resource_type: "health".to_string(),
        };
        let p2 = p.clone();
        assert_eq!(p, p2);
    }

    #[test]
    fn parsed_uri_debug() {
        let p = ParsedUri::GlobalStatus;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("GlobalStatus"));
    }

    // ── generate helpers extended ───────────────────────────────

    #[test]
    fn usage_guide_uri_correct() {
        let ops = vec!["op1".to_string()];
        let args = BTreeMap::new();
        let content = generate_usage_guide("notion", &ops, &args);
        assert_eq!(content.uri, "prompt://connector/notion/how-to-use");
    }

    #[test]
    fn usage_guide_first_message_is_user() {
        let ops = vec!["x".to_string()];
        let args = BTreeMap::new();
        let content = generate_usage_guide("test", &ops, &args);
        assert_eq!(content.messages[0].role, "user");
    }

    #[test]
    fn usage_guide_second_message_is_assistant() {
        let ops = vec!["x".to_string()];
        let args = BTreeMap::new();
        let content = generate_usage_guide("test", &ops, &args);
        assert_eq!(content.messages[1].role, "assistant");
    }

    #[test]
    fn usage_guide_user_message_mentions_connector() {
        let ops = vec![];
        let args = BTreeMap::new();
        let content = generate_usage_guide("datadog", &ops, &args);
        assert!(content.messages[0].content.contains("datadog"));
    }

    #[test]
    fn usage_guide_assistant_mentions_invoke() {
        let ops = vec!["list".to_string()];
        let args = BTreeMap::new();
        let content = generate_usage_guide("github", &ops, &args);
        assert!(content.messages[1].content.contains("fwc invoke"));
    }

    #[test]
    fn usage_guide_assistant_mentions_describe() {
        let ops = vec!["list".to_string()];
        let args = BTreeMap::new();
        let content = generate_usage_guide("github", &ops, &args);
        assert!(content.messages[1].content.contains("fwc describe"));
    }

    #[test]
    fn troubleshoot_guide_uri_correct() {
        let args = BTreeMap::new();
        let content = generate_troubleshoot_guide("linear", &args);
        assert_eq!(content.uri, "prompt://connector/linear/troubleshoot");
    }

    #[test]
    fn troubleshoot_guide_first_message_is_user() {
        let args = BTreeMap::new();
        let content = generate_troubleshoot_guide("test", &args);
        assert_eq!(content.messages[0].role, "user");
    }

    #[test]
    fn troubleshoot_guide_second_message_is_assistant() {
        let args = BTreeMap::new();
        let content = generate_troubleshoot_guide("test", &args);
        assert_eq!(content.messages[1].role, "assistant");
    }

    #[test]
    fn troubleshoot_guide_user_mentions_connector() {
        let args = BTreeMap::new();
        let content = generate_troubleshoot_guide("jira", &args);
        assert!(content.messages[0].content.contains("jira"));
    }

    #[test]
    fn troubleshoot_guide_mentions_dry_run() {
        let args = BTreeMap::new();
        let content = generate_troubleshoot_guide("github", &args);
        assert!(content.messages[1].content.contains("--dry-run"));
    }

    // ── format helpers extended ─────────────────────────────────

    #[test]
    fn format_resources_descriptions_shown() {
        let resources = vec![
            McpResource::new("resource://x", "X", "application/json")
                .with_description("description one"),
        ];
        let s = format_resource_list(&resources);
        assert!(s.contains("description one"));
    }

    #[test]
    fn format_resources_many() {
        let resources: Vec<McpResource> = (0..10)
            .map(|i| {
                McpResource::new(
                    format!("resource://r{i}"),
                    format!("R{i}"),
                    "application/json",
                )
                .with_description(format!("desc {i}"))
            })
            .collect();
        let s = format_resource_list(&resources);
        assert!(s.contains("Resources (10)"));
        assert!(s.contains("resource://r0"));
        assert!(s.contains("resource://r9"));
    }

    #[test]
    fn format_prompts_description_shown() {
        let prompts = vec![McpPrompt::new("prompt://x", "X").with_description("the description")];
        let s = format_prompt_list(&prompts);
        assert!(s.contains("the description"));
    }

    #[test]
    fn format_resources_line_structure() {
        let resources = vec![
            McpResource::new("resource://a", "A", "application/json").with_description("Alpha"),
        ];
        let s = format_resource_list(&resources);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 resource
        assert!(lines[0].starts_with("Resources ("));
        assert!(lines[1].starts_with("  "));
    }

    #[test]
    fn format_prompts_line_structure() {
        let prompts = vec![McpPrompt::new("prompt://a", "A").with_description("Alpha")];
        let s = format_prompt_list(&prompts);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("Prompts ("));
        assert!(lines[1].starts_with("  "));
    }

    #[test]
    fn format_resources_dash_separator() {
        let resources = vec![
            McpResource::new("resource://x", "X", "application/json").with_description("desc"),
        ];
        let s = format_resource_list(&resources);
        // Each resource line has " — " separator
        assert!(s.contains(" — "));
    }

    #[test]
    fn format_prompts_dash_separator() {
        let prompts = vec![McpPrompt::new("prompt://x", "X").with_description("desc")];
        let s = format_prompt_list(&prompts);
        assert!(s.contains(" — "));
    }
}
