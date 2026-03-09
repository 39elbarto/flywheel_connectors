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
}
