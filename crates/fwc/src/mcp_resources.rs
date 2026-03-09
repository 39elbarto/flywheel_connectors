//! MCP resource and prompt exposure for connector state and documentation.
//!
//! Defines the resource and prompt URIs that the MCP server exposes to agents,
//! providing access to connector health, rate limits, operations, history,
//! and documentation.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

// ── Resource URIs ─────────────────────────────────────────────────

/// A registered MCP resource.
#[derive(Clone, Debug, Serialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
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
    pub const fn mime_type(&self) -> &'static str {
        "application/json"
    }

    /// Build an `McpResource` from this pattern.
    pub fn to_resource(&self, connector_id: Option<&str>) -> McpResource {
        McpResource::new(
            self.uri(connector_id),
            self.name(),
            self.mime_type(),
        )
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
#[derive(Clone, Debug, Serialize)]
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
    pub fn new(
        uri: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
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
#[derive(Clone, Debug, Serialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
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
        let mut prompt = McpPrompt::new(
            self.uri(connector_id, operation),
            self.name(),
        )
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
#[derive(Clone, Debug, Serialize)]
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
#[derive(Clone, Debug, Serialize)]
pub struct PromptContent {
    /// The prompt URI that was resolved.
    pub uri: String,
    /// Rendered prompt messages.
    pub messages: Vec<PromptMessage>,
}

/// A single message in a prompt response.
#[derive(Clone, Debug, Serialize)]
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
    pub fn new() -> Self {
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
        for pattern in &[
            PromptPattern::HowToUse,
            PromptPattern::Troubleshoot,
        ] {
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
        self.prompts.push(
            PromptPattern::OperationExample.to_prompt(connector_id, Some(operation)),
        );
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
        assert_eq!(ResourcePattern::ConnectorsStatus.name(), "All Connectors Status");
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
        assert_eq!(ResourcePattern::ConnectorHealth.to_string(), "Connector Health");
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
        assert!(reg
            .find_prompt("prompt://connector/github/op/create_issue/example")
            .is_some());
    }

    #[test]
    fn registry_find_resource() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        assert!(reg
            .find_resource("resource://connector/github/health")
            .is_some());
        assert!(reg.find_resource("resource://connector/slack/health").is_none());
    }

    #[test]
    fn registry_find_prompt() {
        let mut reg = McpResourceRegistry::new();
        reg.register_connector("github");
        assert!(reg
            .find_prompt("prompt://connector/github/how-to-use")
            .is_some());
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
        let prompts = vec![
            McpPrompt::new("prompt://test", "Test")
                .with_description("A test prompt"),
        ];
        let s = format_prompt_list(&prompts);
        assert!(!s.contains("args"));
    }
}
