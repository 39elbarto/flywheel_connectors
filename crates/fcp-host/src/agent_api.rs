//! MCP 2025 agent-facing protocol server surface.
//!
//! Implements the MCP JSON-RPC protocol layer for agent communication
//! with the host gateway. Per SEP-1382 and MCP 2025 specification.
//!
//! This module provides:
//! - MCP protocol types (initialize, tools, resources, JSON-RPC envelope)
//! - Agent session management (lifecycle, timeouts, rate limits)
//! - Method routing for incoming MCP requests
//! - Tool call execution context and results
//! - Conversion helpers between FCP and MCP types

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use fcp_core::{ConnectorId, OperationId};
use serde::{Deserialize, Serialize};

use crate::ToolDescriptor;

// ─────────────────────────────────────────────────────────────────────────────
// MCP Protocol Version
// ─────────────────────────────────────────────────────────────────────────────

/// MCP protocol version for capability negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum McpProtocolVersion {
    /// MCP 2025-03 (current).
    #[serde(rename = "2025-03-26")]
    V2025_03,
    /// MCP 2024-11 (previous).
    #[serde(rename = "2024-11-05")]
    V2024_11,
}

impl McpProtocolVersion {
    /// Returns the version string as used in the protocol.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2025_03 => "2025-03-26",
            Self::V2024_11 => "2024-11-05",
        }
    }

    /// Returns the latest supported version.
    #[must_use]
    pub const fn latest() -> Self {
        Self::V2025_03
    }

    /// Whether this version supports tool annotations.
    #[must_use]
    pub const fn supports_annotations(self) -> bool {
        matches!(self, Self::V2025_03)
    }
}

impl fmt::Display for McpProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Default for McpProtocolVersion {
    fn default() -> Self {
        Self::latest()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Server Capabilities
// ─────────────────────────────────────────────────────────────────────────────

/// Capabilities the MCP server exposes to agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerCapabilities {
    /// Whether the server supports tools/list and tools/call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<McpToolCapability>,

    /// Whether the server supports resources/list and resources/read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<McpResourceCapability>,

    /// Whether the server supports prompts/list and prompts/get.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<McpPromptCapability>,

    /// Whether the server supports logging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<McpLoggingCapability>,
}

impl McpServerCapabilities {
    /// Build a capability set with tools enabled.
    #[must_use]
    pub const fn with_tools() -> Self {
        Self {
            tools: Some(McpToolCapability {
                list_changed: Some(true),
            }),
            resources: None,
            prompts: None,
            logging: None,
        }
    }

    /// Build a full capability set with all features enabled.
    #[must_use]
    pub const fn full() -> Self {
        Self {
            tools: Some(McpToolCapability {
                list_changed: Some(true),
            }),
            resources: Some(McpResourceCapability {
                subscribe: Some(true),
                list_changed: Some(true),
            }),
            prompts: Some(McpPromptCapability {
                list_changed: Some(true),
            }),
            logging: Some(McpLoggingCapability {}),
        }
    }

    /// Whether tools capability is present.
    #[must_use]
    pub const fn has_tools(&self) -> bool {
        self.tools.is_some()
    }

    /// Whether resources capability is present.
    #[must_use]
    pub const fn has_resources(&self) -> bool {
        self.resources.is_some()
    }

    /// Whether prompts capability is present.
    #[must_use]
    pub const fn has_prompts(&self) -> bool {
        self.prompts.is_some()
    }

    /// Whether logging capability is present.
    #[must_use]
    pub const fn has_logging(&self) -> bool {
        self.logging.is_some()
    }
}

impl Default for McpServerCapabilities {
    fn default() -> Self {
        Self::with_tools()
    }
}

/// Tool-related server capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolCapability {
    /// Whether the server sends tool list change notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Resource-related server capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResourceCapability {
    /// Whether the server supports resource subscriptions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<bool>,

    /// Whether the server sends resource list change notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Prompt-related server capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpPromptCapability {
    /// Whether the server sends prompt list change notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Logging server capability (presence indicates support).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpLoggingCapability {}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Server Info
// ─────────────────────────────────────────────────────────────────────────────

/// Server information returned during initialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerInfo {
    /// Server name.
    pub name: String,
    /// Server version.
    pub version: String,
}

impl McpServerInfo {
    /// Build server info for the FCP host.
    #[must_use]
    pub fn fcp_host() -> Self {
        Self {
            name: "fcp-host".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Initialize Request / Response
// ─────────────────────────────────────────────────────────────────────────────

/// MCP initialize request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpInitializeRequest {
    /// Protocol version the client wants to use.
    pub protocol_version: McpProtocolVersion,

    /// Client capabilities.
    pub capabilities: McpClientCapabilities,

    /// Client information.
    pub client_info: McpClientInfo,
}

/// Client capabilities sent during initialization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpClientCapabilities {
    /// Whether the client supports sampling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<serde_json::Value>,

    /// Root URIs for file access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roots: Option<serde_json::Value>,
}

/// Client information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpClientInfo {
    /// Client name.
    pub name: String,
    /// Client version.
    pub version: String,
}

/// MCP initialize response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpInitializeResponse {
    /// Protocol version the server selected.
    pub protocol_version: McpProtocolVersion,

    /// Server capabilities.
    pub capabilities: McpServerCapabilities,

    /// Server info.
    pub server_info: McpServerInfo,
}

impl McpInitializeResponse {
    /// Build a default response for the FCP host with tools enabled.
    #[must_use]
    pub fn fcp_default(requested_version: McpProtocolVersion) -> Self {
        // Negotiate: accept the requested version if supported, else fall back.
        let negotiated = match requested_version {
            McpProtocolVersion::V2025_03 | McpProtocolVersion::V2024_11 => requested_version,
        };
        Self {
            protocol_version: negotiated,
            capabilities: McpServerCapabilities::default(),
            server_info: McpServerInfo::fcp_host(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON-RPC 2.0 Envelope
// ─────────────────────────────────────────────────────────────────────────────

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpJsonRpcRequest {
    /// Must be "2.0".
    pub jsonrpc: String,

    /// Request ID (string or number).
    pub id: serde_json::Value,

    /// Method name.
    pub method: String,

    /// Optional parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl McpJsonRpcRequest {
    /// Create a new JSON-RPC request.
    #[must_use]
    pub fn new(id: serde_json::Value, method: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            method: method.into(),
            params: None,
        }
    }

    /// Create a new JSON-RPC request with params.
    #[must_use]
    pub fn with_params(
        id: serde_json::Value,
        method: impl Into<String>,
        params: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            method: method.into(),
            params: Some(params),
        }
    }

    /// Validate that this is a well-formed JSON-RPC 2.0 request.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.jsonrpc == "2.0" && !self.method.is_empty()
    }
}

/// JSON-RPC 2.0 success response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpJsonRpcResponse {
    /// Must be "2.0".
    pub jsonrpc: String,

    /// Request ID this responds to.
    pub id: serde_json::Value,

    /// Result payload.
    pub result: serde_json::Value,
}

impl McpJsonRpcResponse {
    /// Create a success response.
    #[must_use]
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result,
        }
    }
}

/// JSON-RPC 2.0 error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpJsonRpcErrorResponse {
    /// Must be "2.0".
    pub jsonrpc: String,

    /// Request ID this responds to.
    pub id: serde_json::Value,

    /// Error object.
    pub error: McpJsonRpcError,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpJsonRpcError {
    /// Error code.
    pub code: i32,

    /// Error message.
    pub message: String,

    /// Optional structured data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Error Codes
// ─────────────────────────────────────────────────────────────────────────────

/// Standard MCP error codes.
///
/// Combines JSON-RPC 2.0 standard codes with MCP-specific extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpErrorCode {
    /// JSON-RPC: Invalid request (-32600).
    InvalidRequest,
    /// JSON-RPC: Method not found (-32601).
    MethodNotFound,
    /// JSON-RPC: Invalid params (-32602).
    InvalidParams,
    /// JSON-RPC: Internal error (-32603).
    InternalError,
    /// MCP: Tool not found (-32001).
    ToolNotFound,
    /// MCP: Tool execution error (-32002).
    ToolExecutionError,
    /// MCP: Resource not found (-32003).
    ResourceNotFound,
    /// MCP: Authentication required (-32004).
    AuthenticationRequired,
    /// MCP: Permission denied (-32005).
    PermissionDenied,
    /// MCP: Rate limited (-32006).
    RateLimited,
}

impl McpErrorCode {
    /// Numeric code value.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::ToolNotFound => -32001,
            Self::ToolExecutionError => -32002,
            Self::ResourceNotFound => -32003,
            Self::AuthenticationRequired => -32004,
            Self::PermissionDenied => -32005,
            Self::RateLimited => -32006,
        }
    }

    /// Default message for this error code.
    #[must_use]
    pub const fn default_message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "Invalid request",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::InternalError => "Internal error",
            Self::ToolNotFound => "Tool not found",
            Self::ToolExecutionError => "Tool execution error",
            Self::ResourceNotFound => "Resource not found",
            Self::AuthenticationRequired => "Authentication required",
            Self::PermissionDenied => "Permission denied",
            Self::RateLimited => "Rate limited",
        }
    }

    /// Attempt to parse a numeric code into a known error code.
    #[must_use]
    pub const fn from_code(code: i32) -> Option<Self> {
        match code {
            -32600 => Some(Self::InvalidRequest),
            -32601 => Some(Self::MethodNotFound),
            -32602 => Some(Self::InvalidParams),
            -32603 => Some(Self::InternalError),
            -32001 => Some(Self::ToolNotFound),
            -32002 => Some(Self::ToolExecutionError),
            -32003 => Some(Self::ResourceNotFound),
            -32004 => Some(Self::AuthenticationRequired),
            -32005 => Some(Self::PermissionDenied),
            -32006 => Some(Self::RateLimited),
            _ => None,
        }
    }

    /// Whether this is a JSON-RPC standard code.
    #[must_use]
    pub const fn is_standard_jsonrpc(self) -> bool {
        matches!(
            self,
            Self::InvalidRequest | Self::MethodNotFound | Self::InvalidParams | Self::InternalError
        )
    }

    /// Whether this is an MCP-specific code.
    #[must_use]
    pub const fn is_mcp_specific(self) -> bool {
        !self.is_standard_jsonrpc()
    }
}

impl fmt::Display for McpErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.default_message(), self.code())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Tool List Request / Response
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for tools/list request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolListRequest {
    /// Optional pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// MCP tool entry in tools/list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolListEntry {
    /// Tool name.
    pub name: String,

    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// JSON Schema for input parameters.
    pub input_schema: serde_json::Value,

    /// Optional annotations for risk/behavior metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<McpToolAnnotations>,
}

/// Tool annotations for MCP tools/list entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpToolAnnotations {
    /// Risk level string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,

    /// Safety tier string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_tier: Option<String>,

    /// Idempotency class string.
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

/// Response for tools/list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolListResponse {
    /// List of available tools.
    pub tools: Vec<McpToolListEntry>,

    /// Next cursor for pagination, if more tools remain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Tool Call Request / Response
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for tools/call request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolCallRequest {
    /// Name of the tool to call.
    pub name: String,

    /// Arguments to pass to the tool.
    #[serde(default)]
    pub arguments: serde_json::Value,
}

/// Response for tools/call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolCallResponse {
    /// Content blocks in the response.
    pub content: Vec<McpContentBlock>,

    /// Whether the tool call resulted in an error.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
}

impl McpToolCallResponse {
    /// Create a successful text response.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![McpContentBlock::text(text)],
            is_error: false,
        }
    }

    /// Create an error response with a message.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![McpContentBlock::text(message)],
            is_error: true,
        }
    }

    /// Create a response with multiple content blocks.
    #[must_use]
    pub const fn with_content(content: Vec<McpContentBlock>, is_error: bool) -> Self {
        Self { content, is_error }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Content Block
// ─────────────────────────────────────────────────────────────────────────────

/// Content block in MCP tool call responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum McpContentBlock {
    /// Text content.
    #[serde(rename = "text")]
    Text {
        /// The text content.
        text: String,
    },
    /// Image content.
    #[serde(rename = "image")]
    Image {
        /// Base64-encoded image data.
        data: String,
        /// MIME type (e.g., "image/png").
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    /// Embedded resource content.
    #[serde(rename = "resource")]
    Resource {
        /// Resource URI.
        uri: String,
        /// Optional MIME type.
        #[serde(skip_serializing_if = "Option::is_none", rename = "mimeType")]
        mime_type: Option<String>,
        /// Optional text content.
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
    },
}

impl McpContentBlock {
    /// Create a text content block.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    /// Create an image content block.
    #[must_use]
    pub fn image(data: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Self::Image {
            data: data.into(),
            mime_type: mime_type.into(),
        }
    }

    /// Create a resource content block.
    #[must_use]
    pub fn resource(uri: impl Into<String>) -> Self {
        Self::Resource {
            uri: uri.into(),
            mime_type: None,
            text: None,
        }
    }

    /// Whether this is a text block.
    #[must_use]
    pub const fn is_text(&self) -> bool {
        matches!(self, Self::Text { .. })
    }

    /// Whether this is an image block.
    #[must_use]
    pub const fn is_image(&self) -> bool {
        matches!(self, Self::Image { .. })
    }

    /// Whether this is a resource block.
    #[must_use]
    pub const fn is_resource(&self) -> bool {
        matches!(self, Self::Resource { .. })
    }

    /// Extract text content if this is a text block.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text { text } => Some(text),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Resource List Request / Response
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for resources/list request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResourceListRequest {
    /// Optional pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// A resource entry in resources/list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResourceEntry {
    /// Resource URI.
    pub uri: String,

    /// Human-readable name.
    pub name: String,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optional MIME type.
    #[serde(skip_serializing_if = "Option::is_none", rename = "mimeType")]
    pub mime_type: Option<String>,
}

/// Response for resources/list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResourceListResponse {
    /// Available resources.
    pub resources: Vec<McpResourceEntry>,

    /// Next cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent Session
// ─────────────────────────────────────────────────────────────────────────────

/// Status of an agent session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Session is active and processing requests.
    Active,
    /// Session is idle (no recent activity).
    Idle,
    /// Session has expired due to timeout.
    Expired,
    /// Session was explicitly terminated.
    Terminated,
}

impl SessionStatus {
    /// Whether the session can accept new requests.
    #[must_use]
    pub const fn is_alive(self) -> bool {
        matches!(self, Self::Active | Self::Idle)
    }

    /// Whether the session has ended.
    #[must_use]
    pub const fn is_ended(self) -> bool {
        matches!(self, Self::Expired | Self::Terminated)
    }
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Idle => f.write_str("idle"),
            Self::Expired => f.write_str("expired"),
            Self::Terminated => f.write_str("terminated"),
        }
    }
}

/// Configuration for agent sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSessionConfig {
    /// Idle timeout before session transitions to Idle.
    #[serde(with = "duration_secs")]
    pub idle_timeout: Duration,

    /// Maximum session lifetime.
    #[serde(with = "duration_secs")]
    pub max_lifetime: Duration,

    /// Maximum concurrent tool calls per session.
    pub max_concurrent_calls: u32,

    /// Rate limit: max requests per minute.
    pub rate_limit_per_minute: u32,
}

impl AgentSessionConfig {
    /// Validate the configuration.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.idle_timeout.is_zero() {
            errors.push("idle_timeout must be > 0".to_owned());
        }
        if self.max_lifetime.is_zero() {
            errors.push("max_lifetime must be > 0".to_owned());
        }
        if self.max_lifetime < self.idle_timeout {
            errors.push("max_lifetime must be >= idle_timeout".to_owned());
        }
        if self.max_concurrent_calls == 0 {
            errors.push("max_concurrent_calls must be > 0".to_owned());
        }
        if self.rate_limit_per_minute == 0 {
            errors.push("rate_limit_per_minute must be > 0".to_owned());
        }
        errors
    }

    /// Whether this configuration is valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

impl Default for AgentSessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_mins(5),
            max_lifetime: Duration::from_hours(1),
            max_concurrent_calls: 10,
            rate_limit_per_minute: 60,
        }
    }
}

/// Tracks a connected agent's session state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    /// Unique session identifier.
    pub id: String,

    /// Negotiated protocol version.
    pub protocol_version: McpProtocolVersion,

    /// Client capabilities from initialization.
    pub client_capabilities: McpClientCapabilities,

    /// Client info from initialization.
    pub client_info: McpClientInfo,

    /// When the session was established.
    pub connected_at: DateTime<Utc>,

    /// Last activity timestamp.
    pub last_activity: DateTime<Utc>,

    /// Number of tool calls made in this session.
    pub tool_call_count: u64,

    /// Current session status.
    pub status: SessionStatus,

    /// Session configuration.
    pub config: AgentSessionConfig,
}

impl AgentSession {
    /// Create a new active session from an initialize request.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        request: &McpInitializeRequest,
        config: AgentSessionConfig,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            protocol_version: request.protocol_version,
            client_capabilities: request.capabilities.clone(),
            client_info: request.client_info.clone(),
            connected_at: now,
            last_activity: now,
            tool_call_count: 0,
            status: SessionStatus::Active,
            config,
        }
    }

    /// Record activity on this session.
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
        if self.status == SessionStatus::Idle {
            self.status = SessionStatus::Active;
        }
    }

    /// Record a tool call.
    pub fn record_tool_call(&mut self) {
        self.tool_call_count += 1;
        self.touch();
    }

    /// Transition to idle.
    pub fn mark_idle(&mut self) {
        if self.status == SessionStatus::Active {
            self.status = SessionStatus::Idle;
        }
    }

    /// Expire the session.
    pub const fn expire(&mut self) {
        if self.status.is_alive() {
            self.status = SessionStatus::Expired;
        }
    }

    /// Terminate the session.
    pub const fn terminate(&mut self) {
        self.status = SessionStatus::Terminated;
    }

    /// Duration since last activity.
    #[must_use]
    pub fn idle_duration(&self) -> chrono::Duration {
        Utc::now() - self.last_activity
    }

    /// Duration since session started.
    #[must_use]
    pub fn lifetime(&self) -> chrono::Duration {
        Utc::now() - self.connected_at
    }

    /// Whether the session has exceeded its idle timeout.
    #[must_use]
    pub fn is_idle_expired(&self) -> bool {
        let idle_secs = (Utc::now() - self.last_activity).num_seconds();
        idle_secs >= 0
            && u64::try_from(idle_secs).unwrap_or(u64::MAX) >= self.config.idle_timeout.as_secs()
    }

    /// Whether the session has exceeded its maximum lifetime.
    #[must_use]
    pub fn is_lifetime_expired(&self) -> bool {
        let life_secs = (Utc::now() - self.connected_at).num_seconds();
        life_secs >= 0
            && u64::try_from(life_secs).unwrap_or(u64::MAX) >= self.config.max_lifetime.as_secs()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Method Routing
// ─────────────────────────────────────────────────────────────────────────────

/// Category of MCP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpMethodCategory {
    /// Session initialization.
    Initialize,
    /// List available tools.
    ToolsList,
    /// Call a tool.
    ToolsCall,
    /// List available resources.
    ResourcesList,
    /// Read a resource.
    ResourcesRead,
    /// List available prompts.
    PromptsList,
    /// Get a specific prompt.
    PromptsGet,
    /// Auto-completion.
    Completion,
    /// Set logging level.
    Logging,
    /// Keep-alive ping.
    Ping,
    /// Notifications (client -> server, no response expected).
    Notification,
    /// Unknown method.
    Unknown,
}

impl McpMethodCategory {
    /// Whether this category expects a response.
    #[must_use]
    pub const fn expects_response(self) -> bool {
        !matches!(self, Self::Notification)
    }

    /// Whether this category requires an initialized session.
    #[must_use]
    pub const fn requires_session(self) -> bool {
        !matches!(self, Self::Initialize | Self::Ping | Self::Unknown)
    }
}

impl fmt::Display for McpMethodCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialize => f.write_str("initialize"),
            Self::ToolsList => f.write_str("tools/list"),
            Self::ToolsCall => f.write_str("tools/call"),
            Self::ResourcesList => f.write_str("resources/list"),
            Self::ResourcesRead => f.write_str("resources/read"),
            Self::PromptsList => f.write_str("prompts/list"),
            Self::PromptsGet => f.write_str("prompts/get"),
            Self::Completion => f.write_str("completion/complete"),
            Self::Logging => f.write_str("logging/setLevel"),
            Self::Ping => f.write_str("ping"),
            Self::Notification => f.write_str("notification"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

/// Routes an MCP method string to its category.
#[must_use]
pub fn route_mcp_method(method: &str) -> McpMethodCategory {
    match method {
        "initialize" => McpMethodCategory::Initialize,
        "tools/list" => McpMethodCategory::ToolsList,
        "tools/call" => McpMethodCategory::ToolsCall,
        "resources/list" => McpMethodCategory::ResourcesList,
        "resources/read" => McpMethodCategory::ResourcesRead,
        "prompts/list" => McpMethodCategory::PromptsList,
        "prompts/get" => McpMethodCategory::PromptsGet,
        "completion/complete" => McpMethodCategory::Completion,
        "logging/setLevel" => McpMethodCategory::Logging,
        "ping" => McpMethodCategory::Ping,
        m if m.starts_with("notifications/") => McpMethodCategory::Notification,
        _ => McpMethodCategory::Unknown,
    }
}

/// Stateless MCP method router.
///
/// Provides method routing with optional middleware-like hooks.
#[derive(Debug, Clone)]
pub struct McpMethodRouter {
    /// Additional method aliases (custom extensions).
    custom_routes: HashMap<String, McpMethodCategory>,
}

impl McpMethodRouter {
    /// Create a router with standard MCP methods only.
    #[must_use]
    pub fn new() -> Self {
        Self {
            custom_routes: HashMap::new(),
        }
    }

    /// Register a custom method route.
    pub fn add_route(&mut self, method: impl Into<String>, category: McpMethodCategory) {
        self.custom_routes.insert(method.into(), category);
    }

    /// Route a method string. Custom routes take precedence.
    #[must_use]
    pub fn route(&self, method: &str) -> McpMethodCategory {
        if let Some(&category) = self.custom_routes.get(method) {
            return category;
        }
        route_mcp_method(method)
    }

    /// Number of custom routes registered.
    #[must_use]
    pub fn custom_route_count(&self) -> usize {
        self.custom_routes.len()
    }

    /// All known method names (standard + custom).
    #[must_use]
    pub fn all_methods(&self) -> Vec<String> {
        let mut methods: Vec<String> = vec![
            "initialize".to_owned(),
            "tools/list".to_owned(),
            "tools/call".to_owned(),
            "resources/list".to_owned(),
            "resources/read".to_owned(),
            "prompts/list".to_owned(),
            "prompts/get".to_owned(),
            "completion/complete".to_owned(),
            "logging/setLevel".to_owned(),
            "ping".to_owned(),
        ];
        for key in self.custom_routes.keys() {
            methods.push(key.clone());
        }
        methods.sort();
        methods
    }
}

impl Default for McpMethodRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool Call Execution
// ─────────────────────────────────────────────────────────────────────────────

/// Context for a tool call being executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallContext {
    /// Session ID of the calling agent.
    pub session_id: String,

    /// JSON-RPC request ID.
    pub request_id: serde_json::Value,

    /// Name of the tool being called.
    pub tool_name: String,

    /// Connector ID that owns this tool.
    pub connector_id: ConnectorId,

    /// Operation ID within the connector.
    pub operation_id: OperationId,

    /// Arguments from the client.
    pub arguments: serde_json::Value,

    /// When the call started.
    pub started_at: DateTime<Utc>,
}

impl ToolCallContext {
    /// Create a new tool call context.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        request_id: serde_json::Value,
        tool_name: impl Into<String>,
        connector_id: ConnectorId,
        operation_id: OperationId,
        arguments: serde_json::Value,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            request_id,
            tool_name: tool_name.into(),
            connector_id,
            operation_id,
            arguments,
            started_at: Utc::now(),
        }
    }

    /// Elapsed time since the call started.
    #[must_use]
    pub fn elapsed(&self) -> chrono::Duration {
        Utc::now() - self.started_at
    }
}

/// Result of a tool call execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallResult {
    /// Content blocks from execution.
    pub content: Vec<McpContentBlock>,

    /// Whether the call resulted in an error.
    pub is_error: bool,

    /// Execution duration in milliseconds.
    pub duration_ms: u64,

    /// Optional metadata from the connector.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ToolCallResult {
    /// Create a successful result with text content.
    #[must_use]
    pub fn success_text(text: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            content: vec![McpContentBlock::text(text)],
            is_error: false,
            duration_ms,
            metadata: HashMap::new(),
        }
    }

    /// Create an error result.
    #[must_use]
    pub fn error(message: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            content: vec![McpContentBlock::text(message)],
            is_error: true,
            duration_ms,
            metadata: HashMap::new(),
        }
    }

    /// Convert to an MCP tool call response.
    #[must_use]
    pub fn to_mcp_response(&self) -> McpToolCallResponse {
        McpToolCallResponse {
            content: self.content.clone(),
            is_error: self.is_error,
        }
    }
}

/// Structured error from a tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallError {
    /// Error code.
    pub code: McpErrorCode,

    /// Human-readable error message.
    pub message: String,

    /// Optional structured data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl ToolCallError {
    /// Create a new tool call error.
    #[must_use]
    pub fn new(code: McpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Create a new tool call error with structured data.
    #[must_use]
    pub fn with_data(
        code: McpErrorCode,
        message: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    /// Convert to a JSON-RPC error object.
    #[must_use]
    pub fn to_jsonrpc_error(&self) -> McpJsonRpcError {
        McpJsonRpcError {
            code: self.code.code(),
            message: self.message.clone(),
            data: self.data.clone(),
        }
    }
}

impl fmt::Display for ToolCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversion Helpers
// ─────────────────────────────────────────────────────────────────────────────

impl ToolDescriptor {
    #[must_use]
    const fn mcp_read_only_hint(&self) -> bool {
        matches!(
            (self.safety_tier, self.idempotency),
            (
                fcp_core::SafetyTier::Safe,
                fcp_core::IdempotencyClass::Strict
            )
        )
    }

    #[must_use]
    const fn mcp_destructive_hint(&self) -> bool {
        matches!(
            self.safety_tier,
            fcp_core::SafetyTier::Dangerous | fcp_core::SafetyTier::Critical
        )
    }

    /// Convert to an MCP tools/list entry.
    ///
    /// This keeps MCP hints aligned with the canonical `OperationInfo` export
    /// semantics used elsewhere in the workspace.
    #[must_use]
    pub fn to_mcp_tool_list_entry(&self) -> McpToolListEntry {
        let annotations = McpToolAnnotations {
            risk_level: Some(format!("{:?}", self.risk_level).to_lowercase()),
            safety_tier: Some(format!("{:?}", self.safety_tier).to_lowercase()),
            idempotency: Some(format!("{:?}", self.idempotency).to_lowercase()),
            capability: Some(self.capability.as_str().to_owned()),
            read_only: Some(self.mcp_read_only_hint()),
            destructive: Some(self.mcp_destructive_hint()),
        };

        McpToolListEntry {
            name: self.name.clone(),
            description: Some(self.description.clone()),
            input_schema: self.input_schema.clone(),
            annotations: Some(annotations),
        }
    }
}

/// Build an MCP JSON-RPC error response.
#[must_use]
pub fn build_error_response(
    id: serde_json::Value,
    code: McpErrorCode,
    message: impl Into<String>,
) -> McpJsonRpcErrorResponse {
    McpJsonRpcErrorResponse {
        jsonrpc: "2.0".to_owned(),
        id,
        error: McpJsonRpcError {
            code: code.code(),
            message: message.into(),
            data: None,
        },
    }
}

/// Build an MCP JSON-RPC error response with additional data.
#[must_use]
pub fn build_error_response_with_data(
    id: serde_json::Value,
    code: McpErrorCode,
    message: impl Into<String>,
    data: serde_json::Value,
) -> McpJsonRpcErrorResponse {
    McpJsonRpcErrorResponse {
        jsonrpc: "2.0".to_owned(),
        id,
        error: McpJsonRpcError {
            code: code.code(),
            message: message.into(),
            data: Some(data),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Serde helper for Duration as seconds
// ─────────────────────────────────────────────────────────────────────────────

mod duration_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Serialize / Deserialize for McpErrorCode
// ─────────────────────────────────────────────────────────────────────────────

impl Serialize for McpErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32(self.code())
    }
}

impl<'de> Deserialize<'de> for McpErrorCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let code = i32::deserialize(deserializer)?;
        Self::from_code(code)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown MCP error code: {code}")))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── McpProtocolVersion ──────────────────────────────────────────────

    #[test]
    fn protocol_version_as_str() {
        assert_eq!(McpProtocolVersion::V2025_03.as_str(), "2025-03-26");
        assert_eq!(McpProtocolVersion::V2024_11.as_str(), "2024-11-05");
    }

    #[test]
    fn protocol_version_display() {
        assert_eq!(McpProtocolVersion::V2025_03.to_string(), "2025-03-26");
        assert_eq!(McpProtocolVersion::V2024_11.to_string(), "2024-11-05");
    }

    #[test]
    fn protocol_version_latest() {
        assert_eq!(McpProtocolVersion::latest(), McpProtocolVersion::V2025_03);
    }

    #[test]
    fn protocol_version_default() {
        assert_eq!(McpProtocolVersion::default(), McpProtocolVersion::V2025_03);
    }

    #[test]
    fn protocol_version_serialize() {
        let v = McpProtocolVersion::V2025_03;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"2025-03-26\"");
    }

    #[test]
    fn protocol_version_deserialize() {
        let v: McpProtocolVersion = serde_json::from_str("\"2024-11-05\"").unwrap();
        assert_eq!(v, McpProtocolVersion::V2024_11);
    }

    #[test]
    fn protocol_version_roundtrip() {
        for version in [McpProtocolVersion::V2025_03, McpProtocolVersion::V2024_11] {
            let json = serde_json::to_string(&version).unwrap();
            let back: McpProtocolVersion = serde_json::from_str(&json).unwrap();
            assert_eq!(version, back);
        }
    }

    #[test]
    fn protocol_version_supports_annotations() {
        assert!(McpProtocolVersion::V2025_03.supports_annotations());
        assert!(!McpProtocolVersion::V2024_11.supports_annotations());
    }

    #[test]
    fn protocol_version_equality() {
        assert_eq!(McpProtocolVersion::V2025_03, McpProtocolVersion::V2025_03);
        assert_ne!(McpProtocolVersion::V2025_03, McpProtocolVersion::V2024_11);
    }

    // ── McpServerCapabilities ───────────────────────────────────────────

    #[test]
    fn capabilities_default_has_tools() {
        let caps = McpServerCapabilities::default();
        assert!(caps.has_tools());
        assert!(!caps.has_resources());
        assert!(!caps.has_prompts());
        assert!(!caps.has_logging());
    }

    #[test]
    fn capabilities_with_tools() {
        let caps = McpServerCapabilities::with_tools();
        assert!(caps.has_tools());
        assert!(!caps.has_resources());
    }

    #[test]
    fn capabilities_full() {
        let caps = McpServerCapabilities::full();
        assert!(caps.has_tools());
        assert!(caps.has_resources());
        assert!(caps.has_prompts());
        assert!(caps.has_logging());
    }

    #[test]
    fn capabilities_serialize_default() {
        let caps = McpServerCapabilities::default();
        let json = serde_json::to_value(&caps).unwrap();
        assert!(json.get("tools").is_some());
        // resources/prompts/logging should be absent (skip_serializing_if)
        assert!(json.get("resources").is_none());
        assert!(json.get("prompts").is_none());
        assert!(json.get("logging").is_none());
    }

    #[test]
    fn capabilities_serialize_full() {
        let caps = McpServerCapabilities::full();
        let json = serde_json::to_value(&caps).unwrap();
        assert!(json.get("tools").is_some());
        assert!(json.get("resources").is_some());
        assert!(json.get("prompts").is_some());
        assert!(json.get("logging").is_some());
    }

    #[test]
    fn capabilities_roundtrip() {
        let caps = McpServerCapabilities::full();
        let json = serde_json::to_string(&caps).unwrap();
        let back: McpServerCapabilities = serde_json::from_str(&json).unwrap();
        assert!(back.has_tools());
        assert!(back.has_resources());
        assert!(back.has_prompts());
        assert!(back.has_logging());
    }

    #[test]
    fn tool_capability_list_changed() {
        let caps = McpServerCapabilities::full();
        let tool_cap = caps.tools.unwrap();
        assert_eq!(tool_cap.list_changed, Some(true));
    }

    #[test]
    fn resource_capability_subscribe() {
        let caps = McpServerCapabilities::full();
        let res_cap = caps.resources.unwrap();
        assert_eq!(res_cap.subscribe, Some(true));
        assert_eq!(res_cap.list_changed, Some(true));
    }

    // ── McpServerInfo ───────────────────────────────────────────────────

    #[test]
    fn server_info_fcp_host() {
        let info = McpServerInfo::fcp_host();
        assert_eq!(info.name, "fcp-host");
        assert!(!info.version.is_empty());
    }

    #[test]
    fn server_info_serialize() {
        let info = McpServerInfo::fcp_host();
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["name"], "fcp-host");
    }

    // ── McpInitializeRequest / Response ─────────────────────────────────

    #[test]
    fn initialize_request_serialize() {
        let req = McpInitializeRequest {
            protocol_version: McpProtocolVersion::V2025_03,
            capabilities: McpClientCapabilities::default(),
            client_info: McpClientInfo {
                name: "test-agent".to_owned(),
                version: "1.0.0".to_owned(),
            },
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["protocolVersion"], "2025-03-26");
        assert_eq!(json["clientInfo"]["name"], "test-agent");
    }

    #[test]
    fn initialize_request_roundtrip() {
        let req = McpInitializeRequest {
            protocol_version: McpProtocolVersion::V2024_11,
            capabilities: McpClientCapabilities::default(),
            client_info: McpClientInfo {
                name: "agent-x".to_owned(),
                version: "2.0.0".to_owned(),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: McpInitializeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.protocol_version, McpProtocolVersion::V2024_11);
        assert_eq!(back.client_info.name, "agent-x");
        assert_eq!(back.client_info.version, "2.0.0");
    }

    #[test]
    fn initialize_response_fcp_default_v2025() {
        let resp = McpInitializeResponse::fcp_default(McpProtocolVersion::V2025_03);
        assert_eq!(resp.protocol_version, McpProtocolVersion::V2025_03);
        assert!(resp.capabilities.has_tools());
        assert_eq!(resp.server_info.name, "fcp-host");
    }

    #[test]
    fn initialize_response_fcp_default_v2024() {
        let resp = McpInitializeResponse::fcp_default(McpProtocolVersion::V2024_11);
        assert_eq!(resp.protocol_version, McpProtocolVersion::V2024_11);
    }

    #[test]
    fn initialize_response_serialize() {
        let resp = McpInitializeResponse::fcp_default(McpProtocolVersion::V2025_03);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["protocolVersion"], "2025-03-26");
        assert!(json["capabilities"]["tools"].is_object());
        assert_eq!(json["serverInfo"]["name"], "fcp-host");
    }

    #[test]
    fn initialize_response_roundtrip() {
        let resp = McpInitializeResponse::fcp_default(McpProtocolVersion::V2025_03);
        let json = serde_json::to_string(&resp).unwrap();
        let back: McpInitializeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.protocol_version, McpProtocolVersion::V2025_03);
    }

    // ── JSON-RPC Envelope ───────────────────────────────────────────────

    #[test]
    fn jsonrpc_request_new() {
        let req = McpJsonRpcRequest::new(serde_json::json!(1), "tools/list");
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, serde_json::json!(1));
        assert_eq!(req.method, "tools/list");
        assert!(req.params.is_none());
    }

    #[test]
    fn jsonrpc_request_with_params() {
        let req = McpJsonRpcRequest::with_params(
            serde_json::json!("abc"),
            "tools/call",
            serde_json::json!({"name": "test"}),
        );
        assert_eq!(req.method, "tools/call");
        assert!(req.params.is_some());
    }

    #[test]
    fn jsonrpc_request_is_valid() {
        let req = McpJsonRpcRequest::new(serde_json::json!(1), "tools/list");
        assert!(req.is_valid());
    }

    #[test]
    fn jsonrpc_request_invalid_version() {
        let req = McpJsonRpcRequest {
            jsonrpc: "1.0".to_owned(),
            id: serde_json::json!(1),
            method: "tools/list".to_owned(),
            params: None,
        };
        assert!(!req.is_valid());
    }

    #[test]
    fn jsonrpc_request_invalid_empty_method() {
        let req = McpJsonRpcRequest::new(serde_json::json!(1), "");
        assert!(!req.is_valid());
    }

    #[test]
    fn jsonrpc_request_serialize() {
        let req = McpJsonRpcRequest::new(serde_json::json!(42), "ping");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 42);
        assert_eq!(json["method"], "ping");
    }

    #[test]
    fn jsonrpc_request_roundtrip() {
        let req = McpJsonRpcRequest::with_params(
            serde_json::json!("req-1"),
            "tools/call",
            serde_json::json!({"name": "test", "arguments": {}}),
        );
        let json = serde_json::to_string(&req).unwrap();
        let back: McpJsonRpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.method, "tools/call");
        assert_eq!(back.id, serde_json::json!("req-1"));
    }

    #[test]
    fn jsonrpc_response_success() {
        let resp =
            McpJsonRpcResponse::success(serde_json::json!(1), serde_json::json!({"status": "ok"}));
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, serde_json::json!(1));
        assert_eq!(resp.result["status"], "ok");
    }

    #[test]
    fn jsonrpc_response_serialize() {
        let resp = McpJsonRpcResponse::success(serde_json::json!(1), serde_json::json!("pong"));
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["result"], "pong");
    }

    #[test]
    fn jsonrpc_error_response_serialize() {
        let resp = build_error_response(
            serde_json::json!(1),
            McpErrorCode::MethodNotFound,
            "No such method",
        );
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["error"]["code"], -32601);
        assert_eq!(json["error"]["message"], "No such method");
    }

    #[test]
    fn jsonrpc_error_response_with_data() {
        let resp = build_error_response_with_data(
            serde_json::json!(2),
            McpErrorCode::InvalidParams,
            "Missing field",
            serde_json::json!({"field": "name"}),
        );
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["error"]["code"], -32602);
        assert_eq!(json["error"]["data"]["field"], "name");
    }

    // ── MCP Error Codes ─────────────────────────────────────────────────

    #[test]
    fn error_code_values() {
        assert_eq!(McpErrorCode::InvalidRequest.code(), -32600);
        assert_eq!(McpErrorCode::MethodNotFound.code(), -32601);
        assert_eq!(McpErrorCode::InvalidParams.code(), -32602);
        assert_eq!(McpErrorCode::InternalError.code(), -32603);
        assert_eq!(McpErrorCode::ToolNotFound.code(), -32001);
        assert_eq!(McpErrorCode::ToolExecutionError.code(), -32002);
        assert_eq!(McpErrorCode::ResourceNotFound.code(), -32003);
        assert_eq!(McpErrorCode::AuthenticationRequired.code(), -32004);
        assert_eq!(McpErrorCode::PermissionDenied.code(), -32005);
        assert_eq!(McpErrorCode::RateLimited.code(), -32006);
    }

    #[test]
    fn error_code_from_code_roundtrip() {
        let codes = [
            McpErrorCode::InvalidRequest,
            McpErrorCode::MethodNotFound,
            McpErrorCode::InvalidParams,
            McpErrorCode::InternalError,
            McpErrorCode::ToolNotFound,
            McpErrorCode::ToolExecutionError,
            McpErrorCode::ResourceNotFound,
            McpErrorCode::AuthenticationRequired,
            McpErrorCode::PermissionDenied,
            McpErrorCode::RateLimited,
        ];
        for code in codes {
            let num = code.code();
            let back = McpErrorCode::from_code(num).unwrap();
            assert_eq!(code, back);
        }
    }

    #[test]
    fn error_code_from_unknown() {
        assert!(McpErrorCode::from_code(-99999).is_none());
        assert!(McpErrorCode::from_code(0).is_none());
        assert!(McpErrorCode::from_code(200).is_none());
    }

    #[test]
    fn error_code_is_standard_jsonrpc() {
        assert!(McpErrorCode::InvalidRequest.is_standard_jsonrpc());
        assert!(McpErrorCode::MethodNotFound.is_standard_jsonrpc());
        assert!(McpErrorCode::InvalidParams.is_standard_jsonrpc());
        assert!(McpErrorCode::InternalError.is_standard_jsonrpc());
        assert!(!McpErrorCode::ToolNotFound.is_standard_jsonrpc());
        assert!(!McpErrorCode::RateLimited.is_standard_jsonrpc());
    }

    #[test]
    fn error_code_is_mcp_specific() {
        assert!(!McpErrorCode::InvalidRequest.is_mcp_specific());
        assert!(McpErrorCode::ToolNotFound.is_mcp_specific());
        assert!(McpErrorCode::ToolExecutionError.is_mcp_specific());
        assert!(McpErrorCode::ResourceNotFound.is_mcp_specific());
        assert!(McpErrorCode::AuthenticationRequired.is_mcp_specific());
        assert!(McpErrorCode::PermissionDenied.is_mcp_specific());
        assert!(McpErrorCode::RateLimited.is_mcp_specific());
    }

    #[test]
    fn error_code_default_messages() {
        assert_eq!(
            McpErrorCode::InvalidRequest.default_message(),
            "Invalid request"
        );
        assert_eq!(
            McpErrorCode::MethodNotFound.default_message(),
            "Method not found"
        );
        assert_eq!(
            McpErrorCode::ToolNotFound.default_message(),
            "Tool not found"
        );
        assert_eq!(McpErrorCode::RateLimited.default_message(), "Rate limited");
    }

    #[test]
    fn error_code_display() {
        let s = McpErrorCode::MethodNotFound.to_string();
        assert!(s.contains("Method not found"));
        assert!(s.contains("-32601"));
    }

    #[test]
    fn error_code_serialize() {
        let code = McpErrorCode::ToolNotFound;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "-32001");
    }

    #[test]
    fn error_code_deserialize() {
        let code: McpErrorCode = serde_json::from_str("-32006").unwrap();
        assert_eq!(code, McpErrorCode::RateLimited);
    }

    #[test]
    fn error_code_deserialize_unknown_fails() {
        let result: Result<McpErrorCode, _> = serde_json::from_str("999");
        assert!(result.is_err());
    }

    // ── Tool List Request / Response ────────────────────────────────────

    #[test]
    fn tool_list_request_default() {
        let req = McpToolListRequest::default();
        assert!(req.cursor.is_none());
    }

    #[test]
    fn tool_list_request_with_cursor() {
        let req = McpToolListRequest {
            cursor: Some("page2".to_owned()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["cursor"], "page2");
    }

    #[test]
    fn tool_list_request_without_cursor_omits_field() {
        let req = McpToolListRequest::default();
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("cursor").is_none());
    }

    #[test]
    fn tool_list_response_empty() {
        let resp = McpToolListResponse {
            tools: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["tools"], serde_json::json!([]));
        assert!(json.get("nextCursor").is_none());
    }

    #[test]
    fn tool_list_response_with_tools() {
        let entry = McpToolListEntry {
            name: "read_file".to_owned(),
            description: Some("Read a file".to_owned()),
            input_schema: serde_json::json!({"type": "object"}),
            annotations: None,
        };
        let resp = McpToolListResponse {
            tools: vec![entry],
            next_cursor: Some("cursor-2".to_owned()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["tools"].as_array().unwrap().len(), 1);
        assert_eq!(json["tools"][0]["name"], "read_file");
        assert_eq!(json["nextCursor"], "cursor-2");
    }

    #[test]
    fn tool_list_entry_with_annotations() {
        let entry = McpToolListEntry {
            name: "delete_item".to_owned(),
            description: Some("Delete an item".to_owned()),
            input_schema: serde_json::json!({"type": "object"}),
            annotations: Some(McpToolAnnotations {
                risk_level: Some("high".to_owned()),
                safety_tier: Some("dangerous".to_owned()),
                idempotency: Some("strict".to_owned()),
                capability: Some("items.delete".to_owned()),
                read_only: Some(false),
                destructive: Some(true),
            }),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["annotations"]["riskLevel"], "high");
        assert_eq!(json["annotations"]["destructive"], true);
    }

    #[test]
    fn tool_list_response_roundtrip() {
        let resp = McpToolListResponse {
            tools: vec![McpToolListEntry {
                name: "test".to_owned(),
                description: Some("A test tool".to_owned()),
                input_schema: serde_json::json!({"type": "object", "properties": {}}),
                annotations: None,
            }],
            next_cursor: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: McpToolListResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tools.len(), 1);
        assert_eq!(back.tools[0].name, "test");
    }

    // ── Tool Call Request ───────────────────────────────────────────────

    #[test]
    fn tool_call_request_serialize() {
        let req = McpToolCallRequest {
            name: "get_user".to_owned(),
            arguments: serde_json::json!({"id": "u123"}),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["name"], "get_user");
        assert_eq!(json["arguments"]["id"], "u123");
    }

    #[test]
    fn tool_call_request_empty_args() {
        let req = McpToolCallRequest {
            name: "ping".to_owned(),
            arguments: serde_json::json!({}),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["name"], "ping");
    }

    #[test]
    fn tool_call_request_roundtrip() {
        let req = McpToolCallRequest {
            name: "create_item".to_owned(),
            arguments: serde_json::json!({"title": "New", "count": 5}),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: McpToolCallRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "create_item");
        assert_eq!(back.arguments["count"], 5);
    }

    // ── Tool Call Response ──────────────────────────────────────────────

    #[test]
    fn tool_call_response_text() {
        let resp = McpToolCallResponse::text("Hello world");
        assert!(!resp.is_error);
        assert_eq!(resp.content.len(), 1);
        assert!(resp.content[0].is_text());
    }

    #[test]
    fn tool_call_response_error() {
        let resp = McpToolCallResponse::error("Something broke");
        assert!(resp.is_error);
        assert_eq!(resp.content[0].as_text().unwrap(), "Something broke");
    }

    #[test]
    fn tool_call_response_with_content() {
        let blocks = vec![
            McpContentBlock::text("Part 1"),
            McpContentBlock::text("Part 2"),
        ];
        let resp = McpToolCallResponse::with_content(blocks, false);
        assert_eq!(resp.content.len(), 2);
        assert!(!resp.is_error);
    }

    #[test]
    fn tool_call_response_serialize_success() {
        let resp = McpToolCallResponse::text("ok");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["content"].as_array().unwrap().len(), 1);
        // is_error should be absent when false (skip_serializing_if)
        assert!(json.get("isError").is_none());
    }

    #[test]
    fn tool_call_response_serialize_error() {
        let resp = McpToolCallResponse::error("fail");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["isError"], true);
    }

    // ── Content Block ───────────────────────────────────────────────────

    #[test]
    fn content_block_text() {
        let block = McpContentBlock::text("hello");
        assert!(block.is_text());
        assert!(!block.is_image());
        assert!(!block.is_resource());
        assert_eq!(block.as_text(), Some("hello"));
    }

    #[test]
    fn content_block_image() {
        let block = McpContentBlock::image("aGVsbG8=", "image/png");
        assert!(block.is_image());
        assert!(!block.is_text());
        assert!(block.as_text().is_none());
    }

    #[test]
    fn content_block_resource() {
        let block = McpContentBlock::resource("file:///tmp/data.json");
        assert!(block.is_resource());
        assert!(!block.is_text());
    }

    #[test]
    fn content_block_text_serialize() {
        let block = McpContentBlock::text("test");
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "test");
    }

    #[test]
    fn content_block_image_serialize() {
        let block = McpContentBlock::image("AQID", "image/jpeg");
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "image");
        assert_eq!(json["data"], "AQID");
        assert_eq!(json["mimeType"], "image/jpeg");
    }

    #[test]
    fn content_block_resource_serialize() {
        let block = McpContentBlock::resource("conn://slack/channels");
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "resource");
        assert_eq!(json["uri"], "conn://slack/channels");
    }

    #[test]
    fn content_block_roundtrip_text() {
        let block = McpContentBlock::text("round-trip");
        let json = serde_json::to_string(&block).unwrap();
        let back: McpContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_text(), Some("round-trip"));
    }

    #[test]
    fn content_block_roundtrip_image() {
        let block = McpContentBlock::image("data123", "image/webp");
        let json = serde_json::to_string(&block).unwrap();
        let back: McpContentBlock = serde_json::from_str(&json).unwrap();
        assert!(back.is_image());
    }

    #[test]
    fn content_block_roundtrip_resource() {
        let block = McpContentBlock::Resource {
            uri: "file:///x".to_owned(),
            mime_type: Some("text/plain".to_owned()),
            text: Some("content".to_owned()),
        };
        let json = serde_json::to_string(&block).unwrap();
        let back: McpContentBlock = serde_json::from_str(&json).unwrap();
        assert!(back.is_resource());
    }

    // ── Resource List ───────────────────────────────────────────────────

    #[test]
    fn resource_list_request_default() {
        let req = McpResourceListRequest::default();
        assert!(req.cursor.is_none());
    }

    #[test]
    fn resource_list_response_empty() {
        let resp = McpResourceListResponse {
            resources: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["resources"], serde_json::json!([]));
    }

    #[test]
    fn resource_entry_serialize() {
        let entry = McpResourceEntry {
            uri: "conn://slack/metadata".to_owned(),
            name: "Slack Metadata".to_owned(),
            description: Some("Connector metadata for Slack".to_owned()),
            mime_type: Some("application/json".to_owned()),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["uri"], "conn://slack/metadata");
        assert_eq!(json["name"], "Slack Metadata");
        assert_eq!(json["mimeType"], "application/json");
    }

    #[test]
    fn resource_list_response_roundtrip() {
        let resp = McpResourceListResponse {
            resources: vec![McpResourceEntry {
                uri: "conn://test/info".to_owned(),
                name: "Test".to_owned(),
                description: None,
                mime_type: None,
            }],
            next_cursor: Some("page2".to_owned()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: McpResourceListResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.resources.len(), 1);
        assert_eq!(back.next_cursor.as_deref(), Some("page2"));
    }

    // ── Session Status ──────────────────────────────────────────────────

    #[test]
    fn session_status_is_alive() {
        assert!(SessionStatus::Active.is_alive());
        assert!(SessionStatus::Idle.is_alive());
        assert!(!SessionStatus::Expired.is_alive());
        assert!(!SessionStatus::Terminated.is_alive());
    }

    #[test]
    fn session_status_is_ended() {
        assert!(!SessionStatus::Active.is_ended());
        assert!(!SessionStatus::Idle.is_ended());
        assert!(SessionStatus::Expired.is_ended());
        assert!(SessionStatus::Terminated.is_ended());
    }

    #[test]
    fn session_status_display() {
        assert_eq!(SessionStatus::Active.to_string(), "active");
        assert_eq!(SessionStatus::Idle.to_string(), "idle");
        assert_eq!(SessionStatus::Expired.to_string(), "expired");
        assert_eq!(SessionStatus::Terminated.to_string(), "terminated");
    }

    #[test]
    fn session_status_serialize() {
        let json = serde_json::to_string(&SessionStatus::Active).unwrap();
        assert_eq!(json, "\"active\"");
    }

    #[test]
    fn session_status_roundtrip() {
        for status in [
            SessionStatus::Active,
            SessionStatus::Idle,
            SessionStatus::Expired,
            SessionStatus::Terminated,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: SessionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    // ── AgentSessionConfig ──────────────────────────────────────────────

    #[test]
    fn session_config_default() {
        let config = AgentSessionConfig::default();
        assert_eq!(config.idle_timeout, Duration::from_mins(5));
        assert_eq!(config.max_lifetime, Duration::from_hours(1));
        assert_eq!(config.max_concurrent_calls, 10);
        assert_eq!(config.rate_limit_per_minute, 60);
    }

    #[test]
    fn session_config_default_is_valid() {
        let config = AgentSessionConfig::default();
        assert!(config.is_valid());
        assert!(config.validate().is_empty());
    }

    #[test]
    fn session_config_validate_zero_idle_timeout() {
        let config = AgentSessionConfig {
            idle_timeout: Duration::ZERO,
            ..AgentSessionConfig::default()
        };
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("idle_timeout")));
    }

    #[test]
    fn session_config_validate_zero_max_lifetime() {
        let config = AgentSessionConfig {
            max_lifetime: Duration::ZERO,
            ..AgentSessionConfig::default()
        };
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("max_lifetime")));
    }

    #[test]
    fn session_config_validate_lifetime_less_than_idle() {
        let config = AgentSessionConfig {
            idle_timeout: Duration::from_mins(10),
            max_lifetime: Duration::from_mins(5),
            ..AgentSessionConfig::default()
        };
        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("max_lifetime must be >= idle_timeout"))
        );
    }

    #[test]
    fn session_config_validate_zero_concurrent() {
        let config = AgentSessionConfig {
            max_concurrent_calls: 0,
            ..AgentSessionConfig::default()
        };
        assert!(!config.is_valid());
    }

    #[test]
    fn session_config_validate_zero_rate_limit() {
        let config = AgentSessionConfig {
            rate_limit_per_minute: 0,
            ..AgentSessionConfig::default()
        };
        assert!(!config.is_valid());
    }

    #[test]
    fn session_config_serialize_roundtrip() {
        let config = AgentSessionConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: AgentSessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.idle_timeout, config.idle_timeout);
        assert_eq!(back.max_lifetime, config.max_lifetime);
        assert_eq!(back.max_concurrent_calls, config.max_concurrent_calls);
    }

    // ── AgentSession ────────────────────────────────────────────────────

    fn make_init_request() -> McpInitializeRequest {
        McpInitializeRequest {
            protocol_version: McpProtocolVersion::V2025_03,
            capabilities: McpClientCapabilities::default(),
            client_info: McpClientInfo {
                name: "test-agent".to_owned(),
                version: "1.0.0".to_owned(),
            },
        }
    }

    #[test]
    fn session_new() {
        let req = make_init_request();
        let session = AgentSession::new("sess-1", &req, AgentSessionConfig::default());
        assert_eq!(session.id, "sess-1");
        assert_eq!(session.status, SessionStatus::Active);
        assert_eq!(session.tool_call_count, 0);
        assert_eq!(session.protocol_version, McpProtocolVersion::V2025_03);
        assert_eq!(session.client_info.name, "test-agent");
    }

    #[test]
    fn session_touch_updates_activity() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-2", &req, AgentSessionConfig::default());
        let before = session.last_activity;
        // Touch should update last_activity (may be same ms, but not earlier).
        session.touch();
        assert!(session.last_activity >= before);
    }

    #[test]
    fn session_touch_reactivates_idle() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-3", &req, AgentSessionConfig::default());
        session.mark_idle();
        assert_eq!(session.status, SessionStatus::Idle);
        session.touch();
        assert_eq!(session.status, SessionStatus::Active);
    }

    #[test]
    fn session_record_tool_call() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-4", &req, AgentSessionConfig::default());
        session.record_tool_call();
        assert_eq!(session.tool_call_count, 1);
        session.record_tool_call();
        assert_eq!(session.tool_call_count, 2);
    }

    #[test]
    fn session_mark_idle() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-5", &req, AgentSessionConfig::default());
        session.mark_idle();
        assert_eq!(session.status, SessionStatus::Idle);
    }

    #[test]
    fn session_mark_idle_only_from_active() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-6", &req, AgentSessionConfig::default());
        session.expire();
        session.mark_idle(); // Should not change from Expired to Idle.
        assert_eq!(session.status, SessionStatus::Expired);
    }

    #[test]
    fn session_expire() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-7", &req, AgentSessionConfig::default());
        session.expire();
        assert_eq!(session.status, SessionStatus::Expired);
        assert!(session.status.is_ended());
    }

    #[test]
    fn session_expire_from_idle() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-8", &req, AgentSessionConfig::default());
        session.mark_idle();
        session.expire();
        assert_eq!(session.status, SessionStatus::Expired);
    }

    #[test]
    fn session_expire_does_not_override_terminated() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-9", &req, AgentSessionConfig::default());
        session.terminate();
        session.expire(); // Should not change from Terminated to Expired.
        assert_eq!(session.status, SessionStatus::Terminated);
    }

    #[test]
    fn session_terminate() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-10", &req, AgentSessionConfig::default());
        session.terminate();
        assert_eq!(session.status, SessionStatus::Terminated);
    }

    #[test]
    fn session_terminate_from_any_state() {
        for initial in [
            SessionStatus::Active,
            SessionStatus::Idle,
            SessionStatus::Expired,
        ] {
            let req = make_init_request();
            let mut session = AgentSession::new("sess", &req, AgentSessionConfig::default());
            match initial {
                SessionStatus::Idle => session.mark_idle(),
                SessionStatus::Expired => session.expire(),
                _ => {}
            }
            session.terminate();
            assert_eq!(session.status, SessionStatus::Terminated);
        }
    }

    #[test]
    fn session_lifetime_is_non_negative() {
        let req = make_init_request();
        let session = AgentSession::new("sess-lt", &req, AgentSessionConfig::default());
        assert!(session.lifetime().num_milliseconds() >= 0);
    }

    #[test]
    fn session_idle_duration_is_non_negative() {
        let req = make_init_request();
        let session = AgentSession::new("sess-id", &req, AgentSessionConfig::default());
        assert!(session.idle_duration().num_milliseconds() >= 0);
    }

    // ── Method Routing ──────────────────────────────────────────────────

    #[test]
    fn route_initialize() {
        assert_eq!(
            route_mcp_method("initialize"),
            McpMethodCategory::Initialize
        );
    }

    #[test]
    fn route_tools_list() {
        assert_eq!(route_mcp_method("tools/list"), McpMethodCategory::ToolsList);
    }

    #[test]
    fn route_tools_call() {
        assert_eq!(route_mcp_method("tools/call"), McpMethodCategory::ToolsCall);
    }

    #[test]
    fn route_resources_list() {
        assert_eq!(
            route_mcp_method("resources/list"),
            McpMethodCategory::ResourcesList
        );
    }

    #[test]
    fn route_resources_read() {
        assert_eq!(
            route_mcp_method("resources/read"),
            McpMethodCategory::ResourcesRead
        );
    }

    #[test]
    fn route_prompts_list() {
        assert_eq!(
            route_mcp_method("prompts/list"),
            McpMethodCategory::PromptsList
        );
    }

    #[test]
    fn route_prompts_get() {
        assert_eq!(
            route_mcp_method("prompts/get"),
            McpMethodCategory::PromptsGet
        );
    }

    #[test]
    fn route_completion() {
        assert_eq!(
            route_mcp_method("completion/complete"),
            McpMethodCategory::Completion
        );
    }

    #[test]
    fn route_logging() {
        assert_eq!(
            route_mcp_method("logging/setLevel"),
            McpMethodCategory::Logging
        );
    }

    #[test]
    fn route_ping() {
        assert_eq!(route_mcp_method("ping"), McpMethodCategory::Ping);
    }

    #[test]
    fn route_notification() {
        assert_eq!(
            route_mcp_method("notifications/initialized"),
            McpMethodCategory::Notification
        );
        assert_eq!(
            route_mcp_method("notifications/cancelled"),
            McpMethodCategory::Notification
        );
    }

    #[test]
    fn route_unknown() {
        assert_eq!(route_mcp_method("nonexistent"), McpMethodCategory::Unknown);
        assert_eq!(route_mcp_method(""), McpMethodCategory::Unknown);
        assert_eq!(route_mcp_method("tools/delete"), McpMethodCategory::Unknown);
    }

    #[test]
    fn method_category_expects_response() {
        assert!(McpMethodCategory::Initialize.expects_response());
        assert!(McpMethodCategory::ToolsList.expects_response());
        assert!(McpMethodCategory::ToolsCall.expects_response());
        assert!(McpMethodCategory::Ping.expects_response());
        assert!(!McpMethodCategory::Notification.expects_response());
    }

    #[test]
    fn method_category_requires_session() {
        assert!(!McpMethodCategory::Initialize.requires_session());
        assert!(!McpMethodCategory::Ping.requires_session());
        assert!(!McpMethodCategory::Unknown.requires_session());
        assert!(McpMethodCategory::ToolsList.requires_session());
        assert!(McpMethodCategory::ToolsCall.requires_session());
        assert!(McpMethodCategory::ResourcesList.requires_session());
    }

    #[test]
    fn method_category_display() {
        assert_eq!(McpMethodCategory::Initialize.to_string(), "initialize");
        assert_eq!(McpMethodCategory::ToolsList.to_string(), "tools/list");
        assert_eq!(McpMethodCategory::ToolsCall.to_string(), "tools/call");
        assert_eq!(McpMethodCategory::Ping.to_string(), "ping");
        assert_eq!(McpMethodCategory::Unknown.to_string(), "unknown");
    }

    // ── McpMethodRouter ─────────────────────────────────────────────────

    #[test]
    fn router_standard_methods() {
        let router = McpMethodRouter::new();
        assert_eq!(router.route("tools/list"), McpMethodCategory::ToolsList);
        assert_eq!(router.route("ping"), McpMethodCategory::Ping);
    }

    #[test]
    fn router_custom_route() {
        let mut router = McpMethodRouter::new();
        router.add_route("fcp/discover", McpMethodCategory::ResourcesList);
        assert_eq!(
            router.route("fcp/discover"),
            McpMethodCategory::ResourcesList
        );
    }

    #[test]
    fn router_custom_overrides_standard() {
        let mut router = McpMethodRouter::new();
        router.add_route("ping", McpMethodCategory::Logging);
        assert_eq!(router.route("ping"), McpMethodCategory::Logging);
    }

    #[test]
    fn router_custom_route_count() {
        let mut router = McpMethodRouter::new();
        assert_eq!(router.custom_route_count(), 0);
        router.add_route("custom/one", McpMethodCategory::Unknown);
        assert_eq!(router.custom_route_count(), 1);
        router.add_route("custom/two", McpMethodCategory::Unknown);
        assert_eq!(router.custom_route_count(), 2);
    }

    #[test]
    fn router_all_methods_includes_standard() {
        let router = McpMethodRouter::new();
        let methods = router.all_methods();
        assert!(methods.contains(&"initialize".to_owned()));
        assert!(methods.contains(&"tools/list".to_owned()));
        assert!(methods.contains(&"ping".to_owned()));
    }

    #[test]
    fn router_all_methods_includes_custom() {
        let mut router = McpMethodRouter::new();
        router.add_route("fcp/custom", McpMethodCategory::Unknown);
        let methods = router.all_methods();
        assert!(methods.contains(&"fcp/custom".to_owned()));
    }

    #[test]
    fn router_all_methods_sorted() {
        let router = McpMethodRouter::new();
        let methods = router.all_methods();
        let mut sorted = methods.clone();
        sorted.sort();
        assert_eq!(methods, sorted);
    }

    #[test]
    fn router_default() {
        let router = McpMethodRouter::default();
        assert_eq!(router.custom_route_count(), 0);
    }

    // ── Tool Call Context ───────────────────────────────────────────────

    #[test]
    fn tool_call_context_new() {
        let ctx = ToolCallContext::new(
            "sess-1",
            serde_json::json!(42),
            "read_file",
            ConnectorId::from_static("fs:utility:1.0.0"),
            OperationId::from_static("read_file"),
            serde_json::json!({"path": "/tmp/test"}),
        );
        assert_eq!(ctx.session_id, "sess-1");
        assert_eq!(ctx.request_id, serde_json::json!(42));
        assert_eq!(ctx.tool_name, "read_file");
        assert_eq!(ctx.connector_id.as_str(), "fs:utility:1.0.0");
        assert_eq!(ctx.operation_id.as_str(), "read_file");
        assert_eq!(ctx.arguments["path"], "/tmp/test");
    }

    #[test]
    fn tool_call_context_elapsed_non_negative() {
        let ctx = ToolCallContext::new(
            "sess",
            serde_json::json!(1),
            "op",
            ConnectorId::from_static("c:utility:1.0.0"),
            OperationId::from_static("op"),
            serde_json::json!({}),
        );
        assert!(ctx.elapsed().num_milliseconds() >= 0);
    }

    #[test]
    fn tool_call_context_serialize() {
        let ctx = ToolCallContext::new(
            "sess-ser",
            serde_json::json!("req-1"),
            "test_tool",
            ConnectorId::from_static("test:utility:1.0.0"),
            OperationId::from_static("test_tool"),
            serde_json::json!({"key": "value"}),
        );
        let json = serde_json::to_value(&ctx).unwrap();
        assert_eq!(json["session_id"], "sess-ser");
        assert_eq!(json["tool_name"], "test_tool");
    }

    // ── ToolCallResult ──────────────────────────────────────────────────

    #[test]
    fn tool_call_result_success_text() {
        let result = ToolCallResult::success_text("done", 150);
        assert!(!result.is_error);
        assert_eq!(result.duration_ms, 150);
        assert_eq!(result.content.len(), 1);
        assert_eq!(result.content[0].as_text(), Some("done"));
    }

    #[test]
    fn tool_call_result_error() {
        let result = ToolCallResult::error("boom", 42);
        assert!(result.is_error);
        assert_eq!(result.duration_ms, 42);
    }

    #[test]
    fn tool_call_result_to_mcp_response() {
        let result = ToolCallResult::success_text("ok", 100);
        let resp = result.to_mcp_response();
        assert!(!resp.is_error);
        assert_eq!(resp.content.len(), 1);
    }

    #[test]
    fn tool_call_result_error_to_mcp_response() {
        let result = ToolCallResult::error("fail", 50);
        let resp = result.to_mcp_response();
        assert!(resp.is_error);
    }

    #[test]
    fn tool_call_result_empty_metadata() {
        let result = ToolCallResult::success_text("x", 0);
        assert!(result.metadata.is_empty());
        // Serialize should omit empty metadata.
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("metadata").is_none());
    }

    #[test]
    fn tool_call_result_with_metadata() {
        let mut result = ToolCallResult::success_text("x", 0);
        result
            .metadata
            .insert("connector".to_owned(), serde_json::json!("slack"));
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["metadata"]["connector"], "slack");
    }

    // ── ToolCallError ───────────────────────────────────────────────────

    #[test]
    fn tool_call_error_new() {
        let err = ToolCallError::new(McpErrorCode::ToolNotFound, "No such tool: foo");
        assert_eq!(err.code, McpErrorCode::ToolNotFound);
        assert_eq!(err.message, "No such tool: foo");
        assert!(err.data.is_none());
    }

    #[test]
    fn tool_call_error_with_data() {
        let err = ToolCallError::with_data(
            McpErrorCode::InvalidParams,
            "Bad input",
            serde_json::json!({"field": "name"}),
        );
        assert_eq!(err.code, McpErrorCode::InvalidParams);
        assert!(err.data.is_some());
    }

    #[test]
    fn tool_call_error_to_jsonrpc_error() {
        let err = ToolCallError::new(McpErrorCode::PermissionDenied, "Not allowed");
        let rpc_err = err.to_jsonrpc_error();
        assert_eq!(rpc_err.code, -32005);
        assert_eq!(rpc_err.message, "Not allowed");
    }

    #[test]
    fn tool_call_error_display() {
        let err = ToolCallError::new(McpErrorCode::RateLimited, "Too many requests");
        let s = err.to_string();
        assert!(s.contains("Rate limited"));
        assert!(s.contains("Too many requests"));
    }

    // ── ToolDescriptor to MCP conversion ────────────────────────────────

    #[test]
    fn tool_descriptor_to_mcp_entry() {
        let desc = ToolDescriptor {
            name: "send_message".to_owned(),
            description: "Send a message to a channel".to_owned(),
            input_schema: serde_json::json!({"type": "object", "properties": {"channel": {"type": "string"}}}),
            output_schema: serde_json::json!({"type": "object"}),
            capability: fcp_core::CapabilityId::from_static("messaging.send"),
            risk_level: fcp_core::RiskLevel::Medium,
            safety_tier: fcp_core::SafetyTier::Risky,
            idempotency: fcp_core::IdempotencyClass::None,
            approval_mode: None,
            requires_confirmation: false,
            idempotent: false,
            supports_simulate: Some(false),
            latency_hint: None,
            rate_limits: vec![],
            examples: vec![],
            ai_hints: None,
        };
        let entry = desc.to_mcp_tool_list_entry();
        assert_eq!(entry.name, "send_message");
        assert_eq!(
            entry.description,
            Some("Send a message to a channel".to_owned())
        );
        assert!(entry.annotations.is_some());
        let ann = entry.annotations.unwrap();
        assert_eq!(ann.risk_level, Some("medium".to_owned()));
        assert_eq!(ann.safety_tier, Some("risky".to_owned()));
        assert_eq!(ann.capability, Some("messaging.send".to_owned()));
        assert_eq!(ann.read_only, Some(false));
        assert_eq!(ann.destructive, Some(false));
    }

    #[test]
    fn tool_descriptor_to_mcp_entry_read_only_safe_and_strict() {
        let desc = ToolDescriptor {
            name: "list_items".to_owned(),
            description: "List items".to_owned(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            capability: fcp_core::CapabilityId::from_static("items.list"),
            risk_level: fcp_core::RiskLevel::Low,
            safety_tier: fcp_core::SafetyTier::Safe,
            idempotency: fcp_core::IdempotencyClass::Strict,
            approval_mode: None,
            requires_confirmation: false,
            idempotent: true,
            supports_simulate: Some(false),
            latency_hint: None,
            rate_limits: vec![],
            examples: vec![],
            ai_hints: None,
        };
        let entry = desc.to_mcp_tool_list_entry();
        let ann = entry.annotations.unwrap();
        assert_eq!(ann.read_only, Some(true));
        assert_eq!(ann.destructive, Some(false));
    }

    #[test]
    fn tool_descriptor_to_mcp_entry_low_risk_write_is_not_read_only() {
        let desc = ToolDescriptor {
            name: "send_message".to_owned(),
            description: "Send a message".to_owned(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            capability: fcp_core::CapabilityId::from_static("messaging.send"),
            risk_level: fcp_core::RiskLevel::Low,
            safety_tier: fcp_core::SafetyTier::Safe,
            idempotency: fcp_core::IdempotencyClass::None,
            approval_mode: None,
            requires_confirmation: false,
            idempotent: false,
            supports_simulate: Some(false),
            latency_hint: None,
            rate_limits: vec![],
            examples: vec![],
            ai_hints: None,
        };
        let entry = desc.to_mcp_tool_list_entry();
        let ann = entry.annotations.unwrap();
        assert_eq!(ann.read_only, Some(false));
    }

    #[test]
    fn tool_descriptor_to_mcp_entry_dangerous_is_destructive() {
        let desc = ToolDescriptor {
            name: "delete_all".to_owned(),
            description: "Delete everything".to_owned(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            capability: fcp_core::CapabilityId::from_static("admin.delete"),
            risk_level: fcp_core::RiskLevel::Critical,
            safety_tier: fcp_core::SafetyTier::Dangerous,
            idempotency: fcp_core::IdempotencyClass::None,
            approval_mode: None,
            requires_confirmation: true,
            idempotent: false,
            supports_simulate: Some(false),
            latency_hint: None,
            rate_limits: vec![],
            examples: vec![],
            ai_hints: None,
        };
        let entry = desc.to_mcp_tool_list_entry();
        let ann = entry.annotations.unwrap();
        assert_eq!(ann.destructive, Some(true));
        assert_eq!(ann.read_only, Some(false));
    }

    #[test]
    fn tool_descriptor_to_mcp_entry_critical_is_destructive() {
        let desc = ToolDescriptor {
            name: "nuke_zone".to_owned(),
            description: "Destroy a zone".to_owned(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            capability: fcp_core::CapabilityId::from_static("zone.nuke"),
            risk_level: fcp_core::RiskLevel::Critical,
            safety_tier: fcp_core::SafetyTier::Critical,
            idempotency: fcp_core::IdempotencyClass::None,
            approval_mode: None,
            requires_confirmation: true,
            idempotent: false,
            supports_simulate: Some(false),
            latency_hint: None,
            rate_limits: vec![],
            examples: vec![],
            ai_hints: None,
        };
        let entry = desc.to_mcp_tool_list_entry();
        let ann = entry.annotations.unwrap();
        assert_eq!(ann.destructive, Some(true));
    }

    #[test]
    fn tool_descriptor_to_mcp_entry_preserves_input_schema() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"}
            },
            "required": ["query"]
        });
        let desc = ToolDescriptor {
            name: "search".to_owned(),
            description: "Search".to_owned(),
            input_schema: schema.clone(),
            output_schema: serde_json::json!({}),
            capability: fcp_core::CapabilityId::from_static("search.query"),
            risk_level: fcp_core::RiskLevel::Low,
            safety_tier: fcp_core::SafetyTier::Safe,
            idempotency: fcp_core::IdempotencyClass::Strict,
            approval_mode: None,
            requires_confirmation: false,
            idempotent: true,
            supports_simulate: Some(false),
            latency_hint: None,
            rate_limits: vec![],
            examples: vec![],
            ai_hints: None,
        };
        let entry = desc.to_mcp_tool_list_entry();
        assert_eq!(entry.input_schema, schema);
    }

    // ── build_error_response ────────────────────────────────────────────

    #[test]
    fn build_error_response_structure() {
        let resp = build_error_response(
            serde_json::json!(99),
            McpErrorCode::InternalError,
            "Something went wrong",
        );
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, serde_json::json!(99));
        assert_eq!(resp.error.code, -32603);
        assert_eq!(resp.error.message, "Something went wrong");
        assert!(resp.error.data.is_none());
    }

    #[test]
    fn build_error_response_with_data_structure() {
        let resp = build_error_response_with_data(
            serde_json::json!("abc"),
            McpErrorCode::ToolExecutionError,
            "Failed",
            serde_json::json!({"details": "timeout"}),
        );
        assert_eq!(resp.error.code, -32002);
        assert_eq!(resp.error.data.unwrap()["details"], "timeout");
    }

    #[test]
    fn build_error_response_null_id() {
        let resp = build_error_response(
            serde_json::Value::Null,
            McpErrorCode::InvalidRequest,
            "Parse error",
        );
        assert_eq!(resp.id, serde_json::Value::Null);
    }

    #[test]
    fn build_error_response_serialize() {
        let resp = build_error_response(
            serde_json::json!(1),
            McpErrorCode::AuthenticationRequired,
            "Token expired",
        );
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["error"]["code"], -32004);
        assert_eq!(json["error"]["message"], "Token expired");
    }

    // ── Additional integration-style tests ──────────────────────────────

    #[test]
    fn full_initialize_flow() {
        // Simulate: client sends initialize, server responds.
        let client_req = McpInitializeRequest {
            protocol_version: McpProtocolVersion::V2025_03,
            capabilities: McpClientCapabilities::default(),
            client_info: McpClientInfo {
                name: "claude-desktop".to_owned(),
                version: "3.0.0".to_owned(),
            },
        };

        // Wrap in JSON-RPC.
        let rpc_req = McpJsonRpcRequest::with_params(
            serde_json::json!(1),
            "initialize",
            serde_json::to_value(&client_req).unwrap(),
        );
        assert!(rpc_req.is_valid());
        assert_eq!(
            route_mcp_method(&rpc_req.method),
            McpMethodCategory::Initialize
        );

        // Server builds response.
        let init_resp = McpInitializeResponse::fcp_default(client_req.protocol_version);
        let rpc_resp =
            McpJsonRpcResponse::success(rpc_req.id, serde_json::to_value(&init_resp).unwrap());
        assert_eq!(rpc_resp.jsonrpc, "2.0");

        // Create session.
        let session = AgentSession::new("s-1", &client_req, AgentSessionConfig::default());
        assert_eq!(session.status, SessionStatus::Active);
        assert_eq!(session.client_info.name, "claude-desktop");
    }

    #[test]
    fn full_tool_call_flow() {
        // Simulate tools/call JSON-RPC request.
        let call_req = McpToolCallRequest {
            name: "get_channel".to_owned(),
            arguments: serde_json::json!({"channel_id": "C123"}),
        };
        let rpc_req = McpJsonRpcRequest::with_params(
            serde_json::json!(2),
            "tools/call",
            serde_json::to_value(&call_req).unwrap(),
        );
        assert_eq!(
            route_mcp_method(&rpc_req.method),
            McpMethodCategory::ToolsCall
        );

        // Build context.
        let ctx = ToolCallContext::new(
            "sess-1",
            rpc_req.id,
            &call_req.name,
            ConnectorId::from_static("slack:messaging:1.0.0"),
            OperationId::from_static("get_channel"),
            call_req.arguments,
        );
        assert_eq!(ctx.tool_name, "get_channel");

        // Build result.
        let result = ToolCallResult::success_text(r#"{"id":"C123","name":"general"}"#, 45);
        let mcp_resp = result.to_mcp_response();
        let rpc_resp =
            McpJsonRpcResponse::success(ctx.request_id, serde_json::to_value(&mcp_resp).unwrap());
        assert_eq!(rpc_resp.id, serde_json::json!(2));
    }

    #[test]
    fn full_tool_call_error_flow() {
        let err = ToolCallError::new(McpErrorCode::ToolNotFound, "Tool xyz not found");
        let rpc_err = err.to_jsonrpc_error();
        let resp = McpJsonRpcErrorResponse {
            jsonrpc: "2.0".to_owned(),
            id: serde_json::json!(3),
            error: rpc_err,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["error"]["code"], -32001);
    }

    #[test]
    fn annotations_camel_case_serialization() {
        let ann = McpToolAnnotations {
            risk_level: Some("high".to_owned()),
            safety_tier: Some("dangerous".to_owned()),
            idempotency: Some("none".to_owned()),
            capability: Some("cap.test".to_owned()),
            read_only: Some(false),
            destructive: Some(true),
        };
        let json = serde_json::to_value(&ann).unwrap();
        // Verify camelCase keys.
        assert!(json.get("riskLevel").is_some());
        assert!(json.get("safetyTier").is_some());
        assert!(json.get("readOnly").is_some());
    }

    #[test]
    fn annotations_equality() {
        let a = McpToolAnnotations {
            risk_level: Some("low".to_owned()),
            safety_tier: None,
            idempotency: None,
            capability: None,
            read_only: None,
            destructive: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn client_info_serialize_camel_case() {
        let info = McpClientInfo {
            name: "test".to_owned(),
            version: "1.0".to_owned(),
        };
        let json = serde_json::to_value(&info).unwrap();
        // camelCase fields should exist.
        assert!(json.get("name").is_some());
        assert!(json.get("version").is_some());
    }

    #[test]
    fn client_capabilities_default() {
        let caps = McpClientCapabilities::default();
        assert!(caps.sampling.is_none());
        assert!(caps.roots.is_none());
    }

    #[test]
    fn jsonrpc_request_string_id() {
        let req = McpJsonRpcRequest::new(serde_json::json!("uuid-123"), "tools/list");
        assert_eq!(req.id, serde_json::json!("uuid-123"));
    }

    #[test]
    fn jsonrpc_request_null_id() {
        let req = McpJsonRpcRequest::new(serde_json::Value::Null, "ping");
        assert_eq!(req.id, serde_json::Value::Null);
    }

    #[test]
    fn session_serialize_roundtrip() {
        let req = make_init_request();
        let session = AgentSession::new("rt-sess", &req, AgentSessionConfig::default());
        let json = serde_json::to_string(&session).unwrap();
        let back: AgentSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "rt-sess");
        assert_eq!(back.status, SessionStatus::Active);
        assert_eq!(back.tool_call_count, 0);
    }

    #[test]
    fn multiple_content_blocks_serialize() {
        let blocks = vec![
            McpContentBlock::text("Hello"),
            McpContentBlock::image("base64data", "image/png"),
            McpContentBlock::resource("conn://test/data"),
        ];
        let json = serde_json::to_value(&blocks).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["type"], "text");
        assert_eq!(arr[1]["type"], "image");
        assert_eq!(arr[2]["type"], "resource");
    }

    #[test]
    fn router_unknown_method_fallthrough() {
        let router = McpMethodRouter::new();
        assert_eq!(router.route("fcp/custom"), McpMethodCategory::Unknown);
        assert_eq!(router.route("x"), McpMethodCategory::Unknown);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Additional coverage: edge cases, boundary conditions, error paths
    // ══════════════════════════════════════════════════════════════════════

    // ── McpProtocolVersion extras ────────────────────────────────────────

    #[test]
    fn protocol_version_hash_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(McpProtocolVersion::V2025_03);
        set.insert(McpProtocolVersion::V2025_03);
        assert_eq!(set.len(), 1);
        set.insert(McpProtocolVersion::V2024_11);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn protocol_version_copy_semantics() {
        let v = McpProtocolVersion::V2025_03;
        let v2 = v; // Copy
        assert_eq!(v, v2);
        // Both still usable after copy.
        assert_eq!(v.as_str(), v2.as_str());
    }

    #[test]
    fn protocol_version_deserialize_invalid_fails() {
        let result: Result<McpProtocolVersion, _> = serde_json::from_str("\"3000-01-01\"");
        assert!(result.is_err());
    }

    #[test]
    fn protocol_version_deserialize_non_string_fails() {
        let result: Result<McpProtocolVersion, _> = serde_json::from_str("42");
        assert!(result.is_err());
    }

    // ── McpServerCapabilities extras ─────────────────────────────────────

    #[test]
    fn capabilities_with_tools_full_field_check() {
        let caps = McpServerCapabilities::with_tools();
        let tool_cap = caps.tools.unwrap();
        assert_eq!(tool_cap.list_changed, Some(true));
        assert!(caps.resources.is_none());
        assert!(caps.prompts.is_none());
        assert!(caps.logging.is_none());
    }

    #[test]
    fn capabilities_full_resource_fields() {
        let caps = McpServerCapabilities::full();
        let res = caps.resources.unwrap();
        assert_eq!(res.subscribe, Some(true));
        assert_eq!(res.list_changed, Some(true));
    }

    #[test]
    fn capabilities_full_prompt_fields() {
        let caps = McpServerCapabilities::full();
        let prompt = caps.prompts.unwrap();
        assert_eq!(prompt.list_changed, Some(true));
    }

    #[test]
    fn capabilities_serialize_roundtrip_with_tools() {
        let caps = McpServerCapabilities::with_tools();
        let json = serde_json::to_string(&caps).unwrap();
        let back: McpServerCapabilities = serde_json::from_str(&json).unwrap();
        assert!(back.has_tools());
        assert!(!back.has_resources());
    }

    // ── McpErrorCode extras ──────────────────────────────────────────────

    #[test]
    fn error_code_all_default_messages_non_empty() {
        let codes = [
            McpErrorCode::InvalidRequest,
            McpErrorCode::MethodNotFound,
            McpErrorCode::InvalidParams,
            McpErrorCode::InternalError,
            McpErrorCode::ToolNotFound,
            McpErrorCode::ToolExecutionError,
            McpErrorCode::ResourceNotFound,
            McpErrorCode::AuthenticationRequired,
            McpErrorCode::PermissionDenied,
            McpErrorCode::RateLimited,
        ];
        for code in codes {
            assert!(
                !code.default_message().is_empty(),
                "empty message for {code:?}"
            );
        }
    }

    #[test]
    fn error_code_serde_roundtrip_all() {
        let codes = [
            McpErrorCode::InvalidRequest,
            McpErrorCode::MethodNotFound,
            McpErrorCode::InvalidParams,
            McpErrorCode::InternalError,
            McpErrorCode::ToolNotFound,
            McpErrorCode::ToolExecutionError,
            McpErrorCode::ResourceNotFound,
            McpErrorCode::AuthenticationRequired,
            McpErrorCode::PermissionDenied,
            McpErrorCode::RateLimited,
        ];
        for code in codes {
            let json = serde_json::to_string(&code).unwrap();
            let back: McpErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, back, "roundtrip failed for {code:?}");
        }
    }

    #[test]
    fn error_code_display_all_contain_code_number() {
        let codes = [
            (McpErrorCode::InvalidRequest, "-32600"),
            (McpErrorCode::MethodNotFound, "-32601"),
            (McpErrorCode::InvalidParams, "-32602"),
            (McpErrorCode::InternalError, "-32603"),
            (McpErrorCode::ToolNotFound, "-32001"),
            (McpErrorCode::ToolExecutionError, "-32002"),
            (McpErrorCode::ResourceNotFound, "-32003"),
            (McpErrorCode::AuthenticationRequired, "-32004"),
            (McpErrorCode::PermissionDenied, "-32005"),
            (McpErrorCode::RateLimited, "-32006"),
        ];
        for (code, expected_num) in codes {
            let s = code.to_string();
            assert!(
                s.contains(expected_num),
                "{s} does not contain {expected_num}"
            );
        }
    }

    #[test]
    fn error_code_from_code_boundary_values() {
        // Just outside valid ranges
        assert!(McpErrorCode::from_code(-32599).is_none());
        assert!(McpErrorCode::from_code(-32604).is_none());
        assert!(McpErrorCode::from_code(-32000).is_none());
        assert!(McpErrorCode::from_code(-32007).is_none());
        assert!(McpErrorCode::from_code(i32::MIN).is_none());
        assert!(McpErrorCode::from_code(i32::MAX).is_none());
    }

    #[test]
    fn error_code_standard_vs_mcp_mutual_exclusion() {
        let codes = [
            McpErrorCode::InvalidRequest,
            McpErrorCode::MethodNotFound,
            McpErrorCode::InvalidParams,
            McpErrorCode::InternalError,
            McpErrorCode::ToolNotFound,
            McpErrorCode::ToolExecutionError,
            McpErrorCode::ResourceNotFound,
            McpErrorCode::AuthenticationRequired,
            McpErrorCode::PermissionDenied,
            McpErrorCode::RateLimited,
        ];
        for code in codes {
            assert_ne!(
                code.is_standard_jsonrpc(),
                code.is_mcp_specific(),
                "code {code:?} must be exactly one of standard or mcp-specific"
            );
        }
    }

    #[test]
    fn error_code_hash_in_map() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(McpErrorCode::ToolNotFound, "tool");
        map.insert(McpErrorCode::InvalidRequest, "request");
        assert_eq!(map.get(&McpErrorCode::ToolNotFound), Some(&"tool"));
        assert_eq!(map.get(&McpErrorCode::InvalidRequest), Some(&"request"));
        assert!(!map.contains_key(&McpErrorCode::RateLimited));
    }

    // ── McpJsonRpcRequest extras ─────────────────────────────────────────

    #[test]
    fn jsonrpc_request_with_params_has_params() {
        let req =
            McpJsonRpcRequest::with_params(serde_json::json!(1), "test", serde_json::json!(null));
        // params is Some even if the value is null
        assert!(req.params.is_some());
    }

    #[test]
    fn jsonrpc_request_is_valid_requires_both() {
        // Valid version but empty method
        let req = McpJsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: serde_json::json!(1),
            method: String::new(),
            params: None,
        };
        assert!(!req.is_valid());

        // Invalid version but non-empty method
        let req2 = McpJsonRpcRequest {
            jsonrpc: "1.0".to_owned(),
            id: serde_json::json!(1),
            method: "test".to_owned(),
            params: None,
        };
        assert!(!req2.is_valid());
    }

    #[test]
    fn jsonrpc_request_complex_id() {
        // JSON-RPC spec allows array or object IDs (though unusual)
        let req = McpJsonRpcRequest::new(serde_json::json!([1, 2, 3]), "test");
        let json = serde_json::to_value(&req).unwrap();
        assert!(json["id"].is_array());
    }

    // ── McpJsonRpcResponse extras ────────────────────────────────────────

    #[test]
    fn jsonrpc_response_roundtrip() {
        let resp = McpJsonRpcResponse::success(
            serde_json::json!("req-42"),
            serde_json::json!({"tools": [], "nextCursor": null}),
        );
        let json = serde_json::to_string(&resp).unwrap();
        let back: McpJsonRpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.jsonrpc, "2.0");
        assert_eq!(back.id, serde_json::json!("req-42"));
        assert!(back.result["tools"].is_array());
    }

    #[test]
    fn jsonrpc_error_response_roundtrip() {
        let resp = build_error_response(
            serde_json::json!(7),
            McpErrorCode::ResourceNotFound,
            "Resource gone",
        );
        let json = serde_json::to_string(&resp).unwrap();
        let back: McpJsonRpcErrorResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.jsonrpc, "2.0");
        assert_eq!(back.id, serde_json::json!(7));
        assert_eq!(back.error.code, McpErrorCode::ResourceNotFound.code());
        assert_eq!(back.error.message, "Resource gone");
    }

    // ── McpContentBlock extras ───────────────────────────────────────────

    #[test]
    fn content_block_text_empty_string() {
        let block = McpContentBlock::text("");
        assert!(block.is_text());
        assert_eq!(block.as_text(), Some(""));
    }

    #[test]
    fn content_block_image_as_text_returns_none() {
        let block = McpContentBlock::image("abc", "image/png");
        assert_eq!(block.as_text(), None);
    }

    #[test]
    fn content_block_resource_as_text_returns_none() {
        let block = McpContentBlock::resource("uri://x");
        assert_eq!(block.as_text(), None);
    }

    #[test]
    fn content_block_resource_with_mime_and_text() {
        let block = McpContentBlock::Resource {
            uri: "file:///data.csv".to_owned(),
            mime_type: Some("text/csv".to_owned()),
            text: Some("a,b,c\n1,2,3".to_owned()),
        };
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["mimeType"], "text/csv");
        assert_eq!(json["text"], "a,b,c\n1,2,3");
    }

    #[test]
    fn content_block_resource_without_optional_fields_omits_them() {
        let block = McpContentBlock::resource("conn://test");
        let json = serde_json::to_value(&block).unwrap();
        assert!(json.get("mimeType").is_none());
        assert!(json.get("text").is_none());
    }

    // ── McpToolCallRequest extras ────────────────────────────────────────

    #[test]
    fn tool_call_request_default_arguments() {
        // When arguments is missing in JSON, it should default to null via #[serde(default)]
        let json_str = r#"{"name":"test_tool"}"#;
        let req: McpToolCallRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.name, "test_tool");
        assert!(req.arguments.is_null());
    }

    #[test]
    fn tool_call_request_with_nested_arguments() {
        let req = McpToolCallRequest {
            name: "complex_tool".to_owned(),
            arguments: serde_json::json!({
                "query": "test",
                "filters": [{"field": "status", "value": "active"}],
                "options": {"limit": 10, "offset": 0}
            }),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: McpToolCallRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.arguments["options"]["limit"], 10);
    }

    // ── McpToolCallResponse extras ───────────────────────────────────────

    #[test]
    fn tool_call_response_with_content_error() {
        let blocks = vec![McpContentBlock::text("Error occurred")];
        let resp = McpToolCallResponse::with_content(blocks, true);
        assert!(resp.is_error);
        assert_eq!(resp.content.len(), 1);
    }

    #[test]
    fn tool_call_response_roundtrip_success() {
        let resp = McpToolCallResponse::text("result data");
        let json = serde_json::to_string(&resp).unwrap();
        let back: McpToolCallResponse = serde_json::from_str(&json).unwrap();
        assert!(!back.is_error);
        assert_eq!(back.content.len(), 1);
    }

    #[test]
    fn tool_call_response_roundtrip_error() {
        let resp = McpToolCallResponse::error("failure");
        let json = serde_json::to_string(&resp).unwrap();
        let back: McpToolCallResponse = serde_json::from_str(&json).unwrap();
        assert!(back.is_error);
    }

    #[test]
    fn tool_call_response_empty_content_vec() {
        let resp = McpToolCallResponse::with_content(vec![], false);
        assert!(resp.content.is_empty());
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["content"].as_array().unwrap().len(), 0);
    }

    // ── McpResourceListRequest/Response extras ───────────────────────────

    #[test]
    fn resource_list_request_with_cursor() {
        let req = McpResourceListRequest {
            cursor: Some("next-page".to_owned()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["cursor"], "next-page");
    }

    #[test]
    fn resource_list_request_no_cursor_omits_field() {
        let req = McpResourceListRequest::default();
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("cursor").is_none());
    }

    #[test]
    fn resource_entry_without_optionals() {
        let entry = McpResourceEntry {
            uri: "conn://test".to_owned(),
            name: "Test".to_owned(),
            description: None,
            mime_type: None,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert!(json.get("description").is_none());
        assert!(json.get("mimeType").is_none());
    }

    #[test]
    fn resource_entry_roundtrip() {
        let entry = McpResourceEntry {
            uri: "conn://slack/channels".to_owned(),
            name: "Channels".to_owned(),
            description: Some("List of channels".to_owned()),
            mime_type: Some("application/json".to_owned()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: McpResourceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uri, "conn://slack/channels");
        assert_eq!(back.name, "Channels");
        assert_eq!(back.description.as_deref(), Some("List of channels"));
        assert_eq!(back.mime_type.as_deref(), Some("application/json"));
    }

    // ── SessionStatus extras ─────────────────────────────────────────────

    #[test]
    fn session_status_deserialize_all() {
        let variants = [
            ("\"active\"", SessionStatus::Active),
            ("\"idle\"", SessionStatus::Idle),
            ("\"expired\"", SessionStatus::Expired),
            ("\"terminated\"", SessionStatus::Terminated),
        ];
        for (json_str, expected) in variants {
            let status: SessionStatus = serde_json::from_str(json_str).unwrap();
            assert_eq!(status, expected);
        }
    }

    #[test]
    fn session_status_deserialize_invalid_fails() {
        let result: Result<SessionStatus, _> = serde_json::from_str("\"unknown\"");
        assert!(result.is_err());
    }

    #[test]
    fn session_status_copy_semantics() {
        let s = SessionStatus::Active;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn session_status_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SessionStatus::Active);
        set.insert(SessionStatus::Active);
        set.insert(SessionStatus::Idle);
        assert_eq!(set.len(), 2);
    }

    // ── AgentSessionConfig extras ────────────────────────────────────────

    #[test]
    fn session_config_multiple_validation_errors() {
        let config = AgentSessionConfig {
            idle_timeout: Duration::ZERO,
            max_lifetime: Duration::ZERO,
            max_concurrent_calls: 0,
            rate_limit_per_minute: 0,
        };
        let errors = config.validate();
        // idle_timeout zero, max_lifetime zero, concurrent zero, rate_limit zero
        // Also max_lifetime < idle_timeout won't fire since both are zero
        assert!(
            errors.len() >= 4,
            "expected at least 4 errors, got {}",
            errors.len()
        );
    }

    #[test]
    fn session_config_boundary_lifetime_equals_idle() {
        let config = AgentSessionConfig {
            idle_timeout: Duration::from_mins(5),
            max_lifetime: Duration::from_mins(5),
            max_concurrent_calls: 1,
            rate_limit_per_minute: 1,
        };
        assert!(config.is_valid(), "equal idle and lifetime should be valid");
    }

    #[test]
    fn session_config_serialize_uses_seconds() {
        let config = AgentSessionConfig {
            idle_timeout: Duration::from_mins(2),
            max_lifetime: Duration::from_hours(1),
            max_concurrent_calls: 5,
            rate_limit_per_minute: 30,
        };
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["idle_timeout"], 120);
        assert_eq!(json["max_lifetime"], 3600);
    }

    #[test]
    fn session_config_deserialize_from_seconds() {
        let json_str = r#"{"idle_timeout":60,"max_lifetime":1800,"max_concurrent_calls":8,"rate_limit_per_minute":100}"#;
        let config: AgentSessionConfig = serde_json::from_str(json_str).unwrap();
        assert_eq!(config.idle_timeout, Duration::from_mins(1));
        assert_eq!(config.max_lifetime, Duration::from_mins(30));
        assert_eq!(config.max_concurrent_calls, 8);
        assert_eq!(config.rate_limit_per_minute, 100);
    }

    // ── AgentSession extras ──────────────────────────────────────────────

    #[test]
    fn session_touch_does_not_reactivate_expired() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-exp", &req, AgentSessionConfig::default());
        session.expire();
        session.touch();
        // touch only reactivates Idle, not Expired
        assert_eq!(session.status, SessionStatus::Expired);
    }

    #[test]
    fn session_touch_does_not_reactivate_terminated() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-term", &req, AgentSessionConfig::default());
        session.terminate();
        session.touch();
        assert_eq!(session.status, SessionStatus::Terminated);
    }

    #[test]
    fn session_record_tool_call_also_touches() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-rtc", &req, AgentSessionConfig::default());
        session.mark_idle();
        assert_eq!(session.status, SessionStatus::Idle);
        session.record_tool_call();
        // record_tool_call calls touch(), which reactivates from Idle
        assert_eq!(session.status, SessionStatus::Active);
        assert_eq!(session.tool_call_count, 1);
    }

    #[test]
    fn session_mark_idle_only_from_active_not_terminated() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-mi", &req, AgentSessionConfig::default());
        session.terminate();
        session.mark_idle();
        assert_eq!(session.status, SessionStatus::Terminated);
    }

    #[test]
    fn session_new_with_v2024_protocol() {
        let req = McpInitializeRequest {
            protocol_version: McpProtocolVersion::V2024_11,
            capabilities: McpClientCapabilities::default(),
            client_info: McpClientInfo {
                name: "old-client".to_owned(),
                version: "0.5.0".to_owned(),
            },
        };
        let session = AgentSession::new("old-sess", &req, AgentSessionConfig::default());
        assert_eq!(session.protocol_version, McpProtocolVersion::V2024_11);
        assert_eq!(session.client_info.name, "old-client");
    }

    #[test]
    fn session_connected_at_before_last_activity_or_equal() {
        let req = make_init_request();
        let session = AgentSession::new("sess-ts", &req, AgentSessionConfig::default());
        assert!(session.connected_at <= session.last_activity);
    }

    #[test]
    fn session_serialize_after_state_changes() {
        let req = make_init_request();
        let mut session = AgentSession::new("sess-sc", &req, AgentSessionConfig::default());
        session.record_tool_call();
        session.record_tool_call();
        session.mark_idle();
        let json = serde_json::to_string(&session).unwrap();
        let back: AgentSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tool_call_count, 2);
        assert_eq!(back.status, SessionStatus::Idle);
    }

    // ── McpMethodCategory extras ─────────────────────────────────────────

    #[test]
    fn method_category_display_all_variants() {
        let expected = [
            (McpMethodCategory::Initialize, "initialize"),
            (McpMethodCategory::ToolsList, "tools/list"),
            (McpMethodCategory::ToolsCall, "tools/call"),
            (McpMethodCategory::ResourcesList, "resources/list"),
            (McpMethodCategory::ResourcesRead, "resources/read"),
            (McpMethodCategory::PromptsList, "prompts/list"),
            (McpMethodCategory::PromptsGet, "prompts/get"),
            (McpMethodCategory::Completion, "completion/complete"),
            (McpMethodCategory::Logging, "logging/setLevel"),
            (McpMethodCategory::Ping, "ping"),
            (McpMethodCategory::Notification, "notification"),
            (McpMethodCategory::Unknown, "unknown"),
        ];
        for (cat, s) in expected {
            assert_eq!(cat.to_string(), s);
        }
    }

    #[test]
    fn method_category_requires_session_all() {
        let requires = [
            McpMethodCategory::ToolsList,
            McpMethodCategory::ToolsCall,
            McpMethodCategory::ResourcesList,
            McpMethodCategory::ResourcesRead,
            McpMethodCategory::PromptsList,
            McpMethodCategory::PromptsGet,
            McpMethodCategory::Completion,
            McpMethodCategory::Logging,
            McpMethodCategory::Notification,
        ];
        for cat in requires {
            assert!(cat.requires_session(), "{cat:?} should require session");
        }
        let does_not = [
            McpMethodCategory::Initialize,
            McpMethodCategory::Ping,
            McpMethodCategory::Unknown,
        ];
        for cat in does_not {
            assert!(
                !cat.requires_session(),
                "{cat:?} should not require session"
            );
        }
    }

    #[test]
    fn method_category_expects_response_all() {
        // Only Notification does not expect a response
        let expects = [
            McpMethodCategory::Initialize,
            McpMethodCategory::ToolsList,
            McpMethodCategory::ToolsCall,
            McpMethodCategory::ResourcesList,
            McpMethodCategory::ResourcesRead,
            McpMethodCategory::PromptsList,
            McpMethodCategory::PromptsGet,
            McpMethodCategory::Completion,
            McpMethodCategory::Logging,
            McpMethodCategory::Ping,
            McpMethodCategory::Unknown,
        ];
        for cat in expects {
            assert!(cat.expects_response(), "{cat:?} should expect response");
        }
        assert!(!McpMethodCategory::Notification.expects_response());
    }

    // ── Route MCP method extras ──────────────────────────────────────────

    #[test]
    fn route_various_notification_prefixes() {
        assert_eq!(
            route_mcp_method("notifications/tools/list_changed"),
            McpMethodCategory::Notification
        );
        assert_eq!(
            route_mcp_method("notifications/resources/list_changed"),
            McpMethodCategory::Notification
        );
        assert_eq!(
            route_mcp_method("notifications/progress"),
            McpMethodCategory::Notification
        );
    }

    #[test]
    fn route_case_sensitive() {
        // MCP methods are case-sensitive
        assert_eq!(route_mcp_method("Initialize"), McpMethodCategory::Unknown);
        assert_eq!(route_mcp_method("PING"), McpMethodCategory::Unknown);
        assert_eq!(route_mcp_method("Tools/List"), McpMethodCategory::Unknown);
    }

    // ── McpMethodRouter extras ───────────────────────────────────────────

    #[test]
    fn router_overwrite_custom_route() {
        let mut router = McpMethodRouter::new();
        router.add_route("custom/x", McpMethodCategory::ToolsList);
        router.add_route("custom/x", McpMethodCategory::Logging);
        assert_eq!(router.route("custom/x"), McpMethodCategory::Logging);
        assert_eq!(router.custom_route_count(), 1);
    }

    #[test]
    fn router_notification_passthrough() {
        let router = McpMethodRouter::new();
        assert_eq!(
            router.route("notifications/test"),
            McpMethodCategory::Notification
        );
    }

    #[test]
    fn router_all_methods_count() {
        let router = McpMethodRouter::new();
        // 10 standard methods
        assert_eq!(router.all_methods().len(), 10);
    }

    #[test]
    fn router_all_methods_with_custom_count() {
        let mut router = McpMethodRouter::new();
        router.add_route("fcp/a", McpMethodCategory::Unknown);
        router.add_route("fcp/b", McpMethodCategory::Unknown);
        assert_eq!(router.all_methods().len(), 12);
    }

    #[test]
    fn router_clone() {
        let mut router = McpMethodRouter::new();
        router.add_route("fcp/test", McpMethodCategory::ToolsCall);
        let cloned = router.clone();
        assert_eq!(cloned.route("fcp/test"), McpMethodCategory::ToolsCall);
        assert_eq!(cloned.custom_route_count(), 1);
    }

    // ── ToolCallResult extras ────────────────────────────────────────────

    #[test]
    fn tool_call_result_success_roundtrip() {
        let result = ToolCallResult::success_text("data output", 200);
        let json = serde_json::to_string(&result).unwrap();
        let back: ToolCallResult = serde_json::from_str(&json).unwrap();
        assert!(!back.is_error);
        assert_eq!(back.duration_ms, 200);
        assert_eq!(back.content.len(), 1);
    }

    #[test]
    fn tool_call_result_error_roundtrip() {
        let result = ToolCallResult::error("timeout", 5000);
        let json = serde_json::to_string(&result).unwrap();
        let back: ToolCallResult = serde_json::from_str(&json).unwrap();
        assert!(back.is_error);
        assert_eq!(back.duration_ms, 5000);
    }

    #[test]
    fn tool_call_result_with_metadata_roundtrip() {
        let mut result = ToolCallResult::success_text("ok", 10);
        result
            .metadata
            .insert("key1".to_owned(), serde_json::json!("val1"));
        result
            .metadata
            .insert("key2".to_owned(), serde_json::json!(42));
        let json = serde_json::to_string(&result).unwrap();
        let back: ToolCallResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.metadata.len(), 2);
        assert_eq!(back.metadata["key1"], serde_json::json!("val1"));
        assert_eq!(back.metadata["key2"], serde_json::json!(42));
    }

    #[test]
    fn tool_call_result_zero_duration() {
        let result = ToolCallResult::success_text("instant", 0);
        assert_eq!(result.duration_ms, 0);
    }

    #[test]
    fn tool_call_result_error_to_mcp_preserves_content() {
        let result = ToolCallResult::error("detailed error message", 100);
        let resp = result.to_mcp_response();
        assert!(resp.is_error);
        assert_eq!(resp.content[0].as_text(), Some("detailed error message"));
    }

    // ── ToolCallError extras ─────────────────────────────────────────────

    #[test]
    fn tool_call_error_with_data_to_jsonrpc_preserves_data() {
        let err = ToolCallError::with_data(
            McpErrorCode::ToolExecutionError,
            "Failed to execute",
            serde_json::json!({"retry_after": 30, "request_id": "r-99"}),
        );
        let rpc_err = err.to_jsonrpc_error();
        assert_eq!(rpc_err.code, -32002);
        assert_eq!(rpc_err.message, "Failed to execute");
        let data = rpc_err.data.unwrap();
        assert_eq!(data["retry_after"], 30);
        assert_eq!(data["request_id"], "r-99");
    }

    #[test]
    fn tool_call_error_display_all_codes() {
        let codes = [
            McpErrorCode::InvalidRequest,
            McpErrorCode::MethodNotFound,
            McpErrorCode::InvalidParams,
            McpErrorCode::InternalError,
            McpErrorCode::ToolNotFound,
            McpErrorCode::ToolExecutionError,
            McpErrorCode::ResourceNotFound,
            McpErrorCode::AuthenticationRequired,
            McpErrorCode::PermissionDenied,
            McpErrorCode::RateLimited,
        ];
        for code in codes {
            let err = ToolCallError::new(code, "test message");
            let s = err.to_string();
            assert!(
                s.contains("test message"),
                "display missing message for {code:?}"
            );
            assert!(
                s.contains(&code.code().to_string()),
                "display missing code for {code:?}"
            );
        }
    }

    #[test]
    fn tool_call_error_serialize_roundtrip() {
        let err = ToolCallError::new(McpErrorCode::PermissionDenied, "Access denied");
        let json = serde_json::to_string(&err).unwrap();
        let back: ToolCallError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, McpErrorCode::PermissionDenied);
        assert_eq!(back.message, "Access denied");
        assert!(back.data.is_none());
    }

    #[test]
    fn tool_call_error_with_data_serialize_roundtrip() {
        let err = ToolCallError::with_data(
            McpErrorCode::RateLimited,
            "Slow down",
            serde_json::json!({"retry_ms": 1000}),
        );
        let json = serde_json::to_string(&err).unwrap();
        let back: ToolCallError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, McpErrorCode::RateLimited);
        assert_eq!(back.data.unwrap()["retry_ms"], 1000);
    }

    // ── build_error_response extras ──────────────────────────────────────

    #[test]
    fn build_error_response_all_codes() {
        let codes = [
            McpErrorCode::InvalidRequest,
            McpErrorCode::MethodNotFound,
            McpErrorCode::InvalidParams,
            McpErrorCode::InternalError,
            McpErrorCode::ToolNotFound,
            McpErrorCode::ToolExecutionError,
            McpErrorCode::ResourceNotFound,
            McpErrorCode::AuthenticationRequired,
            McpErrorCode::PermissionDenied,
            McpErrorCode::RateLimited,
        ];
        for code in codes {
            let resp = build_error_response(serde_json::json!(1), code, code.default_message());
            assert_eq!(resp.error.code, code.code());
            assert_eq!(resp.error.message, code.default_message());
        }
    }

    #[test]
    fn build_error_response_with_data_complex_data() {
        let resp = build_error_response_with_data(
            serde_json::json!("req-x"),
            McpErrorCode::InternalError,
            "Crash",
            serde_json::json!({
                "stack": ["frame1", "frame2"],
                "code": "PANIC",
                "timestamp": "2026-03-12T00:00:00Z"
            }),
        );
        let data = resp.error.data.unwrap();
        assert!(data["stack"].is_array());
        assert_eq!(data["stack"].as_array().unwrap().len(), 2);
        assert_eq!(data["code"], "PANIC");
    }

    // ── McpToolAnnotations extras ────────────────────────────────────────

    #[test]
    fn annotations_partial_fields() {
        let ann = McpToolAnnotations {
            risk_level: Some("low".to_owned()),
            safety_tier: None,
            idempotency: None,
            capability: None,
            read_only: Some(true),
            destructive: None,
        };
        let json = serde_json::to_value(&ann).unwrap();
        assert_eq!(json["riskLevel"], "low");
        assert_eq!(json["readOnly"], true);
        // None fields should be omitted
        assert!(json.get("safetyTier").is_none());
        assert!(json.get("idempotency").is_none());
        assert!(json.get("capability").is_none());
        assert!(json.get("destructive").is_none());
    }

    #[test]
    fn annotations_all_none() {
        let ann = McpToolAnnotations {
            risk_level: None,
            safety_tier: None,
            idempotency: None,
            capability: None,
            read_only: None,
            destructive: None,
        };
        let json = serde_json::to_value(&ann).unwrap();
        // All fields should be omitted
        assert!(json.as_object().unwrap().is_empty());
    }

    #[test]
    fn annotations_roundtrip() {
        let ann = McpToolAnnotations {
            risk_level: Some("critical".to_owned()),
            safety_tier: Some("critical".to_owned()),
            idempotency: Some("none".to_owned()),
            capability: Some("admin.nuke".to_owned()),
            read_only: Some(false),
            destructive: Some(true),
        };
        let json = serde_json::to_string(&ann).unwrap();
        let back: McpToolAnnotations = serde_json::from_str(&json).unwrap();
        assert_eq!(ann, back);
    }

    #[test]
    fn annotations_inequality() {
        let a = McpToolAnnotations {
            risk_level: Some("low".to_owned()),
            safety_tier: None,
            idempotency: None,
            capability: None,
            read_only: None,
            destructive: None,
        };
        let b = McpToolAnnotations {
            risk_level: Some("high".to_owned()),
            safety_tier: None,
            idempotency: None,
            capability: None,
            read_only: None,
            destructive: None,
        };
        assert_ne!(a, b);
    }

    // ── McpClientCapabilities extras ─────────────────────────────────────

    #[test]
    fn client_capabilities_with_sampling() {
        let caps = McpClientCapabilities {
            sampling: Some(serde_json::json!({})),
            roots: None,
        };
        let json = serde_json::to_value(&caps).unwrap();
        assert!(json.get("sampling").is_some());
        assert!(json.get("roots").is_none());
    }

    #[test]
    fn client_capabilities_with_roots() {
        let caps = McpClientCapabilities {
            sampling: None,
            roots: Some(serde_json::json!({"listChanged": true})),
        };
        let json = serde_json::to_value(&caps).unwrap();
        assert!(json.get("roots").is_some());
        assert!(json.get("sampling").is_none());
    }

    #[test]
    fn client_capabilities_roundtrip() {
        let caps = McpClientCapabilities {
            sampling: Some(serde_json::json!({"supported": true})),
            roots: Some(serde_json::json!({"listChanged": false})),
        };
        let json = serde_json::to_string(&caps).unwrap();
        let back: McpClientCapabilities = serde_json::from_str(&json).unwrap();
        assert!(back.sampling.is_some());
        assert!(back.roots.is_some());
    }

    // ── McpToolListEntry extras ──────────────────────────────────────────

    #[test]
    fn tool_list_entry_no_description_no_annotations() {
        let entry = McpToolListEntry {
            name: "bare_tool".to_owned(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            annotations: None,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert!(json.get("description").is_none());
        assert!(json.get("annotations").is_none());
    }

    #[test]
    fn tool_list_entry_roundtrip_with_annotations() {
        let entry = McpToolListEntry {
            name: "annotated_tool".to_owned(),
            description: Some("A tool with annotations".to_owned()),
            input_schema: serde_json::json!({"type": "object", "properties": {}}),
            annotations: Some(McpToolAnnotations {
                risk_level: Some("medium".to_owned()),
                safety_tier: Some("risky".to_owned()),
                idempotency: Some("strict".to_owned()),
                capability: Some("test.cap".to_owned()),
                read_only: Some(false),
                destructive: Some(false),
            }),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: McpToolListEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "annotated_tool");
        assert!(back.annotations.is_some());
        let ann = back.annotations.unwrap();
        assert_eq!(ann.risk_level, Some("medium".to_owned()));
    }

    // ── McpServerInfo extras ─────────────────────────────────────────────

    #[test]
    fn server_info_roundtrip() {
        let info = McpServerInfo::fcp_host();
        let json = serde_json::to_string(&info).unwrap();
        let back: McpServerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "fcp-host");
        assert_eq!(back.version, info.version);
    }

    // ── ToolCallContext extras ───────────────────────────────────────────

    #[test]
    fn tool_call_context_roundtrip() {
        let ctx = ToolCallContext::new(
            "sess-rt",
            serde_json::json!(99),
            "my_tool",
            ConnectorId::from_static("conn:utility:2.0.0"),
            OperationId::from_static("my_tool"),
            serde_json::json!({"a": 1}),
        );
        let json = serde_json::to_string(&ctx).unwrap();
        let back: ToolCallContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.session_id, "sess-rt");
        assert_eq!(back.tool_name, "my_tool");
        assert_eq!(back.request_id, serde_json::json!(99));
        assert_eq!(back.arguments["a"], 1);
    }

    #[test]
    fn tool_call_context_empty_arguments() {
        let ctx = ToolCallContext::new(
            "s",
            serde_json::json!(1),
            "noop",
            ConnectorId::from_static("x:utility:1.0.0"),
            OperationId::from_static("noop"),
            serde_json::json!({}),
        );
        assert!(ctx.arguments.as_object().unwrap().is_empty());
    }
}
