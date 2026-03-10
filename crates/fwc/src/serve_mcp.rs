//! MCP server module for exposing connectors as MCP tools via JSON-RPC 2.0.
//!
//! This module implements the data layer of `fwc serve-mcp`. It defines the
//! JSON-RPC protocol types, MCP server state, and pure request-handling logic.
//! The transport layer (stdio, SSE) is out of scope — this module provides
//! the routing and response generation that the transport calls into.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ── JSON-RPC 2.0 Error Codes ────────────────────────────────────────────

/// Parse error: invalid JSON was received by the server.
pub const PARSE_ERROR: i32 = -32_700;
/// Invalid request: the JSON sent is not a valid request object.
pub const INVALID_REQUEST: i32 = -32_600;
/// Method not found: the method does not exist or is not available.
pub const METHOD_NOT_FOUND: i32 = -32_601;
/// Invalid params: invalid method parameters.
pub const INVALID_PARAMS: i32 = -32_602;
/// Internal error: internal JSON-RPC error.
pub const INTERNAL_ERROR: i32 = -32_603;

// ── JSON-RPC 2.0 Protocol Types ─────────────────────────────────────────

/// A JSON-RPC 2.0 request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version, always `"2.0"`.
    pub jsonrpc: String,
    /// Request ID (may be null for notifications).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// Method name to invoke.
    pub method: String,
    /// Optional method parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A JSON-RPC 2.0 response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version, always `"2.0"`.
    pub jsonrpc: String,
    /// Request ID this response corresponds to.
    pub id: Value,
    /// Successful result (mutually exclusive with `error`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error result (mutually exclusive with `result`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Create a success response.
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Return the id.
    pub const fn id(&self) -> &Value {
        &self.id
    }

    /// Return the result if present.
    pub const fn result(&self) -> Option<&Value> {
        self.result.as_ref()
    }

    /// Return whether this response is an error.
    pub const fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// A JSON-RPC 2.0 error object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code.
    pub code: i32,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured data about the error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Create a new error with code and message.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Builder: attach extra data to the error.
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Create a parse error.
    pub fn parse_error(detail: impl Into<String>) -> Self {
        Self::new(PARSE_ERROR, detail)
    }

    /// Create an invalid request error.
    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self::new(INVALID_REQUEST, detail)
    }

    /// Create a method-not-found error.
    pub fn method_not_found(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("Method not found: {method}"))
    }

    /// Create an invalid-params error.
    pub fn invalid_params(detail: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, detail)
    }

    /// Create an internal error.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR, detail)
    }

    /// Return the error code.
    pub const fn code(&self) -> i32 {
        self.code
    }

    /// Return the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ── Transport Mode ──────────────────────────────────────────────────────

/// Transport mode for the MCP server.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Standard I/O (newline-delimited JSON).
    #[default]
    Stdio,
    /// Server-Sent Events over HTTP.
    Sse {
        /// Port to listen on.
        port: u16,
    },
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdio => write!(f, "stdio"),
            Self::Sse { port } => write!(f, "sse:{port}"),
        }
    }
}

// ── MCP Server Configuration ────────────────────────────────────────────

/// Configuration for the MCP server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// Transport mode (stdio or SSE).
    pub transport: TransportMode,
    /// Optional zone filter — only expose connectors in this zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_filter: Option<String>,
    /// Optional connector filter — only expose this specific connector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_filter: Option<String>,
    /// Whether to expose resources.
    #[serde(default = "default_true")]
    pub include_resources: bool,
    /// Whether to expose prompts.
    #[serde(default = "default_true")]
    pub include_prompts: bool,
}

const fn default_true() -> bool {
    true
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            transport: TransportMode::default(),
            zone_filter: None,
            connector_filter: None,
            include_resources: true,
            include_prompts: true,
        }
    }
}

impl McpServerConfig {
    /// Create a new config with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set transport mode.
    pub const fn with_transport(mut self, transport: TransportMode) -> Self {
        self.transport = transport;
        self
    }

    /// Builder: set zone filter.
    pub fn with_zone_filter(mut self, zone: impl Into<String>) -> Self {
        self.zone_filter = Some(zone.into());
        self
    }

    /// Builder: set connector filter.
    pub fn with_connector_filter(mut self, connector: impl Into<String>) -> Self {
        self.connector_filter = Some(connector.into());
        self
    }

    /// Builder: disable resources.
    pub const fn without_resources(mut self) -> Self {
        self.include_resources = false;
        self
    }

    /// Builder: disable prompts.
    pub const fn without_prompts(mut self) -> Self {
        self.include_prompts = false;
        self
    }
}

// ── MCP Server Info ─────────────────────────────────────────────────────

/// Server identity and protocol version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpServerInfo {
    /// Server name.
    pub name: String,
    /// Server version.
    pub version: String,
    /// MCP protocol version supported.
    pub protocol_version: String,
}

impl Default for McpServerInfo {
    fn default() -> Self {
        Self {
            name: "fwc".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: "2024-11-05".to_string(),
        }
    }
}

impl McpServerInfo {
    /// Return the server name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the server version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Return the protocol version.
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }
}

// ── MCP Tool Definition ─────────────────────────────────────────────────

/// An MCP tool registered with the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpToolDefinition {
    /// Tool name (unique identifier for the tool).
    pub name: String,
    /// Human-readable description of what the tool does.
    pub description: String,
    /// JSON Schema describing the tool's input parameters.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    /// Connector that provides this tool.
    pub connector_id: String,
    /// Operation within the connector.
    pub operation_id: String,
}

impl McpToolDefinition {
    /// Create a new tool definition.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
        connector_id: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema,
            connector_id: connector_id.into(),
            operation_id: operation_id.into(),
        }
    }

    /// Return the tool name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the connector that provides this tool.
    pub fn connector_id(&self) -> &str {
        &self.connector_id
    }

    /// Return the operation id.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

// ── MCP Resource Entry ──────────────────────────────────────────────────

/// A resource registered with the MCP server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpResourceEntry {
    /// Resource URI.
    pub uri: String,
    /// Human-readable name.
    pub name: String,
    /// Description of the resource.
    pub description: String,
    /// MIME type of the resource content.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

impl McpResourceEntry {
    /// Create a new resource entry.
    pub fn new(
        uri: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        mime_type: impl Into<String>,
    ) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            description: description.into(),
            mime_type: mime_type.into(),
        }
    }

    /// Return the resource URI.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Return the resource name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

// ── MCP Prompt Entry ────────────────────────────────────────────────────

/// A prompt registered with the MCP server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpPromptEntry {
    /// Prompt name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Arguments accepted by this prompt.
    pub arguments: Vec<PromptArgDef>,
}

impl McpPromptEntry {
    /// Create a new prompt entry.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            arguments: Vec::new(),
        }
    }

    /// Builder: add an argument.
    pub fn with_argument(mut self, arg: PromptArgDef) -> Self {
        self.arguments.push(arg);
        self
    }

    /// Return the prompt name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A single prompt argument definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptArgDef {
    /// Argument name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this argument is required.
    pub required: bool,
}

impl PromptArgDef {
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

// ── Discovered Operation Stub ───────────────────────────────────────────

/// Minimal stub for a discovered operation, used to populate MCP tools
/// without pulling in the full [`crate::readiness::DiscoveredOperation`]
/// dependency graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredOperationStub {
    /// Connector that owns this operation (e.g. `"github"`).
    pub connector_id: String,
    /// Operation identifier (e.g. `"list_issues"`).
    pub operation_id: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the operation's input.
    pub input_schema: Value,
}

impl DiscoveredOperationStub {
    /// Create a new operation stub.
    pub fn new(
        connector_id: impl Into<String>,
        operation_id: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
    ) -> Self {
        Self {
            connector_id: connector_id.into(),
            operation_id: operation_id.into(),
            description: description.into(),
            input_schema,
        }
    }

    /// Return the fully-qualified tool name.
    pub fn tool_name(&self) -> String {
        format!("{}.{}", self.connector_id, self.operation_id)
    }
}

// ── MCP Server State ────────────────────────────────────────────────────

/// Holds the complete state for the MCP server: tools, resources, prompts,
/// configuration, and server identity.
#[derive(Clone, Debug, Default)]
pub struct McpServerState {
    /// Registered MCP tools.
    pub tools: Vec<McpToolDefinition>,
    /// Registered MCP resources.
    pub resources: Vec<McpResourceEntry>,
    /// Registered MCP prompts.
    pub prompts: Vec<McpPromptEntry>,
    /// Server configuration.
    pub config: McpServerConfig,
    /// Server identity info.
    pub server_info: McpServerInfo,
}

impl McpServerState {
    /// Create a new builder for `McpServerState`.
    pub fn builder() -> McpServerBuilder {
        McpServerBuilder::default()
    }

    /// Return the number of registered tools.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Return the number of registered resources.
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    /// Return the number of registered prompts.
    pub fn prompt_count(&self) -> usize {
        self.prompts.len()
    }

    /// Look up a tool by name.
    pub fn find_tool(&self, name: &str) -> Option<&McpToolDefinition> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// Look up a resource by URI.
    pub fn find_resource(&self, uri: &str) -> Option<&McpResourceEntry> {
        self.resources.iter().find(|r| r.uri == uri)
    }

    /// Look up a prompt by name.
    pub fn find_prompt(&self, name: &str) -> Option<&McpPromptEntry> {
        self.prompts.iter().find(|p| p.name == name)
    }

    /// Return tools filtered by connector id.
    pub fn tools_for_connector(&self, connector_id: &str) -> Vec<&McpToolDefinition> {
        self.tools
            .iter()
            .filter(|t| t.connector_id == connector_id)
            .collect()
    }
}

/// Convenience constructor: build an `McpServerState` from a list of
/// [`DiscoveredOperationStub`] values.
pub fn from_operations(ops: &[DiscoveredOperationStub]) -> McpServerState {
    let mut builder = McpServerState::builder();
    for op in ops {
        let tool = McpToolDefinition::new(
            op.tool_name(),
            &op.description,
            op.input_schema.clone(),
            &op.connector_id,
            &op.operation_id,
        );
        builder = builder.with_tool(tool);
    }
    builder.build()
}

// ── Builder ─────────────────────────────────────────────────────────────

/// Builder for [`McpServerState`].
#[derive(Clone, Debug, Default)]
pub struct McpServerBuilder {
    tools: Vec<McpToolDefinition>,
    resources: Vec<McpResourceEntry>,
    prompts: Vec<McpPromptEntry>,
    config: Option<McpServerConfig>,
    server_info: Option<McpServerInfo>,
}

impl McpServerBuilder {
    /// Set the server configuration.
    pub fn with_config(mut self, config: McpServerConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the server info.
    pub fn with_server_info(mut self, info: McpServerInfo) -> Self {
        self.server_info = Some(info);
        self
    }

    /// Register a tool.
    pub fn with_tool(mut self, tool: McpToolDefinition) -> Self {
        self.tools.push(tool);
        self
    }

    /// Register a resource.
    pub fn with_resource(mut self, resource: McpResourceEntry) -> Self {
        self.resources.push(resource);
        self
    }

    /// Register a prompt.
    pub fn with_prompt(mut self, prompt: McpPromptEntry) -> Self {
        self.prompts.push(prompt);
        self
    }

    /// Consume the builder and produce the server state.
    pub fn build(self) -> McpServerState {
        McpServerState {
            tools: self.tools,
            resources: self.resources,
            prompts: self.prompts,
            config: self.config.unwrap_or_default(),
            server_info: self.server_info.unwrap_or_default(),
        }
    }
}

// ── Request Handling ────────────────────────────────────────────────────

/// Route a JSON-RPC request to the appropriate MCP method handler.
///
/// This is a pure function: it reads the server state and the request,
/// and produces a response without performing any I/O.
pub fn handle_request(state: &McpServerState, request: &JsonRpcRequest) -> JsonRpcResponse {
    let id = request.id.clone().unwrap_or(Value::Null);

    match request.method.as_str() {
        "initialize" => handle_initialize(state, id),
        "notifications/initialized" => handle_initialized_notification(id),
        "tools/list" => handle_tools_list(state, id),
        "tools/call" => handle_tools_call(state, id, request.params.as_ref()),
        "resources/list" => handle_resources_list(state, id),
        "resources/read" => handle_resources_read(state, id, request.params.as_ref()),
        "prompts/list" => handle_prompts_list(state, id),
        "prompts/get" => handle_prompts_get(state, id, request.params.as_ref()),
        _ => JsonRpcResponse::error(id, JsonRpcError::method_not_found(&request.method)),
    }
}

/// Parse a raw JSON string into a request and route it.
///
/// Returns a response even if parsing fails (as a parse error).
pub fn handle_raw(state: &McpServerState, raw: &str) -> JsonRpcResponse {
    match serde_json::from_str::<JsonRpcRequest>(raw) {
        Ok(request) => handle_request(state, &request),
        Err(e) => JsonRpcResponse::error(
            Value::Null,
            JsonRpcError::parse_error(format!("Failed to parse request: {e}")),
        ),
    }
}

// ── Method Handlers ─────────────────────────────────────────────────────

fn handle_initialize(state: &McpServerState, id: Value) -> JsonRpcResponse {
    let mut capabilities = json!({
        "tools": {}
    });

    if state.config.include_resources && !state.resources.is_empty() {
        capabilities["resources"] = json!({});
    }
    if state.config.include_prompts && !state.prompts.is_empty() {
        capabilities["prompts"] = json!({});
    }

    JsonRpcResponse::success(
        id,
        json!({
            "protocolVersion": state.server_info.protocol_version,
            "capabilities": capabilities,
            "serverInfo": {
                "name": state.server_info.name,
                "version": state.server_info.version,
            }
        }),
    )
}

fn handle_initialized_notification(id: Value) -> JsonRpcResponse {
    // Acknowledgment — nothing to return beyond success.
    JsonRpcResponse::success(id, json!({}))
}

fn handle_tools_list(state: &McpServerState, id: Value) -> JsonRpcResponse {
    let tools: Vec<Value> = state
        .tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();

    JsonRpcResponse::success(id, json!({ "tools": tools }))
}

fn handle_tools_call(state: &McpServerState, id: Value, params: Option<&Value>) -> JsonRpcResponse {
    let Some(params) = params else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing params for tools/call"),
        );
    };

    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if tool_name.is_empty() {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing 'name' in tools/call params"),
        );
    }

    let Some(tool) = state.find_tool(tool_name) else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Tool not found: {tool_name}")),
        );
    };

    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    // Stub response — actual invocation happens in the transport layer.
    JsonRpcResponse::success(
        id,
        json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "invocation would go here: connector={}, operation={}, arguments={}",
                    tool.connector_id,
                    tool.operation_id,
                    arguments,
                ),
            }],
            "isError": false,
        }),
    )
}

fn handle_resources_list(state: &McpServerState, id: Value) -> JsonRpcResponse {
    if !state.config.include_resources {
        return JsonRpcResponse::success(id, json!({ "resources": [] }));
    }

    let resources: Vec<Value> = state
        .resources
        .iter()
        .map(|r| {
            json!({
                "uri": r.uri,
                "name": r.name,
                "description": r.description,
                "mimeType": r.mime_type,
            })
        })
        .collect();

    JsonRpcResponse::success(id, json!({ "resources": resources }))
}

fn handle_resources_read(
    state: &McpServerState,
    id: Value,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let Some(params) = params else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing params for resources/read"),
        );
    };

    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if uri.is_empty() {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing 'uri' in resources/read params"),
        );
    }

    if !state.config.include_resources {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Resources are disabled; cannot read: {uri}")),
        );
    }

    let Some(resource) = state.find_resource(uri) else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Resource not found: {uri}")),
        );
    };

    // Stub: actual resource content comes from the runtime.
    JsonRpcResponse::success(
        id,
        json!({
            "contents": [{
                "uri": resource.uri,
                "mimeType": resource.mime_type,
                "text": format!("resource content stub for: {}", resource.uri),
            }],
        }),
    )
}

fn handle_prompts_list(state: &McpServerState, id: Value) -> JsonRpcResponse {
    if !state.config.include_prompts {
        return JsonRpcResponse::success(id, json!({ "prompts": [] }));
    }

    let prompts: Vec<Value> = state
        .prompts
        .iter()
        .map(|p| {
            let args: Vec<Value> = p
                .arguments
                .iter()
                .map(|a| {
                    json!({
                        "name": a.name,
                        "description": a.description,
                        "required": a.required,
                    })
                })
                .collect();
            json!({
                "name": p.name,
                "description": p.description,
                "arguments": args,
            })
        })
        .collect();

    JsonRpcResponse::success(id, json!({ "prompts": prompts }))
}

fn handle_prompts_get(
    state: &McpServerState,
    id: Value,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let Some(params) = params else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing params for prompts/get"),
        );
    };

    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if name.is_empty() {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing 'name' in prompts/get params"),
        );
    }

    if !state.config.include_prompts {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Prompts are disabled; cannot get: {name}")),
        );
    }

    let Some(prompt) = state.find_prompt(name) else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Prompt not found: {name}")),
        );
    };

    // Stub: actual prompt rendering comes from the runtime.
    JsonRpcResponse::success(
        id,
        json!({
            "description": prompt.description,
            "messages": [{
                "role": "user",
                "content": {
                    "type": "text",
                    "text": format!("prompt content stub for: {}", prompt.name),
                },
            }],
        }),
    )
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ─────────────────────────────────────────────────────

    fn sample_tool() -> McpToolDefinition {
        McpToolDefinition::new(
            "github.list_issues",
            "List issues in a repository",
            json!({
                "type": "object",
                "required": ["owner", "repo"],
                "properties": {
                    "owner": { "type": "string" },
                    "repo": { "type": "string" }
                }
            }),
            "github",
            "list_issues",
        )
    }

    fn sample_resource() -> McpResourceEntry {
        McpResourceEntry::new(
            "resource://connector/github/health",
            "GitHub Health",
            "Current health snapshot for the GitHub connector",
            "application/json",
        )
    }

    fn sample_prompt() -> McpPromptEntry {
        McpPromptEntry::new("how-to-use-github", "How to use the GitHub connector")
            .with_argument(PromptArgDef::required(
                "task",
                "What you want to accomplish",
            ))
            .with_argument(PromptArgDef::optional("style", "Output style preference"))
    }

    fn sample_state() -> McpServerState {
        McpServerState::builder()
            .with_tool(sample_tool())
            .with_resource(sample_resource())
            .with_prompt(sample_prompt())
            .build()
    }

    fn make_request(method: &str, params: Option<Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: method.to_string(),
            params,
        }
    }

    // ── JSON-RPC Serialization ──────────────────────────────────────

    #[test]
    fn request_roundtrip_with_params() {
        let req = make_request("tools/list", Some(json!({})));
        let serialized = serde_json::to_string(&req).unwrap();
        let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.method, "tools/list");
        assert_eq!(deserialized.jsonrpc, "2.0");
    }

    #[test]
    fn request_roundtrip_without_params() {
        let req = make_request("tools/list", None);
        let serialized = serde_json::to_string(&req).unwrap();
        let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
        assert!(deserialized.params.is_none());
    }

    #[test]
    fn request_roundtrip_without_id() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: "notifications/initialized".to_string(),
            params: None,
        };
        let serialized = serde_json::to_string(&req).unwrap();
        assert!(!serialized.contains("\"id\""));
        let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
        assert!(deserialized.id.is_none());
    }

    #[test]
    fn response_success_roundtrip() {
        let resp = JsonRpcResponse::success(json!(1), json!({"status": "ok"}));
        let serialized = serde_json::to_string(&resp).unwrap();
        let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.id, json!(1));
        assert!(deserialized.result.is_some());
        assert!(deserialized.error.is_none());
    }

    #[test]
    fn response_error_roundtrip() {
        let resp = JsonRpcResponse::error(json!(2), JsonRpcError::method_not_found("bogus"));
        let serialized = serde_json::to_string(&resp).unwrap();
        let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.id, json!(2));
        assert!(deserialized.error.is_some());
        assert!(deserialized.result.is_none());
    }

    #[test]
    fn response_success_omits_error_field() {
        let resp = JsonRpcResponse::success(json!(1), json!("ok"));
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(!serialized.contains("\"error\""));
    }

    #[test]
    fn response_error_omits_result_field() {
        let resp = JsonRpcResponse::error(json!(1), JsonRpcError::internal("boom"));
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(!serialized.contains("\"result\""));
    }

    #[test]
    fn response_id_accessor() {
        let resp = JsonRpcResponse::success(json!(42), json!(null));
        assert_eq!(*resp.id(), json!(42));
    }

    #[test]
    fn response_result_accessor() {
        let resp = JsonRpcResponse::success(json!(1), json!("hello"));
        assert_eq!(resp.result(), Some(&json!("hello")));
    }

    #[test]
    fn response_is_error_true() {
        let resp = JsonRpcResponse::error(json!(1), JsonRpcError::internal("x"));
        assert!(resp.is_error());
    }

    #[test]
    fn response_is_error_false() {
        let resp = JsonRpcResponse::success(json!(1), json!(null));
        assert!(!resp.is_error());
    }

    // ── JSON-RPC Error Codes ────────────────────────────────────────

    #[test]
    fn error_code_parse_error() {
        assert_eq!(PARSE_ERROR, -32_700);
    }

    #[test]
    fn error_code_invalid_request() {
        assert_eq!(INVALID_REQUEST, -32_600);
    }

    #[test]
    fn error_code_method_not_found() {
        assert_eq!(METHOD_NOT_FOUND, -32_601);
    }

    #[test]
    fn error_code_invalid_params() {
        assert_eq!(INVALID_PARAMS, -32_602);
    }

    #[test]
    fn error_code_internal_error() {
        assert_eq!(INTERNAL_ERROR, -32_603);
    }

    #[test]
    fn error_factory_parse() {
        let e = JsonRpcError::parse_error("bad json");
        assert_eq!(e.code(), PARSE_ERROR);
        assert!(e.message().contains("bad json"));
    }

    #[test]
    fn error_factory_invalid_request() {
        let e = JsonRpcError::invalid_request("wrong shape");
        assert_eq!(e.code(), INVALID_REQUEST);
    }

    #[test]
    fn error_factory_method_not_found() {
        let e = JsonRpcError::method_not_found("bogus/method");
        assert_eq!(e.code(), METHOD_NOT_FOUND);
        assert!(e.message().contains("bogus/method"));
    }

    #[test]
    fn error_factory_invalid_params() {
        let e = JsonRpcError::invalid_params("missing name");
        assert_eq!(e.code(), INVALID_PARAMS);
    }

    #[test]
    fn error_factory_internal() {
        let e = JsonRpcError::internal("crash");
        assert_eq!(e.code(), INTERNAL_ERROR);
    }

    #[test]
    fn error_with_data() {
        let e = JsonRpcError::internal("fail").with_data(json!({"detail": "stack trace"}));
        assert!(e.data.is_some());
        assert_eq!(e.data.as_ref().unwrap()["detail"], "stack trace");
    }

    #[test]
    fn error_display_format() {
        let e = JsonRpcError::new(-32_000, "custom error");
        let display = format!("{e}");
        assert!(display.contains("-32000"));
        assert!(display.contains("custom error"));
    }

    // ── Transport Mode ──────────────────────────────────────────────

    #[test]
    fn transport_default_is_stdio() {
        assert_eq!(TransportMode::default(), TransportMode::Stdio);
    }

    #[test]
    fn transport_stdio_display() {
        assert_eq!(TransportMode::Stdio.to_string(), "stdio");
    }

    #[test]
    fn transport_sse_display() {
        let t = TransportMode::Sse { port: 8080 };
        assert_eq!(t.to_string(), "sse:8080");
    }

    #[test]
    fn transport_mode_serde_roundtrip_stdio() {
        let t = TransportMode::Stdio;
        let json = serde_json::to_string(&t).unwrap();
        let back: TransportMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TransportMode::Stdio);
    }

    #[test]
    fn transport_mode_serde_roundtrip_sse() {
        let t = TransportMode::Sse { port: 3000 };
        let json = serde_json::to_string(&t).unwrap();
        let back: TransportMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TransportMode::Sse { port: 3000 });
    }

    // ── Server Config ───────────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let c = McpServerConfig::default();
        assert_eq!(c.transport, TransportMode::Stdio);
        assert!(c.zone_filter.is_none());
        assert!(c.connector_filter.is_none());
        assert!(c.include_resources);
        assert!(c.include_prompts);
    }

    #[test]
    fn config_new_matches_default() {
        let a = McpServerConfig::new();
        let b = McpServerConfig::default();
        assert_eq!(a.transport, b.transport);
        assert_eq!(a.include_resources, b.include_resources);
    }

    #[test]
    fn config_builder_transport() {
        let c = McpServerConfig::new().with_transport(TransportMode::Sse { port: 9090 });
        assert_eq!(c.transport, TransportMode::Sse { port: 9090 });
    }

    #[test]
    fn config_builder_zone_filter() {
        let c = McpServerConfig::new().with_zone_filter("prod");
        assert_eq!(c.zone_filter.as_deref(), Some("prod"));
    }

    #[test]
    fn config_builder_connector_filter() {
        let c = McpServerConfig::new().with_connector_filter("github");
        assert_eq!(c.connector_filter.as_deref(), Some("github"));
    }

    #[test]
    fn config_builder_without_resources() {
        let c = McpServerConfig::new().without_resources();
        assert!(!c.include_resources);
    }

    #[test]
    fn config_builder_without_prompts() {
        let c = McpServerConfig::new().without_prompts();
        assert!(!c.include_prompts);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = McpServerConfig::new()
            .with_transport(TransportMode::Sse { port: 4000 })
            .with_zone_filter("staging");
        let json = serde_json::to_string(&c).unwrap();
        let back: McpServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zone_filter.as_deref(), Some("staging"));
    }

    // ── Server Info ─────────────────────────────────────────────────

    #[test]
    fn server_info_defaults() {
        let info = McpServerInfo::default();
        assert_eq!(info.name(), "fwc");
        assert_eq!(info.protocol_version(), "2024-11-05");
        assert!(!info.version().is_empty());
    }

    #[test]
    fn server_info_serde_roundtrip() {
        let info = McpServerInfo::default();
        let json = serde_json::to_string(&info).unwrap();
        let back: McpServerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name(), info.name());
        assert_eq!(back.protocol_version(), info.protocol_version());
    }

    // ── Tool Definition ─────────────────────────────────────────────

    #[test]
    fn tool_definition_accessors() {
        let t = sample_tool();
        assert_eq!(t.name(), "github.list_issues");
        assert_eq!(t.connector_id(), "github");
        assert_eq!(t.operation_id(), "list_issues");
    }

    #[test]
    fn tool_definition_serde_roundtrip() {
        let t = sample_tool();
        let json = serde_json::to_string(&t).unwrap();
        let back: McpToolDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, t.name);
        assert_eq!(back.connector_id, t.connector_id);
    }

    #[test]
    fn tool_definition_input_schema_key_name() {
        let t = sample_tool();
        let val = serde_json::to_value(&t).unwrap();
        assert!(val.get("inputSchema").is_some());
        assert!(val.get("input_schema").is_none());
    }

    // ── Resource Entry ──────────────────────────────────────────────

    #[test]
    fn resource_entry_accessors() {
        let r = sample_resource();
        assert_eq!(r.uri(), "resource://connector/github/health");
        assert_eq!(r.name(), "GitHub Health");
    }

    #[test]
    fn resource_entry_serde_roundtrip() {
        let r = sample_resource();
        let json = serde_json::to_string(&r).unwrap();
        let back: McpResourceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uri, r.uri);
    }

    #[test]
    fn resource_entry_mime_type_key_name() {
        let r = sample_resource();
        let val = serde_json::to_value(&r).unwrap();
        assert!(val.get("mimeType").is_some());
        assert!(val.get("mime_type").is_none());
    }

    // ── Prompt Entry ────────────────────────────────────────────────

    #[test]
    fn prompt_entry_accessors() {
        let p = sample_prompt();
        assert_eq!(p.name(), "how-to-use-github");
        assert_eq!(p.arguments.len(), 2);
    }

    #[test]
    fn prompt_entry_serde_roundtrip() {
        let p = sample_prompt();
        let json = serde_json::to_string(&p).unwrap();
        let back: McpPromptEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, p.name);
        assert_eq!(back.arguments.len(), 2);
    }

    #[test]
    fn prompt_arg_required() {
        let a = PromptArgDef::required("task", "what to do");
        assert!(a.required);
        assert_eq!(a.name, "task");
    }

    #[test]
    fn prompt_arg_optional() {
        let a = PromptArgDef::optional("style", "output style");
        assert!(!a.required);
        assert_eq!(a.name, "style");
    }

    // ── Discovered Operation Stub ───────────────────────────────────

    #[test]
    fn operation_stub_tool_name() {
        let stub = DiscoveredOperationStub::new(
            "github",
            "list_issues",
            "List issues",
            json!({"type": "object"}),
        );
        assert_eq!(stub.tool_name(), "github.list_issues");
    }

    #[test]
    fn operation_stub_serde_roundtrip() {
        let stub = DiscoveredOperationStub::new(
            "slack",
            "send_message",
            "Send a message",
            json!({"type": "object"}),
        );
        let json = serde_json::to_string(&stub).unwrap();
        let back: DiscoveredOperationStub = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, "slack");
        assert_eq!(back.operation_id, "send_message");
    }

    // ── from_operations ─────────────────────────────────────────────

    #[test]
    fn from_operations_empty() {
        let state = from_operations(&[]);
        assert_eq!(state.tool_count(), 0);
    }

    #[test]
    fn from_operations_single() {
        let ops = vec![DiscoveredOperationStub::new(
            "github",
            "list_issues",
            "List issues",
            json!({"type": "object"}),
        )];
        let state = from_operations(&ops);
        assert_eq!(state.tool_count(), 1);
        let tool = &state.tools[0];
        assert_eq!(tool.name, "github.list_issues");
        assert_eq!(tool.connector_id, "github");
        assert_eq!(tool.operation_id, "list_issues");
    }

    #[test]
    fn from_operations_multiple() {
        let ops = vec![
            DiscoveredOperationStub::new("a", "op1", "desc1", json!({})),
            DiscoveredOperationStub::new("a", "op2", "desc2", json!({})),
            DiscoveredOperationStub::new("b", "op3", "desc3", json!({})),
        ];
        let state = from_operations(&ops);
        assert_eq!(state.tool_count(), 3);
    }

    #[test]
    fn from_operations_preserves_input_schema() {
        let schema = json!({"type": "object", "required": ["x"]});
        let ops = vec![DiscoveredOperationStub::new(
            "c",
            "op",
            "desc",
            schema.clone(),
        )];
        let state = from_operations(&ops);
        assert_eq!(state.tools[0].input_schema, schema);
    }

    // ── Builder API ─────────────────────────────────────────────────

    #[test]
    fn builder_default_state() {
        let state = McpServerState::builder().build();
        assert_eq!(state.tool_count(), 0);
        assert_eq!(state.resource_count(), 0);
        assert_eq!(state.prompt_count(), 0);
        assert_eq!(state.server_info.name(), "fwc");
    }

    #[test]
    fn builder_with_config() {
        let config = McpServerConfig::new().with_zone_filter("dev");
        let state = McpServerState::builder().with_config(config).build();
        assert_eq!(state.config.zone_filter.as_deref(), Some("dev"));
    }

    #[test]
    fn builder_with_server_info() {
        let info = McpServerInfo {
            name: "custom".to_string(),
            version: "1.2.3".to_string(),
            protocol_version: "2024-11-05".to_string(),
        };
        let state = McpServerState::builder().with_server_info(info).build();
        assert_eq!(state.server_info.name(), "custom");
        assert_eq!(state.server_info.version(), "1.2.3");
    }

    #[test]
    fn builder_with_tool() {
        let state = McpServerState::builder().with_tool(sample_tool()).build();
        assert_eq!(state.tool_count(), 1);
    }

    #[test]
    fn builder_with_resource() {
        let state = McpServerState::builder()
            .with_resource(sample_resource())
            .build();
        assert_eq!(state.resource_count(), 1);
    }

    #[test]
    fn builder_with_prompt() {
        let state = McpServerState::builder()
            .with_prompt(sample_prompt())
            .build();
        assert_eq!(state.prompt_count(), 1);
    }

    #[test]
    fn builder_chained() {
        let state = McpServerState::builder()
            .with_tool(sample_tool())
            .with_resource(sample_resource())
            .with_prompt(sample_prompt())
            .build();
        assert_eq!(state.tool_count(), 1);
        assert_eq!(state.resource_count(), 1);
        assert_eq!(state.prompt_count(), 1);
    }

    // ── State Lookups ───────────────────────────────────────────────

    #[test]
    fn find_tool_by_name() {
        let state = sample_state();
        assert!(state.find_tool("github.list_issues").is_some());
    }

    #[test]
    fn find_tool_missing() {
        let state = sample_state();
        assert!(state.find_tool("nonexistent").is_none());
    }

    #[test]
    fn find_resource_by_uri() {
        let state = sample_state();
        assert!(
            state
                .find_resource("resource://connector/github/health")
                .is_some()
        );
    }

    #[test]
    fn find_resource_missing() {
        let state = sample_state();
        assert!(state.find_resource("resource://missing").is_none());
    }

    #[test]
    fn find_prompt_by_name() {
        let state = sample_state();
        assert!(state.find_prompt("how-to-use-github").is_some());
    }

    #[test]
    fn find_prompt_missing() {
        let state = sample_state();
        assert!(state.find_prompt("nonexistent").is_none());
    }

    #[test]
    fn tools_for_connector() {
        let state = McpServerState::builder()
            .with_tool(McpToolDefinition::new(
                "github.list_issues",
                "d1",
                json!({}),
                "github",
                "list_issues",
            ))
            .with_tool(McpToolDefinition::new(
                "github.create_issue",
                "d2",
                json!({}),
                "github",
                "create_issue",
            ))
            .with_tool(McpToolDefinition::new(
                "slack.send",
                "d3",
                json!({}),
                "slack",
                "send",
            ))
            .build();
        assert_eq!(state.tools_for_connector("github").len(), 2);
        assert_eq!(state.tools_for_connector("slack").len(), 1);
        assert_eq!(state.tools_for_connector("missing").len(), 0);
    }

    // ── handle_request: initialize ──────────────────────────────────

    #[test]
    fn handle_initialize_returns_capabilities() {
        let state = sample_state();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["serverInfo"]["name"].is_string());
    }

    #[test]
    fn handle_initialize_includes_resources_capability() {
        let state = sample_state();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        assert!(result["capabilities"]["resources"].is_object());
    }

    #[test]
    fn handle_initialize_includes_prompts_capability() {
        let state = sample_state();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        assert!(result["capabilities"]["prompts"].is_object());
    }

    #[test]
    fn handle_initialize_omits_resources_when_disabled() {
        let config = McpServerConfig::new().without_resources();
        let state = McpServerState::builder().with_config(config).build();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        assert!(result["capabilities"].get("resources").is_none());
    }

    #[test]
    fn handle_initialize_omits_prompts_when_disabled() {
        let config = McpServerConfig::new().without_prompts();
        let state = McpServerState::builder().with_config(config).build();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        assert!(result["capabilities"].get("prompts").is_none());
    }

    #[test]
    fn handle_initialize_omits_resources_when_empty() {
        let state = McpServerState::builder().build();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        // No resources registered, so no resources capability.
        assert!(result["capabilities"].get("resources").is_none());
    }

    #[test]
    fn handle_initialize_server_info() {
        let state = sample_state();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        assert_eq!(result["serverInfo"]["name"], "fwc");
    }

    // ── handle_request: notifications/initialized ───────────────────

    #[test]
    fn handle_initialized_notification_is_ok() {
        let state = sample_state();
        let req = make_request("notifications/initialized", None);
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
    }

    // ── handle_request: tools/list ──────────────────────────────────

    #[test]
    fn handle_tools_list() {
        let state = sample_state();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "github.list_issues");
    }

    #[test]
    fn handle_tools_list_empty() {
        let state = McpServerState::builder().build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn handle_tools_list_includes_schema() {
        let state = sample_state();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let tool = &result["tools"][0];
        assert!(tool["inputSchema"]["properties"]["owner"].is_object());
    }

    // ── handle_request: tools/call ──────────────────────────────────

    #[test]
    fn handle_tools_call_success() {
        let state = sample_state();
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "github.list_issues",
                "arguments": {"owner": "acme", "repo": "widgets"}
            })),
        );
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("invocation would go here"));
        assert!(text.contains("github"));
        assert!(text.contains("list_issues"));
    }

    #[test]
    fn handle_tools_call_includes_arguments_in_stub() {
        let state = sample_state();
        let req = make_request(
            "tools/call",
            Some(json!({"name": "github.list_issues", "arguments": {"owner": "x"}})),
        );
        let resp = handle_request(&state, &req);
        let text = resp.result().unwrap()["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("owner"));
    }

    #[test]
    fn handle_tools_call_missing_params() {
        let state = sample_state();
        let req = make_request("tools/call", None);
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_PARAMS);
    }

    #[test]
    fn handle_tools_call_missing_name() {
        let state = sample_state();
        let req = make_request("tools/call", Some(json!({})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_PARAMS);
    }

    #[test]
    fn handle_tools_call_unknown_tool() {
        let state = sample_state();
        let req = make_request("tools/call", Some(json!({"name": "nonexistent.tool"})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code(), INVALID_PARAMS);
        assert!(err.message().contains("Tool not found"));
    }

    #[test]
    fn handle_tools_call_no_arguments() {
        let state = sample_state();
        let req = make_request("tools/call", Some(json!({"name": "github.list_issues"})));
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
    }

    // ── handle_request: resources/list ──────────────────────────────

    #[test]
    fn handle_resources_list() {
        let state = sample_state();
        let req = make_request("resources/list", None);
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], "resource://connector/github/health");
    }

    #[test]
    fn handle_resources_list_empty_when_disabled() {
        let config = McpServerConfig::new().without_resources();
        let state = McpServerState::builder()
            .with_config(config)
            .with_resource(sample_resource())
            .build();
        let req = make_request("resources/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert!(resources.is_empty());
    }

    // ── handle_request: resources/read ──────────────────────────────

    #[test]
    fn handle_resources_read_success() {
        let state = sample_state();
        let req = make_request(
            "resources/read",
            Some(json!({"uri": "resource://connector/github/health"})),
        );
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["mimeType"], "application/json");
    }

    #[test]
    fn handle_resources_read_missing_params() {
        let state = sample_state();
        let req = make_request("resources/read", None);
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_PARAMS);
    }

    #[test]
    fn handle_resources_read_missing_uri() {
        let state = sample_state();
        let req = make_request("resources/read", Some(json!({})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
    }

    #[test]
    fn handle_resources_read_not_found() {
        let state = sample_state();
        let req = make_request("resources/read", Some(json!({"uri": "resource://missing"})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert!(
            resp.error
                .as_ref()
                .unwrap()
                .message()
                .contains("Resource not found")
        );
    }

    #[test]
    fn handle_resources_read_disabled() {
        let config = McpServerConfig::new().without_resources();
        let state = McpServerState::builder()
            .with_config(config)
            .with_resource(sample_resource())
            .build();
        let req = make_request(
            "resources/read",
            Some(json!({"uri": "resource://connector/github/health"})),
        );
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert!(resp.error.as_ref().unwrap().message().contains("disabled"));
    }

    // ── handle_request: prompts/list ────────────────────────────────

    #[test]
    fn handle_prompts_list() {
        let state = sample_state();
        let req = make_request("prompts/list", None);
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let prompts = result["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0]["name"], "how-to-use-github");
    }

    #[test]
    fn handle_prompts_list_includes_arguments() {
        let state = sample_state();
        let req = make_request("prompts/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let args = result["prompts"][0]["arguments"].as_array().unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0]["name"], "task");
        assert!(args[0]["required"].as_bool().unwrap());
        assert_eq!(args[1]["name"], "style");
        assert!(!args[1]["required"].as_bool().unwrap());
    }

    #[test]
    fn handle_prompts_list_empty_when_disabled() {
        let config = McpServerConfig::new().without_prompts();
        let state = McpServerState::builder()
            .with_config(config)
            .with_prompt(sample_prompt())
            .build();
        let req = make_request("prompts/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let prompts = result["prompts"].as_array().unwrap();
        assert!(prompts.is_empty());
    }

    // ── handle_request: prompts/get ─────────────────────────────────

    #[test]
    fn handle_prompts_get_success() {
        let state = sample_state();
        let req = make_request("prompts/get", Some(json!({"name": "how-to-use-github"})));
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        assert!(result["messages"].is_array());
        assert_eq!(result["messages"][0]["role"], "user");
    }

    #[test]
    fn handle_prompts_get_missing_params() {
        let state = sample_state();
        let req = make_request("prompts/get", None);
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_PARAMS);
    }

    #[test]
    fn handle_prompts_get_missing_name() {
        let state = sample_state();
        let req = make_request("prompts/get", Some(json!({})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
    }

    #[test]
    fn handle_prompts_get_not_found() {
        let state = sample_state();
        let req = make_request("prompts/get", Some(json!({"name": "nonexistent"})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert!(
            resp.error
                .as_ref()
                .unwrap()
                .message()
                .contains("Prompt not found")
        );
    }

    #[test]
    fn handle_prompts_get_disabled() {
        let config = McpServerConfig::new().without_prompts();
        let state = McpServerState::builder()
            .with_config(config)
            .with_prompt(sample_prompt())
            .build();
        let req = make_request("prompts/get", Some(json!({"name": "how-to-use-github"})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert!(resp.error.as_ref().unwrap().message().contains("disabled"));
    }

    // ── handle_request: unknown method ──────────────────────────────

    #[test]
    fn handle_unknown_method() {
        let state = sample_state();
        let req = make_request("bogus/method", None);
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code(), METHOD_NOT_FOUND);
        assert!(err.message().contains("bogus/method"));
    }

    #[test]
    fn handle_empty_method() {
        let state = sample_state();
        let req = make_request("", None);
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), METHOD_NOT_FOUND);
    }

    // ── handle_raw ──────────────────────────────────────────────────

    #[test]
    fn handle_raw_valid_request() {
        let state = sample_state();
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let resp = handle_raw(&state, raw);
        assert!(!resp.is_error());
    }

    #[test]
    fn handle_raw_invalid_json() {
        let state = sample_state();
        let resp = handle_raw(&state, "not valid json");
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), PARSE_ERROR);
    }

    #[test]
    fn handle_raw_missing_method() {
        let state = sample_state();
        let raw = r#"{"jsonrpc":"2.0","id":1}"#;
        let resp = handle_raw(&state, raw);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), PARSE_ERROR);
    }

    // ── Request ID propagation ──────────────────────────────────────

    #[test]
    fn response_preserves_numeric_id() {
        let state = sample_state();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        assert_eq!(resp.id, json!(1));
    }

    #[test]
    fn response_preserves_string_id() {
        let state = sample_state();
        let mut req = make_request("tools/list", None);
        req.id = Some(json!("abc-123"));
        let resp = handle_request(&state, &req);
        assert_eq!(resp.id, json!("abc-123"));
    }

    #[test]
    fn response_null_id_for_notification() {
        let state = sample_state();
        let mut req = make_request("notifications/initialized", None);
        req.id = None;
        let resp = handle_request(&state, &req);
        assert_eq!(resp.id, Value::Null);
    }

    // ── McpServerState default ──────────────────────────────────────

    #[test]
    fn server_state_default_is_empty() {
        let state = McpServerState::default();
        assert_eq!(state.tool_count(), 0);
        assert_eq!(state.resource_count(), 0);
        assert_eq!(state.prompt_count(), 0);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn tools_call_with_null_arguments() {
        let state = sample_state();
        let req = make_request(
            "tools/call",
            Some(json!({"name": "github.list_issues", "arguments": null})),
        );
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
    }

    #[test]
    fn multiple_tools_in_list() {
        let state = McpServerState::builder()
            .with_tool(McpToolDefinition::new("a.op1", "d1", json!({}), "a", "op1"))
            .with_tool(McpToolDefinition::new("b.op2", "d2", json!({}), "b", "op2"))
            .build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let tools = resp.result().unwrap()["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn multiple_resources_in_list() {
        let state = McpServerState::builder()
            .with_resource(McpResourceEntry::new(
                "resource://a",
                "A",
                "desc a",
                "application/json",
            ))
            .with_resource(McpResourceEntry::new(
                "resource://b",
                "B",
                "desc b",
                "text/plain",
            ))
            .build();
        let req = make_request("resources/list", None);
        let resp = handle_request(&state, &req);
        let resources = resp.result().unwrap()["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 2);
    }

    #[test]
    fn multiple_prompts_in_list() {
        let state = McpServerState::builder()
            .with_prompt(McpPromptEntry::new("p1", "prompt 1"))
            .with_prompt(McpPromptEntry::new("p2", "prompt 2"))
            .build();
        let req = make_request("prompts/list", None);
        let resp = handle_request(&state, &req);
        let prompts = resp.result().unwrap()["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 2);
    }

    #[test]
    fn response_jsonrpc_version() {
        let state = sample_state();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        assert_eq!(resp.jsonrpc, "2.0");
    }

    #[test]
    fn error_response_jsonrpc_version() {
        let state = sample_state();
        let req = make_request("bogus", None);
        let resp = handle_request(&state, &req);
        assert_eq!(resp.jsonrpc, "2.0");
    }

    #[test]
    fn handle_raw_with_params() {
        let state = sample_state();
        let raw = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"github.list_issues","arguments":{"owner":"x"}}}"#;
        let resp = handle_raw(&state, raw);
        assert!(!resp.is_error());
        assert_eq!(resp.id, json!(5));
    }
}
