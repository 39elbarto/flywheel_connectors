//! FCP MCP Bridge Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{McpAuth, McpClient},
    error::McpBridgeError,
};

/// Parsed and validated MCP Bridge connector configuration.
#[derive(Debug, Clone)]
struct McpBridgeConfig {
    mcp_url: String,
    auth: McpAuth,
}

impl McpBridgeConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let mcp_url = params
            .get("mcp_url")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty mcp_url in configuration".into(),
            })?
            .to_string();

        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        Ok(Self {
            mcp_url,
            auth: McpAuth { api_key },
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.mcp_url);

        ProvisioningReadiness {
            auth_mode: if self.auth.api_key.is_some() {
                "api_key"
            } else {
                "none"
            },
            token_configured: self.auth.api_key.is_some(),
            network_ok,
            network_message,
            mcp_url: self.mcp_url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    token_configured: bool,
    network_ok: bool,
    network_message: String,
    mcp_url: String,
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP MCP Bridge Connector.
pub struct McpBridgeConnector {
    base: Arc<BaseConnector>,
    config: Option<McpBridgeConfig>,
    client: Option<Arc<McpClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl McpBridgeConnector {
    /// Create a new MCP Bridge connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("mcp-bridge"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for McpBridgeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl McpBridgeConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = McpBridgeConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), mcp_url = %config.mcp_url, "Configuring MCP Bridge connector");

        let client =
            McpClient::new(config.auth.clone(), &config.mcp_url).map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        let session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.mcp-bridge",
            "connector_version": "0.1.0",
            "capabilities": [
                "mcp.tools.read",
                "mcp.tools.write",
                "mcp.resources.read",
                "mcp.prompts.read"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();

        let status = if configured && handshaken {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured - call configure first".into())
            } else {
                None
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_none() {
                Some("MCP client not initialized".into())
            } else {
                None
            },
            critical: true,
        });

        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: if handshaken {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return Self::serialize_self_check_report(report);
        };

        let readiness = config.provisioning_readiness();
        if !readiness.network_ok {
            let mut report = SelfCheckReport::failed(
                "network_constraints_invalid",
                readiness.network_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let Some(_client) = &self.client else {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "MCP client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = typed_operations_info();
        Ok(json!({
            "connector_id": "fcp.mcp-bridge",
            "version": "0.1.0",
            "operations": serde_json::to_value(&ops).unwrap_or_default(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params
            .get("input")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "mcp.tools.list" => self.invoke_tools_list(client).await,
            "mcp.tools.call" => self.invoke_tools_call(client, &input).await,
            "mcp.resources.list" => self.invoke_resources_list(client).await,
            "mcp.resources.read" => self.invoke_resources_read(client, &input).await,
            "mcp.prompts.list" => self.invoke_prompts_list(client).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|e| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(serde_json::Value::as_str) == Some(operation))
        });

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("MCP Bridge connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_tools_list(
        &self,
        client: &McpClient,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let data = client.tools_list().await?;
        Ok(data)
    }

    async fn invoke_tools_call(
        &self,
        client: &McpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let name = require_str(input, "name")?;
        let arguments = input
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if !arguments.is_object() && !arguments.is_null() {
            return Err(McpBridgeError::McpError {
                code: -32602,
                message: "arguments must be an object".into(),
            });
        }
        let args = if arguments.is_null() {
            json!({})
        } else {
            arguments
        };
        let data = client.tools_call(name, &args).await?;
        Ok(data)
    }

    async fn invoke_resources_list(
        &self,
        client: &McpClient,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let data = client.resources_list().await?;
        Ok(data)
    }

    async fn invoke_resources_read(
        &self,
        client: &McpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let uri = require_str(input, "uri")?;
        let data = client.resources_read(uri).await?;
        Ok(data)
    }

    async fn invoke_prompts_list(
        &self,
        client: &McpClient,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let data = client.prompts_list().await?;
        Ok(data)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "mcp_bridge.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "MCP Bridge self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, McpBridgeError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| McpBridgeError::McpError {
            code: -32602,
            message: format!("Missing required field: {field}"),
        })
}

/// Build typed operations info for introspection.
fn typed_operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("mcp.tools.list"),
            summary: "List available tools from the MCP server".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {}}),
            output_schema: json!({"type": "object", "properties": {"tools": {"type": "array"}}}),
            capability: CapabilityId::from_static("mcp.tools.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to discover what tools are available on the MCP server".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("mcp.tools.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mcp.tools.call"),
            summary: "Call a tool on the MCP server".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "arguments": {"type": "object"},
                },
                "required": ["name", "arguments"],
            }),
            output_schema: json!({"type": "object", "properties": {"content": {"type": "array"}}}),
            capability: CapabilityId::from_static("mcp.tools.write"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use to invoke a specific tool on the MCP server by name".into(),
                common_mistakes: vec![
                    "Not providing the tool name".into(),
                    "Passing non-object arguments".into(),
                ],
                examples: vec![],
                related: vec![CapabilityId::from_static("mcp.tools.write")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Policy),
        },
        OperationInfo {
            id: OperationId::from_static("mcp.resources.list"),
            summary: "List available resources from the MCP server".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {}}),
            output_schema: json!({"type": "object", "properties": {"resources": {"type": "array"}}}),
            capability: CapabilityId::from_static("mcp.resources.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to discover available resources on the MCP server".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("mcp.resources.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mcp.resources.read"),
            summary: "Read a resource by URI from the MCP server".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"uri": {"type": "string"}}, "required": ["uri"]}),
            output_schema: json!({"type": "object", "properties": {"contents": {"type": "array"}}}),
            capability: CapabilityId::from_static("mcp.resources.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to read a specific resource by its URI".into(),
                common_mistakes: vec!["Using an invalid resource URI".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("mcp.resources.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mcp.prompts.list"),
            summary: "List available prompts from the MCP server".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {}}),
            output_schema: json!({"type": "object", "properties": {"prompts": {"type": "array"}}}),
            capability: CapabilityId::from_static("mcp.prompts.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to discover available prompt templates on the MCP server".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("mcp.prompts.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

/// Build the operations info for introspection (JSON format for simulate).
fn operations_info() -> serde_json::Value {
    serde_json::to_value(typed_operations_info()).unwrap_or_default()
}

/// Build the provisioning recipe for the MCP Bridge connector.
///
/// MCP Bridge connects to arbitrary MCP servers, so the recipe prompts
/// for the server URL and an optional auth token.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("mcp-bridge.api_token"),
        "1",
        "Provision MCP Bridge connector with an MCP server URL and optional auth token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_url"),
        ProvisioningStepType::PromptUser {
            message: "Enter the MCP server URL (e.g. https://mcp.example.com)".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_token"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your MCP server auth token (leave empty if none)".into(),
            },
        )
        .depends_on(StepId::new("enter_url")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "api_key".into(),
                value_from: StepId::new("enter_token"),
                scope: "connector:fcp.mcp-bridge".into(),
            },
        )
        .depends_on(StepId::new("enter_token")),
    )
}

/// Validate the MCP server URL.
///
/// MCP Bridge is permissive: any host is valid as long as the URL can be
/// parsed. Both HTTP and HTTPS are accepted because MCP servers may run
/// locally over plain HTTP.
fn base_url_policy(mcp_url: &str) -> (bool, String) {
    let parsed = match Url::parse(mcp_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("mcp_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "mcp_url must include a host".into());
    };

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return (
            false,
            format!("mcp_url must use http or https scheme, got: {scheme}"),
        );
    }

    if host.is_empty() {
        return (false, "mcp_url host must not be empty".into());
    }

    (
        true,
        format!("MCP server endpoint accepted by policy checks: {mcp_url}"),
    )
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_valid_params() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
        }))
        .unwrap();
        assert_eq!(config.mcp_url, "http://localhost:3000");
        assert!(config.auth.api_key.is_none());
    }

    #[test]
    fn config_with_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
            "api_key": "sk-test-key",
        }))
        .unwrap();
        assert_eq!(config.mcp_url, "http://localhost:3000");
        assert_eq!(config.auth.api_key, Some("sk-test-key".into()));
    }

    #[test]
    fn config_rejects_missing_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_params() {
        let result = McpBridgeConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_mcp_url() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "  http://localhost:3000  ",
        }))
        .unwrap();
        assert_eq!(config.mcp_url, "http://localhost:3000");
    }

    #[test]
    fn config_ignores_empty_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
            "api_key": "",
        }))
        .unwrap();
        assert!(config.auth.api_key.is_none());
    }

    #[test]
    fn config_ignores_whitespace_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
            "api_key": "   ",
        }))
        .unwrap();
        assert!(config.auth.api_key.is_none());
    }

    #[test]
    fn config_trims_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
            "api_key": "  sk-key  ",
        }))
        .unwrap();
        assert_eq!(config.auth.api_key, Some("sk-key".into()));
    }

    #[test]
    fn require_str_present() {
        let input = json!({"name": "read_file"});
        assert_eq!(require_str(&input, "name").unwrap(), "read_file");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"name": 42});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"name": null});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"name": true});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"name": ["a", "b"]});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 5);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(op.get("id").is_some(), "missing id");
            assert!(op.get("summary").is_some(), "missing summary");
            assert!(op.get("capability").is_some(), "missing capability");
            assert!(op.get("risk_level").is_some(), "missing risk_level");
            assert!(op.get("safety_tier").is_some(), "missing safety_tier");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "read op {} should be low risk",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"mcp.tools.list"));
        assert!(ids.contains(&"mcp.tools.call"));
        assert!(ids.contains(&"mcp.resources.list"));
        assert!(ids.contains(&"mcp.resources.read"));
        assert!(ids.contains(&"mcp.prompts.list"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_tools_call_is_risky() {
        let ops = operations_info();
        let call_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.call")
            .unwrap();
        assert_eq!(call_op["safety_tier"], "risky");
        assert_eq!(call_op["risk_level"], "high");
    }

    #[test]
    fn operations_tools_list_capability() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.list")
            .unwrap();
        assert_eq!(list_op["capability"], "mcp.tools.read");
    }

    #[test]
    fn operations_tools_call_has_no_idempotency() {
        let ops = operations_info();
        let call_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.call")
            .unwrap();
        assert_eq!(call_op["idempotency"], "none");
    }

    #[test]
    fn operations_tools_call_requires_policy_approval() {
        let ops = operations_info();
        let call_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.call")
            .unwrap();
        assert_eq!(call_op["requires_approval"], "policy");
    }

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_when_non_critical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail a".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail b".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn connector_default() {
        let c = McpBridgeConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = McpBridgeConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_new_zero_counters() {
        let c = McpBridgeConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_status_serde_roundtrip_healthy() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_serde_roundtrip_degraded() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_serde_roundtrip_unhealthy() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Healthy;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Degraded);
        assert!(dbg.contains("Degraded"));
    }

    #[test]
    fn doctor_result_deserializes() {
        let v = json!({
            "status": "unhealthy",
            "checks": [
                {"name": "config", "passed": false, "message": "fail", "critical": true}
            ]
        });
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn doctor_check_deserializes() {
        let v = json!({"name": "test", "passed": true, "critical": false});
        let c: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c.name, "test");
        assert!(c.passed);
        assert!(c.message.is_none());
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let cloned = DoctorCheck::clone(&c);
        assert_eq!(cloned.name, "cfg");
        assert_eq!(cloned.message, Some("ok".into()));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = DoctorResult::clone(&r);
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"name": ""});
        assert_eq!(require_str(&input, "name").unwrap(), "");
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"name": {"nested": true}});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_resources_read_capability() {
        let ops = operations_info();
        let r_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.resources.read")
            .unwrap();
        assert_eq!(r_op["capability"], "mcp.resources.read");
    }

    #[test]
    fn operations_prompts_list_capability() {
        let ops = operations_info();
        let p_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.prompts.list")
            .unwrap();
        assert_eq!(p_op["capability"], "mcp.prompts.read");
    }

    #[test]
    fn doctor_check_serializes_without_message_when_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_serializes_with_message_when_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failed");
    }

    #[test]
    fn config_rejects_boolean_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({ "mcp_url": true }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_array_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({ "mcp_url": [1, 2, 3] }));
        assert!(result.is_err());
    }

    // -- Provisioning recipe tests -----------------------------------------------

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "mcp-bridge.api_token");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_url");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_token");
        assert_eq!(recipe.steps[2].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_url");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_token");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "mcp-bridge.api_token");
        assert_eq!(v["steps"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn provisioning_recipe_description_non_empty() {
        let recipe = provisioning_recipe();
        assert!(!recipe.description.is_empty());
    }

    #[test]
    fn provisioning_recipe_step1_is_prompt_user() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            recipe.steps[0].kind,
            ProvisioningStepType::PromptUser { .. }
        ));
    }

    #[test]
    fn provisioning_recipe_step2_is_prompt_secret() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            recipe.steps[1].kind,
            ProvisioningStepType::PromptSecret { .. }
        ));
    }

    #[test]
    fn provisioning_recipe_step3_is_store_secret() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            recipe.steps[2].kind,
            ProvisioningStepType::StoreSecret { .. }
        ));
    }

    #[test]
    fn provisioning_recipe_store_secret_scope() {
        let recipe = provisioning_recipe();
        if let ProvisioningStepType::StoreSecret { scope, key, .. } = &recipe.steps[2].kind {
            assert_eq!(scope, "connector:fcp.mcp-bridge");
            assert_eq!(key, "api_key");
        } else {
            panic!("expected StoreSecret step");
        }
    }

    #[test]
    fn provisioning_recipe_store_secret_value_from() {
        let recipe = provisioning_recipe();
        if let ProvisioningStepType::StoreSecret { value_from, .. } = &recipe.steps[2].kind {
            assert_eq!(value_from.as_str(), "enter_token");
        } else {
            panic!("expected StoreSecret step");
        }
    }

    #[test]
    fn provisioning_recipe_no_approval_required() {
        let recipe = provisioning_recipe();
        for step in &recipe.steps {
            assert!(!step.requires_approval);
        }
    }

    // -- base_url_policy tests ---------------------------------------------------

    #[test]
    fn base_url_policy_accepts_https() {
        let (ok, message) = base_url_policy("https://mcp.example.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_http() {
        let (ok, message) = base_url_policy("http://mcp.example.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:3000");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9090");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_any_host() {
        let (ok, _) = base_url_policy("https://any-host.example.org:8443/v1");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_rejects_ftp_scheme() {
        let (ok, message) = base_url_policy("ftp://files.example.com/data");
        assert!(!ok);
        assert!(message.contains("http or https"));
    }

    #[test]
    fn base_url_policy_rejects_empty() {
        let (ok, _) = base_url_policy("");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_accepts_ipv6() {
        let (ok, _) = base_url_policy("http://[::1]:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_https_with_path() {
        let (ok, _) = base_url_policy("https://mcp.example.com/api/v2");
        assert!(ok);
    }

    // -- ProvisioningReadiness tests ---------------------------------------------

    #[test]
    fn provisioning_readiness_with_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
            "api_key": "test-key",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_key");
        assert!(readiness.token_configured);
        assert!(readiness.network_ok);
        assert_eq!(readiness.mcp_url, "http://localhost:3000");
    }

    #[test]
    fn provisioning_readiness_without_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "http://localhost:3000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "none");
        assert!(!readiness.token_configured);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "https://mcp.example.com",
            "api_key": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_key");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
        assert_eq!(v["mcp_url"], "https://mcp.example.com");
    }

    #[test]
    fn provisioning_readiness_network_message_contains_accepted() {
        let config = McpBridgeConfig::from_params(&json!({
            "mcp_url": "https://mcp.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_message.contains("accepted"));
    }

    // -- is_local_test_host tests ------------------------------------------------

    #[test]
    fn is_local_test_host_localhost() {
        assert!(is_local_test_host("localhost"));
    }

    #[test]
    fn is_local_test_host_127_0_0_1() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_ipv6_loopback() {
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_rejects_remote() {
        assert!(!is_local_test_host("mcp.example.com"));
    }
}
