//! FCP n8n Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{N8nAuth, N8nClient},
    error::N8nError,
};

/// Parsed and validated n8n connector configuration.
#[derive(Debug, Clone)]
struct N8nConfig {
    auth: N8nAuth,
    base_url: String,
}

impl N8nConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "credential_id must be a string".into(),
                })?;
                Some(
                    CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?,
                )
            }
            None => None,
        };

        let auth = match (api_key, credential_id) {
            (Some(key), None) => N8nAuth::ApiKey(key),
            (None, Some(cred_id)) => N8nAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        // n8n is self-hosted, so base_url is REQUIRED.
        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required base_url (n8n is self-hosted)".into(),
            })?
            .to_string();

        Ok(Self { auth, base_url })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                N8nAuth::ApiKey(_) => "api_key",
                N8nAuth::CredentialId(_) => "credential_id",
            },
            api_key_configured: matches!(&self.auth, N8nAuth::ApiKey(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    api_key_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    base_url: String,
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

/// FCP n8n Connector.
pub struct N8nConnector {
    base: Arc<BaseConnector>,
    config: Option<N8nConfig>,
    client: Option<Arc<N8nClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl N8nConnector {
    /// Create a new n8n connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("n8n"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for N8nConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl N8nConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = N8nConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring n8n connector");

        let client =
            N8nClient::new(config.auth.clone(), &config.base_url).map_err(|e| e.to_fcp_error())?;

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
            "connector_id": "fcp.n8n",
            "connector_version": "0.1.0",
            "capabilities": [
                "n8n.workflows.read",
                "n8n.workflows.write",
                "n8n.executions.read"
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
                Some("API client not initialized".into())
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
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        if readiness.requires_credential_injection {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires egress proxy injection; skipping live probe",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = serde_json::to_value(operations_info()).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize operations: {e}"),
        })?;
        Ok(json!({
            "connector_id": "fcp.n8n",
            "version": "0.1.0",
            "operations": ops,
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

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "n8n.workflows.list" => self.invoke_workflows_list(client).await,
            "n8n.workflows.get" => self.invoke_workflows_get(client, &input).await,
            "n8n.workflows.activate" => self.invoke_workflows_activate(client, &input).await,
            "n8n.executions.list" => self.invoke_executions_list(client).await,
            "n8n.executions.get" => self.invoke_executions_get(client, &input).await,
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

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

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
        info!("n8n connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "n8n.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "n8n self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // -- Operation implementations --

    async fn invoke_workflows_list(
        &self,
        client: &N8nClient,
    ) -> Result<serde_json::Value, N8nError> {
        let resp = client.list_workflows().await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "data": data }))
    }

    async fn invoke_workflows_get(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, N8nError> {
        let id = require_str(input, "id")?;
        client.get_workflow(id).await
    }

    async fn invoke_workflows_activate(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, N8nError> {
        let id = require_str(input, "id")?;
        let active = input
            .get("active")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| N8nError::Api {
                status_code: 400,
                message: "Missing required field: active (boolean)".into(),
            })?;
        client.activate_workflow(id, active).await
    }

    async fn invoke_executions_list(
        &self,
        client: &N8nClient,
    ) -> Result<serde_json::Value, N8nError> {
        let resp = client.list_executions().await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "data": data }))
    }

    async fn invoke_executions_get(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, N8nError> {
        let id = require_str(input, "id")?;
        client.get_execution(id).await
    }
}

/// Build the provisioning recipe for the `n8n` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("n8n.api_key"),
        "1",
        "Provision n8n connector with an API key",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_instance_url"),
        ProvisioningStepType::PromptUser {
            message: "Enter your n8n instance URL (e.g. https://n8n.example.com/api/v1)".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_api_key"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your n8n API key".into(),
            },
        )
        .depends_on(StepId::new("enter_instance_url")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_key".into(),
                value_from: StepId::new("enter_api_key"),
                scope: "connector:fcp.n8n".into(),
            },
        )
        .depends_on(StepId::new("enter_api_key")),
    )
}

/// Validate the base URL against the `n8n` connector policy.
///
/// `n8n` is self-hosted, so any hostname is accepted as long as HTTPS is used
/// for non-local endpoints.
fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("base_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    let local = is_local_test_host(host);
    let secure_or_local = parsed.scheme() == "https" || local;

    if secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use HTTPS for non-local hosts (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, N8nError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| N8nError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build a single [`OperationInfo`].
#[allow(clippy::fn_params_excessive_bools)]
#[allow(clippy::too_many_arguments)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "n8n.workflows.list",
            "List all workflows in the n8n instance",
            json!({"type": "object", "required": [], "properties": {}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "array"}}}),
            "n8n.workflows.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all workflows in the n8n instance.".into(),
                common_mistakes: vec![
                    "Assuming only active workflows are returned — inactive workflows are included in the list.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("n8n.workflows.get"),
                    CapabilityId::from_static("n8n.workflows.activate"),
                ],
            },
        ),
        op_info(
            "n8n.workflows.get",
            "Get a specific workflow by ID",
            json!({"type": "object", "required": ["id"], "properties": {"id": {"type": "string", "description": "Workflow identifier"}}}),
            json!({"type": "object", "required": ["id", "name"], "properties": {"id": {"type": "string"}, "name": {"type": "string"}}}),
            "n8n.workflows.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve details of a specific n8n workflow by ID.".into(),
                common_mistakes: vec![
                    "Using the workflow name or slug instead of the numeric workflow ID.".into(),
                ],
                examples: vec![r#"{"id": "1001"}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.workflows.list"),
                    CapabilityId::from_static("n8n.workflows.activate"),
                ],
            },
        ),
        op_info(
            "n8n.workflows.activate",
            "Activate or deactivate an n8n workflow",
            json!({"type": "object", "required": ["id", "active"], "properties": {"id": {"type": "string", "description": "Workflow identifier"}, "active": {"type": "boolean", "description": "Whether to activate (true) or deactivate (false)"}}}),
            json!({"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}),
            "n8n.workflows.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Activate or deactivate an n8n workflow.".into(),
                common_mistakes: vec![
                    "Activating a workflow that has webhook or cron triggers without verifying its trigger configuration first.".into(),
                    "Passing the workflow name instead of the numeric workflow ID.".into(),
                ],
                examples: vec![r#"{"id": "1001", "active": true}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.workflows.get"),
                    CapabilityId::from_static("n8n.workflows.list"),
                ],
            },
        ),
        op_info(
            "n8n.executions.list",
            "List recent workflow executions",
            json!({"type": "object", "required": [], "properties": {}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "array"}}}),
            "n8n.executions.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List recent workflow executions in n8n.".into(),
                common_mistakes: vec![
                    "Expecting executions from all workflows — results may be limited to the most recent across the instance.".into(),
                    "Not paginating when the execution history is large.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("n8n.executions.get"),
                    CapabilityId::from_static("n8n.workflows.list"),
                ],
            },
        ),
        op_info(
            "n8n.executions.get",
            "Get details of a specific execution",
            json!({"type": "object", "required": ["id"], "properties": {"id": {"type": "string", "description": "Execution identifier"}}}),
            json!({"type": "object", "required": ["id", "finished"], "properties": {"id": {"type": "string"}, "finished": {"type": "boolean"}}}),
            "n8n.executions.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve details of a specific workflow execution by ID.".into(),
                common_mistakes: vec![
                    "Using the workflow ID instead of the execution ID.".into(),
                    "Querying an execution before it has finished — check the 'finished' field in the response.".into(),
                ],
                examples: vec![r#"{"id": "50001"}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.executions.list"),
                    CapabilityId::from_static("n8n.workflows.get"),
                ],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_api_key() {
        let config = N8nConfig::from_params(&json!({
            "api_key": "test-api-key",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        assert!(matches!(config.auth, N8nAuth::ApiKey(_)));
        assert_eq!(config.base_url, "https://n8n.example.com/api/v1");
    }

    #[test]
    fn config_from_credential_id() {
        let config = N8nConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = N8nConfig::from_params(&json!({
            "api_key": "key",
            "base_url": "http://localhost:5678/api/v1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "http://localhost:5678/api/v1");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = N8nConfig::from_params(&json!({
            "api_key": "key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = N8nConfig::from_params(&json!({
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = N8nConfig::from_params(&json!({
            "api_key": "",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = N8nConfig::from_params(&json!({
            "api_key": "   ",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = N8nConfig::from_params(&json!({
            "credential_id": 12345,
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = N8nConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_base_url() {
        let result = N8nConfig::from_params(&json!({
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_base_url() {
        let result = N8nConfig::from_params(&json!({
            "api_key": "key",
            "base_url": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_base_url() {
        let result = N8nConfig::from_params(&json!({
            "api_key": "key",
            "base_url": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"id": "1001"});
        assert_eq!(require_str(&input, "id").unwrap(), "1001");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"id": 42});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"id": null});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"id": true});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"id": [1, 2, 3]});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.id.as_ref().is_empty(), "missing id");
            assert!(!op.summary.is_empty(), "missing summary");
            assert!(!op.capability.as_ref().is_empty(), "missing capability");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        // All RiskLevel variants are valid by construction with typed enums.
        let ops = operations_info();
        for op in &ops {
            // Just ensure serialization works
            let v = serde_json::to_value(op.risk_level).unwrap();
            let rl = v.as_str().unwrap();
            assert!(
                ["low", "medium", "high", "critical"].contains(&rl),
                "invalid risk_level: {rl}"
            );
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.safety_tier).unwrap();
            let st = v.as_str().unwrap();
            assert!(
                ["safe", "risky", "dangerous"].contains(&st),
                "invalid safety_tier: {st}"
            );
        }
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".read") {
                assert_eq!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "read op {} should be safe",
                    op.id.as_ref()
                );
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "read op {} should be low risk",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        assert!(ids.contains(&"n8n.workflows.list"));
        assert!(ids.contains(&"n8n.workflows.get"));
        assert!(ids.contains(&"n8n.workflows.activate"));
        assert!(ids.contains(&"n8n.executions.list"));
        assert!(ids.contains(&"n8n.executions.get"));
    }

    #[test]
    fn operations_write_ops_are_risky() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".write") {
                assert_ne!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "write op {} should not be safe",
                    op.id.as_ref()
                );
            }
        }
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
    fn config_trims_api_key() {
        let config = N8nConfig::from_params(&json!({
            "api_key": "  key_test  ",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        match &config.auth {
            N8nAuth::ApiKey(k) => assert_eq!(k, "key_test"),
            N8nAuth::CredentialId(_) => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            // Typed struct always has idempotency; verify serialization round-trips
            let v = serde_json::to_value(op.idempotency).unwrap();
            assert!(
                v.is_string(),
                "op {} idempotency should serialize",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = N8nConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn operations_capabilities_match_manifest() {
        let ops = operations_info();
        let expected_caps = [
            ("n8n.workflows.list", "n8n.workflows.read"),
            ("n8n.workflows.get", "n8n.workflows.read"),
            ("n8n.workflows.activate", "n8n.workflows.write"),
            ("n8n.executions.list", "n8n.executions.read"),
            ("n8n.executions.get", "n8n.executions.read"),
        ];
        for (op_id, expected_cap) in &expected_caps {
            let found = ops
                .iter()
                .any(|o| o.id.as_ref() == *op_id && o.capability.as_ref() == *expected_cap);
            assert!(
                found,
                "operation {op_id} should have capability {expected_cap}"
            );
        }
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
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
    fn config_base_url_trimmed() {
        let config = N8nConfig::from_params(&json!({
            "api_key": "key",
            "base_url": "  https://n8n.example.com/api/v1  ",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://n8n.example.com/api/v1");
    }

    #[test]
    fn connector_new_zero_counters() {
        let c = N8nConnector::new();
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
        assert!(!r.checks[0].passed);
    }

    #[test]
    fn doctor_check_deserializes() {
        let v = json!({"name": "test", "passed": true, "critical": false});
        let c: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c.name, "test");
        assert!(c.passed);
        assert!(!c.critical);
        assert!(c.message.is_none());
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "config".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let cloned = DoctorCheck::clone(&c);
        assert_eq!(cloned.name, "config");
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
    fn config_rejects_boolean_base_url() {
        let result = N8nConfig::from_params(&json!({
            "api_key": "key",
            "base_url": true,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_api_key() {
        let result = N8nConfig::from_params(&json!({
            "api_key": null,
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"id": ""});
        // Empty strings are valid string values, require_str just checks type
        assert_eq!(require_str(&input, "id").unwrap(), "");
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"id": {"nested": "value"}});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "op {} has empty summary",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn require_str_with_float_value() {
        let input = json!({"id": 1.23});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn operations_all_capabilities_prefixed() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            assert!(
                cap.starts_with("n8n."),
                "capability {cap} should start with n8n."
            );
        }
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_debug() {
        let c = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("DoctorCheck"));
        assert!(dbg.contains("test_check"));
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_api_key_mode() {
        let config = N8nConfig::from_params(&json!({
            "api_key": "test-key",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_key");
        assert!(readiness.api_key_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, "https://n8n.example.com/api/v1");
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = N8nConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.api_key_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = N8nConfig::from_params(&json!({
            "api_key": "tok",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_key");
        assert_eq!(v["api_key_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_http_non_local_rejected() {
        let config = N8nConfig::from_params(&json!({
            "api_key": "tok",
            "base_url": "http://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("HTTPS"));
    }

    #[test]
    fn provisioning_readiness_localhost_http_accepted() {
        let config = N8nConfig::from_params(&json!({
            "api_key": "tok",
            "base_url": "http://localhost:5678/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "n8n.api_key");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_instance_url");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_api_key");
        assert_eq!(recipe.steps[2].id.as_str(), "store_api_key");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_instance_url");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_api_key");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "n8n.api_key");
        assert!(v["steps"].as_array().unwrap().len() == 3);
    }

    #[test]
    fn provisioning_recipe_first_step_is_prompt_user() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            &recipe.steps[0].kind,
            ProvisioningStepType::PromptUser { message } if message.contains("n8n instance URL")
        ));
    }

    #[test]
    fn provisioning_recipe_second_step_is_prompt_secret() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            &recipe.steps[1].kind,
            ProvisioningStepType::PromptSecret { message } if message.contains("API key")
        ));
    }

    #[test]
    fn provisioning_recipe_third_step_is_store_secret() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            &recipe.steps[2].kind,
            ProvisioningStepType::StoreSecret { key, scope, .. }
                if key == "api_key" && scope == "connector:fcp.n8n"
        ));
    }

    #[test]
    fn base_url_policy_accepts_any_https_host() {
        let (ok, message) = base_url_policy("https://my-n8n.company.io/api/v1");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:5678");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:5678");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, _) = base_url_policy("http://[::1]:5678");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://n8n.example.com/api/v1");
        assert!(!ok);
        assert!(message.contains("HTTPS"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_rejects_missing_host() {
        let (ok, message) = base_url_policy("file:///etc/passwd");
        assert!(!ok);
        assert!(message.contains("must include a host"));
    }

    #[test]
    fn provisioning_readiness_debug() {
        let config = N8nConfig::from_params(&json!({
            "api_key": "tok",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let config = N8nConfig::from_params(&json!({
            "api_key": "tok",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = ProvisioningReadiness::clone(&readiness);
        assert_eq!(cloned.auth_mode, readiness.auth_mode);
        assert_eq!(cloned.network_ok, readiness.network_ok);
        assert_eq!(cloned.base_url, readiness.base_url);
    }

    #[test]
    fn base_url_policy_accepts_https_custom_port() {
        let (ok, _) = base_url_policy("https://n8n.example.com:8443/api/v1");
        assert!(ok);
    }

    #[test]
    fn is_local_test_host_localhost() {
        assert!(is_local_test_host("localhost"));
    }

    #[test]
    fn is_local_test_host_127() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_ipv6() {
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_ipv6_bracketed() {
        assert!(is_local_test_host("[::1]"));
    }

    #[test]
    fn is_local_test_host_rejects_other() {
        assert!(!is_local_test_host("example.com"));
    }
}
