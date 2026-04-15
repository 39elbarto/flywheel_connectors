//! FCP `ClickUp` Connector implementation.

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
    client::{ClickUpAuth, ClickUpClient, DEFAULT_BASE_URL},
    error::ClickUpError,
};

/// Parsed and validated `ClickUp` connector configuration.
#[derive(Debug, Clone)]
struct ClickUpConfig {
    auth: ClickUpAuth,
    base_url: String,
}

impl ClickUpConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_token = params
            .get("api_token")
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

        let auth = match (api_token, credential_id) {
            (Some(key), None) => ClickUpAuth::ApiToken(key),
            (None, Some(cred_id)) => ClickUpAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self { auth, base_url })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);
        ProvisioningReadiness {
            auth_mode: match &self.auth {
                ClickUpAuth::ApiToken(_) => "api_token",
                ClickUpAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(self.auth, ClickUpAuth::ApiToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

/// Provisioning readiness state.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    token_configured: bool,
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

/// FCP `ClickUp` Connector.
pub struct ClickUpConnector {
    base: Arc<BaseConnector>,
    config: Option<ClickUpConfig>,
    client: Option<Arc<ClickUpClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl ClickUpConnector {
    /// Create a new `ClickUp` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("clickup"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for ClickUpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl ClickUpConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = ClickUpConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring ClickUp connector");

        let client = ClickUpClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

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
            "connector_id": "fcp.clickup",
            "connector_version": "0.1.0",
            "capabilities": [
                "clickup.spaces.read",
                "clickup.lists.read",
                "clickup.tasks.read",
                "clickup.tasks.write"
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
                Some("Not configured — call configure first".into())
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
        let ops = typed_operations_info();
        let ops_value = serde_json::to_value(&ops).unwrap_or_else(|_| json!([]));
        Ok(json!({
            "connector_id": "fcp.clickup",
            "version": "0.1.0",
            "operations": ops_value,
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
            "clickup.spaces.list" => self.invoke_spaces_list(client, &input).await,
            "clickup.lists.list" => self.invoke_lists_list(client, &input).await,
            "clickup.tasks.list" => self.invoke_tasks_list(client, &input).await,
            "clickup.tasks.create" => self.invoke_tasks_create(client, &input).await,
            "clickup.tasks.delete" => self.invoke_tasks_delete(client, &input).await,
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
        info!("ClickUp connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_spaces_list(
        &self,
        client: &ClickUpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ClickUpError> {
        let team_id = require_str(input, "team_id")?;
        let resp = client.list_spaces(team_id).await?;
        let spaces = resp.get("spaces").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "spaces": spaces }))
    }

    async fn invoke_lists_list(
        &self,
        client: &ClickUpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ClickUpError> {
        let space_id = require_str(input, "space_id")?;
        let resp = client.list_lists(space_id).await?;
        let lists = resp.get("lists").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "lists": lists }))
    }

    async fn invoke_tasks_list(
        &self,
        client: &ClickUpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ClickUpError> {
        let list_id = require_str(input, "list_id")?;
        let resp = client.list_tasks(list_id).await?;
        let tasks = resp.get("tasks").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "tasks": tasks }))
    }

    async fn invoke_tasks_create(
        &self,
        client: &ClickUpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ClickUpError> {
        let list_id = require_str(input, "list_id")?;
        let name = require_str(input, "name")?;

        let body = json!({
            "name": name,
        });
        client.create_task(list_id, &body).await
    }

    async fn invoke_tasks_delete(
        &self,
        client: &ClickUpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ClickUpError> {
        let task_id = require_str(input, "task_id")?;
        client.delete_task(task_id).await
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "clickup.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "ClickUp self-check completed"
        );
        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Build the provisioning recipe for the `ClickUp` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("clickup.api_token"),
        "1",
        "Provision ClickUp connector with a personal API token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("open_settings"),
        ProvisioningStepType::OpenUrl {
            url: "https://app.clickup.com/settings/apps".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_token"),
            ProvisioningStepType::PromptSecret {
                message:
                    "Generate a personal API token from ClickUp Settings > Apps and paste it here."
                        .into(),
            },
        )
        .depends_on(StepId::new("open_settings")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "api_token".into(),
                value_from: StepId::new("enter_token"),
                scope: "connector:fcp.clickup".into(),
            },
        )
        .depends_on(StepId::new("enter_token")),
    )
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let Ok(parsed) = Url::parse(base_url) else {
        return (false, format!("base_url could not be parsed: {base_url}"));
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url has no host".into());
    };

    if is_local_test_host(host) {
        return (true, format!("local test host accepted: {host}"));
    }

    if parsed.scheme() != "https" {
        return (
            false,
            format!(
                "non-local host {host} must use https, got {}",
                parsed.scheme()
            ),
        );
    }

    if host == "api.clickup.com" {
        return (true, format!("accepted ClickUp API host: {host}"));
    }

    (
        false,
        format!("host {host} is not a known ClickUp endpoint (expected api.clickup.com)"),
    )
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, ClickUpError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ClickUpError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build a single typed `OperationInfo`.
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

/// Build typed operations info for introspection.
fn typed_operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "clickup.spaces.list",
            "List spaces in a workspace",
            json!({"type": "object", "required": ["team_id"], "properties": {"team_id": {"type": "string", "description": "ClickUp team (workspace) identifier"}}}),
            json!({"type": "object", "required": ["spaces"], "properties": {"spaces": {"type": "array"}}}),
            "clickup.spaces.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all spaces in a ClickUp workspace/team.".into(),
                common_mistakes: vec!["Using the workspace name instead of the numeric team_id; retrieve the team_id from the ClickUp workspace settings or API first.".into()],
                examples: vec!["{\"team_id\": \"9012345\"}".into()],
                related: vec![
                    CapabilityId::from_static("clickup.lists.list"),
                    CapabilityId::from_static("clickup.tasks.list"),
                ],
            },
        ),
        op_info(
            "clickup.lists.list",
            "List lists in a space",
            json!({"type": "object", "required": ["space_id"], "properties": {"space_id": {"type": "string", "description": "ClickUp space identifier"}}}),
            json!({"type": "object", "required": ["lists"], "properties": {"lists": {"type": "array"}}}),
            "clickup.lists.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all lists within a ClickUp space.".into(),
                common_mistakes: vec!["Passing a team_id instead of a space_id; lists belong to spaces, not directly to teams.".into()],
                examples: vec!["{\"space_id\": \"12345678\"}".into()],
                related: vec![
                    CapabilityId::from_static("clickup.spaces.list"),
                    CapabilityId::from_static("clickup.tasks.list"),
                ],
            },
        ),
        op_info(
            "clickup.tasks.list",
            "List tasks in a list",
            json!({"type": "object", "required": ["list_id"], "properties": {"list_id": {"type": "string", "description": "ClickUp list identifier"}}}),
            json!({"type": "object", "required": ["tasks"], "properties": {"tasks": {"type": "array"}}}),
            "clickup.tasks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all tasks within a ClickUp list.".into(),
                common_mistakes: vec!["Not accounting for pagination; the API returns a limited page of tasks by default and additional pages must be fetched separately.".into()],
                examples: vec!["{\"list_id\": \"900100200300\"}".into()],
                related: vec![
                    CapabilityId::from_static("clickup.lists.list"),
                    CapabilityId::from_static("clickup.tasks.create"),
                ],
            },
        ),
        op_info(
            "clickup.tasks.create",
            "Create a new task in a list",
            json!({"type": "object", "required": ["list_id", "name"], "properties": {"list_id": {"type": "string", "description": "ClickUp list identifier"}, "name": {"type": "string", "description": "Name of the task to create"}}}),
            json!({"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}),
            "clickup.tasks.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new task in a ClickUp list.".into(),
                common_mistakes: vec!["Omitting the list_id and trying to create a task directly under a space or folder; tasks must be created within a specific list.".into()],
                examples: vec!["{\"list_id\": \"900100200300\", \"name\": \"Implement login page\"}".into()],
                related: vec![
                    CapabilityId::from_static("clickup.tasks.list"),
                    CapabilityId::from_static("clickup.tasks.delete"),
                ],
            },
        ),
        op_info(
            "clickup.tasks.delete",
            "Delete a task",
            json!({"type": "object", "required": ["task_id"], "properties": {"task_id": {"type": "string", "description": "ClickUp task identifier to delete"}}}),
            json!({"type": "object"}),
            "clickup.tasks.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Permanently delete a task from ClickUp.".into(),
                common_mistakes: vec!["Confusing delete with closing a task; deletion is permanent and cannot be undone, whereas setting status to closed preserves the task.".into()],
                examples: vec!["{\"task_id\": \"abc123xyz\"}".into()],
                related: vec![
                    CapabilityId::from_static("clickup.tasks.list"),
                    CapabilityId::from_static("clickup.tasks.create"),
                ],
            },
        ),
    ]
}

/// Build the operations info for introspection (JSON format, used by simulate).
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "clickup.spaces.list",
            "summary": "List spaces in a workspace",
            "capability": "clickup.spaces.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "clickup.lists.list",
            "summary": "List lists in a space",
            "capability": "clickup.lists.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "clickup.tasks.list",
            "summary": "List tasks in a list",
            "capability": "clickup.tasks.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "clickup.tasks.create",
            "summary": "Create a new task in a list",
            "capability": "clickup.tasks.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "clickup.tasks.delete",
            "summary": "Delete a task",
            "capability": "clickup.tasks.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "none",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_api_token() {
        let config = ClickUpConfig::from_params(&json!({
            "api_token": "test-api-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, ClickUpAuth::ApiToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = ClickUpConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = ClickUpConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://clickup.example.com/v2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://clickup.example.com/v2");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = ClickUpConfig::from_params(&json!({
            "api_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = ClickUpConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_token() {
        let result = ClickUpConfig::from_params(&json!({
            "api_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_token() {
        let result = ClickUpConfig::from_params(&json!({
            "api_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = ClickUpConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = ClickUpConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"task_id": "task_abc"});
        assert_eq!(require_str(&input, "task_id").unwrap(), "task_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "task_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"task_id": 42});
        assert!(require_str(&input, "task_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"task_id": null});
        assert!(require_str(&input, "task_id").is_err());
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
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
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
        assert!(ids.contains(&"clickup.spaces.list"));
        assert!(ids.contains(&"clickup.lists.list"));
        assert!(ids.contains(&"clickup.tasks.list"));
        assert!(ids.contains(&"clickup.tasks.create"));
        assert!(ids.contains(&"clickup.tasks.delete"));
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
    fn config_trims_api_token() {
        let config = ClickUpConfig::from_params(&json!({ "api_token": "  pk_test  " })).unwrap();
        match &config.auth {
            ClickUpAuth::ApiToken(t) => assert_eq!(t, "pk_test"),
            ClickUpAuth::CredentialId(_) => panic!("expected ApiToken"),
        }
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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = ClickUpConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_counters_zero() {
        let c = ClickUpConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    // ── DoctorCheck skip_serializing_if ───────────────────────────

    #[test]
    fn doctor_check_message_none_omitted() {
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
    fn doctor_check_message_some_present() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("err".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "err");
    }

    // ── DoctorStatus serde ────────────────────────────────────────

    #[test]
    fn doctor_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            "healthy"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            "degraded"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            "unhealthy"
        );
    }

    #[test]
    fn doctor_status_deserializes_lowercase() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_eq() {
        let s = DoctorStatus::Healthy;
        let s2 = s; // Copy
        assert_eq!(s, s2);
    }

    // ── DoctorResult serialization roundtrip ──────────────────────

    #[test]
    fn doctor_result_roundtrip() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "c1".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "c2".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "degraded");
        let back: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(back.status, DoctorStatus::Degraded);
        assert_eq!(back.checks.len(), 2);
    }

    // ── operations_info additional checks ─────────────────────────

    #[test]
    fn operations_delete_is_dangerous() {
        for op in operations_info().as_array().unwrap() {
            if op["id"].as_str().unwrap().contains("delete") {
                assert_eq!(op["safety_tier"], "dangerous");
                assert_eq!(op["risk_level"], "high");
            }
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn operations_write_ops_have_correct_capability() {
        for op in operations_info().as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            let cap = op["capability"].as_str().unwrap();
            if id.contains("create") || id.contains("delete") {
                assert!(cap.ends_with(".write"), "write op {id} has cap {cap}");
            }
        }
    }

    // ── require_str edge cases ────────────────────────────────────

    #[test]
    fn require_str_empty_string() {
        let input = json!({"f": ""});
        assert_eq!(require_str(&input, "f").unwrap(), "");
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"f": true});
        assert!(require_str(&input, "f").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"f": [1, 2, 3]});
        assert!(require_str(&input, "f").is_err());
    }

    // ── DoctorResult edge cases ───────────────────────────────────

    #[test]
    fn doctor_multiple_critical_failures() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: true,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    // ── Config edge cases ─────────────────────────────────────────

    #[test]
    fn config_default_base_url_when_none() {
        let config = ClickUpConfig::from_params(&json!({
            "api_token": "tok",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"f": {"nested": true}});
        assert!(require_str(&input, "f").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"f": 3.15});
        assert!(require_str(&input, "f").is_err());
    }

    #[test]
    fn operations_list_ops_are_strict_idempotent() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.contains("list") {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "strict",
                    "list op {id} should be strict idempotent"
                );
            }
        }
    }

    #[test]
    fn operations_create_is_not_idempotent() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.contains("create") {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "none",
                    "create op {id} should have no idempotency"
                );
            }
        }
    }

    #[test]
    fn operations_delete_is_not_idempotent() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.contains("delete") {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "none",
                    "delete op {id} should have no idempotency"
                );
            }
        }
    }

    #[test]
    fn doctor_status_debug() {
        assert!(format!("{:?}", DoctorStatus::Healthy).contains("Healthy"));
        assert!(format!("{:?}", DoctorStatus::Degraded).contains("Degraded"));
        assert!(format!("{:?}", DoctorStatus::Unhealthy).contains("Unhealthy"));
    }

    #[test]
    fn doctor_check_clone_and_debug() {
        let check = DoctorCheck {
            name: "my_check".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let cloned = check.clone();
        assert_eq!(check.name, "my_check");
        assert_eq!(cloned.message.as_deref(), Some("ok"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("DoctorCheck"));
        assert!(dbg.contains("my_check"));
    }

    #[test]
    fn doctor_result_debug_and_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "c".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
        assert!(dbg.contains("Healthy"));
    }

    #[test]
    fn config_debug_and_clone() {
        let config = ClickUpConfig::from_params(&json!({"api_token": "test"})).unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(cloned.base_url, DEFAULT_BASE_URL);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("ClickUpConfig"));
    }

    #[test]
    fn operations_all_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_all_capabilities_prefixed() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("clickup."),
                "capability {cap} should start with clickup."
            );
        }
    }

    // ── Provisioning tests ───────────────────────────────────────

    #[test]
    fn provisioning_readiness_api_token_mode() {
        let config = ClickUpConfig::from_params(&json!({
            "api_token": "pk_test_token",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = ClickUpConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = ClickUpConfig::from_params(&json!({
            "api_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_url_rejected() {
        let config = ClickUpConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("api.clickup.com"));
    }

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "clickup.api_token");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "open_settings");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_token");
        assert_eq!(recipe.steps[2].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "open_settings");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_token");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "clickup.api_token");
        assert!(v["steps"].as_array().unwrap().len() == 3);
    }

    #[test]
    fn provisioning_recipe_store_step_scope() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[2];
        match &store_step.kind {
            ProvisioningStepType::StoreSecret { scope, key, .. } => {
                assert_eq!(scope, "connector:fcp.clickup");
                assert_eq!(key, "api_token");
            }
            other => panic!("expected StoreSecret, got {other:?}"),
        }
    }

    #[test]
    fn base_url_policy_accepts_clickup_https() {
        let (ok, message) = base_url_policy("https://api.clickup.com/api/v2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9090");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://api.clickup.com");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("api.clickup.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn is_local_test_host_values() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
        assert!(!is_local_test_host("api.clickup.com"));
    }

    #[test]
    fn provisioning_readiness_debug_clone() {
        let config = ClickUpConfig::from_params(&json!({"api_token": "t"})).unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = readiness.clone();
        assert_eq!(cloned.auth_mode, readiness.auth_mode);
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }
}
