//! FCP `Pulumi` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use fcp_sdk::migration::ConnectorRuntime;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, PulumiAuth, PulumiClient},
    error::PulumiError,
};

/// Parsed and validated `Pulumi` connector configuration.
#[derive(Debug, Clone)]
struct PulumiConfig {
    auth: PulumiAuth,
    base_url: String,
}

impl PulumiConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
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

        let auth = match (access_token, credential_id) {
            (Some(key), None) => PulumiAuth::BearerToken(key),
            (None, Some(cred_id)) => PulumiAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of access_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing access_token or credential_id in configuration".into(),
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
                PulumiAuth::BearerToken(_) => "bearer_token",
                PulumiAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, PulumiAuth::BearerToken(_)),
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

/// FCP `Pulumi` Connector.
pub struct PulumiConnector {
    base: Arc<BaseConnector>,
    config: Option<PulumiConfig>,
    client: Option<Arc<PulumiClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
    runtime: Option<ConnectorRuntime>,
}

impl PulumiConnector {
    /// Create a new `Pulumi` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("pulumi"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            runtime: None,
        }
    }
}

impl Default for PulumiConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PulumiConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = PulumiConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Pulumi connector");

        let client = PulumiClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.runtime = Some(ConnectorRuntime::new(
            fcp_sdk::migration::ConnectorRuntimeConfig::default(),
        ));
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
            "connector_id": "fcp.pulumi",
            "connector_version": "0.1.0",
            "capabilities": [
                "pulumi.stacks.read",
                "pulumi.stacks.write",
                "pulumi.deployments.read"
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
        Ok(json!({
            "connector_id": "fcp.pulumi",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
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
            "pulumi.stacks.list" => self.invoke_stacks_list(client, &input).await,
            "pulumi.stacks.get" => self.invoke_stacks_get(client, &input).await,
            "pulumi.stacks.create" => self.invoke_stacks_create(client, &input).await,
            "pulumi.stacks.delete" => self.invoke_stacks_delete(client, &input).await,
            "pulumi.stacks.export" => self.invoke_stacks_export(client, &input).await,
            "pulumi.deployments.list" => self.invoke_deployments_list(client, &input).await,
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
        info!("Pulumi connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "pulumi.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Pulumi self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // -- Operation implementations --

    async fn invoke_stacks_list(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = input
            .get("organization")
            .and_then(serde_json::Value::as_str);
        let project = input.get("project").and_then(serde_json::Value::as_str);
        client.list_stacks(organization, project).await
    }

    async fn invoke_stacks_get(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = require_str(input, "organization")?;
        let project = require_str(input, "project")?;
        let stack = require_str(input, "stack")?;
        client.get_stack(organization, project, stack).await
    }

    async fn invoke_stacks_create(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = require_str(input, "organization")?;
        let project = require_str(input, "project")?;
        let stack = require_str(input, "stack")?;
        client.create_stack(organization, project, stack).await
    }

    async fn invoke_stacks_delete(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = require_str(input, "organization")?;
        let project = require_str(input, "project")?;
        let stack = require_str(input, "stack")?;
        client.delete_stack(organization, project, stack).await
    }

    async fn invoke_stacks_export(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = require_str(input, "organization")?;
        let project = require_str(input, "project")?;
        let stack = require_str(input, "stack")?;
        client.export_stack(organization, project, stack).await
    }

    async fn invoke_deployments_list(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = require_str(input, "organization")?;
        let project = require_str(input, "project")?;
        let stack = require_str(input, "stack")?;
        client.list_deployments(organization, project, stack).await
    }
}

/// Build the provisioning recipe for the Pulumi connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("pulumi.access_token"),
        "1",
        "Provision Pulumi connector with a Pulumi Cloud access token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_token"),
        ProvisioningStepType::PromptSecret {
            message: "Paste your Pulumi access token (pul-...)".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("prompt_token"),
                scope: "connector:fcp.pulumi".into(),
            },
        )
        .depends_on(StepId::new("prompt_token")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("prompt_organization"),
            ProvisioningStepType::PromptUser {
                message: "Enter your Pulumi organization name".into(),
            },
        )
        .depends_on(StepId::new("store_token")),
    )
}

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
    let allowed_host = host.eq_ignore_ascii_case("api.pulumi.com")
        || host.eq_ignore_ascii_case("pulumi.com")
        || host
            .to_ascii_lowercase()
            .as_bytes()
            .ends_with(b".pulumi.com")
        || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https and api.pulumi.com or *.pulumi.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, PulumiError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PulumiError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
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
            "pulumi.stacks.list",
            "List stacks in an organization",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "organization": { "type": "string" },
                    "project": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["stacks"],
                "properties": {
                    "stacks": { "type": "array" }
                }
            }),
            "pulumi.stacks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List Pulumi stacks.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"organization": "myorg", "project": "myproject"}"#.into()],
                related: vec![
                    CapabilityId::from_static("pulumi.stacks.get"),
                    CapabilityId::from_static("pulumi.stacks.create"),
                ],
            },
        ),
        op_info(
            "pulumi.stacks.get",
            "Get stack details including outputs",
            json!({
                "type": "object",
                "required": ["organization", "project", "stack"],
                "properties": {
                    "organization": { "type": "string" },
                    "project": { "type": "string" },
                    "stack": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["orgName", "projectName", "stackName"],
                "properties": {
                    "orgName": { "type": "string" },
                    "projectName": { "type": "string" },
                    "stackName": { "type": "string" }
                }
            }),
            "pulumi.stacks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get details for a specific stack including outputs.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"organization": "myorg", "project": "myproject", "stack": "production"}"#
                        .into(),
                ],
                related: vec![
                    CapabilityId::from_static("pulumi.stacks.list"),
                    CapabilityId::from_static("pulumi.stacks.export"),
                ],
            },
        ),
        op_info(
            "pulumi.stacks.create",
            "Create a new stack",
            json!({
                "type": "object",
                "required": ["organization", "project", "stack"],
                "properties": {
                    "organization": { "type": "string" },
                    "project": { "type": "string" },
                    "stack": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["orgName", "projectName", "stackName"],
                "properties": {
                    "orgName": { "type": "string" },
                    "projectName": { "type": "string" },
                    "stackName": { "type": "string" }
                }
            }),
            "pulumi.stacks.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Create a new Pulumi stack.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"organization": "myorg", "project": "myproject", "stack": "staging"}"#
                        .into(),
                ],
                related: vec![
                    CapabilityId::from_static("pulumi.stacks.list"),
                    CapabilityId::from_static("pulumi.stacks.delete"),
                ],
            },
        ),
        op_info(
            "pulumi.stacks.delete",
            "Delete a stack",
            json!({
                "type": "object",
                "required": ["organization", "project", "stack"],
                "properties": {
                    "organization": { "type": "string" },
                    "project": { "type": "string" },
                    "stack": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "pulumi.stacks.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use:
                    "Delete a stack. Cannot be undone; all resources and history are removed."
                        .into(),
                common_mistakes: vec![
                    "Deleting a stack with active resources — destroy first.".into(),
                ],
                examples: vec![
                    r#"{"organization": "myorg", "project": "myproject", "stack": "staging"}"#
                        .into(),
                ],
                related: vec![CapabilityId::from_static("pulumi.stacks.list")],
            },
        ),
        op_info(
            "pulumi.stacks.export",
            "Export stack state as a deployment checkpoint",
            json!({
                "type": "object",
                "required": ["organization", "project", "stack"],
                "properties": {
                    "organization": { "type": "string" },
                    "project": { "type": "string" },
                    "stack": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployment"],
                "properties": {
                    "deployment": { "type": "object" }
                }
            }),
            "pulumi.stacks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Export the full state of a stack for backup or inspection.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"organization": "myorg", "project": "myproject", "stack": "production"}"#
                        .into(),
                ],
                related: vec![CapabilityId::from_static("pulumi.stacks.get")],
            },
        ),
        op_info(
            "pulumi.deployments.list",
            "List recent deployments for a stack",
            json!({
                "type": "object",
                "required": ["organization", "project", "stack"],
                "properties": {
                    "organization": { "type": "string" },
                    "project": { "type": "string" },
                    "stack": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["updates"],
                "properties": {
                    "updates": { "type": "array" }
                }
            }),
            "pulumi.deployments.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List recent deployments/updates for a stack.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"organization": "myorg", "project": "myproject", "stack": "production"}"#
                        .into(),
                ],
                related: vec![CapabilityId::from_static("pulumi.stacks.get")],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_access_token() {
        let config = PulumiConfig::from_params(&json!({
            "access_token": "pul-abc123",
        }))
        .unwrap();
        assert!(matches!(config.auth, PulumiAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = PulumiConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = PulumiConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://pulumi.example.com/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://pulumi.example.com/api");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = PulumiConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = PulumiConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = PulumiConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = PulumiConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = PulumiConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = PulumiConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"organization": "myorg"});
        assert_eq!(require_str(&input, "organization").unwrap(), "myorg");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"organization": 42});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"organization": null});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn operations_info_has_6_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 6);
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
        let ops = operations_info();
        for op in &ops {
            // RiskLevel is an enum, so it's always valid by construction
            let _ = op.risk_level;
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            // SafetyTier is an enum, so it's always valid by construction
            let _ = op.safety_tier;
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
        assert!(ids.contains(&"pulumi.stacks.list"));
        assert!(ids.contains(&"pulumi.stacks.get"));
        assert!(ids.contains(&"pulumi.stacks.create"));
        assert!(ids.contains(&"pulumi.stacks.delete"));
        assert!(ids.contains(&"pulumi.stacks.export"));
        assert!(ids.contains(&"pulumi.deployments.list"));
    }

    #[test]
    fn operations_capabilities_match_manifest() {
        let ops = operations_info();
        let caps: Vec<&str> = ops.iter().map(|o| o.capability.as_ref()).collect();
        assert!(caps.contains(&"pulumi.stacks.read"));
        assert!(caps.contains(&"pulumi.stacks.write"));
        assert!(caps.contains(&"pulumi.deployments.read"));
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
    fn connector_default() {
        let c = PulumiConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_equals_default() {
        let c = PulumiConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(
            v.get("message").is_none(),
            "message should be skipped when None"
        );
    }

    #[test]
    fn doctor_check_serializes_message_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("error detail".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "error detail");
    }

    #[test]
    fn doctor_check_roundtrip() {
        let check = DoctorCheck {
            name: "connectivity".into(),
            passed: true,
            message: Some("All good".into()),
            critical: false,
        };
        let serialized = serde_json::to_string(&check).unwrap();
        let back: DoctorCheck = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.name, "connectivity");
        assert_eq!(back.message, Some("All good".into()));
    }

    #[test]
    fn doctor_status_values_serialize_lowercase() {
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
    fn doctor_status_debug() {
        assert!(format!("{:?}", DoctorStatus::Healthy).contains("Healthy"));
        assert!(format!("{:?}", DoctorStatus::Degraded).contains("Degraded"));
        assert!(format!("{:?}", DoctorStatus::Unhealthy).contains("Unhealthy"));
    }

    #[test]
    fn doctor_status_clone_copy() {
        let s = DoctorStatus::Healthy;
        let c = s;
        assert_eq!(s, c);
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let s = serde_json::to_string(&status).unwrap();
            let back: DoctorStatus = serde_json::from_str(&s).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let result = DoctorResult::from_checks(vec![
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
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_serializes_with_message() {
        let result = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: false,
            message: Some("detail".into()),
            critical: false,
        }]);
        let v = serde_json::to_value(&result).unwrap();
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["checks"][0]["message"], "detail");
    }

    #[test]
    fn operations_delete_is_dangerous() {
        let ops = operations_info();
        let delete_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "pulumi.stacks.delete")
            .unwrap();
        assert_eq!(delete_op.safety_tier, SafetyTier::Dangerous);
        assert_eq!(delete_op.risk_level, RiskLevel::High);
    }

    #[test]
    fn operations_create_is_risky() {
        let ops = operations_info();
        let create_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "pulumi.stacks.create")
            .unwrap();
        assert_eq!(create_op.safety_tier, SafetyTier::Risky);
        assert_eq!(create_op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn operations_export_capability() {
        let ops = operations_info();
        let export_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "pulumi.stacks.export")
            .unwrap();
        assert_eq!(export_op.capability.as_ref(), "pulumi.stacks.read");
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            // IdempotencyClass is a typed enum, always present by construction
            let _ = op.idempotency;
        }
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"organization": ""});
        assert_eq!(require_str(&input, "organization").unwrap(), "");
    }

    #[test]
    fn require_str_with_array_value() {
        let input = json!({"organization": [1, 2, 3]});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"organization": {"nested": true}});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn require_str_with_bool_value() {
        let input = json!({"organization": true});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn require_str_error_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "project").unwrap_err();
        match err {
            PulumiError::Api { message, .. } => {
                assert!(message.contains("project"));
            }
            e => panic!("expected Api, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_both_auth_error_message() {
        let result = PulumiConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_no_auth_error_message() {
        let result = PulumiConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("access_token") || message.contains("credential_id"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_non_string_credential_error_message() {
        let result = PulumiConfig::from_params(&json!({"credential_id": 42}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("must be a string"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_invalid_uuid_credential_error_message() {
        let result = PulumiConfig::from_params(&json!({"credential_id": "not-valid"}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("valid UUID"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_default_base_url_when_absent() {
        let config = PulumiConfig::from_params(&json!({"access_token": "tok"})).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_trims_access_token() {
        let config = PulumiConfig::from_params(&json!({"access_token": "  pul-abc  "})).unwrap();
        match &config.auth {
            PulumiAuth::BearerToken(t) => assert_eq!(t, "pul-abc"),
            PulumiAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    // ── Additional connector tests ────────────────────────────────

    #[test]
    fn operations_all_summaries_non_empty() {
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
    fn operations_list_is_safe_and_low() {
        let ops = operations_info();
        let list_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "pulumi.stacks.list")
            .unwrap();
        assert_eq!(list_op.safety_tier, SafetyTier::Safe);
        assert_eq!(list_op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn operations_get_is_safe_and_low() {
        let ops = operations_info();
        let get_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "pulumi.stacks.get")
            .unwrap();
        assert_eq!(get_op.safety_tier, SafetyTier::Safe);
        assert_eq!(get_op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn doctor_result_debug_format() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let cloned = c.clone();
        assert_eq!(cloned.name, c.name);
        assert_eq!(cloned.passed, c.passed);
        assert_eq!(cloned.message, c.message);
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"field": 1.23});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_integer_value() {
        let input = json!({"field": 99});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_nested_deep_object() {
        let input = json!({"field": {"a": {"b": {"c": "d"}}}});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn doctor_status_deserialize_roundtrip() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_semantics() {
        let status = DoctorStatus::Degraded;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn doctor_status_eq_ne() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_check_debug_format() {
        let c = DoctorCheck {
            name: "api".into(),
            passed: false,
            message: Some("timeout".into()),
            critical: true,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("api"));
        assert!(dbg.contains("timeout"));
    }

    #[test]
    fn operations_all_have_capabilities() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.capability.as_ref().is_empty(),
                "op {} has empty capability",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_ids_all_start_with_pulumi() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            assert!(
                id.starts_with("pulumi."),
                "op {id} should start with pulumi."
            );
        }
    }

    #[test]
    fn operations_all_risk_levels_valid() {
        // RiskLevel is a typed enum, always valid by construction
        let ops = operations_info();
        for op in &ops {
            let _ = op.risk_level;
        }
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_bearer_token_mode() {
        let config = PulumiConfig::from_params(&json!({
            "access_token": "pul-test-token",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "bearer_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = PulumiConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = PulumiConfig::from_params(&json!({
            "access_token": "pul-abc",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "pulumi.access_token");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_ids() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "prompt_token");
        assert_eq!(recipe.steps[1].id.as_str(), "store_token");
        assert_eq!(recipe.steps[2].id.as_str(), "prompt_organization");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "prompt_token");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "pulumi.access_token");
        assert!(v["steps"].as_array().unwrap().len() == 3);
    }

    #[test]
    fn provisioning_recipe_description_non_empty() {
        let recipe = provisioning_recipe();
        assert!(!recipe.description.is_empty());
        assert!(recipe.description.contains("Pulumi"));
    }

    #[test]
    fn base_url_policy_accepts_api_pulumi_https() {
        let (ok, message) = base_url_policy("https://api.pulumi.com/api");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_pulumi_com() {
        let (ok, message) = base_url_policy("https://pulumi.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_subdomain_pulumi() {
        let (ok, _) = base_url_policy("https://app.pulumi.com");
        assert!(ok);
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
        let (ok, message) = base_url_policy("http://api.pulumi.com/api");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("api.pulumi.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = PulumiConfig::from_params(&json!({
            "access_token": "pul-tok",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("api.pulumi.com"));
    }

    #[test]
    fn provisioning_readiness_localhost_base_url_accepted() {
        let config = PulumiConfig::from_params(&json!({
            "access_token": "pul-tok",
            "base_url": "http://localhost:4567",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_debug_format() {
        let config = PulumiConfig::from_params(&json!({
            "access_token": "pul-tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }

    #[test]
    fn is_local_test_host_localhost() {
        assert!(is_local_test_host("localhost"));
    }

    #[test]
    fn is_local_test_host_ipv4() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_ipv6() {
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_rejects_remote() {
        assert!(!is_local_test_host("api.pulumi.com"));
        assert!(!is_local_test_host("example.com"));
    }
}
