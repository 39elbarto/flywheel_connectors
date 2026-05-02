//! FCP Asana Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{AsanaAuth, AsanaClient, DEFAULT_BASE_URL},
    error::AsanaError,
};

#[cfg(test)]
use fcp_manifest::ConnectorManifest;

/// Parsed and validated Asana connector configuration.
#[derive(Debug, Clone)]
struct AsanaConfig {
    auth: AsanaAuth,
    base_url: String,
}

impl AsanaConfig {
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
            (Some(key), None) => AsanaAuth::PersonalAccessToken(key),
            (None, Some(cred_id)) => AsanaAuth::CredentialId(cred_id),
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
        let base_url = validate_base_url_for_auth(&base_url, &auth)?;

        Ok(Self { auth, base_url })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                AsanaAuth::PersonalAccessToken(_) => "personal_access_token",
                AsanaAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, AsanaAuth::PersonalAccessToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

fn validate_base_url_for_auth(base_url: &str, auth: &AsanaAuth) -> FcpResult<String> {
    let parsed = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    // Strip query/fragment/userinfo before the host/scheme checks because
    // the validator returns parsed.to_string() — any of those components
    // would otherwise be preserved and then concatenated into downstream
    // format!("{base_url}/...") URL construction, leaking attacker-chosen
    // values into every Asana API request or baking userinfo into the
    // URL that silently overrides the PAT the connector sets via the
    // Authorization header. Same hygiene already in whatsapp / stripe /
    // notion / telegram / discord / gmail after earlier patches.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }
    let canonical = parsed.to_string().trim_end_matches('/').to_string();

    match auth {
        AsanaAuth::PersonalAccessToken(_) => {
            let (allowed, message) = base_url_policy(&canonical);
            if !allowed {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message,
                });
            }
        }
        AsanaAuth::CredentialId(_) => {
            let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must include a host".into(),
            })?;
            let local = is_local_test_host(host);
            let secure_or_local = parsed.scheme() == "https" || local;
            if !secure_or_local {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                            .into(),
                });
            }
        }
    }

    Ok(canonical)
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

/// FCP Asana Connector.
pub struct AsanaConnector {
    base: Arc<BaseConnector>,
    config: Option<AsanaConfig>,
    client: Option<Arc<AsanaClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl AsanaConnector {
    /// Create a new Asana connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("asana"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for AsanaConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl AsanaConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = AsanaConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Asana connector");

        let client = AsanaClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.session_id = None;
        self.base.set_handshaken(false);
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
            "connector_id": "fcp.asana",
            "connector_version": "0.1.0",
            "capabilities": [
                "asana.workspaces.read",
                "asana.projects.read",
                "asana.tasks.read",
                "asana.tasks.write",
                "asana.tasks.delete",
                "asana.sections.read"
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
            "connector_id": "fcp.asana",
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
            "asana.workspaces.list" => self.invoke_workspaces_list(client).await,
            "asana.projects.list" => self.invoke_projects_list(client, &input).await,
            "asana.projects.get" => self.invoke_projects_get(client, &input).await,
            "asana.tasks.list" => self.invoke_tasks_list(client, &input).await,
            "asana.tasks.get" => self.invoke_tasks_get(client, &input).await,
            "asana.tasks.create" => self.invoke_tasks_create(client, &input).await,
            "asana.tasks.update" => self.invoke_tasks_update(client, &input).await,
            "asana.tasks.delete" => self.invoke_tasks_delete(client, &input).await,
            "asana.sections.list" => self.invoke_sections_list(client, &input).await,
            "asana.tasks.search" => self.invoke_tasks_search(client, &input).await,
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
        info!("Asana connector shutting down");
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
            event = "asana.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Asana self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // -- Operation implementations --

    async fn invoke_workspaces_list(
        &self,
        client: &AsanaClient,
    ) -> Result<serde_json::Value, AsanaError> {
        let resp = client.list_workspaces().await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "data": data }))
    }

    async fn invoke_projects_list(
        &self,
        client: &AsanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AsanaError> {
        let workspace_gid = require_str(input, "workspace_gid")?;
        let resp = client.list_projects(workspace_gid).await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "data": data }))
    }

    async fn invoke_projects_get(
        &self,
        client: &AsanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AsanaError> {
        let project_gid = require_str(input, "project_gid")?;
        let resp = client.get_project(project_gid).await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!({}));
        Ok(json!({ "data": data }))
    }

    async fn invoke_tasks_list(
        &self,
        client: &AsanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AsanaError> {
        let project_gid = require_str(input, "project_gid")?;
        let resp = client.list_tasks(project_gid).await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "data": data }))
    }

    async fn invoke_tasks_get(
        &self,
        client: &AsanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AsanaError> {
        let task_gid = require_str(input, "task_gid")?;
        let resp = client.get_task(task_gid).await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!({}));
        Ok(json!({ "data": data }))
    }

    async fn invoke_tasks_create(
        &self,
        client: &AsanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AsanaError> {
        let _name = require_str(input, "name")?;
        let body = json!({ "data": input });
        let resp = client.create_task(&body).await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!({}));
        Ok(json!({ "data": data }))
    }

    async fn invoke_tasks_update(
        &self,
        client: &AsanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AsanaError> {
        let task_gid = require_str(input, "task_gid")?;
        // Remove task_gid from the body sent to the API
        let mut update_body = input.clone();
        if let Some(obj) = update_body.as_object_mut() {
            obj.remove("task_gid");
        }
        let body = json!({ "data": update_body });
        let resp = client.update_task(task_gid, &body).await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!({}));
        Ok(json!({ "data": data }))
    }

    async fn invoke_tasks_delete(
        &self,
        client: &AsanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AsanaError> {
        let task_gid = require_str(input, "task_gid")?;
        client.delete_task(task_gid).await
    }

    async fn invoke_sections_list(
        &self,
        client: &AsanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AsanaError> {
        let project_gid = require_str(input, "project_gid")?;
        let resp = client.list_sections(project_gid).await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "data": data }))
    }

    async fn invoke_tasks_search(
        &self,
        client: &AsanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AsanaError> {
        let workspace_gid = require_str(input, "workspace_gid")?;
        let query = require_str(input, "query")?;
        let resp = client.search_tasks(workspace_gid, query).await?;
        let data = resp.get("data").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "data": data }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, AsanaError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AsanaError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the provisioning recipe for the Asana connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("asana.personal_access_token"),
        "1",
        "Provision Asana connector with a personal access token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("open_developer_console"),
        ProvisioningStepType::OpenUrl {
            url: "https://app.asana.com/0/developer-console".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_token"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your Asana personal access token".into(),
            },
        )
        .depends_on(StepId::new("open_developer_console")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("enter_token"),
                scope: "connector:fcp.asana".into(),
            },
        )
        .depends_on(StepId::new("enter_token")),
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
    let allowed_host = host.eq_ignore_ascii_case("app.asana.com")
        || host.eq_ignore_ascii_case("api.asana.com")
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
                "Endpoint must use https and app.asana.com or api.asana.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
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
            "asana.workspaces.list",
            "List workspaces",
            json!({"type": "object", "required": []}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "array"}}}),
            "asana.workspaces.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List Asana workspaces.".into(),
                common_mistakes: vec!["Confusing workspaces with organizations; both are returned by this endpoint and organizations are a type of workspace with additional features.".into()],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("asana.projects.list")],
            },
        ),
        op_info(
            "asana.projects.list",
            "List projects in a workspace",
            json!({"type": "object", "required": ["workspace_gid"], "properties": {"workspace_gid": {"type": "string", "description": "Workspace GID"}}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "array"}}}),
            "asana.projects.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List projects in an Asana workspace.".into(),
                common_mistakes: vec!["Passing a project GID instead of a workspace GID; the workspace_gid parameter must be the workspace's numeric GID, not a project identifier.".into()],
                examples: vec!["{\"workspace_gid\": \"1234567890\"}".into()],
                related: vec![
                    CapabilityId::from_static("asana.workspaces.list"),
                    CapabilityId::from_static("asana.tasks.list"),
                ],
            },
        ),
        op_info(
            "asana.projects.get",
            "Get a single project",
            json!({"type": "object", "required": ["project_gid"], "properties": {"project_gid": {"type": "string"}}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "object"}}}),
            "asana.projects.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve a single Asana project by its GID.".into(),
                common_mistakes: vec!["Using a workspace GID instead of a project GID.".into()],
                examples: vec!["{\"project_gid\": \"1234567890\"}".into()],
                related: vec![CapabilityId::from_static("asana.projects.list")],
            },
        ),
        op_info(
            "asana.tasks.list",
            "List tasks in a project",
            json!({"type": "object", "required": ["project_gid"], "properties": {"project_gid": {"type": "string", "description": "Project GID"}}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "array"}}}),
            "asana.tasks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List tasks in an Asana project.".into(),
                common_mistakes: vec!["Only top-level tasks in the project are returned; subtasks are not included and must be fetched separately using the parent task's GID.".into()],
                examples: vec!["{\"project_gid\": \"1234567890\"}".into()],
                related: vec![
                    CapabilityId::from_static("asana.tasks.create"),
                    CapabilityId::from_static("asana.projects.list"),
                ],
            },
        ),
        op_info(
            "asana.tasks.get",
            "Get a single task",
            json!({"type": "object", "required": ["task_gid"], "properties": {"task_gid": {"type": "string"}}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "object"}}}),
            "asana.tasks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve a single Asana task by its GID.".into(),
                common_mistakes: vec!["Confusing task GID with task name or project GID.".into()],
                examples: vec!["{\"task_gid\": \"1234567890\"}".into()],
                related: vec![CapabilityId::from_static("asana.tasks.list")],
            },
        ),
        op_info(
            "asana.tasks.create",
            "Create a new task",
            json!({"type": "object", "required": ["workspace", "name"], "properties": {"workspace": {"type": "string"}, "name": {"type": "string"}, "notes": {"type": "string"}}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "object"}}}),
            "asana.tasks.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new task.".into(),
                common_mistakes: vec!["Creating a task with only workspace and name places it in no project; add a projects or memberships field to assign it to a specific project.".into()],
                examples: vec!["{\"workspace\": \"1234567890\", \"name\": \"Fix login timeout\", \"notes\": \"Users report 30s timeouts\"}".into()],
                related: vec![
                    CapabilityId::from_static("asana.tasks.list"),
                    CapabilityId::from_static("asana.tasks.delete"),
                ],
            },
        ),
        op_info(
            "asana.tasks.update",
            "Update an existing task",
            json!({"type": "object", "required": ["task_gid"], "properties": {"task_gid": {"type": "string"}, "name": {"type": "string"}, "notes": {"type": "string"}}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "object"}}}),
            "asana.tasks.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Update fields on an existing Asana task.".into(),
                common_mistakes: vec!["Omitting the task_gid from the request; it is required to identify which task to update.".into()],
                examples: vec!["{\"task_gid\": \"1234567890\", \"name\": \"Updated task name\"}".into()],
                related: vec![
                    CapabilityId::from_static("asana.tasks.get"),
                    CapabilityId::from_static("asana.tasks.list"),
                ],
            },
        ),
        op_info(
            "asana.tasks.delete",
            "Delete a task",
            json!({"type": "object", "required": ["task_gid"], "properties": {"task_gid": {"type": "string", "description": "Task GID"}}}),
            json!({"type": "object"}),
            "asana.tasks.delete",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Delete a task. Cannot be undone.".into(),
                common_mistakes: vec!["Deleting a task also removes all of its subtasks permanently; verify the task has no subtasks you want to keep before deleting.".into()],
                examples: vec!["{\"task_gid\": \"1234567890\"}".into()],
                related: vec![CapabilityId::from_static("asana.tasks.list")],
            },
        ),
        op_info(
            "asana.sections.list",
            "List sections in a project",
            json!({"type": "object", "required": ["project_gid"], "properties": {"project_gid": {"type": "string"}}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "array"}}}),
            "asana.sections.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List sections within an Asana project.".into(),
                common_mistakes: vec!["Using a workspace GID instead of a project GID for the project_gid parameter.".into()],
                examples: vec!["{\"project_gid\": \"1234567890\"}".into()],
                related: vec![CapabilityId::from_static("asana.projects.list")],
            },
        ),
        op_info(
            "asana.tasks.search",
            "Search tasks in a workspace",
            json!({"type": "object", "required": ["workspace_gid", "query"], "properties": {"workspace_gid": {"type": "string"}, "query": {"type": "string"}}}),
            json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "array"}}}),
            "asana.tasks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Search for tasks across a workspace by keyword.".into(),
                common_mistakes: vec!["Using a project GID instead of a workspace GID; search operates at the workspace level.".into()],
                examples: vec!["{\"workspace_gid\": \"1234567890\", \"query\": \"login bug\"}".into()],
                related: vec![
                    CapabilityId::from_static("asana.tasks.list"),
                    CapabilityId::from_static("asana.workspaces.list"),
                ],
            },
        ),
    ]
}

/// Build the operations info for introspection (JSON format, used by simulate).
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "asana.workspaces.list",
            "summary": "List workspaces",
            "capability": "asana.workspaces.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "asana.projects.list",
            "summary": "List projects in a workspace",
            "capability": "asana.projects.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "asana.projects.get",
            "summary": "Get a single project",
            "capability": "asana.projects.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "asana.tasks.list",
            "summary": "List tasks in a project",
            "capability": "asana.tasks.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "asana.tasks.get",
            "summary": "Get a single task",
            "capability": "asana.tasks.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "asana.tasks.create",
            "summary": "Create a new task",
            "capability": "asana.tasks.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "asana.tasks.update",
            "summary": "Update an existing task",
            "capability": "asana.tasks.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "asana.tasks.delete",
            "summary": "Delete a task",
            "capability": "asana.tasks.delete",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "none",
        },
        {
            "id": "asana.sections.list",
            "summary": "List sections in a project",
            "capability": "asana.sections.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "asana.tasks.search",
            "summary": "Search tasks in a workspace",
            "capability": "asana.tasks.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_access_token() {
        let config = AsanaConfig::from_params(&json!({
            "access_token": "1/1234567890:abcdef",
        }))
        .unwrap();
        assert!(matches!(config.auth, AsanaAuth::PersonalAccessToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = AsanaConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let result = AsanaConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://asana.example.com/api/1.0",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_credential_id_allows_custom_base_url() {
        let config = AsanaConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://asana-proxy.internal/api/1.0",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://asana-proxy.internal/api/1.0");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = AsanaConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = AsanaConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = AsanaConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = AsanaConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = AsanaConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = AsanaConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config =
            AsanaConfig::from_params(&json!({ "access_token": "  1/test_token  " })).unwrap();
        match &config.auth {
            AsanaAuth::PersonalAccessToken(t) => assert_eq!(t, "1/test_token"),
            AsanaAuth::CredentialId(_) => panic!("expected PersonalAccessToken"),
        }
    }

    #[test]
    fn require_str_present() {
        let input = json!({"task_gid": "12345"});
        assert_eq!(require_str(&input, "task_gid").unwrap(), "12345");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "task_gid").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"task_gid": 42});
        assert!(require_str(&input, "task_gid").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"task_gid": null});
        assert!(require_str(&input, "task_gid").is_err());
    }

    #[test]
    fn operations_info_has_10_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 10);
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
        assert!(ids.contains(&"asana.workspaces.list"));
        assert!(ids.contains(&"asana.projects.list"));
        assert!(ids.contains(&"asana.projects.get"));
        assert!(ids.contains(&"asana.tasks.list"));
        assert!(ids.contains(&"asana.tasks.get"));
        assert!(ids.contains(&"asana.tasks.create"));
        assert!(ids.contains(&"asana.tasks.update"));
        assert!(ids.contains(&"asana.tasks.delete"));
        assert!(ids.contains(&"asana.sections.list"));
        assert!(ids.contains(&"asana.tasks.search"));
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
    fn connector_default() {
        let c = AsanaConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    // ── Additional connector coverage ────────────────────────────

    #[test]
    fn connector_new_fields() {
        let c = AsanaConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_default_base_url() {
        let config = AsanaConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_error_message_both_auth() {
        let result = AsanaConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, code } => {
                assert!(message.contains("exactly one"), "got: {message}");
                assert_eq!(code, 1003);
            }
            e => panic!("expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn config_error_message_no_auth() {
        let result = AsanaConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing"), "got: {message}");
            }
            e => panic!("expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn config_error_non_string_credential() {
        let result = AsanaConfig::from_params(&json!({
            "credential_id": 42,
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("string"), "got: {message}");
            }
            e => panic!("expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn config_error_invalid_uuid() {
        let result = AsanaConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("UUID"), "got: {message}");
            }
            e => panic!("expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"task_gid": [1, 2, 3]});
        assert!(require_str(&input, "task_gid").is_err());
    }

    #[test]
    fn require_str_bool_value() {
        let input = json!({"task_gid": true});
        assert!(require_str(&input, "task_gid").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"task_gid": ""});
        assert_eq!(require_str(&input, "task_gid").unwrap(), "");
    }

    #[test]
    fn operations_write_ops_are_risky_or_dangerous() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.contains("write") {
                let tier = op["safety_tier"].as_str().unwrap();
                assert!(
                    tier == "risky" || tier == "dangerous",
                    "write op {} should be risky or dangerous, got {tier}",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_delete_is_dangerous() {
        let ops = operations_info();
        let delete_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"].as_str() == Some("asana.tasks.delete"))
            .unwrap();
        assert_eq!(delete_op["safety_tier"].as_str().unwrap(), "dangerous");
        assert_eq!(delete_op["risk_level"].as_str().unwrap(), "high");
    }

    #[test]
    fn operations_tasks_delete_requires_dedicated_capability() {
        let ops = operations_info();
        let delete_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"].as_str() == Some("asana.tasks.delete"))
            .unwrap();
        let create_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"].as_str() == Some("asana.tasks.create"))
            .unwrap();
        let update_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"].as_str() == Some("asana.tasks.update"))
            .unwrap();

        assert_eq!(
            delete_op["capability"].as_str().unwrap(),
            "asana.tasks.delete"
        );
        assert_eq!(
            create_op["capability"].as_str().unwrap(),
            "asana.tasks.write"
        );
        assert_eq!(
            update_op["capability"].as_str().unwrap(),
            "asana.tasks.write"
        );
    }

    #[test]
    fn manifest_tasks_delete_requires_dedicated_capability() {
        let manifest = ConnectorManifest::parse_str(include_str!("../manifest.toml"))
            .expect("manifest should validate");

        let delete_op = manifest
            .provides
            .operations
            .get("asana.tasks.delete")
            .expect("delete operation should exist");
        let create_op = manifest
            .provides
            .operations
            .get("asana.tasks.create")
            .expect("create operation should exist");
        let update_op = manifest
            .provides
            .operations
            .get("asana.tasks.update")
            .expect("update operation should exist");

        assert_eq!(delete_op.capability.as_str(), "asana.tasks.delete");
        assert_eq!(create_op.capability.as_str(), "asana.tasks.write");
        assert_eq!(update_op.capability.as_str(), "asana.tasks.write");
        assert!(
            manifest
                .capabilities
                .optional
                .iter()
                .any(|cap| cap.as_str() == "asana.tasks.delete")
        );
        assert_eq!(
            manifest
                .rate_limits
                .operation_pools
                .get("asana.tasks.delete")
                .map(|pools| pools.iter().map(|pool| pool.as_str()).collect::<Vec<_>>()),
            Some(vec!["asana.tasks.delete"])
        );
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_advertises_dedicated_tasks_delete_capability() {
        let mut connector = AsanaConnector::new();
        connector
            .handle_configure(json!({
                "access_token": "tok"
            }))
            .await
            .unwrap();

        let response = connector
            .handle_handshake(json!({
                "session_id": "test-session"
            }))
            .await
            .unwrap();
        let capabilities = response["capabilities"].as_array().unwrap();

        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == Some("asana.tasks.write"))
        );
        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == Some("asana.tasks.delete"))
        );
    }

    #[test]
    fn operations_create_is_medium_risk() {
        let ops = operations_info();
        let create_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"].as_str() == Some("asana.tasks.create"))
            .unwrap();
        assert_eq!(create_op["risk_level"].as_str().unwrap(), "medium");
        assert_eq!(create_op["safety_tier"].as_str().unwrap(), "risky");
    }

    #[test]
    fn operations_update_is_medium_risk() {
        let ops = operations_info();
        let update_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"].as_str() == Some("asana.tasks.update"))
            .unwrap();
        assert_eq!(update_op["risk_level"].as_str().unwrap(), "medium");
    }

    #[test]
    fn operations_all_strict_or_none_idempotency() {
        let ops = operations_info();
        let valid = ["strict", "none"];
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idem),
                "op {} has invalid idempotency: {idem}",
                op["id"]
            );
        }
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let v = serde_json::to_value(status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(back, status);
        }
    }

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
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(!v.contains("message"));
    }

    #[test]
    fn doctor_check_includes_message_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed!".into()),
            critical: true,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(v.contains("message"));
        assert!(v.contains("failed!"));
    }

    #[test]
    fn doctor_result_serde_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        let back: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(back.status, DoctorStatus::Healthy);
        assert_eq!(back.checks.len(), 1);
    }

    #[test]
    fn doctor_check_clone_debug() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let cloned = check.clone();
        assert_eq!(cloned.name, "test_check");
        let dbg = format!("{check:?}");
        assert!(dbg.contains("test_check"));
    }

    #[test]
    fn doctor_result_clone_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let cloned = r.clone();
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn operations_capabilities_map_correctly() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            let cap = op["capability"].as_str().unwrap();
            if id.contains("workspaces") {
                assert_eq!(cap, "asana.workspaces.read");
            } else if id.contains("projects") {
                assert_eq!(cap, "asana.projects.read");
            } else if id.contains("sections") {
                assert_eq!(cap, "asana.sections.read");
            }
        }
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_personal_access_token_mode() {
        let config = AsanaConfig::from_params(&json!({
            "access_token": "1/1234567890:abcdef",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "personal_access_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = AsanaConfig::from_params(&json!({
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
        let config = AsanaConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "personal_access_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = AsanaConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("app.asana.com"));
    }

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "asana.personal_access_token");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "open_developer_console");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_token");
        assert_eq!(recipe.steps[2].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(
            recipe.steps[1].depends_on[0].as_str(),
            "open_developer_console"
        );
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_token");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "asana.personal_access_token");
        assert!(v["steps"].as_array().unwrap().len() == 3);
    }

    #[test]
    fn validate_base_url_for_auth_rejects_query_string_with_pat() {
        let auth = AsanaAuth::PersonalAccessToken("pat_test".into());
        let err =
            validate_base_url_for_auth("https://app.asana.com/api/1.0?leak=x", &auth).unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("query"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_base_url_for_auth_rejects_fragment_with_pat() {
        let auth = AsanaAuth::PersonalAccessToken("pat_test".into());
        let err =
            validate_base_url_for_auth("https://app.asana.com/api/1.0#frag", &auth).unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_base_url_for_auth_rejects_userinfo_with_pat() {
        let auth = AsanaAuth::PersonalAccessToken("pat_test".into());
        let err = validate_base_url_for_auth("https://attacker:pw@app.asana.com/api/1.0", &auth)
            .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_base_url_for_auth_rejects_query_string_with_credential_id() {
        let cid = fcp_core::CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let auth = AsanaAuth::CredentialId(cid);
        let err = validate_base_url_for_auth("https://any-vault-proxy.example/api/?leak=x", &auth)
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_base_url_for_auth_accepts_clean_asana_url() {
        let auth = AsanaAuth::PersonalAccessToken("pat_test".into());
        let out = validate_base_url_for_auth("https://app.asana.com/api/1.0", &auth).unwrap();
        assert_eq!(out, "https://app.asana.com/api/1.0");
    }

    #[test]
    fn base_url_policy_accepts_app_asana_https() {
        let (ok, message) = base_url_policy("https://app.asana.com/api/1.0");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_api_asana_https() {
        let (ok, message) = base_url_policy("https://api.asana.com");
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
    fn base_url_policy_accepts_localhost_https() {
        let (ok, _) = base_url_policy("https://localhost:8443");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://app.asana.com/api/1.0");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("app.asana.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn is_local_test_host_localhost() {
        assert!(is_local_test_host("localhost"));
    }

    #[test]
    fn is_local_test_host_loopback_v4() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_loopback_v6() {
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_rejects_remote() {
        assert!(!is_local_test_host("app.asana.com"));
        assert!(!is_local_test_host("evil.example.com"));
    }

    #[test]
    fn provisioning_readiness_debug_format() {
        let config = AsanaConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let config = AsanaConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = readiness.clone();
        assert_eq!(readiness.auth_mode, cloned.auth_mode);
        assert_eq!(readiness.network_ok, cloned.network_ok);
        assert_eq!(readiness.base_url, cloned.base_url);
    }

    #[test]
    fn provisioning_recipe_description() {
        let recipe = provisioning_recipe();
        assert!(recipe.description.contains("personal access token"));
    }

    #[test]
    fn base_url_policy_case_insensitive_host() {
        let (ok, _) = base_url_policy("https://APP.ASANA.COM/api/1.0");
        assert!(ok);
        let (ok2, _) = base_url_policy("https://Api.Asana.Com");
        assert!(ok2);
    }
}
