//! FCP `Bitbucket` Connector implementation.

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
    client::{BitbucketAuth, BitbucketClient, DEFAULT_BASE_URL},
    error::BitbucketError,
};

/// Parsed and validated `Bitbucket` connector configuration.
#[derive(Debug, Clone)]
struct BitbucketConfig {
    auth: BitbucketAuth,
    base_url: String,
}

impl BitbucketConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let app_password_username = params
            .get("username")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let app_password_value = params
            .get("app_password")
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

        let has_app_password = app_password_username.is_some() && app_password_value.is_some();
        let has_access_token = access_token.is_some();
        let has_credential_id = credential_id.is_some();

        // Count how many auth methods are provided.
        let auth_count =
            u8::from(has_app_password) + u8::from(has_access_token) + u8::from(has_credential_id);

        if auth_count > 1 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message:
                    "Provide exactly one of: access_token, app_password (with username), or credential_id"
                        .into(),
            });
        }

        let auth = if let (Some(u), Some(p)) =
            (app_password_username.clone(), app_password_value.clone())
        {
            BitbucketAuth::AppPassword {
                username: u,
                app_password: p,
            }
        } else if let Some(token) = access_token {
            BitbucketAuth::AccessToken(token)
        } else if let Some(cred_id) = credential_id {
            BitbucketAuth::CredentialId(cred_id)
        } else {
            // Check for partial app password config.
            if app_password_username.is_some() || app_password_value.is_some() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Both username and app_password are required for app password auth"
                        .into(),
                });
            }
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message:
                    "Missing access_token, app_password (with username), or credential_id in configuration"
                        .into(),
            });
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
                BitbucketAuth::AppPassword { .. } => "app_password",
                BitbucketAuth::AccessToken(_) => "access_token",
                BitbucketAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, BitbucketAuth::AccessToken(_)),
            app_password_configured: matches!(&self.auth, BitbucketAuth::AppPassword { .. }),
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
    app_password_configured: bool,
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

/// FCP `Bitbucket` Connector.
pub struct BitbucketConnector {
    base: Arc<BaseConnector>,
    config: Option<BitbucketConfig>,
    client: Option<Arc<BitbucketClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl BitbucketConnector {
    /// Create a new `Bitbucket` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("bitbucket"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for BitbucketConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl BitbucketConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = BitbucketConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Bitbucket connector");

        let client = BitbucketClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.bitbucket",
            "connector_version": "0.1.0",
            "capabilities": [
                "bitbucket.user.read",
                "bitbucket.repositories.read",
                "bitbucket.pull_requests.read",
                "bitbucket.pull_requests.write",
                "bitbucket.branches.read",
                "bitbucket.commits.read",
                "bitbucket.pipelines.read",
                "bitbucket.workspaces.read"
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
            "connector_id": "fcp.bitbucket",
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
            "bitbucket.user.get" => self.invoke_user_get(client).await,
            "bitbucket.repositories.list" => self.invoke_repositories_list(client, &input).await,
            "bitbucket.repositories.get" => self.invoke_repositories_get(client, &input).await,
            "bitbucket.pull_requests.list" => self.invoke_pull_requests_list(client, &input).await,
            "bitbucket.pull_requests.get" => self.invoke_pull_requests_get(client, &input).await,
            "bitbucket.pull_requests.create" => {
                self.invoke_pull_requests_create(client, &input).await
            }
            "bitbucket.branches.list" => self.invoke_branches_list(client, &input).await,
            "bitbucket.commits.list" => self.invoke_commits_list(client, &input).await,
            "bitbucket.pipelines.list" => self.invoke_pipelines_list(client, &input).await,
            "bitbucket.workspaces.list" => self.invoke_workspaces_list(client).await,
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
        info!("Bitbucket connector shutting down");
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

    async fn invoke_user_get(
        &self,
        client: &BitbucketClient,
    ) -> Result<serde_json::Value, BitbucketError> {
        let resp = client.get_user().await?;
        Ok(json!({ "user": resp }))
    }

    async fn invoke_workspaces_list(
        &self,
        client: &BitbucketClient,
    ) -> Result<serde_json::Value, BitbucketError> {
        let resp = client.list_workspaces().await?;
        let values = resp.get("values").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "workspaces": values }))
    }

    async fn invoke_repositories_list(
        &self,
        client: &BitbucketClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitbucketError> {
        let workspace = require_str(input, "workspace")?;
        let resp = client.list_repositories(workspace).await?;
        let values = resp.get("values").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "repositories": values }))
    }

    async fn invoke_repositories_get(
        &self,
        client: &BitbucketClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitbucketError> {
        let workspace = require_str(input, "workspace")?;
        let repo_slug = require_str(input, "repo_slug")?;
        let resp = client.get_repository(workspace, repo_slug).await?;
        Ok(json!({ "repository": resp }))
    }

    async fn invoke_pull_requests_list(
        &self,
        client: &BitbucketClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitbucketError> {
        let workspace = require_str(input, "workspace")?;
        let repo_slug = require_str(input, "repo_slug")?;
        let resp = client.list_pull_requests(workspace, repo_slug).await?;
        let values = resp.get("values").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "pull_requests": values }))
    }

    async fn invoke_pull_requests_get(
        &self,
        client: &BitbucketClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitbucketError> {
        let workspace = require_str(input, "workspace")?;
        let repo_slug = require_str(input, "repo_slug")?;
        let pr_id = require_str(input, "pr_id")?;
        let resp = client.get_pull_request(workspace, repo_slug, pr_id).await?;
        Ok(json!({ "pull_request": resp }))
    }

    async fn invoke_pull_requests_create(
        &self,
        client: &BitbucketClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitbucketError> {
        let workspace = require_str(input, "workspace")?;
        let repo_slug = require_str(input, "repo_slug")?;
        let title = require_str(input, "title")?;
        let source_branch = require_str(input, "source_branch")?;
        let destination_branch = input
            .get("destination_branch")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("main");

        let body = json!({
            "title": title,
            "source": {
                "branch": {
                    "name": source_branch,
                }
            },
            "destination": {
                "branch": {
                    "name": destination_branch,
                }
            }
        });

        client
            .create_pull_request(workspace, repo_slug, &body)
            .await
    }

    async fn invoke_branches_list(
        &self,
        client: &BitbucketClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitbucketError> {
        let workspace = require_str(input, "workspace")?;
        let repo_slug = require_str(input, "repo_slug")?;
        let resp = client.list_branches(workspace, repo_slug).await?;
        let values = resp.get("values").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "branches": values }))
    }

    async fn invoke_commits_list(
        &self,
        client: &BitbucketClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitbucketError> {
        let workspace = require_str(input, "workspace")?;
        let repo_slug = require_str(input, "repo_slug")?;
        let resp = client.list_commits(workspace, repo_slug).await?;
        let values = resp.get("values").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "commits": values }))
    }

    async fn invoke_pipelines_list(
        &self,
        client: &BitbucketClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BitbucketError> {
        let workspace = require_str(input, "workspace")?;
        let repo_slug = require_str(input, "repo_slug")?;
        let resp = client.list_pipelines(workspace, repo_slug).await?;
        let values = resp.get("values").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "pipelines": values }))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "bitbucket.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Bitbucket self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, BitbucketError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BitbucketError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the provisioning recipe for the Bitbucket connector.
///
/// Bitbucket uses app passwords for API access. The recipe walks the user through
/// creating an app password and storing it alongside the username.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("bitbucket.app_password"),
        "1",
        "Provision Bitbucket connector with an app password",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("open_app_passwords"),
        ProvisioningStepType::OpenUrl {
            url: "https://bitbucket.org/account/settings/app-passwords/".into(),
        },
    ))
    .with_step(ProvisioningStep::new(
        StepId::new("enter_username"),
        ProvisioningStepType::PromptUser {
            message: "Enter your Bitbucket username".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_app_password"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your Bitbucket app password".into(),
            },
        )
        .depends_on(StepId::new("open_app_passwords")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_credentials"),
            ProvisioningStepType::StoreSecret {
                key: "app_password".into(),
                value_from: StepId::new("enter_app_password"),
                scope: "connector:fcp.bitbucket".into(),
            },
        )
        .depends_on(StepId::new("enter_username"))
        .depends_on(StepId::new("enter_app_password")),
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
    let allowed_host = host.eq_ignore_ascii_case("api.bitbucket.org")
        || host.eq_ignore_ascii_case("bitbucket.org")
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
                "Endpoint must use https and api.bitbucket.org or bitbucket.org (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("bitbucket.user.get"),
            summary: "Get the authenticated user".into(),
            input_schema: json!({
                "type": "object",
                "required": [],
                "properties": {}
            }),
            output_schema: json!({
                "type": "object",
                "required": ["user"],
                "properties": {
                    "user": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static("bitbucket.user.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Get the currently authenticated Bitbucket user.".into(),
                common_mistakes: vec![],
                examples: vec![r"{}".into()],
                related: vec![CapabilityId::from_static("bitbucket.workspaces.list")],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("bitbucket.repositories.list"),
            summary: "List repositories in a workspace".into(),
            input_schema: json!({
                "type": "object",
                "required": ["workspace"],
                "properties": {
                    "workspace": { "type": "string", "description": "Workspace slug" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["repositories"],
                "properties": {
                    "repositories": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static("bitbucket.repositories.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List repositories in a Bitbucket workspace.".into(),
                common_mistakes: vec![
                    "Using a username instead of the workspace slug — Bitbucket Cloud uses workspace slugs, not the legacy username-based paths.".into(),
                ],
                examples: vec![r#"{"workspace": "myteam"}"#.into()],
                related: vec![
                    CapabilityId::from_static("bitbucket.pull_requests.list"),
                    CapabilityId::from_static("bitbucket.issues.list"),
                ],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("bitbucket.repositories.get"),
            summary: "Get a repository by workspace and slug".into(),
            input_schema: json!({
                "type": "object",
                "required": ["workspace", "repo_slug"],
                "properties": {
                    "workspace": { "type": "string" },
                    "repo_slug": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["repository"],
                "properties": {
                    "repository": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static("bitbucket.repositories.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Get details about a specific Bitbucket repository.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"workspace": "myteam", "repo_slug": "backend"}"#.into()],
                related: vec![CapabilityId::from_static("bitbucket.repositories.list")],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("bitbucket.pull_requests.list"),
            summary: "List pull requests in a repository".into(),
            input_schema: json!({
                "type": "object",
                "required": ["workspace", "repo_slug"],
                "properties": {
                    "workspace": { "type": "string" },
                    "repo_slug": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["pull_requests"],
                "properties": {
                    "pull_requests": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static("bitbucket.pull_requests.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List pull requests in a repository.".into(),
                common_mistakes: vec![
                    "Assuming only open PRs are returned — the default includes all states; use the state filter to scope to OPEN, MERGED, or DECLINED.".into(),
                ],
                examples: vec![r#"{"workspace": "myteam", "repo_slug": "backend"}"#.into()],
                related: vec![
                    CapabilityId::from_static("bitbucket.repositories.list"),
                    CapabilityId::from_static("bitbucket.pull_requests.create"),
                ],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("bitbucket.pull_requests.get"),
            summary: "Get a specific pull request".into(),
            input_schema: json!({
                "type": "object",
                "required": ["workspace", "repo_slug", "pr_id"],
                "properties": {
                    "workspace": { "type": "string" },
                    "repo_slug": { "type": "string" },
                    "pr_id": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["pull_request"],
                "properties": {
                    "pull_request": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static("bitbucket.pull_requests.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Get details about a specific pull request.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"workspace": "myteam", "repo_slug": "backend", "pr_id": "42"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("bitbucket.pull_requests.list")],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("bitbucket.pull_requests.create"),
            summary: "Create a new pull request".into(),
            input_schema: json!({
                "type": "object",
                "required": ["workspace", "repo_slug", "title", "source_branch"],
                "properties": {
                    "workspace": { "type": "string" },
                    "repo_slug": { "type": "string" },
                    "title": { "type": "string" },
                    "source_branch": { "type": "string" },
                    "destination_branch": { "type": "string", "description": "Target branch (defaults to main)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("bitbucket.pull_requests.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Create a new pull request.".into(),
                common_mistakes: vec![
                    "Not specifying the destination branch — if omitted it defaults to the repo's main branch, which may not be the intended merge target.".into(),
                ],
                examples: vec![
                    r#"{"workspace": "myteam", "repo_slug": "backend", "title": "Fix login bug", "source_branch": "fix/login"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("bitbucket.pull_requests.list")],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("bitbucket.branches.list"),
            summary: "List branches in a repository".into(),
            input_schema: json!({
                "type": "object",
                "required": ["workspace", "repo_slug"],
                "properties": {
                    "workspace": { "type": "string" },
                    "repo_slug": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["branches"],
                "properties": {
                    "branches": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static("bitbucket.branches.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List branches in a Bitbucket repository.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"workspace": "myteam", "repo_slug": "backend"}"#.into()],
                related: vec![CapabilityId::from_static("bitbucket.repositories.list")],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("bitbucket.commits.list"),
            summary: "List commits in a repository".into(),
            input_schema: json!({
                "type": "object",
                "required": ["workspace", "repo_slug"],
                "properties": {
                    "workspace": { "type": "string" },
                    "repo_slug": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["commits"],
                "properties": {
                    "commits": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static("bitbucket.commits.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List commits in a Bitbucket repository.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"workspace": "myteam", "repo_slug": "backend"}"#.into()],
                related: vec![CapabilityId::from_static("bitbucket.repositories.list")],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("bitbucket.pipelines.list"),
            summary: "List pipelines in a repository".into(),
            input_schema: json!({
                "type": "object",
                "required": ["workspace", "repo_slug"],
                "properties": {
                    "workspace": { "type": "string" },
                    "repo_slug": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["pipelines"],
                "properties": {
                    "pipelines": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static("bitbucket.pipelines.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List CI/CD pipelines.".into(),
                common_mistakes: vec![
                    "Expecting pipelines on repos without a bitbucket-pipelines.yml — Pipelines must be configured in the repository before they can be listed.".into(),
                ],
                examples: vec![r#"{"workspace": "myteam", "repo_slug": "backend"}"#.into()],
                related: vec![CapabilityId::from_static("bitbucket.repositories.list")],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("bitbucket.workspaces.list"),
            summary: "List workspaces accessible by the authenticated user".into(),
            input_schema: json!({
                "type": "object",
                "required": [],
                "properties": {}
            }),
            output_schema: json!({
                "type": "object",
                "required": ["workspaces"],
                "properties": {
                    "workspaces": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static("bitbucket.workspaces.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List Bitbucket workspaces accessible by the authenticated user.".into(),
                common_mistakes: vec![],
                examples: vec![r"{}".into()],
                related: vec![CapabilityId::from_static("bitbucket.repositories.list")],
            },
            description: None,
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_access_token() {
        let config = BitbucketConfig::from_params(&json!({
            "access_token": "test-access-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, BitbucketAuth::AccessToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_app_password() {
        let config = BitbucketConfig::from_params(&json!({
            "username": "myuser",
            "app_password": "my-app-password",
        }))
        .unwrap();
        assert!(matches!(config.auth, BitbucketAuth::AppPassword { .. }));
    }

    #[test]
    fn config_from_credential_id() {
        let config = BitbucketConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = BitbucketConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://bitbucket.example.com/2.0",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://bitbucket.example.com/2.0");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = BitbucketConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = BitbucketConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = BitbucketConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = BitbucketConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = BitbucketConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = BitbucketConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_username_without_app_password() {
        let result = BitbucketConfig::from_params(&json!({
            "username": "myuser",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_app_password_without_username() {
        let result = BitbucketConfig::from_params(&json!({
            "app_password": "my-pass",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config =
            BitbucketConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            BitbucketAuth::AccessToken(t) => assert_eq!(t, "tok_test"),
            _ => panic!("expected AccessToken"),
        }
    }

    #[test]
    fn require_str_present() {
        let input = json!({"workspace": "myteam"});
        assert_eq!(require_str(&input, "workspace").unwrap(), "myteam");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "workspace").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"workspace": 42});
        assert!(require_str(&input, "workspace").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"workspace": null});
        assert!(require_str(&input, "workspace").is_err());
    }

    #[test]
    fn operations_info_has_10_operations() {
        assert_eq!(operations_info().len(), 10);
    }

    #[test]
    fn operations_all_have_summaries() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "op {:?} has empty summary",
                op.id.as_ref()
            );
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
            // All RiskLevel enum variants are valid by construction
            let _ = op.risk_level;
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            // All SafetyTier enum variants are valid by construction
            let _ = op.safety_tier;
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
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
        assert!(ids.contains(&"bitbucket.user.get"));
        assert!(ids.contains(&"bitbucket.repositories.list"));
        assert!(ids.contains(&"bitbucket.repositories.get"));
        assert!(ids.contains(&"bitbucket.pull_requests.list"));
        assert!(ids.contains(&"bitbucket.pull_requests.get"));
        assert!(ids.contains(&"bitbucket.pull_requests.create"));
        assert!(ids.contains(&"bitbucket.branches.list"));
        assert!(ids.contains(&"bitbucket.commits.list"));
        assert!(ids.contains(&"bitbucket.pipelines.list"));
        assert!(ids.contains(&"bitbucket.workspaces.list"));
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
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            // IdempotencyClass is always present by construction in typed OperationInfo
            let _ = op.idempotency;
        }
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = BitbucketConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = BitbucketConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_request_count_starts_at_zero() {
        let c = BitbucketConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_error_count_starts_at_zero() {
        let c = BitbucketConnector::new();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_rejects_three_auth_methods() {
        let result = BitbucketConfig::from_params(&json!({
            "access_token": "tok",
            "username": "u",
            "app_password": "p",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_access_token_plus_app_password() {
        let result = BitbucketConfig::from_params(&json!({
            "access_token": "tok",
            "username": "u",
            "app_password": "p",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_app_password_plus_credential_id() {
        let result = BitbucketConfig::from_params(&json!({
            "username": "u",
            "app_password": "p",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_app_password_username() {
        let config = BitbucketConfig::from_params(&json!({
            "username": "  user  ",
            "app_password": "pass",
        }))
        .unwrap();
        match &config.auth {
            BitbucketAuth::AppPassword { username, .. } => assert_eq!(username, "user"),
            _ => panic!("expected AppPassword"),
        }
    }

    #[test]
    fn doctor_check_serializes_with_message() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: false,
            message: Some("failure reason".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["name"], "test_check");
        assert_eq!(v["passed"], false);
        assert_eq!(v["message"], "failure reason");
        assert_eq!(v["critical"], true);
    }

    #[test]
    fn doctor_check_serializes_without_message() {
        let check = DoctorCheck {
            name: "ok_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["name"], "ok_check");
        assert_eq!(v["passed"], true);
        // message should be skipped when None
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let statuses = [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ];
        for status in &statuses {
            let v = serde_json::to_value(status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(*status, back);
        }
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let c = r.clone();
        assert_eq!(c.status, DoctorStatus::Healthy);
        assert_eq!(c.checks.len(), 1);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn operations_write_ops_not_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            if cap.contains("write") {
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
    fn operations_create_pr_is_risky() {
        let ops = operations_info();
        let create_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitbucket.pull_requests.create")
            .unwrap();
        assert_eq!(create_op.safety_tier, SafetyTier::Risky);
        assert_eq!(create_op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn operations_user_get_summary() {
        let ops = operations_info();
        let user_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "bitbucket.user.get")
            .unwrap();
        assert!(user_op.summary.len() > 5);
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"workspace": true});
        assert!(require_str(&input, "workspace").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"workspace": ["a", "b"]});
        assert!(require_str(&input, "workspace").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"workspace": {"nested": true}});
        assert!(require_str(&input, "workspace").is_err());
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_access_token_mode() {
        let config = BitbucketConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "access_token");
        assert!(readiness.token_configured);
        assert!(!readiness.app_password_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_app_password_mode() {
        let config = BitbucketConfig::from_params(&json!({
            "username": "myuser",
            "app_password": "my-app-pass",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "app_password");
        assert!(!readiness.token_configured);
        assert!(readiness.app_password_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = BitbucketConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(!readiness.app_password_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = BitbucketConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "access_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["app_password_configured"], false);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = BitbucketConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("api.bitbucket.org"));
    }

    #[test]
    fn provisioning_recipe_has_4_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "bitbucket.app_password");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 4);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "open_app_passwords");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_username");
        assert_eq!(recipe.steps[2].id.as_str(), "enter_app_password");
        assert_eq!(recipe.steps[3].id.as_str(), "store_credentials");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        // open_app_passwords has no deps
        assert!(recipe.steps[0].depends_on.is_empty());
        // enter_username has no deps
        assert!(recipe.steps[1].depends_on.is_empty());
        // enter_app_password depends on open_app_passwords
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "open_app_passwords");
        // store_credentials depends on enter_username and enter_app_password
        assert_eq!(recipe.steps[3].depends_on.len(), 2);
        let store_deps: Vec<&str> = recipe.steps[3]
            .depends_on
            .iter()
            .map(|d| d.as_str())
            .collect();
        assert!(store_deps.contains(&"enter_username"));
        assert!(store_deps.contains(&"enter_app_password"));
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "bitbucket.app_password");
        assert_eq!(v["steps"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn base_url_policy_accepts_api_bitbucket_org_https() {
        let (ok, message) = base_url_policy("https://api.bitbucket.org");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_bitbucket_org_https() {
        let (ok, message) = base_url_policy("https://bitbucket.org");
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
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, msg) = base_url_policy("http://[::1]:8080");
        assert!(ok, "Expected ok=true but got msg: {msg}");
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://api.bitbucket.org");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("api.bitbucket.org"));
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
    fn is_local_test_host_127() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_ipv6() {
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_rejects_remote() {
        assert!(!is_local_test_host("api.bitbucket.org"));
        assert!(!is_local_test_host("example.com"));
    }

    #[test]
    fn provisioning_readiness_debug_format() {
        let config = BitbucketConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
        assert!(dbg.contains("access_token"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let config = BitbucketConfig::from_params(&json!({
            "username": "u",
            "app_password": "p",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = readiness.clone();
        assert_eq!(readiness.auth_mode, "app_password");
        assert_eq!(cloned.auth_mode, "app_password");
        assert_eq!(readiness.base_url, cloned.base_url);
    }
}
