//! FCP Dropbox Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OAuthRecipe, OperationId, OperationInfo, ProvisioningRecipe,
    ProvisioningStep, ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport,
    StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, DEFAULT_CONTENT_URL, DropboxAuth, DropboxClient},
    error::DropboxError,
};

/// Parsed and validated Dropbox connector configuration.
#[derive(Debug, Clone)]
struct DropboxConfig {
    auth: DropboxAuth,
    base_url: String,
    content_url: String,
}

impl DropboxConfig {
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
            (Some(token), None) => DropboxAuth::BearerToken(token),
            (None, Some(cred_id)) => DropboxAuth::CredentialId(cred_id),
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
        reject_base_url_qfu("base_url", &base_url)?;

        let content_url = params
            .get("content_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_CONTENT_URL)
            .to_string();
        reject_base_url_qfu("content_url", &content_url)?;

        Ok(Self {
            auth,
            base_url,
            content_url,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                DropboxAuth::BearerToken(_) => "bearer_token",
                DropboxAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, DropboxAuth::BearerToken(_)),
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

/// FCP Dropbox Connector.
pub struct DropboxConnector {
    base: Arc<BaseConnector>,
    config: Option<DropboxConfig>,
    client: Option<Arc<DropboxClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl DropboxConnector {
    /// Create a new Dropbox connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("dropbox"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for DropboxConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl DropboxConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = DropboxConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Dropbox connector");

        let client = DropboxClient::new(
            config.auth.clone(),
            Some(&config.base_url),
            Some(&config.content_url),
        )
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
            "connector_id": "fcp.dropbox",
            "connector_version": "0.1.0",
            "capabilities": [
                "dropbox.files.read",
                "dropbox.files.write",
                "dropbox.account.read"
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
            "connector_id": "fcp.dropbox",
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
            "dropbox.files.list" => self.invoke_files_list(client, &input).await,
            "dropbox.files.list_continue" => self.invoke_files_list_continue(client, &input).await,
            "dropbox.files.get_metadata" => self.invoke_files_get_metadata(client, &input).await,
            "dropbox.files.create_folder" => self.invoke_files_create_folder(client, &input).await,
            "dropbox.files.delete" => self.invoke_files_delete(client, &input).await,
            "dropbox.files.move" => self.invoke_files_move(client, &input).await,
            "dropbox.files.copy" => self.invoke_files_copy(client, &input).await,
            "dropbox.files.search" => self.invoke_files_search(client, &input).await,
            "dropbox.account.get_space_usage" => self.invoke_account_get_space_usage(client).await,
            "dropbox.account.get_current" => self.invoke_account_get_current(client).await,
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
        info!("Dropbox connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations ------------------------------------------------

    async fn invoke_files_list(
        &self,
        client: &DropboxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DropboxError> {
        let path = require_str(input, "path")?;
        client.list_folder(path).await
    }

    async fn invoke_files_get_metadata(
        &self,
        client: &DropboxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DropboxError> {
        let path = require_str(input, "path")?;
        client.get_metadata(path).await
    }

    async fn invoke_files_delete(
        &self,
        client: &DropboxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DropboxError> {
        let path = require_str(input, "path")?;
        client.delete(path).await
    }

    async fn invoke_files_list_continue(
        &self,
        client: &DropboxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DropboxError> {
        let cursor = require_str(input, "cursor")?;
        client.list_folder_continue(cursor).await
    }

    async fn invoke_files_create_folder(
        &self,
        client: &DropboxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DropboxError> {
        let path = require_str(input, "path")?;
        client.create_folder(path).await
    }

    async fn invoke_files_move(
        &self,
        client: &DropboxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DropboxError> {
        let from_path = require_str(input, "from_path")?;
        let to_path = require_str(input, "to_path")?;
        client.move_path(from_path, to_path).await
    }

    async fn invoke_files_copy(
        &self,
        client: &DropboxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DropboxError> {
        let from_path = require_str(input, "from_path")?;
        let to_path = require_str(input, "to_path")?;
        client.copy_path(from_path, to_path).await
    }

    async fn invoke_files_search(
        &self,
        client: &DropboxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DropboxError> {
        let query = require_str(input, "query")?;
        client.search(query).await
    }

    async fn invoke_account_get_space_usage(
        &self,
        client: &DropboxClient,
    ) -> Result<serde_json::Value, DropboxError> {
        client.get_space_usage().await
    }

    async fn invoke_account_get_current(
        &self,
        client: &DropboxClient,
    ) -> Result<serde_json::Value, DropboxError> {
        client.get_current_account().await
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "dropbox.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Dropbox self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, DropboxError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DropboxError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the provisioning recipe for the Dropbox connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("dropbox.oauth2"),
        "1",
        "Provision Dropbox connector with OAuth2 Authorization Code (PKCE)",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("oauth_authorize"),
        ProvisioningStepType::Oauth {
            flow: OAuthRecipe::AuthorizationCodePkce {
                authorization_url: "https://www.dropbox.com/oauth2/authorize".into(),
                token_url: "https://api.dropboxapi.com/oauth2/token".into(),
                scopes: vec![
                    "files.metadata.read".into(),
                    "files.metadata.write".into(),
                    "files.content.read".into(),
                    "files.content.write".into(),
                    "account_info.read".into(),
                ],
                auto_browser: true,
                callback_port: 8080,
            },
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("oauth_authorize"),
                scope: "connector:fcp.dropbox".into(),
            },
        )
        .depends_on(StepId::new("oauth_authorize")),
    )
}

/// Reject base_url / content_url overrides with userinfo, query, or
/// fragment. The DropboxClient concatenates base_url via
/// format!("{}{endpoint}", self.base_url) (client.rs:191) and similarly
/// uses content_url for content endpoints. Without this check, a
/// base_url like `https://api.dropboxapi.com/2?leak=x` would leak
/// attacker-chosen query values on every request and put the endpoint
/// path after the `?` boundary. Userinfo
/// (`https://attacker:pw@api.dropboxapi.com/2`) would bake into every
/// request URL and silently override the OAuth Authorization header.
/// Matches the hygiene in airtable / asana / gmail / notion / hubspot
/// / whatsapp / linear / clickup / monday / bitbucket / intercom.
fn reject_base_url_qfu(field: &str, url: &str) -> FcpResult<()> {
    let parsed = Url::parse(url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} could not be parsed: {error}"),
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must not include userinfo"),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must not include a query string or fragment"),
        });
    }
    Ok(())
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
    let allowed_host = host.eq_ignore_ascii_case("api.dropboxapi.com")
        || host.eq_ignore_ascii_case("content.dropboxapi.com")
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
                "Endpoint must use https and api.dropboxapi.com or content.dropboxapi.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Build a single [`OperationInfo`].
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
            "dropbox.files.list",
            "List files and folders in a path",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "Folder path (empty string for root)" }
                }
            }),
            json!({
                "type": "object",
                "required": ["entries"],
                "properties": {
                    "entries": { "type": "array" }
                }
            }),
            "dropbox.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List files and folders at a Dropbox path.".into(),
                common_mistakes: vec![
                    "Using / instead of empty string for root.".into(),
                ],
                examples: vec![r#"{"path": "/Documents"}"#.into()],
                related: vec![
                    CapabilityId::from_static("dropbox.files.get_metadata"),
                    CapabilityId::from_static("dropbox.files.delete"),
                ],
            },
        ),
        op_info(
            "dropbox.files.list_continue",
            "Continue listing files using a cursor",
            json!({
                "type": "object",
                "required": ["cursor"],
                "properties": {
                    "cursor": { "type": "string", "description": "Pagination cursor from a previous list call" }
                }
            }),
            json!({
                "type": "object",
                "required": ["entries"],
                "properties": {
                    "entries": { "type": "array" }
                }
            }),
            "dropbox.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Continue paginating through a large folder listing.".into(),
                common_mistakes: vec![
                    "Reusing an expired cursor; cursors are only valid for a short time after the initial list call.".into(),
                ],
                examples: vec![r#"{"cursor": "ZtkX9_EHj3x7PMkVuFIhwKYXEpwpLMyy..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("dropbox.files.list"),
                ],
            },
        ),
        op_info(
            "dropbox.files.get_metadata",
            "Get metadata for a file or folder",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["name", "path_display"],
                "properties": {
                    "name": { "type": "string" },
                    "path_display": { "type": "string" }
                }
            }),
            "dropbox.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get metadata for a specific file or folder.".into(),
                common_mistakes: vec![
                    "Passing a Dropbox shared link URL instead of a file path; use the full path like /Documents/file.txt.".into(),
                ],
                examples: vec![r#"{"path": "/Documents/report.pdf"}"#.into()],
                related: vec![
                    CapabilityId::from_static("dropbox.files.list"),
                ],
            },
        ),
        op_info(
            "dropbox.files.create_folder",
            "Create a new folder",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "Path for the new folder" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "path_display": { "type": "string" }
                }
            }),
            "dropbox.files.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new folder at the given path.".into(),
                common_mistakes: vec![
                    "Attempting to create a folder that already exists; Dropbox returns a conflict error.".into(),
                ],
                examples: vec![r#"{"path": "/Documents/New Folder"}"#.into()],
                related: vec![
                    CapabilityId::from_static("dropbox.files.list"),
                    CapabilityId::from_static("dropbox.files.delete"),
                ],
            },
        ),
        op_info(
            "dropbox.files.delete",
            "Delete a file or folder",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "dropbox.files.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Delete a file or folder. Moves to trash (recoverable for 30 days).".into(),
                common_mistakes: vec![
                    "Paths must start with a forward slash and are case-insensitive; passing a relative path without a leading slash will fail.".into(),
                ],
                examples: vec![r#"{"path": "/Documents/old_report.pdf"}"#.into()],
                related: vec![
                    CapabilityId::from_static("dropbox.files.list"),
                ],
            },
        ),
        op_info(
            "dropbox.files.move",
            "Move a file or folder",
            json!({
                "type": "object",
                "required": ["from_path", "to_path"],
                "properties": {
                    "from_path": { "type": "string", "description": "Source path" },
                    "to_path": { "type": "string", "description": "Destination path" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "path_display": { "type": "string" }
                }
            }),
            "dropbox.files.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Move a file or folder from one path to another.".into(),
                common_mistakes: vec![
                    "Providing a destination path that already exists without handling the conflict.".into(),
                ],
                examples: vec![r#"{"from_path": "/Documents/old.pdf", "to_path": "/Archive/old.pdf"}"#.into()],
                related: vec![
                    CapabilityId::from_static("dropbox.files.copy"),
                    CapabilityId::from_static("dropbox.files.list"),
                ],
            },
        ),
        op_info(
            "dropbox.files.copy",
            "Copy a file or folder",
            json!({
                "type": "object",
                "required": ["from_path", "to_path"],
                "properties": {
                    "from_path": { "type": "string", "description": "Source path" },
                    "to_path": { "type": "string", "description": "Destination path" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "path_display": { "type": "string" }
                }
            }),
            "dropbox.files.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Copy a file or folder from one path to another.".into(),
                common_mistakes: vec![
                    "Providing a destination path that already exists without handling the conflict.".into(),
                ],
                examples: vec![r#"{"from_path": "/Documents/report.pdf", "to_path": "/Backup/report.pdf"}"#.into()],
                related: vec![
                    CapabilityId::from_static("dropbox.files.move"),
                    CapabilityId::from_static("dropbox.files.list"),
                ],
            },
        ),
        op_info(
            "dropbox.files.search",
            "Search for files by name or content",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string", "description": "Search query string" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "matches": { "type": "array" }
                }
            }),
            "dropbox.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Search for files by name or content across the Dropbox account.".into(),
                common_mistakes: vec![
                    "Expecting instant results; Dropbox search may take time to index recent changes.".into(),
                ],
                examples: vec![r#"{"query": "quarterly report"}"#.into()],
                related: vec![
                    CapabilityId::from_static("dropbox.files.list"),
                    CapabilityId::from_static("dropbox.files.get_metadata"),
                ],
            },
        ),
        op_info(
            "dropbox.account.get_space_usage",
            "Get space usage for the current account",
            json!({ "type": "object" }),
            json!({
                "type": "object",
                "properties": {
                    "used": { "type": "integer" },
                    "allocation": { "type": "object" }
                }
            }),
            "dropbox.account.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Check how much storage space is used and available.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("dropbox.account.get_current"),
                ],
            },
        ),
        op_info(
            "dropbox.account.get_current",
            "Get current account information",
            json!({ "type": "object" }),
            json!({
                "type": "object",
                "properties": {
                    "account_id": { "type": "string" },
                    "name": { "type": "object" },
                    "email": { "type": "string" }
                }
            }),
            "dropbox.account.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get the current authenticated account information.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("dropbox.account.get_space_usage"),
                ],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_access_token() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, DropboxAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.content_url, DEFAULT_CONTENT_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = DropboxConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://dropbox.example.com/2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://dropbox.example.com/2");
    }

    #[test]
    fn config_custom_content_url() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "content_url": "https://content.example.com/2",
        }))
        .unwrap();
        assert_eq!(config.content_url, "https://content.example.com/2");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = DropboxConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = DropboxConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = DropboxConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = DropboxConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = DropboxConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config =
            DropboxConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            DropboxAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            DropboxAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn config_default_urls() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.dropboxapi.com/2");
        assert_eq!(config.content_url, "https://content.dropboxapi.com/2");
    }

    #[test]
    fn config_both_custom_urls() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://custom.api.dropbox.com",
            "content_url": "https://custom.content.dropbox.com",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://custom.api.dropbox.com");
        assert_eq!(config.content_url, "https://custom.content.dropbox.com");
    }

    #[test]
    fn require_str_present() {
        let input = json!({"path": "/Documents"});
        assert_eq!(require_str(&input, "path").unwrap(), "/Documents");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"path": 42});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"path": null});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"path": [1, 2, 3]});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"path": true});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"path": ""});
        // Empty string is valid for Dropbox root path
        assert_eq!(require_str(&input, "path").unwrap(), "");
    }

    #[test]
    fn operations_info_has_10_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 10);
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
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            if cap.ends_with(".read") {
                assert!(
                    matches!(op.safety_tier, SafetyTier::Safe),
                    "read op {} should be safe",
                    op.id.as_ref()
                );
                assert!(
                    matches!(op.risk_level, RiskLevel::Low),
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
        assert!(ids.contains(&"dropbox.files.list"));
        assert!(ids.contains(&"dropbox.files.list_continue"));
        assert!(ids.contains(&"dropbox.files.get_metadata"));
        assert!(ids.contains(&"dropbox.files.create_folder"));
        assert!(ids.contains(&"dropbox.files.delete"));
        assert!(ids.contains(&"dropbox.files.move"));
        assert!(ids.contains(&"dropbox.files.copy"));
        assert!(ids.contains(&"dropbox.files.search"));
        assert!(ids.contains(&"dropbox.account.get_space_usage"));
        assert!(ids.contains(&"dropbox.account.get_current"));
    }

    #[test]
    fn operations_files_list_is_strict_idempotent() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "dropbox.files.list")
            .unwrap();
        assert!(matches!(op.idempotency, IdempotencyClass::Strict));
    }

    #[test]
    fn operations_files_delete_is_dangerous() {
        let ops = operations_info();
        let del_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "dropbox.files.delete")
            .unwrap();
        assert!(matches!(del_op.safety_tier, SafetyTier::Dangerous));
        assert!(matches!(del_op.risk_level, RiskLevel::High));
    }

    #[test]
    fn operations_account_capability_correct() {
        let ops = operations_info();
        let account_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "dropbox.account.get_current")
            .unwrap();
        assert_eq!(account_op.capability.as_ref(), "dropbox.account.read");
    }

    #[test]
    fn operations_files_read_capability_correct() {
        let ops = operations_info();
        let list_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "dropbox.files.list")
            .unwrap();
        assert_eq!(list_op.capability.as_ref(), "dropbox.files.read");

        let meta_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "dropbox.files.get_metadata")
            .unwrap();
        assert_eq!(meta_op.capability.as_ref(), "dropbox.files.read");
    }

    #[test]
    fn operations_delete_capability_correct() {
        let ops = operations_info();
        let del_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "dropbox.files.delete")
            .unwrap();
        assert_eq!(del_op.capability.as_ref(), "dropbox.files.write");
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn operations_write_ops_are_not_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            if cap.ends_with(".write") {
                assert!(
                    !matches!(op.safety_tier, SafetyTier::Safe),
                    "write op {} should not be safe",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.ai_hints.when_to_use.is_empty(),
                "op {} missing when_to_use hint",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_serializes_to_json() {
        let ops = operations_info();
        let val = serde_json::to_value(&ops).unwrap();
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 10);
        for op in arr {
            assert!(op.get("id").is_some());
            assert!(op.get("summary").is_some());
            assert!(op.get("ai_hints").is_some());
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
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
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
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_mixed_failures() {
        let checks = vec![
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
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_check_skips_none_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(v.get("message").is_none());
    }

    #[test]
    fn doctor_check_includes_some_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("something wrong".into()),
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "something wrong");
    }

    #[test]
    fn connector_default() {
        let c = DropboxConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_is_unconfigured() {
        let c = DropboxConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = DropboxConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
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
    fn doctor_status_deserializes() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
    }

    #[test]
    fn require_str_nested_object() {
        let input = json!({"path": {"nested": true}});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn operations_files_move_capability() {
        let ops = operations_info();
        let mv = ops
            .iter()
            .find(|o| o.id.as_ref() == "dropbox.files.move")
            .unwrap();
        assert_eq!(mv.capability.as_ref(), "dropbox.files.write");
    }

    #[test]
    fn operations_files_copy_capability() {
        let ops = operations_info();
        let cp = ops
            .iter()
            .find(|o| o.id.as_ref() == "dropbox.files.copy")
            .unwrap();
        assert_eq!(cp.capability.as_ref(), "dropbox.files.write");
    }

    #[test]
    fn operations_search_capability() {
        let ops = operations_info();
        let search = ops
            .iter()
            .find(|o| o.id.as_ref() == "dropbox.files.search")
            .unwrap();
        assert_eq!(search.capability.as_ref(), "dropbox.files.read");
        assert!(matches!(search.safety_tier, SafetyTier::Safe));
    }

    #[test]
    fn operations_space_usage_capability() {
        let ops = operations_info();
        let sp = ops
            .iter()
            .find(|o| o.id.as_ref() == "dropbox.account.get_space_usage")
            .unwrap();
        assert_eq!(sp.capability.as_ref(), "dropbox.account.read");
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_result_deserialize_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let json_str = serde_json::to_string(&r).unwrap();
        let r2: DoctorResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(r2.status, DoctorStatus::Healthy);
        assert_eq!(r2.checks.len(), 1);
        assert_eq!(r2.checks[0].name, "cfg");
    }

    #[test]
    fn doctor_status_debug_format() {
        let s = DoctorStatus::Unhealthy;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Unhealthy"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn config_clone_preserves_fields() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok_clone_test",
            "base_url": "https://custom.dbx.com/2",
            "content_url": "https://content.dbx.com/2",
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, cloned.base_url);
        assert_eq!(config.content_url, cloned.content_url);
    }

    #[test]
    fn config_debug_format() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok_debug",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("DropboxConfig"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn operations_summaries_are_non_empty() {
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
    fn connector_new_no_session_id() {
        let c = DropboxConnector::new();
        assert!(c.session_id.is_none());
    }

    #[test]
    fn doctor_check_deserialize_with_message() {
        let v = json!({
            "name": "handshake",
            "passed": false,
            "message": "not done",
            "critical": false,
        });
        let check: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(check.name, "handshake");
        assert!(!check.passed);
        assert_eq!(check.message, Some("not done".into()));
    }

    #[test]
    fn doctor_status_deserialize_rejects_invalid() {
        let r: Result<DoctorStatus, _> = serde_json::from_value(json!("bogus"));
        assert!(r.is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"path": {"sub": "val"}});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"path": 2.71});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn operations_capabilities_start_with_dropbox() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            assert!(
                cap.starts_with("dropbox."),
                "op {} capability '{}' does not start with dropbox.",
                op.id.as_ref(),
                cap
            );
        }
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_result_clone_preserves_checks() {
        let r = DoctorResult::from_checks(vec![
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
        ]);
        let cloned = r.clone();
        assert_eq!(cloned.status, DoctorStatus::Degraded);
        assert_eq!(cloned.checks.len(), 2);
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_bearer_token_mode() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "test-token",
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
        let config = DropboxConfig::from_params(&json!({
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
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "dropbox.oauth2");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "oauth_authorize");
        assert_eq!(recipe.steps[1].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "oauth_authorize");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "dropbox.oauth2");
        assert!(v["steps"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn provisioning_recipe_oauth_step_has_correct_urls() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let oauth_step = &v["steps"][0];
        let flow = &oauth_step["flow"];
        assert_eq!(
            flow["authorization_url"],
            "https://www.dropbox.com/oauth2/authorize"
        );
        assert_eq!(flow["token_url"], "https://api.dropboxapi.com/oauth2/token");
    }

    #[test]
    fn provisioning_recipe_oauth_step_has_scopes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let oauth_step = &v["steps"][0];
        let scopes = oauth_step["flow"]["scopes"].as_array().unwrap();
        assert!(!scopes.is_empty());
        assert!(
            scopes
                .iter()
                .any(|s| s.as_str() == Some("files.metadata.read"))
        );
    }

    #[test]
    fn provisioning_recipe_store_step_scope() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let store_step = &v["steps"][1];
        assert_eq!(store_step["scope"], "connector:fcp.dropbox");
        assert_eq!(store_step["key"], "access_token");
    }

    #[test]
    fn base_url_policy_accepts_dropbox_api_https() {
        let (ok, message) = base_url_policy("https://api.dropboxapi.com/2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_content_dropbox_https() {
        let (ok, message) = base_url_policy("https://content.dropboxapi.com/2");
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
        let (ok, message) = base_url_policy("http://api.dropboxapi.com/2");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("api.dropboxapi.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_case_insensitive_host() {
        let (ok, _) = base_url_policy("https://API.DROPBOXAPI.COM/2");
        assert!(ok);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("api.dropboxapi.com"));
    }

    #[test]
    fn provisioning_readiness_debug_format() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
        assert!(dbg.contains("bearer_token"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        #[allow(clippy::redundant_clone)]
        let cloned = readiness.clone();
        assert_eq!(readiness.auth_mode, cloned.auth_mode);
        assert_eq!(readiness.network_ok, cloned.network_ok);
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
    fn is_local_test_host_rejects_external() {
        assert!(!is_local_test_host("api.dropboxapi.com"));
        assert!(!is_local_test_host("example.com"));
    }

    #[test]
    fn from_params_accepts_clean_urls() {
        let config = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://api.dropboxapi.com/2",
            "content_url": "https://content.dropboxapi.com/2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.dropboxapi.com/2");
        assert_eq!(config.content_url, "https://content.dropboxapi.com/2");
    }

    #[test]
    fn from_params_rejects_base_url_query_string() {
        let err = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://api.dropboxapi.com/2?leak=x",
        }))
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("base_url"), "got: {message}");
                assert!(message.contains("query"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_params_rejects_base_url_fragment() {
        let err = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://api.dropboxapi.com/2#frag",
        }))
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn from_params_rejects_base_url_userinfo() {
        let err = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://attacker:pw@api.dropboxapi.com/2",
        }))
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_params_rejects_content_url_query_string() {
        let err = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "content_url": "https://content.dropboxapi.com/2?leak=x",
        }))
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("content_url"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_params_rejects_content_url_userinfo() {
        let err = DropboxConfig::from_params(&json!({
            "access_token": "tok",
            "content_url": "https://attacker:pw@content.dropboxapi.com/2",
        }))
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }
}
