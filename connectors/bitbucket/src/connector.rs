//! FCP `Bitbucket` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
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

        let has_app_password =
            app_password_username.is_some() && app_password_value.is_some();
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

        let auth = if let (Some(u), Some(p)) = (app_password_username.clone(), app_password_value.clone()) {
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
        Ok(json!({
            "connector_id": "fcp.bitbucket",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.bitbucket",
            "version": "0.1.0",
            "operations": operations_info(),
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
            "bitbucket.repositories.list" => {
                self.invoke_repositories_list(client, &input).await
            }
            "bitbucket.repositories.get" => {
                self.invoke_repositories_get(client, &input).await
            }
            "bitbucket.pull_requests.list" => {
                self.invoke_pull_requests_list(client, &input).await
            }
            "bitbucket.pull_requests.get" => {
                self.invoke_pull_requests_get(client, &input).await
            }
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
        info!("Bitbucket connector shutting down");
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
        let resp = client
            .get_pull_request(workspace, repo_slug, pr_id)
            .await?;
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

        client.create_pull_request(workspace, repo_slug, &body).await
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

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "bitbucket.user.get",
            "summary": "Get the authenticated user",
            "capability": "bitbucket.user.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bitbucket.repositories.list",
            "summary": "List repositories in a workspace",
            "capability": "bitbucket.repositories.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bitbucket.repositories.get",
            "summary": "Get a repository by workspace and slug",
            "capability": "bitbucket.repositories.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bitbucket.pull_requests.list",
            "summary": "List pull requests in a repository",
            "capability": "bitbucket.pull_requests.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bitbucket.pull_requests.get",
            "summary": "Get a specific pull request",
            "capability": "bitbucket.pull_requests.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bitbucket.pull_requests.create",
            "summary": "Create a new pull request",
            "capability": "bitbucket.pull_requests.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "bitbucket.branches.list",
            "summary": "List branches in a repository",
            "capability": "bitbucket.branches.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bitbucket.commits.list",
            "summary": "List commits in a repository",
            "capability": "bitbucket.commits.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bitbucket.pipelines.list",
            "summary": "List pipelines in a repository",
            "capability": "bitbucket.pipelines.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bitbucket.workspaces.list",
            "summary": "List workspaces accessible by the authenticated user",
            "capability": "bitbucket.workspaces.read",
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
        let c = BitbucketConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }
}
