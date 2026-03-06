//! FCP Dropbox Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
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

        let content_url = params
            .get("content_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_CONTENT_URL)
            .to_string();

        Ok(Self {
            auth,
            base_url,
            content_url,
        })
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
        Ok(json!({
            "connector_id": "fcp.dropbox",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.dropbox",
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
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, DropboxError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DropboxError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "dropbox.files.list",
            "summary": "List files and folders in a path",
            "capability": "dropbox.files.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "dropbox.files.list_continue",
            "summary": "Continue listing files using a cursor",
            "capability": "dropbox.files.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "dropbox.files.get_metadata",
            "summary": "Get metadata for a file or folder",
            "capability": "dropbox.files.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "dropbox.files.create_folder",
            "summary": "Create a new folder",
            "capability": "dropbox.files.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "dropbox.files.delete",
            "summary": "Delete a file or folder",
            "capability": "dropbox.files.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "none",
        },
        {
            "id": "dropbox.files.move",
            "summary": "Move a file or folder",
            "capability": "dropbox.files.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "dropbox.files.copy",
            "summary": "Copy a file or folder",
            "capability": "dropbox.files.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "dropbox.files.search",
            "summary": "Search for files by name or content",
            "capability": "dropbox.files.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "dropbox.account.get_space_usage",
            "summary": "Get space usage for the current account",
            "capability": "dropbox.account.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "dropbox.account.get_current",
            "summary": "Get current account information",
            "capability": "dropbox.account.read",
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
    fn operations_files_list_is_strict_idempotent() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "dropbox.files.list")
            .unwrap();
        assert_eq!(op["idempotency"], "strict");
    }

    #[test]
    fn operations_files_delete_is_dangerous() {
        let ops = operations_info();
        let del_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "dropbox.files.delete")
            .unwrap();
        assert_eq!(del_op["safety_tier"], "dangerous");
        assert_eq!(del_op["risk_level"], "high");
    }

    #[test]
    fn operations_account_capability_correct() {
        let ops = operations_info();
        let account_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "dropbox.account.get_current")
            .unwrap();
        assert_eq!(account_op["capability"], "dropbox.account.read");
    }

    #[test]
    fn operations_files_read_capability_correct() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "dropbox.files.list")
            .unwrap();
        assert_eq!(list_op["capability"], "dropbox.files.read");

        let meta_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "dropbox.files.get_metadata")
            .unwrap();
        assert_eq!(meta_op["capability"], "dropbox.files.read");
    }

    #[test]
    fn operations_delete_capability_correct() {
        let ops = operations_info();
        let del_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "dropbox.files.delete")
            .unwrap();
        assert_eq!(del_op["capability"], "dropbox.files.write");
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn operations_write_ops_are_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".write") {
                assert_ne!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "write op {} should not be safe",
                    op["id"]
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
        assert_eq!(serde_json::to_value(DoctorStatus::Healthy).unwrap(), "healthy");
        assert_eq!(serde_json::to_value(DoctorStatus::Degraded).unwrap(), "degraded");
        assert_eq!(serde_json::to_value(DoctorStatus::Unhealthy).unwrap(), "unhealthy");
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
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "dropbox.files.move")
            .unwrap();
        assert_eq!(mv["capability"], "dropbox.files.write");
    }

    #[test]
    fn operations_files_copy_capability() {
        let ops = operations_info();
        let cp = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "dropbox.files.copy")
            .unwrap();
        assert_eq!(cp["capability"], "dropbox.files.write");
    }

    #[test]
    fn operations_search_capability() {
        let ops = operations_info();
        let search = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "dropbox.files.search")
            .unwrap();
        assert_eq!(search["capability"], "dropbox.files.read");
        assert_eq!(search["safety_tier"], "safe");
    }

    #[test]
    fn operations_space_usage_capability() {
        let ops = operations_info();
        let sp = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "dropbox.account.get_space_usage")
            .unwrap();
        assert_eq!(sp["capability"], "dropbox.account.read");
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
}
