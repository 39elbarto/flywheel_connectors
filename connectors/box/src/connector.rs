//! FCP `Box` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{BoxAuth, BoxClient, DEFAULT_BASE_URL, DEFAULT_UPLOAD_URL},
    error::BoxError,
};

/// Parsed and validated `Box` connector configuration.
#[derive(Debug, Clone)]
struct BoxConfig {
    auth: BoxAuth,
    base_url: String,
    upload_url: String,
}

impl BoxConfig {
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
            (Some(token), None) => BoxAuth::BearerToken(token),
            (None, Some(cred_id)) => BoxAuth::CredentialId(cred_id),
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

        let upload_url = params
            .get("upload_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_UPLOAD_URL)
            .to_string();

        Ok(Self {
            auth,
            base_url,
            upload_url,
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

/// FCP `Box` Connector.
pub struct BoxConnector {
    base: Arc<BaseConnector>,
    config: Option<BoxConfig>,
    client: Option<Arc<BoxClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl BoxConnector {
    /// Create a new `Box` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("box"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for BoxConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl BoxConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = BoxConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Box connector");

        let client = BoxClient::new(
            config.auth.clone(),
            Some(&config.base_url),
            Some(&config.upload_url),
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
            "connector_id": "fcp.box",
            "connector_version": "0.1.0",
            "capabilities": [
                "box.files.read",
                "box.files.write",
                "box.folders.read",
                "box.sharing.read"
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
            "connector_id": "fcp.box",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.box",
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
            "box.files.get" => self.invoke_files_get(client, &input).await,
            "box.files.upload" => self.invoke_files_upload(client, &input).await,
            "box.files.delete" => self.invoke_files_delete(client, &input).await,
            "box.folders.list" => self.invoke_folders_list(client, &input).await,
            "box.sharing.list" => self.invoke_sharing_list(client, &input).await,
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
        info!("Box connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations ------------------------------------------------

    async fn invoke_files_get(
        &self,
        client: &BoxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BoxError> {
        let file_id = require_str(input, "file_id")?;
        client.get_file(file_id).await
    }

    async fn invoke_files_upload(
        &self,
        client: &BoxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BoxError> {
        let folder_id = require_str(input, "folder_id")?;
        let name = require_str(input, "name")?;
        let content = input.get("content").and_then(serde_json::Value::as_str);
        client.upload_file(folder_id, name, content).await
    }

    async fn invoke_files_delete(
        &self,
        client: &BoxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BoxError> {
        let file_id = require_str(input, "file_id")?;
        client.delete_file(file_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_folders_list(
        &self,
        client: &BoxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BoxError> {
        let folder_id = require_str(input, "folder_id")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let offset = input.get("offset").and_then(serde_json::Value::as_i64);
        client.list_folder_items(folder_id, limit, offset).await
    }

    async fn invoke_sharing_list(
        &self,
        client: &BoxClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BoxError> {
        let file_id = require_str(input, "file_id")?;
        client.list_file_collaborations(file_id).await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, BoxError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BoxError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
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
            "box.files.get",
            "Get file metadata from Box",
            json!({
                "type": "object",
                "required": ["file_id"],
                "properties": {
                    "file_id": {"type": "string", "description": "Box file identifier"}
                }
            }),
            json!({
                "type": "object",
                "required": ["id", "name"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"}
                }
            }),
            "box.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve metadata for a specific file in Box.".into(),
                common_mistakes: vec![
                    "Using a file name or path instead of the numeric Box file ID.".into(),
                ],
                examples: vec![r#"{"file_id": "123456789"}"#.into()],
                related: vec![
                    CapabilityId::from_static("box.folders.list"),
                    CapabilityId::from_static("box.files.upload"),
                    CapabilityId::from_static("box.files.delete"),
                ],
            },
        ),
        op_info(
            "box.files.upload",
            "Upload a file to Box",
            json!({
                "type": "object",
                "required": ["folder_id", "name"],
                "properties": {
                    "folder_id": {"type": "string", "description": "Target folder ID for the upload"},
                    "name": {"type": "string", "description": "Name for the uploaded file"}
                }
            }),
            json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": {"type": "string"}
                }
            }),
            "box.files.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Upload a new file to a Box folder.".into(),
                common_mistakes: vec![
                    "Using folder_id \"0\" uploads to root; verify the target folder ID with box.folders.list first to avoid misplaced files.".into(),
                ],
                examples: vec![r#"{"folder_id": "0", "name": "report.pdf"}"#.into()],
                related: vec![
                    CapabilityId::from_static("box.folders.list"),
                    CapabilityId::from_static("box.files.get"),
                ],
            },
        ),
        op_info(
            "box.files.delete",
            "Delete a file from Box",
            json!({
                "type": "object",
                "required": ["file_id"],
                "properties": {
                    "file_id": {"type": "string", "description": "Box file identifier to delete"}
                }
            }),
            json!({"type": "object", "required": []}),
            "box.files.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Permanently delete a file from Box.".into(),
                common_mistakes: vec![
                    "Passing a folder ID instead of a file ID; use box.folders.list to confirm the item type before deleting.".into(),
                ],
                examples: vec![r#"{"file_id": "123456789"}"#.into()],
                related: vec![
                    CapabilityId::from_static("box.files.get"),
                    CapabilityId::from_static("box.folders.list"),
                ],
            },
        ),
        op_info(
            "box.folders.list",
            "List contents of a Box folder",
            json!({
                "type": "object",
                "required": ["folder_id"],
                "properties": {
                    "folder_id": {"type": "string", "description": "Folder ID (0 for root)"}
                }
            }),
            json!({
                "type": "object",
                "required": ["entries"],
                "properties": {
                    "entries": {"type": "array"}
                }
            }),
            "box.folders.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List contents of a Box folder.".into(),
                common_mistakes: vec![
                    "Forgetting that folder_id \"0\" refers to the root folder; omitting it or passing an empty string will fail.".into(),
                ],
                examples: vec![r#"{"folder_id": "0"}"#.into()],
                related: vec![
                    CapabilityId::from_static("box.files.get"),
                    CapabilityId::from_static("box.files.upload"),
                ],
            },
        ),
        op_info(
            "box.sharing.list",
            "List sharing collaborations for a Box file",
            json!({
                "type": "object",
                "required": ["file_id"],
                "properties": {
                    "file_id": {"type": "string", "description": "Box file identifier"}
                }
            }),
            json!({
                "type": "object",
                "required": ["entries"],
                "properties": {
                    "entries": {"type": "array"}
                }
            }),
            "box.sharing.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List sharing collaborations for a Box file.".into(),
                common_mistakes: vec![
                    "Expecting shared link URLs in the response; this returns collaboration objects with user roles, not share links.".into(),
                ],
                examples: vec![r#"{"file_id": "123456789"}"#.into()],
                related: vec![
                    CapabilityId::from_static("box.files.get"),
                    CapabilityId::from_static("box.folders.list"),
                ],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn config_from_access_token() {
        let config = BoxConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, BoxAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.upload_url, DEFAULT_UPLOAD_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = BoxConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = BoxConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://box.example.com/2.0",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://box.example.com/2.0");
    }

    #[test]
    fn config_custom_upload_url() {
        let config = BoxConfig::from_params(&json!({
            "access_token": "tok",
            "upload_url": "https://upload.example.com/api/2.0",
        }))
        .unwrap();
        assert_eq!(config.upload_url, "https://upload.example.com/api/2.0");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = BoxConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = BoxConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = BoxConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = BoxConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = BoxConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = BoxConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config = BoxConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            BoxAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            BoxAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn require_str_present() {
        let input = json!({"file_id": "12345"});
        assert_eq!(require_str(&input, "file_id").unwrap(), "12345");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"file_id": 42});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"file_id": null});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"file_id": [1, 2, 3]});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"file_id": true});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = ops_json();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 5);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = ops_json();
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
        let ops = ops_json();
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
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = ops_json();
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
        let ops = ops_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"box.files.get"));
        assert!(ids.contains(&"box.files.upload"));
        assert!(ids.contains(&"box.files.delete"));
        assert!(ids.contains(&"box.folders.list"));
        assert!(ids.contains(&"box.sharing.list"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_files_get_is_strict_idempotent() {
        let ops = ops_json();
        let get_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "box.files.get")
            .unwrap();
        assert_eq!(get_op["idempotency"], "strict");
    }

    #[test]
    fn operations_files_upload_is_not_idempotent() {
        let ops = ops_json();
        let up_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "box.files.upload")
            .unwrap();
        assert_eq!(up_op["idempotency"], "none");
    }

    #[test]
    fn operations_files_delete_is_dangerous() {
        let ops = ops_json();
        let del_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "box.files.delete")
            .unwrap();
        assert_eq!(del_op["safety_tier"], "dangerous");
        assert_eq!(del_op["risk_level"], "high");
    }

    #[test]
    fn operations_sharing_capability_correct() {
        let ops = ops_json();
        let share_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "box.sharing.list")
            .unwrap();
        assert_eq!(share_op["capability"], "box.sharing.read");
    }

    #[test]
    fn operations_folders_list_capability_correct() {
        let ops = ops_json();
        let folder_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "box.folders.list")
            .unwrap();
        assert_eq!(folder_op["capability"], "box.folders.read");
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
        let c = BoxConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_is_unconfigured() {
        let c = BoxConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn config_default_urls() {
        let config = BoxConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.box.com/2.0");
        assert_eq!(config.upload_url, "https://upload.box.com/api/2.0");
    }

    #[test]
    fn config_both_custom_urls() {
        let config = BoxConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://custom.api.box.com",
            "upload_url": "https://custom.upload.box.com",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://custom.api.box.com");
        assert_eq!(config.upload_url, "https://custom.upload.box.com");
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
        let s2: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s2, DoctorStatus::Degraded);
    }

    #[test]
    fn require_str_nested_object_is_err() {
        let input = json!({"file_id": {"nested": true}});
        assert!(require_str(&input, "file_id").is_err());
    }

    #[test]
    fn require_str_empty_string_is_valid() {
        let input = json!({"file_id": ""});
        assert_eq!(require_str(&input, "file_id").unwrap(), "");
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = BoxConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn operations_write_ops_are_not_safe() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
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
    fn doctor_check_debug_format() {
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
    fn doctor_result_debug_format() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn operations_files_upload_is_risky() {
        let ops = ops_json();
        let up_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "box.files.upload")
            .unwrap();
        assert_eq!(up_op["safety_tier"], "risky");
        assert_eq!(up_op["risk_level"], "medium");
    }

    #[test]
    fn operations_files_get_capability_correct() {
        let ops = ops_json();
        let get_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "box.files.get")
            .unwrap();
        assert_eq!(get_op["capability"], "box.files.read");
    }
}
