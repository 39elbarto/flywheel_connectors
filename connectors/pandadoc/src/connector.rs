//! FCP `PandaDoc` Connector implementation.

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
    client::{DEFAULT_BASE_URL, PandaDocAuth, PandaDocClient},
    error::PandaDocError,
};

/// Parsed and validated `PandaDoc` connector configuration.
#[derive(Debug, Clone)]
struct PandaDocConfig {
    auth: PandaDocAuth,
    base_url: String,
}

impl PandaDocConfig {
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
            (Some(key), None) => PandaDocAuth::BearerToken(key),
            (None, Some(cred_id)) => PandaDocAuth::CredentialId(cred_id),
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

/// FCP `PandaDoc` Connector.
pub struct PandaDocConnector {
    base: Arc<BaseConnector>,
    config: Option<PandaDocConfig>,
    client: Option<Arc<PandaDocClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl PandaDocConnector {
    /// Create a new `PandaDoc` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("pandadoc"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for PandaDocConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PandaDocConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = PandaDocConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring PandaDoc connector");

        let client = PandaDocClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.pandadoc",
            "connector_version": "0.1.0",
            "capabilities": [
                "pandadoc.documents.read",
                "pandadoc.documents.write",
                "pandadoc.templates.read"
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
            "connector_id": "fcp.pandadoc",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.pandadoc",
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
            "pandadoc.documents.list" => self.invoke_documents_list(client, &input).await,
            "pandadoc.documents.get" => self.invoke_documents_get(client, &input).await,
            "pandadoc.documents.create" => self.invoke_documents_create(client, &input).await,
            "pandadoc.documents.send" => self.invoke_documents_send(client, &input).await,
            "pandadoc.documents.delete" => self.invoke_documents_delete(client, &input).await,
            "pandadoc.templates.list" => self.invoke_templates_list(client).await,
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
        info!("PandaDoc connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_documents_list(
        &self,
        client: &PandaDocClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PandaDocError> {
        let status = input.get("status").and_then(serde_json::Value::as_str);
        let count = input.get("count").and_then(serde_json::Value::as_i64);
        client.list_documents(status, count).await
    }

    async fn invoke_documents_get(
        &self,
        client: &PandaDocClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PandaDocError> {
        let document_id = require_str(input, "document_id")?;
        client.get_document(document_id).await
    }

    async fn invoke_documents_create(
        &self,
        client: &PandaDocClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PandaDocError> {
        let _ = require_str(input, "name")?;
        let _ = require_str(input, "template_uuid")?;
        if !input
            .get("recipients")
            .is_some_and(serde_json::Value::is_array)
        {
            return Err(PandaDocError::Api {
                status_code: 400,
                message: "Missing required field: recipients (must be an array)".into(),
            });
        }
        client.create_document(input).await
    }

    async fn invoke_documents_send(
        &self,
        client: &PandaDocClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PandaDocError> {
        let document_id = require_str(input, "document_id")?;
        let mut body = json!({});
        if let Some(message) = input.get("message").and_then(serde_json::Value::as_str) {
            body["message"] = json!(message);
        }
        client.send_document(document_id, &body).await
    }

    async fn invoke_documents_delete(
        &self,
        client: &PandaDocClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PandaDocError> {
        let document_id = require_str(input, "document_id")?;
        client.delete_document(document_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_templates_list(
        &self,
        client: &PandaDocClient,
    ) -> Result<serde_json::Value, PandaDocError> {
        client.list_templates().await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, PandaDocError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PandaDocError::Api {
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
            "pandadoc.documents.list",
            "List documents",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "status": {"type": "string", "description": "Filter by status (draft, sent, completed, etc.)"},
                    "count": {"type": "integer", "maximum": 100}
                }
            }),
            json!({
                "type": "object",
                "required": ["results"],
                "properties": {"results": {"type": "array"}}
            }),
            "pandadoc.documents.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List PandaDoc documents, optionally filtered by status.".into(),
                common_mistakes: vec![
                    "The status filter values are specific strings (draft, sent, completed, viewed, waiting_approval); using arbitrary values returns empty results.".into(),
                ],
                examples: vec![r#"{"status": "draft", "count": 20}"#.into()],
                related: vec![
                    CapabilityId::from_static("pandadoc.documents.get"),
                    CapabilityId::from_static("pandadoc.documents.create"),
                ],
            },
        ),
        op_info(
            "pandadoc.documents.get",
            "Get document details",
            json!({
                "type": "object",
                "required": ["document_id"],
                "properties": {
                    "document_id": {"type": "string"}
                }
            }),
            json!({
                "type": "object",
                "required": ["id", "name", "status"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "status": {"type": "string"}
                }
            }),
            "pandadoc.documents.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get details for a specific document.".into(),
                common_mistakes: vec![
                    "The document_id is a PandaDoc UUID, not the document name; use pandadoc.documents.list to look up the ID.".into(),
                ],
                examples: vec![r#"{"document_id": "doc_abc123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("pandadoc.documents.list"),
                ],
            },
        ),
        op_info(
            "pandadoc.documents.create",
            "Create a document from a template",
            json!({
                "type": "object",
                "required": ["name", "template_uuid", "recipients"],
                "properties": {
                    "name": {"type": "string"},
                    "template_uuid": {"type": "string"},
                    "recipients": {"type": "array", "description": "List of recipient objects with email and role"}
                }
            }),
            json!({
                "type": "object",
                "required": ["id", "status"],
                "properties": {
                    "id": {"type": "string"},
                    "status": {"type": "string"}
                }
            }),
            "pandadoc.documents.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new document from a template.".into(),
                common_mistakes: vec![
                    "Forgetting to specify recipients.".into(),
                ],
                examples: vec![
                    r#"{"name": "NDA for Acme", "template_uuid": "tpl_abc123", "recipients": [{"email": "bob@acme.com", "role": "signer"}]}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("pandadoc.templates.list"),
                    CapabilityId::from_static("pandadoc.documents.send"),
                ],
            },
        ),
        op_info(
            "pandadoc.documents.send",
            "Send a document for signing",
            json!({
                "type": "object",
                "required": ["document_id"],
                "properties": {
                    "document_id": {"type": "string"},
                    "message": {"type": "string", "description": "Optional message to include in the email"}
                }
            }),
            json!({
                "type": "object",
                "required": ["id", "status"],
                "properties": {
                    "id": {"type": "string"},
                    "status": {"type": "string"}
                }
            }),
            "pandadoc.documents.write",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Send a document to recipients for signing.".into(),
                common_mistakes: vec![
                    "Sending a document that is not in draft status.".into(),
                ],
                examples: vec![
                    r#"{"document_id": "doc_abc123", "message": "Please sign this NDA."}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("pandadoc.documents.create"),
                    CapabilityId::from_static("pandadoc.documents.get"),
                ],
            },
        ),
        op_info(
            "pandadoc.documents.delete",
            "Delete a document",
            json!({
                "type": "object",
                "required": ["document_id"],
                "properties": {
                    "document_id": {"type": "string"}
                }
            }),
            json!({"type": "object"}),
            "pandadoc.documents.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Delete a document. Cannot be undone.".into(),
                common_mistakes: vec![
                    "Deleting a document that has already been sent or completed will also revoke signer access; verify the document status with pandadoc.documents.get first.".into(),
                ],
                examples: vec![r#"{"document_id": "doc_abc123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("pandadoc.documents.list"),
                ],
            },
        ),
        op_info(
            "pandadoc.templates.list",
            "List available templates",
            json!({"type": "object", "required": []}),
            json!({
                "type": "object",
                "required": ["results"],
                "properties": {"results": {"type": "array"}}
            }),
            "pandadoc.templates.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List available document templates.".into(),
                common_mistakes: vec![
                    "Only active templates are returned; archived or deleted templates will not appear in the list.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("pandadoc.documents.create"),
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
    fn config_from_api_key() {
        let config = PandaDocConfig::from_params(&json!({
            "api_key": "test-api-key",
        }))
        .unwrap();
        assert!(matches!(config.auth, PandaDocAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = PandaDocConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = PandaDocConfig::from_params(&json!({
            "api_key": "tok",
            "base_url": "https://pandadoc.example.com/v1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://pandadoc.example.com/v1");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = PandaDocConfig::from_params(&json!({
            "api_key": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = PandaDocConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = PandaDocConfig::from_params(&json!({
            "api_key": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = PandaDocConfig::from_params(&json!({
            "api_key": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = PandaDocConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = PandaDocConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"document_id": "doc_abc"});
        assert_eq!(require_str(&input, "document_id").unwrap(), "doc_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "document_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"document_id": 42});
        assert!(require_str(&input, "document_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"document_id": null});
        assert!(require_str(&input, "document_id").is_err());
    }

    #[test]
    fn operations_info_has_6_operations() {
        let ops = ops_json();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 6);
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
    fn read_operations_are_safe() {
        let ops = ops_json();
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
        let ops = ops_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"pandadoc.documents.list"));
        assert!(ids.contains(&"pandadoc.documents.get"));
        assert!(ids.contains(&"pandadoc.documents.create"));
        assert!(ids.contains(&"pandadoc.documents.send"));
        assert!(ids.contains(&"pandadoc.documents.delete"));
        assert!(ids.contains(&"pandadoc.templates.list"));
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
        let config = PandaDocConfig::from_params(&json!({ "api_key": "  pd_test  " })).unwrap();
        match &config.auth {
            PandaDocAuth::BearerToken(t) => assert_eq!(t, "pd_test"),
            PandaDocAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = PandaDocConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_equals_default() {
        let c = PandaDocConnector::new();
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
        let ops = ops_json();
        let delete_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "pandadoc.documents.delete")
            .unwrap();
        assert_eq!(delete_op["safety_tier"], "dangerous");
        assert_eq!(delete_op["risk_level"], "high");
    }

    #[test]
    fn operations_send_is_risky() {
        let ops = ops_json();
        let send_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "pandadoc.documents.send")
            .unwrap();
        assert_eq!(send_op["safety_tier"], "risky");
        assert_eq!(send_op["risk_level"], "high");
    }

    #[test]
    fn operations_create_is_risky() {
        let ops = ops_json();
        let create_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "pandadoc.documents.create")
            .unwrap();
        assert_eq!(create_op["safety_tier"], "risky");
    }

    #[test]
    fn operations_templates_list_capability() {
        let ops = ops_json();
        let tpl_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "pandadoc.templates.list")
            .unwrap();
        assert_eq!(tpl_op["capability"], "pandadoc.templates.read");
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"document_id": ""});
        assert_eq!(require_str(&input, "document_id").unwrap(), "");
    }

    #[test]
    fn require_str_with_array_value() {
        let input = json!({"document_id": [1, 2, 3]});
        assert!(require_str(&input, "document_id").is_err());
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"document_id": {"nested": true}});
        assert!(require_str(&input, "document_id").is_err());
    }

    #[test]
    fn require_str_with_bool_value() {
        let input = json!({"document_id": true});
        assert!(require_str(&input, "document_id").is_err());
    }

    #[test]
    fn require_str_error_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "template_uuid").unwrap_err();
        match err {
            PandaDocError::Api { message, .. } => {
                assert!(message.contains("template_uuid"));
            }
            e => panic!("expected Api, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_both_auth_error_message() {
        let result = PandaDocConfig::from_params(&json!({
            "api_key": "tok",
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
        let result = PandaDocConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("api_key") || message.contains("credential_id"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_non_string_credential_error_message() {
        let result = PandaDocConfig::from_params(&json!({"credential_id": 42}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("must be a string"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_invalid_uuid_credential_error_message() {
        let result = PandaDocConfig::from_params(&json!({"credential_id": "not-valid"}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("valid UUID"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_default_base_url_when_absent() {
        let config = PandaDocConfig::from_params(&json!({"api_key": "tok"})).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"document_id": 1.23});
        assert!(require_str(&input, "document_id").is_err());
    }

    #[test]
    fn require_str_nested_object_value() {
        let input = json!({"document_id": {"inner": "val"}});
        assert!(require_str(&input, "document_id").is_err());
    }

    #[test]
    fn doctor_result_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "roundtrip".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.status, DoctorStatus::Healthy);
        assert_eq!(r2.checks.len(), 1);
        assert_eq!(r2.checks[0].name, "roundtrip");
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "cloned".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let c2 = c.clone();
        assert_eq!(c.name, "cloned");
        assert_eq!(c2.message, Some("ok".into()));
    }

    #[test]
    fn doctor_check_debug() {
        let c = DoctorCheck {
            name: "dbg".into(),
            passed: false,
            message: None,
            critical: true,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("dbg"));
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn operations_all_prefixed_pandadoc() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("pandadoc."),
                "op {id} missing pandadoc. prefix"
            );
        }
    }

    #[test]
    fn operations_valid_idempotency_values() {
        let valid = ["strict", "best_effort", "none"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idem),
                "invalid idempotency {idem} for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_list_documents_is_safe() {
        let ops = ops_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "pandadoc.documents.list")
            .unwrap();
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["risk_level"], "low");
        assert_eq!(op["idempotency"], "strict");
    }

    #[test]
    fn connector_request_and_error_counts_default_zero() {
        let c = PandaDocConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_error_codes_are_1003() {
        let cases = vec![
            json!({}),
            json!({"credential_id": 42}),
            json!({"credential_id": "not-valid"}),
            json!({"api_key": "tok", "credential_id": "550e8400-e29b-41d4-a716-446655440000"}),
        ];
        for case in cases {
            let err = PandaDocConfig::from_params(&case).unwrap_err();
            match err {
                FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1003),
                e => panic!("expected InvalidRequest, got {e:?}"),
            }
        }
    }

    #[test]
    fn doctor_result_mixed_critical_non_critical_failures() {
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
                critical: false,
            },
        ]);
        // Critical failure takes precedence
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_ne() {
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Unhealthy);
    }

    #[test]
    fn config_debug_shows_auth_label() {
        let config = PandaDocConfig::from_params(&json!({"api_key": "secret-key-123"})).unwrap();
        let dbg = format!("{config:?}");
        // The debug should show the config but not leak the actual key
        assert!(dbg.contains("PandaDocConfig"));
    }
}
