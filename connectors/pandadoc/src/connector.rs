//! FCP `PandaDoc` Connector implementation.

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

    const fn auth_mode(&self) -> &'static str {
        match &self.auth {
            PandaDocAuth::BearerToken(_) => "api_key",
            PandaDocAuth::CredentialId(_) => "credential_id",
        }
    }

    const fn rate_limit_profile(&self) -> &'static str {
        match &self.auth {
            PandaDocAuth::BearerToken(_) => "api_key: standard PandaDoc API rate limits",
            PandaDocAuth::CredentialId(_) => {
                "credential_id: authenticated via egress proxy injection"
            }
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: self.auth_mode(),
            api_key_configured: matches!(self.auth, PandaDocAuth::BearerToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            rate_limit_profile: self.rate_limit_profile(),
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
    rate_limit_profile: &'static str,
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

        let Some(client) = &self.client else {
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

        let mut report = match client.list_documents(None, Some(1)).await {
            Ok(_) => SelfCheckReport::ok(),
            Err(error) => {
                if error.is_retryable() {
                    SelfCheckReport::degraded("connectivity_retryable", error.to_string())
                } else {
                    SelfCheckReport::failed("connectivity_failed", error.to_string())
                }
            }
        };
        report.details = Some(json!({ "provisioning": readiness }));

        Self::serialize_self_check_report(report)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "pandadoc.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "PandaDoc self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = typed_operations_info();
        Ok(json!({
            "connector_id": "fcp.pandadoc",
            "version": "0.1.0",
            "operations": serde_json::to_value(&ops).unwrap_or_default(),
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
        info!("PandaDoc connector shutting down");
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

/// Build the provisioning recipe for the `PandaDoc` connector.
fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("pandadoc/api-key"),
        "1",
        "Provision PandaDoc connector with an API key",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_api_key"),
        ProvisioningStepType::PromptSecret {
            message: "Enter your PandaDoc API key (Settings > Integrations > API > API Key)".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_key".into(),
                value_from: StepId::new("prompt_api_key"),
                scope: "connector:fcp.pandadoc".into(),
            },
        )
        .depends_on(StepId::new("prompt_api_key")),
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
    let allowed_host = host.eq_ignore_ascii_case("api.pandadoc.com") || local;
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
                "Endpoint must use https and api.pandadoc.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, PandaDocError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PandaDocError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build typed operations info for introspection.
fn typed_operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("pandadoc.documents.list"),
            summary: "List documents".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"status": {"type": "string"}, "count": {"type": "integer"}}}),
            output_schema: json!({"type": "object", "properties": {"documents": {"type": "array"}}}),
            capability: CapabilityId::from_static("pandadoc.documents.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to list documents, optionally filtered by status".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("pandadoc.documents.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pandadoc.documents.get"),
            summary: "Get document details".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"document_id": {"type": "string"}}, "required": ["document_id"]}),
            output_schema: json!({"type": "object", "properties": {"document": {"type": "object"}}}),
            capability: CapabilityId::from_static("pandadoc.documents.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to retrieve details of a specific document".into(),
                common_mistakes: vec!["Not providing document_id".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("pandadoc.documents.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pandadoc.documents.create"),
            summary: "Create a document from a template".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"name": {"type": "string"}, "template_uuid": {"type": "string"}, "recipients": {"type": "array"}}, "required": ["name", "template_uuid", "recipients"]}),
            output_schema: json!({"type": "object", "properties": {"document": {"type": "object"}}}),
            capability: CapabilityId::from_static("pandadoc.documents.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use to create a new document from a template with recipients".into(),
                common_mistakes: vec!["Forgetting to provide recipients array".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("pandadoc.documents.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pandadoc.documents.send"),
            summary: "Send a document for signing".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"document_id": {"type": "string"}, "message": {"type": "string"}}, "required": ["document_id"]}),
            output_schema: json!({"type": "object", "properties": {"status": {"type": "string"}}}),
            capability: CapabilityId::from_static("pandadoc.documents.write"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to send a completed document to recipients for signing".into(),
                common_mistakes: vec!["Sending a document that is not in draft status".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("pandadoc.documents.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pandadoc.documents.delete"),
            summary: "Delete a document".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"document_id": {"type": "string"}}, "required": ["document_id"]}),
            output_schema: json!({"type": "object", "properties": {"deleted": {"type": "boolean"}}}),
            capability: CapabilityId::from_static("pandadoc.documents.write"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to permanently delete a document — this cannot be undone".into(),
                common_mistakes: vec!["Deleting a document that is actively being signed".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("pandadoc.documents.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pandadoc.templates.list"),
            summary: "List available templates".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {}}),
            output_schema: json!({"type": "object", "properties": {"templates": {"type": "array"}}}),
            capability: CapabilityId::from_static("pandadoc.templates.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to discover available templates for document creation".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("pandadoc.templates.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

/// Build the operations info for introspection (JSON format for simulate).
fn operations_info() -> serde_json::Value {
    serde_json::to_value(typed_operations_info()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 6);
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
        let ops = operations_info();
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
        let ops = operations_info();
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
        let ops = operations_info();
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
        let ops = operations_info();
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
            PandaDocError::InvalidInput(msg) => {
                assert!(msg.contains("template_uuid"));
            }
            e => panic!("expected InvalidInput, got {e:?}"),
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
        let ops = operations_info();
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
        let ops = operations_info();
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
        let ops = operations_info();
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

    #[test]
    fn provisioning_readiness_api_key_mode() {
        let config = PandaDocConfig::from_params(&json!({
            "api_key": "test-key",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_key");
        assert!(readiness.api_key_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(
            readiness.rate_limit_profile,
            "api_key: standard PandaDoc API rate limits"
        );
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = PandaDocConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.api_key_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert_eq!(
            readiness.rate_limit_profile,
            "credential_id: authenticated via egress proxy injection"
        );
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = PandaDocConfig::from_params(&json!({
            "api_key": "test-key",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_key");
        assert_eq!(v["api_key_configured"], true);
        assert!(v["network_message"].as_str().unwrap().contains("accepted"));
    }

    #[test]
    fn provisioning_recipe_has_two_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "pandadoc/api-key");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
    }

    #[test]
    fn provisioning_recipe_step_ids() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "prompt_api_key");
        assert_eq!(recipe.steps[1].id.as_str(), "store_api_key");
    }

    #[test]
    fn provisioning_recipe_store_depends_on_prompt() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[1];
        assert_eq!(store_step.depends_on.len(), 1);
        assert_eq!(store_step.depends_on[0].as_str(), "prompt_api_key");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "pandadoc/api-key");
        assert!(v["steps"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn base_url_policy_accepts_pandadoc_https() {
        let (ok, message) = base_url_policy("https://api.pandadoc.com/public/v1");
        assert!(ok, "should accept pandadoc https: {message}");
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok, "should accept localhost");
    }

    #[test]
    fn base_url_policy_rejects_http_non_local_host() {
        let (ok, message) = base_url_policy("http://api.pandadoc.com/public/v1");
        assert!(!ok, "should reject http for non-local host");
        assert!(message.contains("https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com/v1");
        assert!(!ok, "should reject unknown host: {message}");
    }

    #[test]
    fn base_url_policy_accepts_ipv4_localhost() {
        let (ok, _) = base_url_policy("http://127.0.0.1:3000");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_ipv6_localhost() {
        let (ok, _) = base_url_policy("http://[::1]:3000");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_unparseable_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn provisioning_readiness_network_rejects_bad_url() {
        let config = PandaDocConfig::from_params(&json!({
            "api_key": "test-key",
            "base_url": "http://evil.example.com/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
    }
}
