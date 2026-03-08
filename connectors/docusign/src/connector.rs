//! FCP `DocuSign` Connector implementation.

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
    client::{DEFAULT_BASE_URL, DocuSignAuth, DocuSignClient, ListEnvelopesParams},
    error::DocuSignError,
};

/// Parsed and validated `DocuSign` connector configuration.
#[derive(Debug, Clone)]
struct DocuSignConfig {
    auth: DocuSignAuth,
    base_url: String,
}

impl DocuSignConfig {
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
            (Some(token), None) => DocuSignAuth::BearerToken(token),
            (None, Some(cred_id)) => DocuSignAuth::CredentialId(cred_id),
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

/// FCP `DocuSign` Connector.
pub struct DocuSignConnector {
    base: Arc<BaseConnector>,
    config: Option<DocuSignConfig>,
    client: Option<Arc<DocuSignClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl DocuSignConnector {
    /// Create a new `DocuSign` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("docusign"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for DocuSignConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl DocuSignConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = DocuSignConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring DocuSign connector");

        let client = DocuSignClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.docusign",
            "connector_version": "0.1.0",
            "capabilities": [
                "docusign.read",
                "docusign.write",
                "docusign.send"
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
            "connector_id": "fcp.docusign",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.docusign",
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
            "docusign.list_envelopes" => self.invoke_list_envelopes(client, &input).await,
            "docusign.get_envelope" => self.invoke_get_envelope(client, &input).await,
            "docusign.create_envelope" => self.invoke_create_envelope(client, &input).await,
            "docusign.send_envelope" => self.invoke_send_envelope(client, &input).await,
            "docusign.void_envelope" => self.invoke_void_envelope(client, &input).await,
            "docusign.add_recipients" => self.invoke_add_recipients(client, &input).await,
            "docusign.list_templates" => self.invoke_list_templates(client, &input).await,
            "docusign.get_template" => self.invoke_get_template(client, &input).await,
            "docusign.download_documents" => self.invoke_download_documents(client, &input).await,
            "docusign.stream_connect_events" => {
                self.invoke_stream_connect_events(client, &input).await
            }
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
        info!("DocuSign connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_list_envelopes(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let params = ListEnvelopesParams {
            account_id,
            from_date: input.get("from_date").and_then(serde_json::Value::as_str),
            to_date: input.get("to_date").and_then(serde_json::Value::as_str),
            status: input.get("status").and_then(serde_json::Value::as_str),
            search_text: input.get("search_text").and_then(serde_json::Value::as_str),
            count: input.get("count").and_then(serde_json::Value::as_i64),
            start_position: input
                .get("start_position")
                .and_then(serde_json::Value::as_str),
        };
        client.list_envelopes(&params).await
    }

    async fn invoke_get_envelope(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let include = input.get("include").and_then(serde_json::Value::as_str);
        let data = client
            .get_envelope(account_id, envelope_id, include)
            .await?;
        Ok(json!({ "envelope": data }))
    }

    async fn invoke_create_envelope(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_definition =
            input
                .get("envelope_definition")
                .ok_or_else(|| DocuSignError::Api {
                    status_code: 400,
                    message: "Missing required field: envelope_definition".into(),
                })?;
        client
            .create_envelope(account_id, envelope_definition)
            .await
    }

    async fn invoke_send_envelope(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        client.send_envelope(account_id, envelope_id).await
    }

    async fn invoke_void_envelope(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let voided_reason = require_str(input, "voided_reason")?;
        client
            .void_envelope(account_id, envelope_id, voided_reason)
            .await
    }

    async fn invoke_add_recipients(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let recipients = input.get("recipients").ok_or_else(|| DocuSignError::Api {
            status_code: 400,
            message: "Missing required field: recipients".into(),
        })?;
        let data = client
            .add_recipients(account_id, envelope_id, recipients)
            .await?;
        Ok(json!({ "recipients": data }))
    }

    async fn invoke_list_templates(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let search_text = input.get("search_text").and_then(serde_json::Value::as_str);
        client.list_templates(account_id, search_text).await
    }

    async fn invoke_get_template(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let template_id = require_str(input, "template_id")?;
        let data = client.get_template(account_id, template_id).await?;
        Ok(json!({ "template": data }))
    }

    async fn invoke_download_documents(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let document_id = input.get("document_id").and_then(serde_json::Value::as_str);
        let bytes = client
            .download_documents(account_id, envelope_id, document_id)
            .await?;
        let encoded = base64_encode(&bytes);
        Ok(json!({ "document": serde_json::Value::String(encoded) }))
    }

    async fn invoke_stream_connect_events(
        &self,
        _client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let _account_id = require_str(input, "account_id")?;
        let since_ts = input.get("since_ts").and_then(serde_json::Value::as_str);
        // Streaming is a placeholder — real implementation would poll Connect logs
        // or use a webhook receiver. For now, return an empty events array.
        Ok(json!({
            "events": [],
            "since_ts": since_ts,
            "streaming": true,
        }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, DocuSignError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DocuSignError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Simple base64 encoding with padding.
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
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
            "docusign.list_envelopes",
            "List envelopes with optional status and date filters",
            json!({
                "type": "object",
                "required": ["account_id"],
                "properties": {
                    "account_id": {"type": "string", "description": "DocuSign account ID"},
                    "from_date": {"type": "string", "description": "ISO 8601 start date filter"},
                    "to_date": {"type": "string", "description": "ISO 8601 end date filter"},
                    "status": {"type": "string", "description": "Filter by envelope status"},
                    "search_text": {"type": "string", "description": "Search text in envelope metadata"},
                    "count": {"type": "integer", "minimum": 1, "maximum": 100},
                    "start_position": {"type": "string", "description": "Pagination offset"}
                }
            }),
            json!({
                "type": "object",
                "required": ["envelopes"],
                "properties": {"envelopes": {"type": "array"}}
            }),
            "docusign.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List envelopes with optional filtering by status, date range, or search text.".into(),
                common_mistakes: vec![
                    "Not specifying from_date — the API requires at least from_date or a status filter.".into(),
                ],
                examples: vec![
                    r#"{"account_id": "abc-123", "from_date": "2026-01-01T00:00:00Z", "status": "completed"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("docusign.get_envelope"),
                    CapabilityId::from_static("docusign.download_documents"),
                ],
            },
        ),
        op_info(
            "docusign.get_envelope",
            "Get envelope status, metadata, and recipient progress",
            json!({
                "type": "object",
                "required": ["account_id", "envelope_id"],
                "properties": {
                    "account_id": {"type": "string", "description": "DocuSign account ID"},
                    "envelope_id": {"type": "string", "description": "Envelope ID"},
                    "include": {"type": "string", "description": "Comma-separated additional data to include (e.g., 'recipients,documents')"}
                }
            }),
            json!({
                "type": "object",
                "required": ["envelope"],
                "properties": {"envelope": {"type": "object"}}
            }),
            "docusign.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Check the status and details of an envelope.".into(),
                common_mistakes: vec![
                    "Not using include parameter to get recipients or documents in a single call.".into(),
                ],
                examples: vec![
                    r#"{"account_id": "abc-123", "envelope_id": "env-456", "include": "recipients"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("docusign.list_envelopes"),
                    CapabilityId::from_static("docusign.download_documents"),
                ],
            },
        ),
        op_info(
            "docusign.create_envelope",
            "Create a new envelope with documents and recipients",
            json!({
                "type": "object",
                "required": ["account_id", "envelope_definition"],
                "properties": {
                    "account_id": {"type": "string", "description": "DocuSign account ID"},
                    "envelope_definition": {"type": "object", "description": "Full envelope definition (documents, recipients, tabs, status)"}
                }
            }),
            json!({
                "type": "object",
                "required": ["envelope_id", "status", "uri"],
                "properties": {
                    "envelope_id": {"type": "string"},
                    "status": {"type": "string"},
                    "uri": {"type": "string"}
                }
            }),
            "docusign.write",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new envelope to send documents for signature.".into(),
                common_mistakes: vec![
                    "Setting status='sent' without confirming with the user first — this immediately sends to recipients.".into(),
                    "Not base64-encoding document content in the envelope definition.".into(),
                    "Missing required recipient tabs (signature/initial positions).".into(),
                ],
                examples: vec![
                    r#"{"account_id": "abc-123", "envelope_definition": {"emailSubject": "Please sign", "status": "created"}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("docusign.get_envelope"),
                    CapabilityId::from_static("docusign.send_envelope"),
                    CapabilityId::from_static("docusign.add_recipients"),
                ],
            },
        ),
        op_info(
            "docusign.send_envelope",
            "Send a draft envelope to recipients for signing",
            json!({
                "type": "object",
                "required": ["account_id", "envelope_id"],
                "properties": {
                    "account_id": {"type": "string", "description": "DocuSign account ID"},
                    "envelope_id": {"type": "string", "description": "Envelope ID to send"}
                }
            }),
            json!({
                "type": "object",
                "required": ["envelope_id"],
                "properties": {"envelope_id": {"type": "string"}}
            }),
            "docusign.send",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Send a draft envelope to all recipients. This triggers real emails to signers.".into(),
                common_mistakes: vec![
                    "Sending without verifying all recipients and documents are correct.".into(),
                    "Sending envelopes that are already in 'sent' or 'completed' status.".into(),
                ],
                examples: vec![
                    r#"{"account_id": "abc-123", "envelope_id": "env-456"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("docusign.create_envelope"),
                    CapabilityId::from_static("docusign.void_envelope"),
                ],
            },
        ),
        op_info(
            "docusign.void_envelope",
            "Void a sent envelope that has not been completed",
            json!({
                "type": "object",
                "required": ["account_id", "envelope_id", "voided_reason"],
                "properties": {
                    "account_id": {"type": "string", "description": "DocuSign account ID"},
                    "envelope_id": {"type": "string", "description": "Envelope ID to void"},
                    "voided_reason": {"type": "string", "description": "Reason for voiding (shown to recipients)"}
                }
            }),
            json!({"type": "object"}),
            "docusign.send",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Cancel a sent envelope. Cannot be undone once voided.".into(),
                common_mistakes: vec![
                    "Voiding already-completed envelopes (not possible).".into(),
                    "Providing a vague voided_reason (recipients see this).".into(),
                ],
                examples: vec![
                    r#"{"account_id": "abc-123", "envelope_id": "env-456", "voided_reason": "Document needs revision"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("docusign.get_envelope"),
                    CapabilityId::from_static("docusign.send_envelope"),
                ],
            },
        ),
        op_info(
            "docusign.add_recipients",
            "Add or modify recipients on a draft envelope",
            json!({
                "type": "object",
                "required": ["account_id", "envelope_id", "recipients"],
                "properties": {
                    "account_id": {"type": "string", "description": "DocuSign account ID"},
                    "envelope_id": {"type": "string", "description": "Envelope ID to modify"},
                    "recipients": {"type": "object", "description": "Recipients object with signers, carbonCopies, etc."}
                }
            }),
            json!({
                "type": "object",
                "required": ["recipients"],
                "properties": {"recipients": {"type": "object"}}
            }),
            "docusign.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Add or update recipients on a draft envelope before sending.".into(),
                common_mistakes: vec![
                    "Adding recipients to an already-sent envelope (use correct recipients endpoint).".into(),
                    "Not specifying routingOrder for sequential signing.".into(),
                ],
                examples: vec![
                    r#"{"account_id": "abc-123", "envelope_id": "env-456", "recipients": {"signers": [{"email": "bob@example.com", "name": "Bob", "recipientId": "2"}]}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("docusign.create_envelope"),
                    CapabilityId::from_static("docusign.send_envelope"),
                ],
            },
        ),
        op_info(
            "docusign.list_templates",
            "List available templates in an account",
            json!({
                "type": "object",
                "required": ["account_id"],
                "properties": {
                    "account_id": {"type": "string", "description": "DocuSign account ID"},
                    "search_text": {"type": "string", "description": "Search templates by name"}
                }
            }),
            json!({
                "type": "object",
                "required": ["templates"],
                "properties": {"templates": {"type": "array"}}
            }),
            "docusign.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List available envelope templates to use when creating envelopes.".into(),
                common_mistakes: vec![
                    "Confusing account-level templates with personal templates — results depend on the account_id and the authenticated user's template sharing permissions.".into(),
                ],
                examples: vec![r#"{"account_id": "abc-123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("docusign.get_template"),
                    CapabilityId::from_static("docusign.create_envelope"),
                ],
            },
        ),
        op_info(
            "docusign.get_template",
            "Get template details including documents and recipients",
            json!({
                "type": "object",
                "required": ["account_id", "template_id"],
                "properties": {
                    "account_id": {"type": "string", "description": "DocuSign account ID"},
                    "template_id": {"type": "string", "description": "Template ID"}
                }
            }),
            json!({
                "type": "object",
                "required": ["template"],
                "properties": {"template": {"type": "object"}}
            }),
            "docusign.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Inspect a template's structure before using it to create envelopes.".into(),
                common_mistakes: vec![
                    "Using the template name instead of the template ID — templates must be referenced by their GUID, not their display name.".into(),
                ],
                examples: vec![r#"{"account_id": "abc-123", "template_id": "tmpl-789"}"#.into()],
                related: vec![
                    CapabilityId::from_static("docusign.list_templates"),
                    CapabilityId::from_static("docusign.create_envelope"),
                ],
            },
        ),
        op_info(
            "docusign.download_documents",
            "Download signed documents from a completed envelope",
            json!({
                "type": "object",
                "required": ["account_id", "envelope_id"],
                "properties": {
                    "account_id": {"type": "string", "description": "DocuSign account ID"},
                    "envelope_id": {"type": "string", "description": "Envelope ID"},
                    "document_id": {"type": "string", "description": "Specific document ID to download (omit for combined PDF)"}
                }
            }),
            json!({
                "type": "object",
                "required": ["document"],
                "properties": {"document": {"type": "string", "description": "Document content (base64-encoded PDF)"}}
            }),
            "docusign.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Download signed documents as PDF. Omit document_id to get all documents combined.".into(),
                common_mistakes: vec![
                    "Downloading from non-completed envelopes (documents may not have final signatures).".into(),
                ],
                examples: vec![
                    r#"{"account_id": "abc-123", "envelope_id": "env-456"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("docusign.get_envelope"),
                    CapabilityId::from_static("docusign.list_envelopes"),
                ],
            },
        ),
        op_info(
            "docusign.stream_connect_events",
            "Stream DocuSign Connect webhook events",
            json!({
                "type": "object",
                "required": ["account_id"],
                "properties": {
                    "account_id": {"type": "string", "description": "DocuSign account ID"},
                    "since_ts": {"type": "string", "description": "ISO 8601 timestamp to resume from"}
                }
            }),
            json!({
                "type": "object",
                "required": ["event"],
                "properties": {"event": {"type": "object", "description": "Connect webhook event payload"}}
            }),
            "docusign.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Stream real-time envelope status changes via DocuSign Connect webhooks.".into(),
                common_mistakes: vec![
                    "Not persisting since_ts for reconnection idempotency.".into(),
                    "Not validating Connect HMAC signatures.".into(),
                ],
                examples: vec![r#"{"account_id": "abc-123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("docusign.get_envelope"),
                    CapabilityId::from_static("docusign.list_envelopes"),
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
        let config = DocuSignConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, DocuSignAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = DocuSignConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = DocuSignConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://na2.docusign.net/restapi/v2.1/accounts",
        }))
        .unwrap();
        assert_eq!(
            config.base_url,
            "https://na2.docusign.net/restapi/v2.1/accounts"
        );
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = DocuSignConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = DocuSignConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = DocuSignConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = DocuSignConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = DocuSignConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = DocuSignConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config =
            DocuSignConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            DocuSignAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            DocuSignAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn require_str_present() {
        let input = json!({"account_id": "abc-123"});
        assert_eq!(require_str(&input, "account_id").unwrap(), "abc-123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"account_id": 42});
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"account_id": null});
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"account_id": true});
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"account_id": ["abc"]});
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn operations_info_has_10_operations() {
        let ops = ops_json();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 10);
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
        assert!(ids.contains(&"docusign.list_envelopes"));
        assert!(ids.contains(&"docusign.get_envelope"));
        assert!(ids.contains(&"docusign.create_envelope"));
        assert!(ids.contains(&"docusign.send_envelope"));
        assert!(ids.contains(&"docusign.void_envelope"));
        assert!(ids.contains(&"docusign.add_recipients"));
        assert!(ids.contains(&"docusign.list_templates"));
        assert!(ids.contains(&"docusign.get_template"));
        assert!(ids.contains(&"docusign.download_documents"));
        assert!(ids.contains(&"docusign.stream_connect_events"));
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
    fn operations_write_ops_are_risky() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap == "docusign.write" {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "risky",
                    "write op {} should be risky",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_send_ops_are_dangerous() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap == "docusign.send" {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "dangerous",
                    "send op {} should be dangerous",
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
    fn connector_default() {
        let c = DocuSignConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(&[]), "");
    }

    #[test]
    fn base64_encode_one_byte() {
        // 'A' (65) -> QQ==
        assert_eq!(base64_encode(&[65]), "QQ==");
    }

    #[test]
    fn base64_encode_two_bytes() {
        // 'AB' -> QUI=
        assert_eq!(base64_encode(&[65, 66]), "QUI=");
    }

    #[test]
    fn base64_encode_three_bytes() {
        // 'ABC' -> QUJD
        assert_eq!(base64_encode(&[65, 66, 67]), "QUJD");
    }

    #[test]
    fn base64_encode_hello() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn base64_encode_pdf_header() {
        // PDF magic bytes (4 bytes -> 8 base64 chars with padding)
        assert_eq!(base64_encode(b"%PDF"), "JVBERg==");
    }

    #[test]
    fn operations_idempotency_values_valid() {
        let valid = ["strict", "best_effort", "none"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idem),
                "invalid idempotency: {idem} for op {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_capabilities_valid() {
        let valid = ["docusign.read", "docusign.write", "docusign.send"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                valid.contains(&cap),
                "invalid capability: {cap} for op {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "empty summary for op {:?}", op["id"]);
        }
    }

    #[test]
    fn operations_ids_follow_naming_convention() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("docusign."),
                "op id should start with 'docusign.': {id}"
            );
        }
    }

    #[test]
    fn operations_read_count() {
        let ops = ops_json();
        let read_count = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("docusign.read"))
            .count();
        assert_eq!(read_count, 6);
    }

    #[test]
    fn operations_write_count() {
        let ops = ops_json();
        let write_count = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("docusign.write"))
            .count();
        assert_eq!(write_count, 2);
    }

    #[test]
    fn operations_send_count() {
        let ops = ops_json();
        let send_count = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("docusign.send"))
            .count();
        assert_eq!(send_count, 2);
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail1".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail2".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn doctor_check_skip_serializing_none_message() {
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
    fn doctor_check_serializes_some_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("check failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "check failed");
    }

    #[test]
    fn config_default_base_url_when_not_specified() {
        let config = DocuSignConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn doctor_result_multiple_critical_failures_count() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("f1".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("f2".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn doctor_status_serde_healthy() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            "healthy"
        );
    }

    #[test]
    fn doctor_status_serde_degraded() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            "degraded"
        );
    }

    #[test]
    fn doctor_status_serde_unhealthy() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            "unhealthy"
        );
    }

    #[test]
    fn connector_new_eq_default() {
        let a = DocuSignConnector::new();
        let b = DocuSignConnector::default();
        assert!(a.config.is_none());
        assert!(b.config.is_none());
        assert_eq!(a.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(b.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn base64_encode_six_bytes() {
        // "abcdef" -> YWJjZGVm
        assert_eq!(base64_encode(b"abcdef"), "YWJjZGVm");
    }

    #[test]
    fn base64_encode_binary_data() {
        let data: [u8; 4] = [0xFF, 0x00, 0xAB, 0xCD];
        let encoded = base64_encode(&data);
        assert_eq!(encoded.len(), 8); // 4 bytes -> 8 base64 chars
    }

    #[test]
    fn require_str_empty_string_is_ok() {
        let input = json!({"x": ""});
        assert_eq!(require_str(&input, "x").unwrap(), "");
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"x": {"nested": true}});
        assert!(require_str(&input, "x").is_err());
    }
}
