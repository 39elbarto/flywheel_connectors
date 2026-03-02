//! FCP Gmail Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::GmailClient, error::GmailError};

/// FCP Gmail Connector.
pub struct GmailConnector {
    base: Arc<BaseConnector>,
    client: Option<GmailClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl GmailConnector {
    /// Create a new Gmail connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("gmail"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let token =
            params
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing token in configuration".into(),
                })?;

        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let mut client = GmailClient::new(token).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Gmail connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:gmail-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "gmail.send_message",
                    "Send an email message",
                    json!({
                        "type": "object",
                        "required": ["raw"],
                        "properties": {
                            "raw": { "type": "string", "description": "Base64url-encoded RFC 2822 message" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.messages.send",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a new email. The raw field must be a base64url-encoded RFC 2822 message.".into(),
                        common_mistakes: vec!["Using standard base64 instead of base64url encoding".into()],
                        examples: vec![
                            r#"{"raw": "RnJvbTogc2VuZGVyQGV4YW1wbGUuY29tClRvOiByZWNpcGllbnRAZXhhbXBsZS5jb20KU3ViamVjdDogVGVzdAoKSGVsbG8h"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.get_message"),
                            CapabilityId::from_static("gmail.list_messages"),
                        ],
                    },
                ),
                op_info(
                    "gmail.get_message",
                    "Get a single email message by ID",
                    json!({
                        "type": "object",
                        "required": ["message_id"],
                        "properties": {
                            "message_id": { "type": "string", "description": "Gmail message ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.messages.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve full details of a specific email message.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"message_id": "18d1234abc567890"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.list_messages"),
                            CapabilityId::from_static("gmail.get_thread"),
                        ],
                    },
                ),
                op_info(
                    "gmail.list_messages",
                    "List email messages with optional search query",
                    json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "string", "description": "Gmail search query (same syntax as web UI)" },
                            "max_results": { "type": "integer", "description": "Max messages to return" },
                            "page_token": { "type": "string", "description": "Pagination token" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "array" },
                            "next_page_token": { "type": "string" },
                            "result_size_estimate": { "type": "integer" }
                        }
                    }),
                    "gmail.messages.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List or search email messages. Uses Gmail search syntax.".into(),
                        common_mistakes: vec!["Expecting full message bodies; list returns only IDs and thread IDs".into()],
                        examples: vec![
                            r#"{"query": "from:notifications@github.com is:unread", "max_results": 10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.get_message"),
                        ],
                    },
                ),
                op_info(
                    "gmail.modify_message",
                    "Modify message labels (add or remove)",
                    json!({
                        "type": "object",
                        "required": ["message_id"],
                        "properties": {
                            "message_id": { "type": "string", "description": "Gmail message ID" },
                            "add_label_ids": { "type": "array", "items": { "type": "string" }, "description": "Label IDs to add" },
                            "remove_label_ids": { "type": "array", "items": { "type": "string" }, "description": "Label IDs to remove" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.messages.modify",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Add or remove labels from a message (e.g., mark as read, archive).".into(),
                        common_mistakes: vec!["Using label names instead of label IDs".into()],
                        examples: vec![
                            r#"{"message_id": "18d1234abc", "remove_label_ids": ["UNREAD"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.list_labels"),
                            CapabilityId::from_static("gmail.get_message"),
                        ],
                    },
                ),
                op_info(
                    "gmail.trash_message",
                    "Move a message to trash",
                    json!({
                        "type": "object",
                        "required": ["message_id"],
                        "properties": {
                            "message_id": { "type": "string", "description": "Gmail message ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.messages.modify",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Move an email message to the trash.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"message_id": "18d1234abc567890"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gmail.get_message")],
                    },
                ),
                op_info(
                    "gmail.get_thread",
                    "Get an email thread with all messages",
                    json!({
                        "type": "object",
                        "required": ["thread_id"],
                        "properties": {
                            "thread_id": { "type": "string", "description": "Gmail thread ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "thread": { "type": "object" } } }),
                    "gmail.threads.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve all messages in an email thread/conversation.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"thread_id": "18d1234abc567890"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.get_message"),
                            CapabilityId::from_static("gmail.list_messages"),
                        ],
                    },
                ),
                op_info(
                    "gmail.list_labels",
                    "List all Gmail labels",
                    json!({ "type": "object", "properties": {} }),
                    json!({
                        "type": "object",
                        "properties": { "labels": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "gmail.labels.manage",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all labels in the Gmail account (system and user-created).".into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("gmail.modify_message")],
                    },
                ),
                op_info(
                    "gmail.get_draft",
                    "Get a draft by ID",
                    json!({
                        "type": "object",
                        "required": ["draft_id"],
                        "properties": {
                            "draft_id": { "type": "string", "description": "Gmail draft ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "draft": { "type": "object" } } }),
                    "gmail.messages.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a saved email draft.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"draft_id": "r1234567890"}"#.into()],
                        related: vec![CapabilityId::from_static("gmail.send_draft")],
                    },
                ),
                op_info(
                    "gmail.send_draft",
                    "Send a previously saved draft",
                    json!({
                        "type": "object",
                        "required": ["draft_id"],
                        "properties": {
                            "draft_id": { "type": "string", "description": "Gmail draft ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.messages.send",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a draft that was previously created and saved.".into(),
                        common_mistakes: vec!["The draft is deleted after sending".into()],
                        examples: vec![r#"{"draft_id": "r1234567890"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("gmail.get_draft"),
                            CapabilityId::from_static("gmail.send_message"),
                        ],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "gmail.send_message" => self.invoke_send_message(input).await,
            "gmail.get_message" => self.invoke_get_message(input).await,
            "gmail.list_messages" => self.invoke_list_messages(input).await,
            "gmail.modify_message" => self.invoke_modify_message(input).await,
            "gmail.trash_message" => self.invoke_trash_message(input).await,
            "gmail.get_thread" => self.invoke_get_thread(input).await,
            "gmail.list_labels" => self.invoke_list_labels().await,
            "gmail.get_draft" => self.invoke_get_draft(input).await,
            "gmail.send_draft" => self.invoke_send_draft(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let raw = require_str(&input, "raw")?;

        let message = client
            .send_message(raw)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_get_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_id = require_str(&input, "message_id")?;

        let message = client
            .get_message(message_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_list_messages(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = input.get("query").and_then(|v| v.as_str());
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_messages(query, max_results, page_token)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({
            "messages": result.messages,
            "next_page_token": result.next_page_token,
            "result_size_estimate": result.result_size_estimate
        }))
    }

    async fn invoke_modify_message(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_id = require_str(&input, "message_id")?;

        let add_labels: Vec<String> = input
            .get("add_label_ids")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let remove_labels: Vec<String> = input
            .get("remove_label_ids")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let message = client
            .modify_message(message_id, &add_labels, &remove_labels)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_trash_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_id = require_str(&input, "message_id")?;

        let message = client
            .trash_message(message_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_get_thread(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let thread_id = require_str(&input, "thread_id")?;

        let thread = client
            .get_thread(thread_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "thread": thread }))
    }

    async fn invoke_list_labels(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let labels = client
            .list_labels()
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "labels": labels }))
    }

    async fn invoke_get_draft(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let draft_id = require_str(&input, "draft_id")?;

        let draft = client
            .get_draft(draft_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "draft": draft }))
    }

    async fn invoke_send_draft(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let draft_id = require_str(&input, "draft_id")?;

        let message = client
            .send_draft(draft_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Gmail connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GmailConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

#[allow(clippy::fn_params_excessive_bools)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = GmailConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gmail.messages.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = GmailConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = GmailConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gmail.list_labels"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "gmail.list_labels");

        let result = connector
            .handle_invoke(json!({
                "operation": "gmail.list_labels",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = GmailConnector::new();
        connector.client = Some(
            GmailClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gmail.get_message"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "gmail.get_message");

        let result = connector
            .handle_invoke(json!({
                "operation": "gmail.get_message",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("message_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = GmailConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"gmail.send_message"));
        assert!(op_ids.contains(&"gmail.get_message"));
        assert!(op_ids.contains(&"gmail.list_messages"));
        assert!(op_ids.contains(&"gmail.modify_message"));
        assert!(op_ids.contains(&"gmail.trash_message"));
        assert!(op_ids.contains(&"gmail.get_thread"));
        assert!(op_ids.contains(&"gmail.list_labels"));
        assert!(op_ids.contains(&"gmail.get_draft"));
        assert!(op_ids.contains(&"gmail.send_draft"));
        assert_eq!(ops.len(), 9);
    }
}
