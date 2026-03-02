//! FCP Twilio Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::TwilioClient, error::TwilioError};

/// FCP Twilio Connector.
pub struct TwilioConnector {
    base: Arc<BaseConnector>,
    pub(crate) client: Option<TwilioClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl TwilioConnector {
    /// Create a new Twilio connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("twilio"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let account_sid =
            params
                .get("account_sid")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing account_sid in configuration".into(),
                })?;

        let auth_token =
            params
                .get("auth_token")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing auth_token in configuration".into(),
                })?;

        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let mut client =
            TwilioClient::new(account_sid, auth_token).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Twilio connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
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
            manifest_hash: "sha256:twilio-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 50,
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
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                // ── Messaging ────────────────────────────────────────
                op_info(
                    "twilio.send_message",
                    "Send an SMS or MMS message",
                    json!({
                        "type": "object",
                        "required": ["to", "from", "body"],
                        "properties": {
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "body": { "type": "string" },
                            "media_url": { "type": "array", "items": { "type": "string" } },
                            "status_callback": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "date_created": { "type": "string" },
                            "price": { "type": "string" }
                        }
                    }),
                    "twilio.message",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send an SMS or MMS. Requires a Twilio phone number as sender.".into(),
                        common_mistakes: vec![
                            "Not using E.164 format for phone numbers.".into(),
                        ],
                        examples: vec![
                            r#"{"to": "+15551234567", "from": "+15559876543", "body": "Hello from FCP!"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.get_message"),
                            CapabilityId::from_static("twilio.list_messages"),
                        ],
                    },
                ),
                op_info(
                    "twilio.get_message",
                    "Get details of a specific message",
                    json!({
                        "type": "object",
                        "required": ["message_sid"],
                        "properties": {
                            "message_sid": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "body": { "type": "string" },
                            "date_created": { "type": "string" },
                            "price": { "type": "string" },
                            "num_media": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve message details including delivery status.".into(),
                        common_mistakes: vec![
                            "Using a Call SID instead of a Message SID.".into(),
                        ],
                        examples: vec![
                            r#"{"message_sid": "SMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.send_message"),
                            CapabilityId::from_static("twilio.list_messages"),
                        ],
                    },
                ),
                op_info(
                    "twilio.list_messages",
                    "List messages with filtering",
                    json!({
                        "type": "object",
                        "properties": {
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "date_sent": { "type": "string" },
                            "page_size": { "type": "integer" },
                            "page": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "array" },
                            "next_page_uri": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List messages with optional filters.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"to": "+15551234567", "page_size": 20}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.get_message"),
                            CapabilityId::from_static("twilio.send_message"),
                        ],
                    },
                ),
                // ── Voice ────────────────────────────────────────────
                op_info(
                    "twilio.create_call",
                    "Initiate an outbound voice call",
                    json!({
                        "type": "object",
                        "required": ["to", "from", "url"],
                        "properties": {
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "url": { "type": "string" },
                            "status_callback": { "type": "string" },
                            "timeout": { "type": "integer" },
                            "record": { "type": "boolean" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "date_created": { "type": "string" }
                        }
                    }),
                    "twilio.voice",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Initiate a voice call. Requires a TwiML URL. Use with extreme caution.".into(),
                        common_mistakes: vec![
                            "Not providing a valid TwiML URL.".into(),
                            "Setting record=true without user consent.".into(),
                        ],
                        examples: vec![
                            r#"{"to": "+15551234567", "from": "+15559876543", "url": "https://example.com/twiml"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.get_call"),
                            CapabilityId::from_static("twilio.list_recordings"),
                        ],
                    },
                ),
                op_info(
                    "twilio.get_call",
                    "Get details of a specific voice call",
                    json!({
                        "type": "object",
                        "required": ["call_sid"],
                        "properties": {
                            "call_sid": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "duration": { "type": "string" },
                            "date_created": { "type": "string" },
                            "price": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve call details including duration and cost.".into(),
                        common_mistakes: vec![
                            "Using a Message SID instead of a Call SID.".into(),
                        ],
                        examples: vec![
                            r#"{"call_sid": "CAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.create_call"),
                            CapabilityId::from_static("twilio.list_recordings"),
                        ],
                    },
                ),
                // ── Recordings and Media ─────────────────────────────
                op_info(
                    "twilio.list_recordings",
                    "List call recordings",
                    json!({
                        "type": "object",
                        "properties": {
                            "call_sid": { "type": "string" },
                            "date_created": { "type": "string" },
                            "page_size": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "recordings": { "type": "array" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List call recordings. Filter by call_sid for a specific call.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"call_sid": "CAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.download_recording"),
                            CapabilityId::from_static("twilio.get_call"),
                        ],
                    },
                ),
                op_info(
                    "twilio.download_recording",
                    "Download a call recording audio file",
                    json!({
                        "type": "object",
                        "required": ["recording_sid"],
                        "properties": {
                            "recording_sid": { "type": "string" },
                            "format": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "data": { "type": "string" },
                            "content_type": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Download a call recording. Use format=mp3 for smaller files.".into(),
                        common_mistakes: vec![
                            "Not checking recording status before downloading.".into(),
                        ],
                        examples: vec![
                            r#"{"recording_sid": "RExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "format": "mp3"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("twilio.list_recordings")],
                    },
                ),
                op_info(
                    "twilio.download_media",
                    "Download MMS media attached to a message",
                    json!({
                        "type": "object",
                        "required": ["message_sid", "media_sid"],
                        "properties": {
                            "message_sid": { "type": "string" },
                            "media_sid": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "data": { "type": "string" },
                            "content_type": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Download media attached to an MMS message.".into(),
                        common_mistakes: vec![
                            "Not extracting media_sid from the message first.".into(),
                        ],
                        examples: vec![
                            r#"{"message_sid": "SMxxx", "media_sid": "MExxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.get_message"),
                            CapabilityId::from_static("twilio.download_recording"),
                        ],
                    },
                ),
                // ── Account ──────────────────────────────────────────
                op_info(
                    "twilio.get_account",
                    "Get Twilio account details",
                    json!({ "type": "object", "properties": {} }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "friendly_name": { "type": "string" },
                            "status": { "type": "string" },
                            "type": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Check account status and balance.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("twilio.list_phone_numbers")],
                    },
                ),
                op_info(
                    "twilio.list_phone_numbers",
                    "List Twilio phone numbers on the account",
                    json!({
                        "type": "object",
                        "properties": {
                            "phone_number": { "type": "string" },
                            "page_size": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "incoming_phone_numbers": { "type": "array" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List phone numbers to find available sender numbers.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![
                            CapabilityId::from_static("twilio.send_message"),
                            CapabilityId::from_static("twilio.create_call"),
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
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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
            "twilio.send_message" => self.invoke_send_message(input).await,
            "twilio.get_message" => self.invoke_get_message(input).await,
            "twilio.list_messages" => self.invoke_list_messages(input).await,
            "twilio.create_call" => self.invoke_create_call(input).await,
            "twilio.get_call" => self.invoke_get_call(input).await,
            "twilio.list_recordings" => self.invoke_list_recordings(input).await,
            "twilio.download_recording" => self.invoke_download_recording(input).await,
            "twilio.download_media" => self.invoke_download_media(input).await,
            "twilio.get_account" => self.invoke_get_account().await,
            "twilio.list_phone_numbers" => self.invoke_list_phone_numbers(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = require_str(&input, "to")?;
        let from = require_str(&input, "from")?;
        let body = require_str(&input, "body")?;

        let media_url: Option<Vec<String>> =
            input
                .get("media_url")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                });
        let status_callback = input.get("status_callback").and_then(|v| v.as_str());

        let resp = client
            .send_message(to, from, body, media_url.as_deref(), status_callback)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_get_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_sid = require_str(&input, "message_sid")?;

        let resp = client
            .get_message(message_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_messages(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = input.get("to").and_then(|v| v.as_str());
        let from = input.get("from").and_then(|v| v.as_str());
        let date_sent = input.get("date_sent").and_then(|v| v.as_str());
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let page = input.get("page").and_then(|v| v.as_u64()).map(|v| v as u32);

        let resp = client
            .list_messages(to, from, date_sent, page_size, page)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "messages": resp.messages,
            "next_page_uri": resp.next_page_uri,
        }))
    }

    async fn invoke_create_call(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = require_str(&input, "to")?;
        let from = require_str(&input, "from")?;
        let url = require_str(&input, "url")?;
        let status_callback = input.get("status_callback").and_then(|v| v.as_str());
        let timeout = input
            .get("timeout")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let record = input.get("record").and_then(|v| v.as_bool());

        let resp = client
            .create_call(to, from, url, status_callback, timeout, record)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_get_call(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let call_sid = require_str(&input, "call_sid")?;

        let resp = client
            .get_call(call_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_recordings(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let call_sid = input.get("call_sid").and_then(|v| v.as_str());
        let date_created = input.get("date_created").and_then(|v| v.as_str());
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let resp = client
            .list_recordings(call_sid, date_created, page_size)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "recordings": resp.recordings,
            "next_page_uri": resp.next_page_uri,
        }))
    }

    async fn invoke_download_recording(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let recording_sid = require_str(&input, "recording_sid")?;
        let format = input.get("format").and_then(|v| v.as_str());

        let (data, content_type) = client
            .download_recording(recording_sid, format)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({ "data": data, "content_type": content_type }))
    }

    async fn invoke_download_media(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_sid = require_str(&input, "message_sid")?;
        let media_sid = require_str(&input, "media_sid")?;

        let (data, content_type) = client
            .download_media(message_sid, media_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({ "data": data, "content_type": content_type }))
    }

    async fn invoke_get_account(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resp = client
            .get_account()
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_phone_numbers(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let phone_number = input.get("phone_number").and_then(|v| v.as_str());
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let resp = client
            .list_phone_numbers(phone_number, page_size)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "incoming_phone_numbers": resp.incoming_phone_numbers,
            "next_page_uri": resp.next_page_uri,
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Twilio connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for TwilioConnector {
    fn default() -> Self {
        Self::new()
    }
}

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
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints,
        rate_limit: None,
        requires_approval: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

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
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["twilio.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = TwilioConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = TwilioConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["twilio.get_message"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "twilio.get_message");
        let result = connector
            .handle_invoke(json!({
                "operation": "twilio.get_message",
                "input": { "message_sid": "SMtest" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = TwilioConnector::new();
        connector.client = Some(
            TwilioClient::new("ACtest123", "test_token")
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
                "capabilities_requested": ["twilio.send_message"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "twilio.send_message");
        let result = connector
            .handle_invoke(json!({
                "operation": "twilio.send_message",
                "input": { "to": "+15551234567", "from": "+15559876543" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("body")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"twilio.send_message"));
        assert!(op_ids.contains(&"twilio.get_message"));
        assert!(op_ids.contains(&"twilio.list_messages"));
        assert!(op_ids.contains(&"twilio.create_call"));
        assert!(op_ids.contains(&"twilio.get_call"));
        assert!(op_ids.contains(&"twilio.list_recordings"));
        assert!(op_ids.contains(&"twilio.download_recording"));
        assert!(op_ids.contains(&"twilio.download_media"));
        assert!(op_ids.contains(&"twilio.get_account"));
        assert!(op_ids.contains(&"twilio.list_phone_numbers"));
        assert_eq!(ops.len(), 10);
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
