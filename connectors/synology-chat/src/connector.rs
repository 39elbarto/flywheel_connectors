//! `Synology Chat` connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_sdk::prelude::*;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::client::{
    SynologyChatClient, SynologyChatMessageRequest, SynologyChatPayload, normalize_inbound_event,
};
use crate::types::{
    InboundWebhookPayload, SynologyChatConfig, SynologyChatStateModel, TokenVerification,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "synology_chat.read";
const CAP_WRITE: &str = "synology_chat.write";
const CAP_WEBHOOK: &str = "synology_chat.webhook";
const OP_SEND_MESSAGE: &str = "synology_chat.send_message";
const OP_SEND_PAYLOAD: &str = "synology_chat.send_payload";
const OP_INGEST_OUTGOING_WEBHOOK: &str = "synology_chat.ingest_outgoing_webhook";
const OP_WEBHOOK_NORMALIZE: &str = "synology_chat.webhook.normalize";
const OP_HEALTH: &str = "synology_chat.health";

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: String,
    critical: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    passed: bool,
    checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    fn new(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().all(|check| !check.critical || check.passed);
        Self { passed, checks }
    }
}

#[derive(Debug)]
struct SynologyChatState {
    model: SynologyChatStateModel,
    client: SynologyChatClient,
    runtime: ConnectorRuntime,
    outgoing_token: Option<String>,
}

#[derive(Debug)]
pub struct SynologyChatConnector {
    base: BaseConnector,
    state: Option<SynologyChatState>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl SynologyChatConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.synology-chat")),
            state: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = vec![DoctorCheck {
            name: "configured".into(),
            passed: self.state.is_some(),
            message: if self.state.is_some() {
                "Configuration loaded".into()
            } else {
                "Connector is not configured".into()
            },
            critical: true,
        }];

        if let Some(state) = &self.state {
            checks.push(DoctorCheck {
                name: "delivery_target".into(),
                passed: true,
                message: state.model.delivery_target.incoming_url_redacted.clone(),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "outgoing_token".into(),
                passed: state.model.outgoing_token_configured,
                message: if state.model.outgoing_token_configured {
                    "configured for forwarded outgoing-webhook ingest".into()
                } else {
                    "not configured; inbound normalization remains disabled".into()
                },
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "receive_path".into(),
                passed: true,
                message: match state.model.receive_path {
                    crate::types::SynologyChatReceivePath::Disabled => "disabled".into(),
                    crate::types::SynologyChatReceivePath::ForwardedOutgoingWebhook => {
                        "forwarded_outgoing_webhook".into()
                    }
                },
                critical: false,
            });
        }

        DoctorResult::new(checks)
    }

    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        vec![
            OperationInfo {
                id: OperationId::from_static(OP_SEND_MESSAGE),
                summary: "Send a Synology Chat message".into(),
                description: Some("Deliver a message through a Synology Chat incoming webhook.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["text"],
                    "properties": {
                        "text": { "type": "string" },
                        "user_id": { "type": "string" },
                        "user_ids": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "bot_name": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use this to deliver a message to a Synology Chat webhook target.".into(),
                    common_mistakes: vec![
                        "This connector delivers outbound webhook requests; it does not yet host the outgoing-webhook receive path.".into()
                    ],
                    examples: vec!["{\"text\":\"Hello from Flywheel\"}".into()],
                    related: vec![CapabilityId::from_static(OP_HEALTH)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEND_PAYLOAD),
                summary: "Send a raw Synology Chat webhook payload".into(),
                description: Some("Forward an arbitrary JSON object to a Synology Chat incoming webhook for advanced card or attachment use cases.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["payload"],
                    "properties": {
                        "payload": { "type": "object" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use this when the simple text operation is too limited and you need to pass a Synology Chat webhook payload through directly.".into(),
                    common_mistakes: vec![
                        "payload must be a JSON object that the Synology Chat webhook endpoint understands.".into()
                    ],
                    examples: vec!["{\"payload\":{\"text\":\"Hello\",\"attachments\":[{\"text\":\"Details\"}]}}".into()],
                    related: vec![CapabilityId::from_static(OP_SEND_MESSAGE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_INGEST_OUTGOING_WEBHOOK),
                summary: "Validate and normalize a forwarded Synology Chat outgoing-webhook payload"
                    .into(),
                description: Some(
                    "Normalize a host-forwarded Synology Chat outgoing-webhook payload into a stable event envelope without pretending this connector hosts the listener.".into(),
                ),
                input_schema: json!({
                    "type": "object",
                    "required": ["payload"],
                    "properties": {
                        "payload": {
                            "type": "object",
                            "required": [
                                "token",
                                "channel_id",
                                "channel_type",
                                "user_id",
                                "username",
                                "post_id",
                                "thread_id",
                                "timestamp",
                                "text"
                            ],
                            "properties": {
                                "token": { "type": "string" },
                                "channel_id": { "type": ["string", "integer"] },
                                "channel_type": { "type": ["string", "integer"] },
                                "channel_name": { "type": "string" },
                                "user_id": { "type": ["string", "integer"] },
                                "username": { "type": "string" },
                                "post_id": { "type": ["string", "integer"] },
                                "thread_id": { "type": ["string", "integer"] },
                                "timestamp": { "type": ["string", "integer"] },
                                "text": { "type": "string" },
                                "trigger_word": { "type": "string" },
                                "file_url": { "type": "string" },
                                "attachments": { "type": "array" },
                                "files": { "type": "array" },
                                "file": {}
                            }
                        },
                        "delivery_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["event"],
                    "properties": {
                        "event": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static(CAP_WEBHOOK),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this when fcp-host forwards a Synology Chat outgoing-webhook payload and you need channel, thread, sender, and attachment metadata in a stable shape.".into(),
                    common_mistakes: vec![
                        "Passing the raw form-encoded HTTP body instead of the parsed payload object".into(),
                        "Calling this operation without configuring outgoing_token first".into(),
                    ],
                    examples: vec![
                        "{\"payload\":{\"token\":\"shared-secret\",\"channel_id\":\"34\",\"channel_type\":\"1\",\"channel_name\":\"Labb\",\"user_id\":\"4\",\"username\":\"mikael\",\"post_id\":\"146028888128\",\"thread_id\":\"0\",\"timestamp\":\"1646827836131\",\"text\":\"Tjena\",\"trigger_word\":\"Tjena\"}}".into(),
                    ],
                    related: vec![
                        CapabilityId::from_static(OP_HEALTH),
                        CapabilityId::from_static(OP_SEND_MESSAGE),
                    ],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_WEBHOOK_NORMALIZE),
                summary: "Normalize a raw inbound Synology Chat webhook payload".into(),
                description: Some(
                    "Accept a raw inbound Synology Chat webhook payload and return a normalized event envelope. If outgoing_token is configured, token verification is performed and the result is included. Unlike ingest_outgoing_webhook, this operation does not reject on token mismatch — it reports the verification status and lets the caller decide.".into(),
                ),
                input_schema: json!({
                    "type": "object",
                    "required": ["payload"],
                    "properties": {
                        "payload": {
                            "type": "object",
                            "properties": {
                                "user_id": {},
                                "username": { "type": "string" },
                                "post_id": {},
                                "channel_id": {},
                                "channel_name": { "type": "string" },
                                "channel_type": {},
                                "text": { "type": "string" },
                                "timestamp": {},
                                "token": { "type": "string" },
                                "trigger_word": { "type": "string" },
                                "thread_id": {},
                                "file_url": { "type": "string" }
                            }
                        }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["event"],
                    "properties": {
                        "event": { "type": "object" },
                        "token_verification": { "type": "string" }
                    }
                }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this to normalize any inbound Synology Chat webhook payload into a stable event shape, with optional token verification.".into(),
                    common_mistakes: vec![
                        "Passing the raw HTTP body instead of the parsed JSON payload object".into(),
                    ],
                    examples: vec![
                        "{\"payload\":{\"token\":\"abc\",\"channel_id\":34,\"user_id\":4,\"username\":\"mikael\",\"text\":\"Hello\"}}".into(),
                    ],
                    related: vec![
                        CapabilityId::from_static(OP_INGEST_OUTGOING_WEBHOOK),
                        CapabilityId::from_static(OP_HEALTH),
                    ],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_HEALTH),
                summary: "Report connector health".into(),
                description: Some("Return configured webhook target details.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this before attempting outbound delivery.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_SEND_MESSAGE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let required_cap = match req.operation.as_str() {
            OP_SEND_MESSAGE | OP_SEND_PAYLOAD => CapabilityId::from_static(CAP_WRITE),
            OP_INGEST_OUTGOING_WEBHOOK => CapabilityId::from_static(CAP_WEBHOOK),
            OP_WEBHOOK_NORMALIZE | OP_HEALTH => CapabilityId::from_static(CAP_READ),
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify(req.capability_token, &required_cap, &req.operation, &[])?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let output = match req.operation.as_str() {
            OP_SEND_MESSAGE => {
                let text = req
                    .input
                    .get("text")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing text".into(),
                    })?;
                let user_ids = optional_user_ids(&req.input)?;
                let bot_name = req.input.get("bot_name").and_then(|value| value.as_str());
                let request = SynologyChatMessageRequest::new(text, &user_ids, bot_name)
                    .map_err(|error| error.to_fcp_error())?;
                state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?
                    .into_json()
            }
            OP_SEND_PAYLOAD => {
                let payload = req
                    .input
                    .get("payload")
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing payload".into(),
                    })?;
                let payload = SynologyChatPayload::from_value(payload)
                    .map_err(|error| error.to_fcp_error())?;
                state
                    .client
                    .send_payload(&payload)
                    .await
                    .map_err(|error| error.to_fcp_error())?
                    .into_json()
            }
            OP_INGEST_OUTGOING_WEBHOOK => normalize_outgoing_webhook(&req.input, state)?,
            OP_WEBHOOK_NORMALIZE => invoke_webhook_normalize(&req.input, state)?,
            OP_HEALTH => json!({
                "status": "ok",
                "delivery_target": &state.model.delivery_target,
                "request_timeout_ms": state.model.request_timeout_ms,
                "allow_insecure_ssl": state.model.allow_insecure_ssl,
                "outgoing_token_configured": state.model.outgoing_token_configured,
                "receive_path": &state.model.receive_path,
                "reply_semantics": &state.model.reply_semantics,
                "manifest_hash": Self::manifest_hash(),
            }),
            _ => unreachable!(),
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for SynologyChatConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn optional_user_ids(input: &serde_json::Value) -> FcpResult<Vec<String>> {
    if let Some(user_ids) = input.get("user_ids") {
        let values = user_ids
            .as_array()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "user_ids must be an array of strings".into(),
            })?;
        let mut result = Vec::with_capacity(values.len());
        for value in values {
            let user_id = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "user_ids must contain only strings".into(),
            })?;
            if user_id.trim().is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "user_ids must not contain empty strings".into(),
                });
            }
            let trimmed = user_id.trim();
            if !result.iter().any(|existing| existing == trimmed) {
                result.push(trimmed.to_string());
            }
        }
        return Ok(result);
    }

    Ok(input
        .get("user_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| vec![value.to_string()])
        .unwrap_or_default())
}

fn normalize_outgoing_webhook(input: &Value, state: &SynologyChatState) -> FcpResult<Value> {
    let configured_token =
        state
            .outgoing_token
            .as_deref()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "outgoing_token must be configured for outgoing webhook ingest".into(),
            })?;
    let payload = input
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "payload must be a JSON object".into(),
        })?;

    let payload_token = required_payload_string(payload, "token")?;
    if payload_token != configured_token {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Outgoing webhook token verification failed".into(),
        });
    }

    let channel_id = required_payload_string_or_integer(payload, "channel_id")?;
    let channel_type = required_payload_string_or_integer(payload, "channel_type")?;
    let channel_name = optional_payload_string(payload, "channel_name");
    let user_id = required_payload_string_or_integer(payload, "user_id")?;
    let username = required_payload_string(payload, "username")?;
    let post_id = required_payload_string_or_integer(payload, "post_id")?;
    let thread_id = required_payload_string_or_integer(payload, "thread_id")?;
    let timestamp_ms = required_payload_i64(payload, "timestamp")?;
    let text = required_payload_string(payload, "text")?;
    let trigger_word = optional_payload_string(payload, "trigger_word");
    let attachments = normalize_inbound_attachments(payload);
    let is_threaded = !matches!(thread_id.as_str(), "" | "0");

    let channel_uri = format!("synology-chat://channels/{channel_id}");
    let sender_uri = format!("synology-chat://users/{user_id}");
    let message_uri = if is_threaded {
        format!("{channel_uri}/threads/{thread_id}/posts/{post_id}")
    } else {
        format!("{channel_uri}/posts/{post_id}")
    };
    let delivery_id = input
        .get("delivery_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map_or_else(
            || format!("synology-chat:{channel_id}:{post_id}:{timestamp_ms}"),
            ToString::to_string,
        );
    let thread = if is_threaded {
        json!({
            "id": &thread_id,
            "resource_uri": format!("{channel_uri}/threads/{thread_id}"),
            "is_threaded": true,
        })
    } else {
        json!({
            "id": null,
            "resource_uri": null,
            "is_threaded": false,
        })
    };

    Ok(json!({
        "event": {
            "topic": "synology_chat.outgoing_webhook.received",
            "event_type": "outgoing_webhook",
            "delivery_id": delivery_id,
            "resource_uri": &message_uri,
            "channel": {
                "id": &channel_id,
                "type": &channel_type,
                "name": &channel_name,
                "resource_uri": &channel_uri,
            },
            "thread": thread,
            "sender": {
                "user_id": &user_id,
                "username": &username,
                "resource_uri": &sender_uri,
            },
            "message": {
                "post_id": &post_id,
                "text": &text,
                "trigger_word": &trigger_word,
                "timestamp_ms": timestamp_ms,
            },
            "attachments": attachments,
            "reply": {
                "mode": "outgoing_webhook_response",
                "supports_text": true,
                "supports_file_url": true,
                "audience": {
                    "user_id": &user_id,
                    "username": &username,
                },
            },
        }
    }))
}

fn invoke_webhook_normalize(input: &Value, state: &SynologyChatState) -> FcpResult<Value> {
    let payload_value = input
        .get("payload")
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "Missing payload".into(),
        })?;

    let payload: InboundWebhookPayload =
        serde_json::from_value(payload_value.clone()).map_err(|error| {
            FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid inbound webhook payload: {error}"),
            }
        })?;

    let (event, verification) = normalize_inbound_event(
        &payload,
        state.outgoing_token.as_deref(),
        payload_value.clone(),
    );

    let verification_str = match verification {
        TokenVerification::Verified => "verified",
        TokenVerification::Mismatch => "mismatch",
        TokenVerification::MissingFromPayload => "missing_from_payload",
        TokenVerification::NotConfigured => "not_configured",
    };

    let event_value = serde_json::to_value(&event).map_err(|error| FcpError::Internal {
        message: format!("Failed to serialize normalized event: {error}"),
    })?;

    Ok(json!({
        "event": event_value,
        "token_verification": verification_str,
    }))
}

fn normalize_inbound_attachments(payload: &Map<String, Value>) -> Vec<Value> {
    let mut attachments = Vec::new();

    if let Some(file_url) = optional_payload_string(payload, "file_url") {
        attachments.push(json!({
            "source": "file_url",
            "kind": "external_file",
            "url": file_url,
        }));
    }

    if let Some(file) = payload.get("file") {
        attachments.push(normalize_attachment_value(file, "file"));
    }

    for key in ["attachments", "files"] {
        if let Some(values) = payload.get(key).and_then(Value::as_array) {
            for (index, value) in values.iter().enumerate() {
                let source = format!("{key}[{index}]");
                attachments.push(normalize_attachment_value(value, &source));
            }
        }
    }

    attachments
}

fn normalize_attachment_value(value: &Value, source: &str) -> Value {
    match value {
        Value::Object(object) => json!({
            "source": source,
            "kind": detect_attachment_kind(object),
            "name": first_payload_scalar(object, &["name", "filename", "file_name", "title"]),
            "url": first_payload_scalar(object, &["url", "file_url", "download_url", "href"]),
            "mime_type": first_payload_scalar(object, &["mime_type", "content_type", "type"]),
            "text": first_payload_scalar(object, &["text", "label", "caption"]),
        }),
        Value::String(text) => json!({
            "source": source,
            "kind": "string",
            "value": text,
        }),
        _ => json!({
            "source": source,
            "kind": "raw",
            "value": value,
        }),
    }
}

fn detect_attachment_kind(object: &Map<String, Value>) -> &'static str {
    let mime_type = first_payload_scalar(object, &["mime_type", "content_type", "type"]);
    if let Some(mime_type) = mime_type {
        if mime_type.starts_with("image/") {
            return "image";
        }
        return "typed_attachment";
    }
    if first_payload_scalar(object, &["url", "file_url", "download_url", "href"]).is_some() {
        return "external_file";
    }
    if first_payload_scalar(object, &["text", "label", "caption"]).is_some() {
        return "card";
    }
    "attachment"
}

fn required_payload_string(payload: &Map<String, Value>, field: &str) -> FcpResult<String> {
    optional_payload_string(payload, field).ok_or_else(|| FcpError::InvalidRequest {
        code: 1005,
        message: format!("payload.{field} must be a non-empty string"),
    })
}

fn required_payload_string_or_integer(
    payload: &Map<String, Value>,
    field: &str,
) -> FcpResult<String> {
    optional_payload_string_or_integer(payload, field).ok_or_else(|| FcpError::InvalidRequest {
        code: 1005,
        message: format!("payload.{field} must be a non-empty string or integer"),
    })
}

fn required_payload_i64(payload: &Map<String, Value>, field: &str) -> FcpResult<i64> {
    let value = payload.get(field).ok_or_else(|| FcpError::InvalidRequest {
        code: 1005,
        message: format!("payload.{field} is required"),
    })?;
    match value {
        Value::Number(number) => {
            let parsed = number.as_i64().ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("payload.{field} must be a signed 64-bit integer"),
            })?;
            if parsed < 0 {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("payload.{field} must be a non-negative integer timestamp"),
                });
            }
            Ok(parsed)
        }
        Value::String(raw) => raw
            .trim()
            .parse::<i64>()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1005,
                message: format!("payload.{field} must be an integer timestamp"),
            })
            .and_then(|parsed| {
                if parsed < 0 {
                    Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: format!(
                            "payload.{field} must be a non-negative integer timestamp"
                        ),
                    })
                } else {
                    Ok(parsed)
                }
            }),
        _ => Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("payload.{field} must be an integer timestamp"),
        }),
    }
}

fn optional_payload_string(payload: &Map<String, Value>, field: &str) -> Option<String> {
    payload.get(field).and_then(string_value)
}

fn optional_payload_string_or_integer(payload: &Map<String, Value>, field: &str) -> Option<String> {
    payload.get(field).and_then(string_or_integer_value)
}

fn first_payload_scalar(payload: &Map<String, Value>, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find_map(|field| payload.get(*field).and_then(scalar_to_string))
}

fn scalar_to_string(value: &Value) -> Option<String> {
    string_value(value)
        .or_else(|| value.as_i64().map(|number| number.to_string()))
        .or_else(|| value.as_u64().map(|number| number.to_string()))
        .or_else(|| value.as_bool().map(|flag| flag.to_string()))
}

fn string_value(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        _ => None,
    }
}

fn string_or_integer_value(value: &Value) -> Option<String> {
    string_value(value)
        .or_else(|| value.as_i64().map(|number| number.to_string()))
        .or_else(|| value.as_u64().map(|number| number.to_string()))
}

fcp_core::impl_fcp_sealed!(SynologyChatConnector);

#[async_trait]
impl FcpConnector for SynologyChatConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = SynologyChatConfig::from_value(config)?;
        let model = config.state_model();
        let outgoing_token = config.outgoing_token().map(ToString::to_string);
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms())),
        );
        let client =
            SynologyChatClient::from_config(&config).map_err(|error| error.to_fcp_error())?;
        self.state = Some(SynologyChatState {
            model,
            client,
            runtime,
            outgoing_token,
        });
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: granted_capabilities(req.capabilities_requested),
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snapshot = if self.state.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.state.is_some(),
            "delivery_target": self.state.as_ref().map(|state| &state.model.delivery_target),
            "request_timeout_ms": self.state.as_ref().map(|state| state.model.request_timeout_ms),
            "allow_insecure_ssl": self.state.as_ref().map(|state| state.model.allow_insecure_ssl),
            "outgoing_token_configured": self.state.as_ref().map(|state| state.model.outgoing_token_configured),
            "receive_path": self.state.as_ref().map(|state| &state.model.receive_path),
            "reply_semantics": self.state.as_ref().map(|state| &state.model.reply_semantics),
            "manifest_hash": Self::manifest_hash(),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(state) = &self.state else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };
        let report = SelfCheckReport::ok();
        Ok(SelfCheckReport {
            details: Some(json!({
                "delivery_target": &state.model.delivery_target,
                "request_timeout_ms": state.model.request_timeout_ms,
                "allow_insecure_ssl": state.model.allow_insecure_ssl,
                "outgoing_token_configured": state.model.outgoing_token_configured,
                "receive_path": &state.model.receive_path,
                "reply_semantics": &state.model.reply_semantics,
            })),
            ..report
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(state) = &self.state {
            state.runtime.shutdown();
        }
        self.state = None;
        self.verifier = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        if self.state.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) = verifier.verify(req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| matches!(capability.as_str(), CAP_READ | CAP_WRITE | CAP_WEBHOOK))
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_SEND_MESSAGE | OP_SEND_PAYLOAD => Ok(CapabilityId::from_static(CAP_WRITE)),
        OP_INGEST_OUTGOING_WEBHOOK => Ok(CapabilityId::from_static(CAP_WEBHOOK)),
        OP_WEBHOOK_NORMALIZE | OP_HEALTH => Ok(CapabilityId::from_static(CAP_READ)),
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("Unknown operation: {operation}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_core::{CapabilityConstraints, CapabilityToken, RequestId, ZoneId};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};

    use super::*;

    fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [4u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
                CapabilityId::from_static(CAP_WEBHOOK),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
    ) -> CapabilityToken {
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .constraints_cbor(&cbor)
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_returns_configured_surface() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi"
            }))
            .await
            .expect("configure should succeed");
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");
        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("synology-health"),
                connector_id: ConnectorId::from_static("fcp.synology-chat"),
                operation: OperationId::from_static(OP_HEALTH),
                zone_id: ZoneId::work(),
                input: json!({}),
                capability_token: capability_token(&signing_key, CAP_READ, OP_HEALTH),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("health should succeed");
        let result = response.result.expect("result");
        assert_eq!(result["status"], "ok");
        assert_eq!(
            result["delivery_target"]["incoming_url_redacted"],
            "https://nas.example.com:443/webapi/..."
        );
        assert_eq!(result["reply_semantics"], "outbound_only");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_reports_state_model_details() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi",
                "request_timeout_ms": 25_000,
                "allow_insecure_ssl": true,
                "outgoing_token": "top-secret"
            }))
            .await
            .expect("configure should succeed");

        let report = connector
            .self_check()
            .await
            .expect("self_check should succeed");
        let details = report.details.expect("details should be present");
        assert_eq!(
            details["delivery_target"]["incoming_url_redacted"],
            "https://nas.example.com:443/webapi/..."
        );
        assert_eq!(details["request_timeout_ms"], 25_000);
        assert_eq!(details["allow_insecure_ssl"], true);
        assert_eq!(details["outgoing_token_configured"], true);
        assert_eq!(details["receive_path"], "forwarded_outgoing_webhook");
        assert_eq!(details["reply_semantics"], "outgoing_webhook_response");
    }

    #[test]
    fn introspection_reports_expected_operations_and_event_caps() {
        let introspection = SynologyChatConnector::new().introspect();
        let operation_ids = introspection
            .operations
            .iter()
            .map(|operation| operation.id.as_str().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            operation_ids,
            vec![
                OP_SEND_MESSAGE.to_string(),
                OP_SEND_PAYLOAD.to_string(),
                OP_INGEST_OUTGOING_WEBHOOK.to_string(),
                OP_WEBHOOK_NORMALIZE.to_string(),
                OP_HEALTH.to_string()
            ]
        );

        let event_caps = introspection
            .event_caps
            .expect("event caps should be present");
        assert!(!event_caps.streaming);
        assert!(!event_caps.replay);
        assert_eq!(event_caps.min_buffer_events, 0);
        assert!(!event_caps.requires_ack);
    }

    #[test]
    fn optional_user_ids_prefers_array_over_single_id() {
        let user_ids = optional_user_ids(&json!({
            "user_id": "legacy",
            "user_ids": ["one", " two ", "one"]
        }))
        .expect("user IDs should parse");
        assert_eq!(user_ids, vec!["one".to_string(), "two".to_string()]);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_webhook_normalize_returns_normalized_event() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi",
                "outgoing_token": "shared-secret"
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");

        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("webhook-normalize-1"),
                connector_id: ConnectorId::from_static("fcp.synology-chat"),
                operation: OperationId::from_static(OP_WEBHOOK_NORMALIZE),
                zone_id: ZoneId::work(),
                input: json!({
                    "payload": {
                        "token": "shared-secret",
                        "channel_id": 34,
                        "user_id": 4,
                        "username": "mikael",
                        "text": "Tjena",
                        "timestamp": "1646827836131",
                        "trigger_word": "Tjena",
                        "thread_id": "0"
                    }
                }),
                capability_token: capability_token(&signing_key, CAP_READ, OP_WEBHOOK_NORMALIZE),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("webhook normalize should succeed");

        let result = response.result.expect("result");
        assert_eq!(result["token_verification"], "verified");
        let event = &result["event"];
        assert_eq!(event["event_type"], "inbound_webhook");
        assert_eq!(event["channel_id"], "34");
        assert_eq!(event["sender_id"], "4");
        assert_eq!(event["sender_name"], "mikael");
        assert_eq!(event["text"], "Tjena");
        assert_eq!(event["timestamp"], "1646827836131");
        assert_eq!(event["trigger_word"], "Tjena");
        assert_eq!(event["is_threaded"], false);
        assert_eq!(event["token_verified"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_webhook_normalize_token_mismatch_reports_status() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi",
                "outgoing_token": "correct-token"
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");

        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("webhook-normalize-mismatch"),
                connector_id: ConnectorId::from_static("fcp.synology-chat"),
                operation: OperationId::from_static(OP_WEBHOOK_NORMALIZE),
                zone_id: ZoneId::work(),
                input: json!({
                    "payload": {
                        "token": "wrong-token",
                        "text": "Hello"
                    }
                }),
                capability_token: capability_token(&signing_key, CAP_READ, OP_WEBHOOK_NORMALIZE),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("webhook normalize should succeed even on mismatch");

        let result = response.result.expect("result");
        assert_eq!(result["token_verification"], "mismatch");
        assert_eq!(result["event"]["token_verified"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_webhook_normalize_no_token_configured() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi"
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");

        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("webhook-normalize-notoken"),
                connector_id: ConnectorId::from_static("fcp.synology-chat"),
                operation: OperationId::from_static(OP_WEBHOOK_NORMALIZE),
                zone_id: ZoneId::work(),
                input: json!({
                    "payload": {
                        "channel_id": "chan-1",
                        "username": "alice",
                        "text": "Hi there"
                    }
                }),
                capability_token: capability_token(&signing_key, CAP_READ, OP_WEBHOOK_NORMALIZE),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("webhook normalize should succeed");

        let result = response.result.expect("result");
        assert_eq!(result["token_verification"], "not_configured");
        let event = &result["event"];
        assert_eq!(event["event_type"], "inbound_webhook");
        assert_eq!(event["channel_id"], "chan-1");
        assert_eq!(event["sender_name"], "alice");
        assert_eq!(event["text"], "Hi there");
        assert!(event["token_verified"].is_null());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_webhook_normalize_minimal_payload() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi"
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");

        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("webhook-normalize-minimal"),
                connector_id: ConnectorId::from_static("fcp.synology-chat"),
                operation: OperationId::from_static(OP_WEBHOOK_NORMALIZE),
                zone_id: ZoneId::work(),
                input: json!({ "payload": {} }),
                capability_token: capability_token(&signing_key, CAP_READ, OP_WEBHOOK_NORMALIZE),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("webhook normalize should succeed with empty payload");

        let result = response.result.expect("result");
        assert_eq!(result["token_verification"], "not_configured");
        let event = &result["event"];
        assert_eq!(event["event_type"], "inbound_webhook");
        assert!(event["channel_id"].is_null());
        assert!(event["sender_id"].is_null());
        assert!(event["text"].is_null());
        assert_eq!(event["is_threaded"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_webhook_normalize_missing_payload_field_errors() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi"
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");

        let error = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("webhook-normalize-nopayload"),
                connector_id: ConnectorId::from_static("fcp.synology-chat"),
                operation: OperationId::from_static(OP_WEBHOOK_NORMALIZE),
                zone_id: ZoneId::work(),
                input: json!({}),
                capability_token: capability_token(&signing_key, CAP_READ, OP_WEBHOOK_NORMALIZE),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect_err("should fail without payload");

        match error {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert!(message.contains("Missing payload"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_webhook_normalize_threaded_message() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi"
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");

        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("webhook-normalize-threaded"),
                connector_id: ConnectorId::from_static("fcp.synology-chat"),
                operation: OperationId::from_static(OP_WEBHOOK_NORMALIZE),
                zone_id: ZoneId::work(),
                input: json!({
                    "payload": {
                        "channel_id": 42,
                        "user_id": 7,
                        "username": "bob",
                        "text": "Reply in thread",
                        "thread_id": "thread-456",
                        "file_url": "https://nas.local/file.pdf"
                    }
                }),
                capability_token: capability_token(&signing_key, CAP_READ, OP_WEBHOOK_NORMALIZE),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("webhook normalize should succeed");

        let result = response.result.expect("result");
        let event = &result["event"];
        assert_eq!(event["is_threaded"], true);
        assert_eq!(event["thread_id"], "thread-456");
        assert_eq!(event["file_url"], "https://nas.local/file.pdf");
        assert_eq!(event["sender_name"], "bob");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_webhook_normalize_preserves_raw_payload() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi"
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");

        let input_payload = json!({
            "text": "Hello",
            "custom_field": "custom_value",
            "nested": { "key": 42 }
        });

        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("webhook-normalize-raw"),
                connector_id: ConnectorId::from_static("fcp.synology-chat"),
                operation: OperationId::from_static(OP_WEBHOOK_NORMALIZE),
                zone_id: ZoneId::work(),
                input: json!({ "payload": input_payload }),
                capability_token: capability_token(&signing_key, CAP_READ, OP_WEBHOOK_NORMALIZE),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("webhook normalize should succeed");

        let result = response.result.expect("result");
        let raw = &result["event"]["raw"];
        assert_eq!(raw["text"], "Hello");
        assert_eq!(raw["custom_field"], "custom_value");
        assert_eq!(raw["nested"]["key"], 42);
    }
}
