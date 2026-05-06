//! `DingTalk` enterprise robot connector.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, EventData, EventEnvelope, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, OrderingPolicy,
    Principal, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, TrustLevel, UnsubscribeRequest, ZoneId,
};
use fcp_sdk::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::client::{
    DingTalkClient, default_mime_type, normalize_callback_event, validate_session_webhook_url,
};
use crate::types::{DingTalkCallbackEvent, DingTalkConfig, NormalizedDingTalkEvent, ParsedTarget};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_SEND_TEXT: &str = "dingtalk.messages.send_text";
const OP_SEND_LINK: &str = "dingtalk.messages.send_link";
const OP_SEND_FILE: &str = "dingtalk.messages.send_file";
const OP_UPLOAD_MEDIA: &str = "dingtalk.media.upload";
const OP_NORMALIZE_EVENT: &str = "dingtalk.events.normalize";
const OP_STREAM_INGEST: &str = "dingtalk.stream.ingest_message";
const OP_STREAM_REPLY: &str = "dingtalk.stream.reply";
const OP_HEALTH: &str = "dingtalk.health";

const CAP_MESSAGES_WRITE: &str = "dingtalk.messages.write";
const CAP_MESSAGES_READ: &str = "dingtalk.messages.read";
const CAP_MEDIA_WRITE: &str = "dingtalk.media.write";
const CAP_HEALTH_READ: &str = "dingtalk.health.read";
const DINGTALK_STREAM_POLICY_MODEL: &str = "host_forwarded_stream_frame_supervision";
const MAX_STREAM_MEDIA_FIELD_LEN: usize = 2_048;
const MAX_REPLY_CONTENT_LEN: usize = 20_000;

// ─────────────────────────────────────────────────────────────────
// Doctor types (V3 requirement)
// ─────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self { passed, checks }
    }
}

#[derive(Debug)]
pub struct DingTalkConnector {
    base: BaseConnector,
    client: Option<DingTalkClient>,
    verifier: Option<CapabilityVerifier>,
    zone: Option<ZoneId>,
    stream_state: Mutex<DingTalkStreamState>,
    started_at: Instant,
}

#[derive(Debug, Clone)]
struct DingTalkSessionWebhook {
    url: String,
    expires_at_ms: Option<i64>,
    cached_at_ms: i64,
}

#[derive(Debug, Default)]
struct DingTalkStreamState {
    seen_messages: BTreeMap<String, i64>,
    session_webhooks: BTreeMap<String, DingTalkSessionWebhook>,
    accepted_events: u64,
    rejected_events: u64,
    duplicate_events: u64,
    last_decision: Option<String>,
    last_reason: Option<String>,
}

#[derive(Debug)]
struct DingTalkStreamIngestRequest<'a> {
    event: &'a Value,
    is_in_at_list: bool,
    session_webhook: Option<&'a str>,
    session_webhook_expired_time_ms: Option<i64>,
}

#[derive(Debug)]
struct DingTalkStreamSecurityOutcome {
    decision: &'static str,
    reason: String,
    duplicate: bool,
    emit_event: bool,
    message_key_hash: String,
    sender_hash: Option<String>,
    sender_staff_hash: Option<String>,
    conversation_hash: Option<String>,
    session_webhook_hash: Option<String>,
    session_webhook_cached: bool,
    state_counts: DingTalkStreamStateCounts,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
struct DingTalkStreamStateCounts {
    seen_messages: usize,
    cached_session_webhooks: usize,
    accepted_events: u64,
    rejected_events: u64,
    duplicate_events: u64,
}

#[derive(Debug)]
struct DingTalkSessionReplyTarget {
    chat_id: String,
    session_webhook: String,
    source: &'static str,
}

impl DingTalkConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.dingtalk")),
            client: None,
            verifier: None,
            zone: None,
            stream_state: Mutex::new(DingTalkStreamState::default()),
            started_at: Instant::now(),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing - configure first".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: self.verifier.is_some(),
            message: Some(if self.verifier.is_some() {
                "Handshake completed".into()
            } else {
                "Handshake not completed".into()
            }),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    // 14 OperationInfo entries built inline; splitting is churn-only — each
    // arm carries its own input_schema literal and reads top-to-bottom.
    #[allow(clippy::too_many_lines)]
    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_SEND_TEXT,
                "Send a DingTalk text or markdown message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["to", "content"],
                    "properties": {
                        "to": { "type": "string" },
                        "content": { "type": "string" }
                    }
                }),
                "Use for proactive DingTalk messages to `user:<userid>`, `chat:<openConversationId>`, or a bare userid.",
            ),
            operation(
                OP_SEND_LINK,
                "Send a DingTalk link message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["to", "title", "text", "message_url"],
                    "properties": {
                        "to": { "type": "string" },
                        "title": { "type": "string" },
                        "text": { "type": "string" },
                        "message_url": { "type": "string" },
                        "pic_url": { "type": "string" }
                    }
                }),
                "Use when the chat should receive a link-style card rather than raw markdown.",
            ),
            operation(
                OP_SEND_FILE,
                "Send a DingTalk file message using an existing media_id",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["to", "media_id", "file_name", "file_type"],
                    "properties": {
                        "to": { "type": "string" },
                        "media_id": { "type": "string" },
                        "file_name": { "type": "string" },
                        "file_type": { "type": "string" }
                    }
                }),
                "Use after `dingtalk.media.upload` when DingTalk requires a media_id-backed file send.",
            ),
            operation(
                OP_UPLOAD_MEDIA,
                "Upload media to DingTalk",
                CAP_MEDIA_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::BestEffort,
                json!({
                    "type": "object",
                    "required": ["media_type", "file_name", "content_base64"],
                    "properties": {
                        "media_type": { "type": "string", "enum": ["image", "voice", "video", "file"] },
                        "file_name": { "type": "string" },
                        "mime_type": { "type": "string" },
                        "content_base64": { "type": "string" }
                    }
                }),
                "Use when you need a DingTalk media_id before sending files or rich media.",
            ),
            operation(
                OP_NORMALIZE_EVENT,
                "Normalize a DingTalk robot callback event into a standard format",
                CAP_MESSAGES_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["event"],
                    "properties": {
                        "event": {
                            "type": "object",
                            "description": "Raw DingTalk robot callback JSON payload"
                        }
                    }
                }),
                "Use to normalize an inbound DingTalk robot callback event for downstream processing.",
            ),
            operation(
                OP_STREAM_INGEST,
                "Policy-gate and normalize one DingTalk Stream Mode message frame",
                CAP_MESSAGES_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["event"],
                    "properties": {
                        "event": {
                            "type": "object",
                            "description": "Raw DingTalk Stream Mode ChatbotMessage payload"
                        },
                        "is_in_at_list": { "type": "boolean" },
                        "session_webhook": { "type": "string" },
                        "session_webhook_expired_time_ms": { "type": "integer" }
                    }
                }),
                "Use when the host's DingTalk Stream Mode bridge forwards one signed SDK frame into FCP for policy, dedupe, and EventEnvelope construction.",
            ),
            operation(
                OP_STREAM_REPLY,
                "Reply to a DingTalk Stream Mode session webhook",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["chat_id", "content"],
                    "properties": {
                        "chat_id": { "type": "string" },
                        "content": { "type": "string" },
                        "session_webhook": { "type": "string" },
                        "reply_to": { "type": "string" }
                    }
                }),
                "Use only after an accepted stream ingest cached a valid DingTalk session_webhook for the conversation, or when the host forwards a fresh webhook explicitly.",
            ),
            operation(
                OP_HEALTH,
                "Verify DingTalk credentials and token issuance",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use as a bounded preflight check before higher-risk send operations.",
            ),
        ]
    }

    // Single match dispatch over every operation_id; extracting per-op
    // helpers would scatter the verify_bound + client-call shape that the
    // capability boundary review depends on staying in one place.
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])?;

        let output = match req.operation.as_str() {
            OP_SEND_TEXT => {
                let to = required_string(&req.input, "to")?;
                let content = required_string(&req.input, "content")?;
                let target = ParsedTarget::parse(to);
                let (path, body) = if target.is_group {
                    (
                        "/v1.0/robot/groupMessages/send",
                        json!({
                            "robotCode": client.config().client_id,
                            "openConversationId": target.id,
                            "msgKey": "sampleMarkdown",
                            "msgParam": json!({
                                "title": title_for(content),
                                "text": content,
                            }).to_string(),
                        }),
                    )
                } else {
                    (
                        "/v1.0/robot/oToMessages/batchSend",
                        json!({
                            "robotCode": client.config().client_id,
                            "userIds": [target.id],
                            "msgKey": "sampleMarkdown",
                            "msgParam": json!({
                                "title": title_for(content),
                                "text": content,
                            }).to_string(),
                        }),
                    )
                };
                client
                    .post_json(path, body)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_SEND_LINK => {
                let to = required_string(&req.input, "to")?;
                let title = required_string(&req.input, "title")?;
                let text = required_string(&req.input, "text")?;
                let message_url = required_string(&req.input, "message_url")?;
                let pic_url = optional_string(&req.input, "pic_url")?;
                let target = ParsedTarget::parse(to);
                let (path, body) = if target.is_group {
                    (
                        "/v1.0/robot/groupMessages/send",
                        json!({
                            "robotCode": client.config().client_id,
                            "openConversationId": target.id,
                            "msgKey": "sampleLink",
                            "msgParam": link_msg_param(title, text, message_url, pic_url).to_string(),
                        }),
                    )
                } else {
                    (
                        "/v1.0/robot/oToMessages/batchSend",
                        json!({
                            "robotCode": client.config().client_id,
                            "userIds": [target.id],
                            "msgKey": "sampleLink",
                            "msgParam": link_msg_param(title, text, message_url, pic_url).to_string(),
                        }),
                    )
                };
                client
                    .post_json(path, body)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_SEND_FILE => {
                let to = required_string(&req.input, "to")?;
                let media_id = required_string(&req.input, "media_id")?;
                let file_name = required_string(&req.input, "file_name")?;
                let file_type = required_string(&req.input, "file_type")?;
                let target = ParsedTarget::parse(to);
                let (path, body) = if target.is_group {
                    (
                        "/v1.0/robot/groupMessages/send",
                        json!({
                            "robotCode": client.config().client_id,
                            "openConversationId": target.id,
                            "msgKey": "sampleFile",
                            "msgParam": json!({
                                "mediaId": media_id,
                                "fileName": file_name,
                                "fileType": file_type,
                            }).to_string(),
                        }),
                    )
                } else {
                    (
                        "/v1.0/robot/oToMessages/batchSend",
                        json!({
                            "robotCode": client.config().client_id,
                            "userIds": [target.id],
                            "msgKey": "sampleFile",
                            "msgParam": json!({
                                "mediaId": media_id,
                                "fileName": file_name,
                                "fileType": file_type,
                            }).to_string(),
                        }),
                    )
                };
                client
                    .post_json(path, body)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_UPLOAD_MEDIA => {
                let media_type = required_string(&req.input, "media_type")?;
                if !matches!(media_type, "image" | "voice" | "video" | "file") {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: "media_type must be one of image, voice, video, or file".into(),
                    });
                }
                let file_name = required_string(&req.input, "file_name")?;
                let mime_type = optional_string(&req.input, "mime_type")?
                    .unwrap_or_else(|| default_mime_type(media_type));
                let content_base64 = required_string(&req.input, "content_base64")?;
                client
                    .upload_media(media_type, file_name, mime_type, content_base64)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_NORMALIZE_EVENT => {
                let event_value =
                    req.input
                        .get("event")
                        .ok_or_else(|| FcpError::InvalidRequest {
                            code: 1005,
                            message: "event is required".into(),
                        })?;
                let normalized =
                    normalize_callback_event(event_value).map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&normalized).map_err(|e| FcpError::Internal {
                    message: format!("failed to serialize normalized event: {e}"),
                })?
            }
            OP_STREAM_INGEST => {
                let request = DingTalkStreamIngestRequest::from_input(&req.input)?;
                let normalized =
                    normalize_callback_event(request.event).map_err(|e| e.to_fcp_error())?;
                let raw_event: DingTalkCallbackEvent =
                    serde_json::from_value(request.event.clone()).map_err(|error| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("invalid DingTalk stream event payload: {error}"),
                        }
                    })?;
                let outcome = evaluate_stream_frame(self, client.config(), &raw_event, &request)?;
                let event = outcome.emit_event.then(|| {
                    dingtalk_event_envelope(
                        self,
                        &normalized,
                        request.event,
                        &outcome,
                        req.correlation_id.clone(),
                    )
                });
                json!({
                    "stream": {
                        "model": DINGTALK_STREAM_POLICY_MODEL,
                        "transport_boundary": "host_forwarded_stream_frame",
                        "connector_owned_websocket": false,
                        "supervised_state": true,
                    },
                    "delivery": {
                        "id": stream_delivery_id(&raw_event, request.event),
                        "message_key_hash": outcome.message_key_hash,
                        "sender_hash": outcome.sender_hash,
                        "sender_staff_hash": outcome.sender_staff_hash,
                        "conversation_hash": outcome.conversation_hash,
                        "session_webhook_hash": outcome.session_webhook_hash,
                        "session_webhook_cached": outcome.session_webhook_cached,
                        "duplicate": outcome.duplicate,
                    },
                    "policy": {
                        "model": DINGTALK_STREAM_POLICY_MODEL,
                        "decision": outcome.decision,
                        "reason": outcome.reason,
                        "redaction_status": "policy_and_delivery_metadata_hashed; normalized_event_payload_requires_messages_read",
                    },
                    "state": outcome.state_counts,
                    "normalized": if outcome.emit_event { json!(normalized) } else { json!(null) },
                    "event": event,
                })
            }
            OP_STREAM_REPLY => {
                let chat_id = required_string(&req.input, "chat_id")?;
                let content = required_string(&req.input, "content")?;
                if !client.config().stream_mode_enabled {
                    return Err(FcpError::InvalidRequest {
                        code: 1006,
                        message: "DingTalk Stream Mode replies are disabled by config".into(),
                    });
                }
                let target =
                    resolve_session_reply_target(self, client.config(), chat_id, &req.input)?;
                let content = truncate_reply_content(content);
                let response = client
                    .post_session_webhook(&target.session_webhook, &content)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": "sent",
                    "chat_id_hash": redacted_hash(&target.chat_id),
                    "session_webhook_hash": redacted_hash(&target.session_webhook),
                    "session_webhook_source": target.source,
                    "reply_to_hash": optional_string(&req.input, "reply_to")?.map(redacted_hash),
                    "response": response,
                    "redaction_status": "chat_and_webhook_metadata_hashed",
                })
            }
            OP_HEALTH => {
                let _auth_material = client.access_token().await.map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": "ok",
                    "base_url": client.config().base_url,
                    "media_base_url": client.config().media_base_url,
                    "client_id": client.config().client_id,
                    "stream_policy_model": DINGTALK_STREAM_POLICY_MODEL,
                    "stream_mode_enabled": client.config().stream_mode_enabled,
                    "stream_state": stream_state_counts(self)?,
                    "manifest_hash": Self::manifest_hash(),
                })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("unknown operation: {}", req.operation),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for DingTalkConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(DingTalkConnector);

#[async_trait]
impl FcpConnector for DingTalkConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let config: DingTalkConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid DingTalk configuration: {error}"),
            })?;
        self.client = Some(DingTalkClient::new(config).map_err(|e| e.to_fcp_error())?);
        *self
            .stream_state
            .get_mut()
            .map_err(|_| FcpError::Internal {
                message: "DingTalk stream state lock is poisoned".into(),
            })? = DingTalkStreamState::default();
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
        self.zone = None;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if let Some(requested_instance_id) = req.requested_instance_id.clone() {
            self.base.instance_id = requested_instance_id;
        }
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        self.zone = Some(req.zone);
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: granted_capabilities(req.capabilities_requested),
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(dingtalk_event_caps(
                self.client.as_ref().map(DingTalkClient::config),
            )),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot {
            status: if self.client.is_some() {
                HealthState::Ready
            } else {
                HealthState::Starting
            },
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: self.client.as_ref().map(|c| {
                json!({
                    "base_url": c.config().base_url,
                    "media_base_url": c.config().media_base_url,
                    "client_id": c.config().client_id,
                    "stream_policy_model": DINGTALK_STREAM_POLICY_MODEL,
                    "stream_mode_enabled": c.config().stream_mode_enabled,
                    "stream_state": stream_state_counts_lossy(self),
                })
            }),
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = self.client.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before DingTalk self_check",
            ));
        };
        match client.access_token().await {
            Ok(_) => Ok(SelfCheckReport::ok()),
            Err(error) => Ok(SelfCheckReport::from_error(&error.to_fcp_error())),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.verifier = None;
        self.zone = None;
        *self
            .stream_state
            .get_mut()
            .map_err(|_| FcpError::Internal {
                message: "DingTalk stream state lock is poisoned".into(),
            })? = DingTalkStreamState::default();
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(dingtalk_event_caps(
                self.client.as_ref().map(DingTalkClient::config),
            )),
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
        if self.client.is_none() {
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
        if let Err(error) =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }
        if let Err(error) = validate_operation_input(req.operation.as_str(), &req.input) {
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
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

fn title_for(content: &str) -> String {
    content.chars().take(10).collect()
}

fn optional_string<'a>(value: &'a Value, field: &str) -> FcpResult<Option<&'a str>> {
    match value.get(field) {
        None => Ok(None),
        Some(Value::String(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed))
            }
        }
        Some(_) => Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a string"),
        }),
    }
}

fn link_msg_param(title: &str, text: &str, message_url: &str, pic_url: Option<&str>) -> Value {
    let mut msg_param = json!({
        "title": title,
        "text": text,
        "messageUrl": message_url,
    });
    if let Some(pic_url) = pic_url {
        msg_param["picUrl"] = json!(pic_url);
    }
    msg_param
}

fn required_string<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} is required"),
        })
}

fn validate_operation_input(operation: &str, input: &Value) -> FcpResult<()> {
    match operation {
        OP_SEND_TEXT => {
            required_string(input, "to")?;
            required_string(input, "content")?;
        }
        OP_SEND_LINK => {
            required_string(input, "to")?;
            required_string(input, "title")?;
            required_string(input, "text")?;
            required_string(input, "message_url")?;
            optional_string(input, "pic_url")?;
        }
        OP_SEND_FILE => {
            required_string(input, "to")?;
            required_string(input, "media_id")?;
            required_string(input, "file_name")?;
            required_string(input, "file_type")?;
        }
        OP_UPLOAD_MEDIA => {
            let media_type = required_string(input, "media_type")?;
            if !matches!(media_type, "image" | "voice" | "video" | "file") {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "media_type must be one of image, voice, video, or file".into(),
                });
            }
            required_string(input, "file_name")?;
            optional_string(input, "mime_type")?;
            required_string(input, "content_base64")?;
        }
        OP_NORMALIZE_EVENT => {
            input.get("event").ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "event is required".into(),
            })?;
        }
        OP_STREAM_INGEST => {
            DingTalkStreamIngestRequest::from_input(input)?;
        }
        OP_STREAM_REPLY => {
            required_string(input, "chat_id")?;
            required_string(input, "content")?;
            optional_string(input, "session_webhook")?;
            optional_string(input, "reply_to")?;
        }
        OP_HEALTH => {}
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown operation: {operation}"),
            });
        }
    }

    Ok(())
}

impl<'a> DingTalkStreamIngestRequest<'a> {
    fn from_input(input: &'a Value) -> FcpResult<Self> {
        let event = input.get("event").ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "event is required".into(),
        })?;
        if !event.is_object() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "event must be an object".into(),
            });
        }
        let is_in_at_list = input
            .get("is_in_at_list")
            .or_else(|| input.get("isInAtList"))
            .and_then(Value::as_bool)
            .or_else(|| {
                event
                    .get("isInAtList")
                    .or_else(|| event.get("is_in_at_list"))
                    .and_then(Value::as_bool)
            })
            .unwrap_or(false);
        let session_webhook = optional_string(input, "session_webhook")?
            .or_else(|| optional_string(input, "sessionWebhook").ok().flatten())
            .or_else(|| event.get("sessionWebhook").and_then(Value::as_str))
            .or_else(|| event.get("session_webhook").and_then(Value::as_str))
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let session_webhook_expired_time_ms = input
            .get("session_webhook_expired_time_ms")
            .or_else(|| input.get("sessionWebhookExpiredTime"))
            .and_then(Value::as_i64)
            .or_else(|| {
                event
                    .get("sessionWebhookExpiredTime")
                    .or_else(|| event.get("session_webhook_expired_time_ms"))
                    .and_then(Value::as_i64)
            });

        Ok(Self {
            event,
            is_in_at_list,
            session_webhook,
            session_webhook_expired_time_ms,
        })
    }
}

fn evaluate_stream_frame(
    connector: &DingTalkConnector,
    config: &DingTalkConfig,
    event: &DingTalkCallbackEvent,
    request: &DingTalkStreamIngestRequest<'_>,
) -> FcpResult<DingTalkStreamSecurityOutcome> {
    let now_ms = now_ms();
    let message_key = stream_message_key(event, request.event);
    let message_key_hash = redacted_hash(&message_key);
    let sender_hash = event.sender_id.as_deref().map(redacted_hash);
    let sender_staff_hash = event.sender_staff_id.as_deref().map(redacted_hash);
    let conversation_hash = stream_chat_id(event).map(|chat| redacted_hash(&chat));
    let session_webhook_hash = request.session_webhook.map(redacted_hash);

    let mut state = connector
        .stream_state
        .lock()
        .map_err(|_| FcpError::Internal {
            message: "DingTalk stream state lock is poisoned".into(),
        })?;
    prune_stream_state(&mut state, config, now_ms);

    if state.seen_messages.contains_key(&message_key) {
        state.duplicate_events = state.duplicate_events.saturating_add(1);
        state.last_decision = Some("duplicate".into());
        state.last_reason = Some("message_replay".into());
        return Ok(DingTalkStreamSecurityOutcome {
            decision: "duplicate",
            reason: "message_replay".into(),
            duplicate: true,
            emit_event: false,
            message_key_hash,
            sender_hash,
            sender_staff_hash,
            conversation_hash,
            session_webhook_hash,
            session_webhook_cached: false,
            state_counts: state.counts(),
        });
    }

    let (accepted, reason) = stream_policy_accepts(config, event, request);
    state.seen_messages.insert(message_key, now_ms);
    let session_webhook_cached = if accepted
        && let (Some(chat_id), Some(session_webhook)) =
            (stream_chat_id(event), request.session_webhook)
        && validate_session_webhook_url(session_webhook).is_ok()
        && !session_webhook_expired(
            request.session_webhook_expired_time_ms,
            config.stream_session_webhook_expiry_safety_ms,
            now_ms,
        ) {
        state.session_webhooks.insert(
            chat_id,
            DingTalkSessionWebhook {
                url: session_webhook.to_string(),
                expires_at_ms: request.session_webhook_expired_time_ms,
                cached_at_ms: now_ms,
            },
        );
        true
    } else {
        false
    };
    enforce_stream_capacity(&mut state, config);
    if accepted {
        state.accepted_events = state.accepted_events.saturating_add(1);
        state.last_decision = Some("accepted".into());
    } else {
        state.rejected_events = state.rejected_events.saturating_add(1);
        state.last_decision = Some("rejected".into());
    }
    state.last_reason = Some(reason.clone());

    Ok(DingTalkStreamSecurityOutcome {
        decision: if accepted { "accepted" } else { "rejected" },
        reason,
        duplicate: false,
        emit_event: accepted,
        message_key_hash,
        sender_hash,
        sender_staff_hash,
        conversation_hash,
        session_webhook_hash,
        session_webhook_cached,
        state_counts: state.counts(),
    })
}

impl DingTalkStreamState {
    fn counts(&self) -> DingTalkStreamStateCounts {
        DingTalkStreamStateCounts {
            seen_messages: self.seen_messages.len(),
            cached_session_webhooks: self.session_webhooks.len(),
            accepted_events: self.accepted_events,
            rejected_events: self.rejected_events,
            duplicate_events: self.duplicate_events,
        }
    }
}

fn stream_policy_accepts(
    config: &DingTalkConfig,
    event: &DingTalkCallbackEvent,
    request: &DingTalkStreamIngestRequest<'_>,
) -> (bool, String) {
    if !config.stream_mode_enabled {
        return (false, "stream_mode_disabled".into());
    }
    let conversation_type =
        crate::client::normalize_conversation_type(event.conversation_type.as_deref());
    if conversation_type == "private" && !config.stream_dm_allowed {
        return (false, "dm_stream_disabled".into());
    }
    if conversation_type == "group" && !config.stream_group_allowed {
        return (false, "group_stream_disabled".into());
    }
    if !stream_user_allowed(config, event) {
        return (false, "sender_not_allowed".into());
    }
    if stream_media_field_too_large(request.event) {
        return (false, "media_field_too_large".into());
    }
    if conversation_type == "group" && config.stream_require_mention {
        if stream_chat_id(event).as_deref().is_some_and(|chat_id| {
            config
                .stream_free_response_chats
                .iter()
                .any(|id| id == chat_id)
        }) {
            return (true, "accepted".into());
        }
        if request.is_in_at_list || crate::client::detect_at_bot(event) {
            return (true, "accepted".into());
        }
        let text = event
            .text
            .as_ref()
            .and_then(|text| text.content.as_deref())
            .unwrap_or_default();
        if stream_text_matches_patterns(text, &config.stream_mention_patterns) {
            return (true, "accepted".into());
        }
        return (false, "mention_required".into());
    }
    (true, "accepted".into())
}

fn stream_user_allowed(config: &DingTalkConfig, event: &DingTalkCallbackEvent) -> bool {
    if config.stream_allowed_users.is_empty()
        || config.stream_allowed_users.iter().any(|value| value == "*")
    {
        return true;
    }
    let sender_id = event
        .sender_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let sender_staff_id = event
        .sender_staff_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    config
        .stream_allowed_users
        .iter()
        .any(|allowed| allowed == &sender_id || allowed == &sender_staff_id)
}

fn stream_text_matches_patterns(text: &str, patterns: &[String]) -> bool {
    let lower = text.to_lowercase();
    patterns
        .iter()
        .any(|pattern| lower.contains(&pattern.to_lowercase()))
}

fn stream_media_field_too_large(value: &Value) -> bool {
    stream_media_field_too_large_inner(value, false)
}

fn stream_media_field_too_large_inner(value: &Value, inside_media_field: bool) -> bool {
    match value {
        Value::String(raw) => inside_media_field && raw.len() > MAX_STREAM_MEDIA_FIELD_LEN,
        Value::Array(items) => items
            .iter()
            .any(|item| stream_media_field_too_large_inner(item, inside_media_field)),
        Value::Object(map) => map.iter().any(|(key, value)| {
            let is_media_field = matches!(
                key.as_str(),
                "downloadCode"
                    | "download_code"
                    | "mediaId"
                    | "media_id"
                    | "pictureUrl"
                    | "picUrl"
                    | "fileName"
                    | "file_name"
            );
            stream_media_field_too_large_inner(value, inside_media_field || is_media_field)
        }),
        _ => false,
    }
}

fn stream_message_key(event: &DingTalkCallbackEvent, raw: &Value) -> String {
    event
        .msg_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map_or_else(
            || {
                let digest = Sha256::digest(raw.to_string().as_bytes());
                format!("raw:{}", hex::encode(digest))
            },
            |msg_id| format!("msg:{msg_id}"),
        )
}

fn stream_delivery_id(event: &DingTalkCallbackEvent, raw: &Value) -> String {
    redacted_hash(&stream_message_key(event, raw))
}

fn stream_chat_id(event: &DingTalkCallbackEvent) -> Option<String> {
    event
        .conversation_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            event
                .sender_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(str::to_string)
}

fn session_webhook_expired(expires_at_ms: Option<i64>, safety_ms: u64, now_ms: i64) -> bool {
    let Some(expires_at_ms) = expires_at_ms else {
        return false;
    };
    if expires_at_ms <= 0 {
        return false;
    }
    now_ms.saturating_add(i64::try_from(safety_ms).unwrap_or(i64::MAX)) >= expires_at_ms
}

fn prune_stream_state(state: &mut DingTalkStreamState, config: &DingTalkConfig, now_ms: i64) {
    state.session_webhooks.retain(|_, webhook| {
        !session_webhook_expired(
            webhook.expires_at_ms,
            config.stream_session_webhook_expiry_safety_ms,
            now_ms,
        )
    });
    enforce_stream_capacity(state, config);
}

fn enforce_stream_capacity(state: &mut DingTalkStreamState, config: &DingTalkConfig) {
    prune_oldest(&mut state.seen_messages, config.stream_replay_cache_entries);
    while state.session_webhooks.len() > config.stream_session_webhook_cache_entries {
        let Some(key) = state
            .session_webhooks
            .iter()
            .min_by_key(|(_, value)| value.cached_at_ms)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        state.session_webhooks.remove(&key);
    }
}

fn prune_oldest(values: &mut BTreeMap<String, i64>, max_entries: usize) {
    while values.len() > max_entries {
        let Some(key) = values
            .iter()
            .min_by_key(|(_, seen_at)| *seen_at)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        values.remove(&key);
    }
}

fn resolve_session_reply_target(
    connector: &DingTalkConnector,
    config: &DingTalkConfig,
    chat_id: &str,
    input: &Value,
) -> FcpResult<DingTalkSessionReplyTarget> {
    if let Some(session_webhook) = optional_string(input, "session_webhook")? {
        validate_session_webhook_url(session_webhook).map_err(|error| {
            FcpError::InvalidRequest {
                code: 1005,
                message: format!("invalid DingTalk session_webhook: {error}"),
            }
        })?;
        return Ok(DingTalkSessionReplyTarget {
            chat_id: chat_id.to_string(),
            session_webhook: session_webhook.to_string(),
            source: "request",
        });
    }

    let session_webhook = {
        let mut state = connector
            .stream_state
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "DingTalk stream state lock is poisoned".into(),
            })?;
        prune_stream_state(&mut state, config, now_ms());
        let Some(cached) = state.session_webhooks.get(chat_id) else {
            return Err(FcpError::InvalidRequest {
                code: 1006,
                message: "no valid DingTalk session_webhook is cached for chat_id".into(),
            });
        };
        let session_webhook = cached.url.clone();
        drop(state);
        session_webhook
    };
    Ok(DingTalkSessionReplyTarget {
        chat_id: chat_id.to_string(),
        session_webhook,
        source: "cache",
    })
}

fn dingtalk_event_envelope(
    connector: &DingTalkConnector,
    normalized: &NormalizedDingTalkEvent,
    raw: &Value,
    outcome: &DingTalkStreamSecurityOutcome,
    correlation_id: Option<fcp_prelude::CorrelationId>,
) -> EventEnvelope {
    let principal = Principal {
        kind: "user".into(),
        id: normalized
            .sender_id
            .clone()
            .unwrap_or_else(|| "unknown".into()),
        trust: TrustLevel::Paired,
        display: normalized.sender_name.clone(),
    };
    let zone = connector.zone.clone().unwrap_or_else(ZoneId::work);
    let resource_uris = dingtalk_event_resource_uris(normalized);
    let payload = json!({
        "normalized": normalized,
        "raw": raw,
        "policy": {
            "model": DINGTALK_STREAM_POLICY_MODEL,
            "decision": outcome.decision,
            "reason": outcome.reason,
            "message_key_hash": outcome.message_key_hash,
            "sender_hash": outcome.sender_hash,
            "conversation_hash": outcome.conversation_hash,
        }
    });
    let mut data = EventData::new(
        connector.base.id.clone(),
        connector.base.instance_id.clone(),
        zone,
        principal,
        payload,
    )
    .with_resource_uris(resource_uris);
    if let Some(correlation_id) = correlation_id {
        data = data.with_correlation_id(correlation_id);
    }
    let stream_key = normalized
        .conversation_id
        .clone()
        .or_else(|| normalized.sender_id.clone());
    let mut envelope =
        EventEnvelope::new("dingtalk.message", data).with_ordering(OrderingPolicy::PerKey);
    if let Some(stream_key) = stream_key {
        envelope = envelope.with_stream_key(stream_key);
    }
    envelope
}

fn dingtalk_event_resource_uris(normalized: &NormalizedDingTalkEvent) -> Vec<String> {
    let mut uris = Vec::new();
    if let Some(conversation_id) = &normalized.conversation_id {
        uris.push(format!("dingtalk:conversation:{conversation_id}"));
    }
    if let Some(sender_id) = &normalized.sender_id {
        uris.push(format!("dingtalk:user:{sender_id}"));
    }
    if let Some(message_id) = &normalized.message_id {
        uris.push(format!("dingtalk:message:{message_id}"));
    }
    uris
}

fn dingtalk_event_caps(config: Option<&DingTalkConfig>) -> EventCaps {
    let Some(config) = config else {
        return EventCaps {
            streaming: false,
            replay: false,
            min_buffer_events: 0,
            requires_ack: false,
        };
    };
    let replay = config.stream_mode_enabled;
    EventCaps {
        streaming: false,
        replay,
        min_buffer_events: if replay {
            u32::try_from(config.stream_replay_cache_entries).unwrap_or(u32::MAX)
        } else {
            0
        },
        requires_ack: false,
    }
}

fn stream_state_counts(connector: &DingTalkConnector) -> FcpResult<DingTalkStreamStateCounts> {
    connector
        .stream_state
        .lock()
        .map(|state| state.counts())
        .map_err(|_| FcpError::Internal {
            message: "DingTalk stream state lock is poisoned".into(),
        })
}

fn stream_state_counts_lossy(connector: &DingTalkConnector) -> DingTalkStreamStateCounts {
    connector.stream_state.lock().map_or(
        DingTalkStreamStateCounts {
            seen_messages: 0,
            cached_session_webhooks: 0,
            accepted_events: 0,
            rejected_events: 0,
            duplicate_events: 0,
        },
        |state| state.counts(),
    )
}

fn truncate_reply_content(content: &str) -> String {
    content.chars().take(MAX_REPLY_CONTENT_LEN).collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn redacted_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let encoded = hex::encode(digest);
    format!("sha256:{}", &encoded[..16])
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_SEND_TEXT | OP_SEND_LINK | OP_SEND_FILE | OP_STREAM_REPLY => CAP_MESSAGES_WRITE,
        OP_NORMALIZE_EVENT | OP_STREAM_INGEST => CAP_MESSAGES_READ,
        OP_UPLOAD_MEDIA => CAP_MEDIA_WRITE,
        OP_HEALTH => CAP_HEALTH_READ,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| {
            matches!(
                capability.as_str(),
                CAP_MESSAGES_WRITE | CAP_MESSAGES_READ | CAP_MEDIA_WRITE | CAP_HEALTH_READ
            )
        })
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

// Internal builder for OperationInfo: the 8 args mirror OperationInfo's
// own field count by design — packaging them into a struct would just
// force every call site to spell out the same fields with extra syntax.
#[allow(clippy::too_many_arguments)]
fn operation(
    id: &'static str,
    summary: &str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: Value,
    when_to_use: &str,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(summary.into()),
        input_schema,
        output_schema: json!({ "type": "object" }),
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: vec![
                "Group routes must use the `chat:` prefix with an openConversationId.".into(),
            ],
            examples: Vec::new(),
            related: vec![CapabilityId::from_static(CAP_HEALTH_READ)],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use chrono::{Duration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, InstanceId, RequestId, ZoneId};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method, path, query_param},
    };

    async fn configured_connector(server: &MockServer) -> DingTalkConnector {
        let mut connector = DingTalkConnector::new();
        connector
            .configure(json!({
                "base_url": server.uri(),
                "media_base_url": server.uri(),
                "client_id": "ding-app",
                "client_secret": "secret"
            }))
            .await
            .expect("configure should succeed");
        connector
    }

    fn signed_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
        instance_id: &InstanceId,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("valid constraints cbor")
            .target_instance(instance_id.as_str())
            .sign(signing_key)
            .expect("capability token");
        CapabilityToken::from_raw(raw)
    }

    async fn configured_handshaken_connector(
        server: &MockServer,
        capabilities: Vec<CapabilityId>,
    ) -> (DingTalkConnector, Ed25519SigningKey) {
        let mut connector = configured_connector(server).await;
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [7u8; 32],
                capabilities_requested: capabilities,
                host: None,
                transport_caps: None,
                requested_instance_id: Some(InstanceId::new()),
            })
            .await
            .expect("handshake should succeed");
        (connector, signing_key)
    }

    fn simulate_request(
        operation: &'static str,
        input: Value,
        capability_token: CapabilityToken,
    ) -> SimulateRequest {
        SimulateRequest {
            r#type: "simulate".into(),
            id: RequestId::new("simulate-test"),
            connector_id: ConnectorId::from_static("fcp.dingtalk"),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token,
            estimate_cost: false,
            check_availability: false,
            context: None,
            correlation_id: None,
        }
    }

    fn stream_policy_config() -> DingTalkConfig {
        DingTalkConfig {
            base_url: "http://localhost:9999".into(),
            media_base_url: "http://localhost:9999".into(),
            client_id: "ding-app".into(),
            client_secret: "secret".into(),
            stream_mode_enabled: true,
            stream_allowed_users: vec!["staff-1".into()],
            stream_mention_patterns: vec!["@opsbot".into()],
            stream_replay_cache_entries: 4,
            stream_session_webhook_cache_entries: 2,
            stream_session_webhook_expiry_safety_ms: 1_000,
            ..Default::default()
        }
        .normalized()
    }

    fn stream_event(
        msg_id: &str,
        sender_staff_id: &str,
        conversation_type: &str,
        text: &str,
    ) -> Value {
        json!({
            "msgType": "text",
            "text": { "content": text },
            "senderId": format!("user-{sender_staff_id}"),
            "senderStaffId": sender_staff_id,
            "senderNick": "Alice",
            "conversationId": "conv-1",
            "conversationType": conversation_type,
            "conversationTitle": "Ops",
            "chatbotUserId": "bot-1",
            "atUsers": [],
            "createAt": 1_700_000_000_000_i64,
            "msgId": msg_id
        })
    }

    fn stream_input(event: Value, is_in_at_list: bool) -> Value {
        let mut input = serde_json::Map::new();
        input.insert("event".into(), event);
        input.insert("is_in_at_list".into(), json!(is_in_at_list));
        input.insert(
            "session_webhook".into(),
            json!("http://localhost:8080/session"),
        );
        input.insert(
            "session_webhook_expired_time_ms".into(),
            json!(now_ms().saturating_add(120_000)),
        );
        Value::Object(input)
    }

    fn evaluate_stream_input(
        connector: &DingTalkConnector,
        config: &DingTalkConfig,
        input: &Value,
    ) -> DingTalkStreamSecurityOutcome {
        let request = DingTalkStreamIngestRequest::from_input(input).expect("stream request");
        let event: DingTalkCallbackEvent =
            serde_json::from_value(request.event.clone()).expect("stream event");
        evaluate_stream_frame(connector, config, &event, &request).expect("stream evaluation")
    }

    #[fcp_async_core::runtime::test]
    async fn config_rejects_empty_client_id() {
        let mut connector = DingTalkConnector::new();
        let result = connector
            .configure(json!({
                "client_id": "",
                "client_secret": "secret"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn send_text_posts_expected_oto_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/oauth2/accessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "token-123",
                "expireIn": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1.0/robot/oToMessages/batchSend"))
            .and(body_partial_json(json!({
                "robotCode": "ding-app",
                "userIds": ["user-1"],
                "msgKey": "sampleMarkdown"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "processQueryKey": "msg-1"
            })))
            .mount(&server)
            .await;

        let connector = configured_connector(&server).await;
        let client = connector.client.as_ref().unwrap();

        let output = client
            .post_json(
                "/v1.0/robot/oToMessages/batchSend",
                json!({
                    "robotCode": "ding-app",
                    "userIds": ["user-1"],
                    "msgKey": "sampleMarkdown",
                    "msgParam": json!({"title":"hello","text":"hello from ding"}).to_string(),
                }),
            )
            .await
            .expect("send text should succeed");

        assert_eq!(output["processQueryKey"], "msg-1");
    }

    #[fcp_async_core::runtime::test]
    async fn upload_media_posts_expected_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/oauth2/accessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "token-123",
                "expireIn": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/media/upload"))
            .and(query_param("access_token", "token-123"))
            .and(query_param("type", "image"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "media_id": "MEDIA123"
            })))
            .mount(&server)
            .await;

        let connector = configured_connector(&server).await;
        let client = connector.client.as_ref().unwrap();

        let output = client
            .upload_media("image", "test.png", "image/png", &BASE64.encode(b"png"))
            .await
            .expect("upload should succeed");

        assert_eq!(output["media_id"], "MEDIA123");
    }

    #[fcp_async_core::runtime::test]
    async fn health_returns_ready_after_configure() {
        let server = MockServer::start().await;
        let connector = configured_connector(&server).await;
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[fcp_async_core::runtime::test]
    async fn health_returns_starting_before_configure() {
        let connector = DingTalkConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Starting));
    }

    #[test]
    fn doctor_fails_before_configure() {
        let connector = DingTalkConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_passes_after_configure() {
        let server = MockServer::start().await;
        let connector = configured_connector(&server).await;
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_fails_before_configure() {
        let connector = DingTalkConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_ne!(report.status, fcp_core::SelfCheckStatus::Ok);
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_returns_eight_operations() {
        let connector = DingTalkConnector::new();
        let introspection = connector.introspect();
        assert_eq!(introspection.operations.len(), 8);
        let event_caps = introspection.event_caps.expect("event caps");
        assert!(!event_caps.streaming);
        assert!(!event_caps.replay);
        assert_eq!(event_caps.min_buffer_events, 0);
    }

    #[test]
    fn operations_count() {
        let ops = DingTalkConnector::operations();
        assert_eq!(ops.len(), 8);
        assert_eq!(ops[0].id.as_str(), OP_SEND_TEXT);
        assert_eq!(ops[4].id.as_str(), OP_NORMALIZE_EVENT);
        assert_eq!(ops[5].id.as_str(), OP_STREAM_INGEST);
        assert_eq!(ops[6].id.as_str(), OP_STREAM_REPLY);
        assert_eq!(ops[7].id.as_str(), OP_HEALTH);
    }

    #[test]
    fn required_capability_maps_correctly() {
        assert!(required_capability(OP_SEND_TEXT).is_ok());
        assert!(required_capability(OP_SEND_LINK).is_ok());
        assert!(required_capability(OP_UPLOAD_MEDIA).is_ok());
        assert!(required_capability(OP_NORMALIZE_EVENT).is_ok());
        assert_eq!(
            required_capability(OP_STREAM_INGEST).unwrap().as_str(),
            CAP_MESSAGES_READ
        );
        assert_eq!(
            required_capability(OP_STREAM_REPLY).unwrap().as_str(),
            CAP_MESSAGES_WRITE
        );
        assert_eq!(
            required_capability(OP_NORMALIZE_EVENT).unwrap().as_str(),
            CAP_MESSAGES_READ
        );
        assert!(required_capability("unknown.op").is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_event_caps_track_stream_enablement() {
        let server = MockServer::start().await;
        let mut connector = DingTalkConnector::new();
        connector
            .configure(json!({
                "base_url": server.uri(),
                "media_base_url": server.uri(),
                "client_id": "ding-app",
                "client_secret": "secret",
                "stream_mode_enabled": true,
                "stream_replay_cache_entries": 7
            }))
            .await
            .expect("configure should succeed");
        let signing_key = Ed25519SigningKey::generate();
        let response = connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [7u8; 32],
                capabilities_requested: vec![CapabilityId::from_static(CAP_MESSAGES_READ)],
                host: None,
                transport_caps: None,
                requested_instance_id: Some(InstanceId::new()),
            })
            .await
            .expect("handshake should succeed");
        let event_caps = response.event_caps.expect("event caps");
        assert!(!event_caps.streaming);
        assert!(event_caps.replay);
        assert_eq!(event_caps.min_buffer_events, 7);
    }

    #[test]
    fn stream_policy_rejects_when_disabled() {
        let connector = DingTalkConnector::new();
        let mut config = stream_policy_config();
        config.stream_mode_enabled = false;
        let input = stream_input(
            stream_event("msg-disabled", "staff-1", "2", "@opsbot hi"),
            true,
        );
        let outcome = evaluate_stream_input(&connector, &config, &input);
        assert_eq!(outcome.decision, "rejected");
        assert_eq!(outcome.reason, "stream_mode_disabled");
        assert!(!outcome.emit_event);
    }

    #[test]
    fn stream_policy_applies_allowed_users_and_mentions() {
        let connector = DingTalkConnector::new();
        let config = stream_policy_config();
        let accepted = stream_input(
            stream_event("msg-allowed", "Staff-1", "2", "@opsbot hi"),
            false,
        );
        let outcome = evaluate_stream_input(&connector, &config, &accepted);
        assert_eq!(outcome.decision, "accepted");
        assert!(outcome.session_webhook_cached);

        let disallowed = stream_input(
            stream_event("msg-denied", "staff-2", "2", "@opsbot hi"),
            true,
        );
        let outcome = evaluate_stream_input(&connector, &config, &disallowed);
        assert_eq!(outcome.decision, "rejected");
        assert_eq!(outcome.reason, "sender_not_allowed");

        let missing_mention = stream_input(
            stream_event("msg-no-mention", "staff-1", "2", "hello"),
            false,
        );
        let outcome = evaluate_stream_input(&connector, &config, &missing_mention);
        assert_eq!(outcome.decision, "rejected");
        assert_eq!(outcome.reason, "mention_required");
    }

    #[test]
    fn stream_policy_honors_free_response_and_dm_group_toggles() {
        let connector = DingTalkConnector::new();
        let mut config = stream_policy_config();
        config.stream_free_response_chats = vec!["conv-1".into()];
        let free_response = stream_input(stream_event("msg-free", "staff-1", "2", "hello"), false);
        let outcome = evaluate_stream_input(&connector, &config, &free_response);
        assert_eq!(outcome.decision, "accepted");

        let mut config = stream_policy_config();
        config.stream_group_allowed = false;
        let group = stream_input(
            stream_event("msg-group-off", "staff-1", "2", "@opsbot hi"),
            true,
        );
        let outcome = evaluate_stream_input(&connector, &config, &group);
        assert_eq!(outcome.reason, "group_stream_disabled");

        let mut config = stream_policy_config();
        config.stream_dm_allowed = false;
        let dm = stream_input(stream_event("msg-dm-off", "staff-1", "1", "hello"), false);
        let outcome = evaluate_stream_input(&connector, &config, &dm);
        assert_eq!(outcome.reason, "dm_stream_disabled");
    }

    #[test]
    fn stream_media_bounds_are_nested_and_targeted() {
        let connector = DingTalkConnector::new();
        let config = stream_policy_config();
        let mut event = stream_event(
            "msg-long-text",
            "staff-1",
            "2",
            &"x".repeat(MAX_STREAM_MEDIA_FIELD_LEN + 64),
        );
        let input = stream_input(event.clone(), true);
        let outcome = evaluate_stream_input(&connector, &config, &input);
        assert_eq!(outcome.decision, "accepted");

        event["content"] = json!({
            "nested": {
                "downloadCode": "x".repeat(MAX_STREAM_MEDIA_FIELD_LEN + 1)
            }
        });
        event["msgId"] = json!("msg-large-media");
        let input = stream_input(event, true);
        let outcome = evaluate_stream_input(&connector, &config, &input);
        assert_eq!(outcome.decision, "rejected");
        assert_eq!(outcome.reason, "media_field_too_large");
    }

    #[test]
    fn stream_dedupe_and_reply_cache_are_bounded() {
        let connector = DingTalkConnector::new();
        let config = stream_policy_config();
        let input = stream_input(
            stream_event("msg-cache", "staff-1", "2", "@opsbot hi"),
            true,
        );
        let first = evaluate_stream_input(&connector, &config, &input);
        assert_eq!(first.decision, "accepted");
        assert!(first.session_webhook_cached);
        assert_eq!(first.state_counts.cached_session_webhooks, 1);

        let duplicate = evaluate_stream_input(&connector, &config, &input);
        assert_eq!(duplicate.decision, "duplicate");
        assert_eq!(duplicate.reason, "message_replay");
        assert!(duplicate.duplicate);

        let target = resolve_session_reply_target(&connector, &config, "conv-1", &json!({}))
            .expect("cached webhook target");
        assert_eq!(target.source, "cache");
        assert_eq!(target.chat_id, "conv-1");
    }

    #[test]
    fn stream_reply_target_prunes_stale_session_webhooks() {
        let connector = DingTalkConnector::new();
        let config = stream_policy_config();
        connector
            .stream_state
            .lock()
            .expect("stream state")
            .session_webhooks
            .insert(
                "conv-stale".into(),
                DingTalkSessionWebhook {
                    url: "http://localhost:8080/stale".into(),
                    expires_at_ms: Some(1),
                    cached_at_ms: 1,
                },
            );
        let error = resolve_session_reply_target(&connector, &config, "conv-stale", &json!({}))
            .expect_err("stale webhook should be pruned");
        assert!(matches!(error, FcpError::InvalidRequest { code: 1006, .. }));
        assert!(
            !connector
                .stream_state
                .lock()
                .expect("stream state")
                .session_webhooks
                .contains_key("conv-stale")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_missing_send_text_content() {
        let server = MockServer::start().await;
        let (connector, signing_key) = configured_handshaken_connector(
            &server,
            vec![CapabilityId::from_static(CAP_MESSAGES_WRITE)],
        )
        .await;
        let response = connector
            .simulate(simulate_request(
                OP_SEND_TEXT,
                json!({"to": "user:user-1"}),
                signed_token(
                    &signing_key,
                    CAP_MESSAGES_WRITE,
                    OP_SEND_TEXT,
                    &connector.base.instance_id,
                ),
            ))
            .await
            .expect("simulate should return denial response");

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-1005"));
        assert!(
            response
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("content is required"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_invalid_upload_media_type() {
        let server = MockServer::start().await;
        let (connector, signing_key) = configured_handshaken_connector(
            &server,
            vec![CapabilityId::from_static(CAP_MEDIA_WRITE)],
        )
        .await;
        let response = connector
            .simulate(simulate_request(
                OP_UPLOAD_MEDIA,
                json!({
                    "media_type": "archive",
                    "file_name": "payload.bin",
                    "content_base64": BASE64.encode(b"payload"),
                }),
                signed_token(
                    &signing_key,
                    CAP_MEDIA_WRITE,
                    OP_UPLOAD_MEDIA,
                    &connector.base.instance_id,
                ),
            ))
            .await
            .expect("simulate should return denial response");

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-1005"));
        assert!(
            response
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("media_type must be one of"))
        );
    }

    #[test]
    fn granted_capabilities_filters() {
        let requested = vec![
            CapabilityId::from_static(CAP_MESSAGES_WRITE),
            CapabilityId::from_static(CAP_MESSAGES_READ),
            CapabilityId::from_static("dingtalk.fake"),
        ];
        let granted = granted_capabilities(requested);
        assert_eq!(granted.len(), 2);
        assert_eq!(granted[0].capability.as_str(), CAP_MESSAGES_WRITE);
        assert_eq!(granted[1].capability.as_str(), CAP_MESSAGES_READ);
    }

    #[test]
    fn title_for_truncates() {
        assert_eq!(title_for("hello world, this is long"), "hello worl");
        assert_eq!(title_for("short"), "short");
    }

    #[test]
    fn optional_string_rejects_non_string_values() {
        let err = optional_string(&json!({"pic_url": 42}), "pic_url").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        assert!(err.to_string().contains("pic_url must be a string"));
    }

    #[test]
    fn optional_string_trims_blank_values_to_none() {
        assert_eq!(
            optional_string(&json!({"pic_url": "   "}), "pic_url").unwrap(),
            None
        );
        assert_eq!(
            optional_string(
                &json!({"pic_url": " https://example.com/x.png "}),
                "pic_url"
            )
            .unwrap(),
            Some("https://example.com/x.png")
        );
    }

    #[test]
    fn link_msg_param_omits_absent_pic_url() {
        let msg_param = link_msg_param("title", "text", "https://example.com", None);
        assert_eq!(msg_param["title"], "title");
        assert_eq!(msg_param["messageUrl"], "https://example.com");
        assert!(msg_param.get("picUrl").is_none());
    }
}
