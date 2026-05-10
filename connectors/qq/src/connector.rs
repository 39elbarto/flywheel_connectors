//! Tencent `QQ` bot connector.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, EventInfo, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest, ZoneId,
};
use fcp_sdk::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::client::{
    QqClient, channel_message_body, direct_message_body, normalize_message_event,
    sanitize_path_segment,
};
use crate::error::QqError;
use crate::types::{
    CAP_EVENTS_READ, CAP_GATEWAY_READ, CAP_HEALTH_READ, CAP_MESSAGES_WRITE, EVENT_QQ_EVENT_DROPPED,
    EVENT_QQ_MESSAGE_AUTHORIZED, OP_EVENTS_NORMALIZE, OP_GATEWAY_PROJECT_EVENT, OP_GET_GATEWAY,
    OP_HEALTH, OP_SEND_C2C, OP_SEND_CHANNEL, OP_SEND_GROUP, QqConfig, QqGatewayEvent,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

#[derive(Clone, Copy)]
struct QqSendOperationSpec {
    target_field: &'static str,
    path_prefix: &'static str,
    target_kind: &'static str,
    log_operation: &'static str,
    body: fn(&str, Option<&str>) -> Value,
}

const QQ_SEND_CHANNEL_SPEC: QqSendOperationSpec = QqSendOperationSpec {
    target_field: "channel_id",
    path_prefix: "/channels/",
    target_kind: "channel",
    log_operation: "send_channel",
    body: channel_message_body,
};

const QQ_SEND_GROUP_SPEC: QqSendOperationSpec = QqSendOperationSpec {
    target_field: "group_openid",
    path_prefix: "/v2/groups/",
    target_kind: "group",
    log_operation: "send_group",
    body: direct_message_body,
};

const QQ_SEND_C2C_SPEC: QqSendOperationSpec = QqSendOperationSpec {
    target_field: "openid",
    path_prefix: "/v2/users/",
    target_kind: "c2c",
    log_operation: "send_c2c",
    body: direct_message_body,
};

fn default_qq_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_qq_chat_coordination_config(
    value: Option<&Value>,
    base: ChatCoordinationConfig,
) -> FcpResult<ChatCoordinationConfig> {
    let Some(value) = value else {
        return Ok(base);
    };
    let object = value.as_object().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "chat_coordination must be an object".into(),
    })?;

    let mut config = base;
    if let Some(enabled) = object.get("enabled") {
        config = config.with_enabled(json_bool(enabled, "chat_coordination.enabled")?);
    }
    if let Some(ttl_seconds) = object.get("ttl_seconds") {
        let seconds = ttl_seconds
            .as_u64()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "chat_coordination.ttl_seconds must be an integer".into(),
            })?;
        if seconds == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "chat_coordination.ttl_seconds must be greater than zero".into(),
            });
        }
        config = config.with_ttl(Duration::from_secs(seconds));
    }
    if let Some(fail_open) = object.get("fail_open") {
        config = config.with_fail_open(json_bool(fail_open, "chat_coordination.fail_open")?);
    }
    if let Some(allowlist) = object.get("allowlist_channels") {
        let channels = allowlist
            .as_array()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "chat_coordination.allowlist_channels must be an array".into(),
            })?;
        let mut normalized = Vec::with_capacity(channels.len());
        for channel in channels {
            let raw = channel.as_str().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "chat_coordination.allowlist_channels entries must be strings".into(),
            })?;
            let channel_id = raw.trim();
            if channel_id.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_coordination.allowlist_channels entries must not be empty"
                        .into(),
                });
            }
            normalized.push(ChannelId::new(channel_id.to_owned()));
        }
        config = config.with_allowlist_channels(normalized);
    }
    if let Some(backend) = object.get("backend") {
        config = config.with_backend(parse_chat_coordination_backend(backend)?);
    }
    if let Some(dm_mode) = object.get("dm_mode") {
        config = config.with_dm_mode(parse_chat_coordination_dm_mode(dm_mode)?);
    }
    Ok(config)
}

fn json_bool(value: &Value, field: &str) -> FcpResult<bool> {
    value.as_bool().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be a boolean"),
    })
}

fn parse_chat_coordination_backend(value: &Value) -> FcpResult<ChatCoordinationBackend> {
    match value.as_str() {
        Some("agent_mail") => Ok(ChatCoordinationBackend::AgentMail),
        Some("mesh_gossip") => Ok(ChatCoordinationBackend::MeshGossip),
        Some("in_memory") => Ok(ChatCoordinationBackend::InMemory),
        Some(other) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("unsupported chat_coordination.backend: {other}"),
        }),
        None => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "chat_coordination.backend must be a string".into(),
        }),
    }
}

fn parse_chat_coordination_dm_mode(value: &Value) -> FcpResult<DmMode> {
    match value.as_str() {
        Some("skip") => Ok(DmMode::Skip),
        Some("treat_as_thread") => Ok(DmMode::TreatAsThread),
        Some(other) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("unsupported chat_coordination.dm_mode: {other}"),
        }),
        None => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "chat_coordination.dm_mode must be a string".into(),
        }),
    }
}

fn qq_coordination_audit_records(
    decision: &ChatCoordinationSendDecision,
    backend: ChatCoordinationBackend,
    claimant_agent_id: &AgentId,
) -> Vec<ChatCoordinationAuditRecord> {
    let mut records = decision.audit_records().to_vec();
    if let Some(record) = decision.send_executed_audit_record(backend, claimant_agent_id) {
        records.push(record);
    }
    records
}

fn empty_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false
    })
}

fn nonblank_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "\\S"
    })
}

fn target_id_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "^[^/\\\\]+$",
        "not": {
            "pattern": "\\.\\.|%2[fFeE]|%5[cC]"
        }
    })
}

fn send_message_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": true,
        "properties": {
            "id": { "type": "string" },
            "timestamp": { "type": "string" },
            "coordination": {
                "type": "array",
                "description": "Redacted chat coordination audit records"
            }
        }
    })
}

fn channel_send_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["channel_id", "content"],
        "additionalProperties": false,
        "properties": {
            "channel_id": target_id_schema(),
            "content": nonblank_string_schema(),
            "msg_id": { "type": "string" }
        }
    })
}

fn group_send_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["group_openid", "content"],
        "additionalProperties": false,
        "properties": {
            "group_openid": target_id_schema(),
            "content": nonblank_string_schema(),
            "msg_id": { "type": "string" }
        }
    })
}

fn c2c_send_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["openid", "content"],
        "additionalProperties": false,
        "properties": {
            "openid": target_id_schema(),
            "content": nonblank_string_schema(),
            "msg_id": { "type": "string" }
        }
    })
}

fn gateway_event_schema() -> Value {
    json!({
        "type": "object",
        "required": ["op"],
        "additionalProperties": false,
        "properties": {
            "op": {
                "type": "integer",
                "minimum": 0,
                "maximum": 255
            },
            "s": {
                "type": ["integer", "null"],
                "minimum": 0
            },
            "t": {
                "type": ["string", "null"],
                "maxLength": 64,
                "pattern": "^[A-Z0-9_]+$"
            },
            "d": {
                "type": ["object", "null"],
                "additionalProperties": true
            },
            "id": {
                "type": ["string", "null"],
                "maxLength": 256
            }
        }
    })
}

fn gateway_event_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["event"],
        "additionalProperties": false,
        "properties": {
            "event": gateway_event_schema()
        }
    })
}

fn normalized_event_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "event_type",
            "message_id",
            "channel_id",
            "guild_id",
            "group_id",
            "sender_id",
            "sender_name",
            "text",
            "timestamp",
            "is_reply",
            "reply_to",
            "has_attachments",
            "routing",
            "raw"
        ],
        "additionalProperties": false,
        "properties": {
            "event_type": { "type": "string" },
            "message_id": { "type": ["string", "null"] },
            "channel_id": { "type": ["string", "null"] },
            "guild_id": { "type": ["string", "null"] },
            "group_id": { "type": ["string", "null"] },
            "sender_id": { "type": ["string", "null"] },
            "sender_name": { "type": ["string", "null"] },
            "text": { "type": ["string", "null"] },
            "timestamp": { "type": ["string", "null"] },
            "is_reply": { "type": "boolean" },
            "reply_to": { "type": ["string", "null"] },
            "has_attachments": { "type": "boolean" },
            "routing": {
                "type": "string",
                "enum": ["channel", "group", "c2c"]
            },
            "raw": {
                "type": ["object", "null"],
                "additionalProperties": true
            }
        }
    })
}

fn inbound_policy_decision_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "allowed",
            "reason_code",
            "routing",
            "sender_id",
            "target_id",
            "mentioned_bot"
        ],
        "additionalProperties": false,
        "properties": {
            "allowed": { "type": "boolean" },
            "reason_code": { "type": "string" },
            "routing": {
                "type": "string",
                "enum": ["channel", "group", "c2c"]
            },
            "sender_id": { "type": ["string", "null"] },
            "target_id": { "type": ["string", "null"] },
            "mentioned_bot": { "type": "boolean" }
        }
    })
}

fn gateway_runtime_snapshot_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "enabled",
            "session_id",
            "last_sequence",
            "heartbeat_interval_ms",
            "heartbeat_sent_count",
            "heartbeat_ack_count",
            "reconnect_attempts",
            "max_reconnect_attempts",
            "reconnect_backoff_ms",
            "queue_depth",
            "max_queue_depth",
            "dedupe_size",
            "dedupe_window_size",
            "accepted_events",
            "dropped_events",
            "duplicate_events",
            "stale_sequence_events"
        ],
        "additionalProperties": false,
        "properties": {
            "enabled": { "type": "boolean" },
            "session_id": { "type": ["string", "null"] },
            "last_sequence": { "type": "integer", "minimum": 0 },
            "heartbeat_interval_ms": { "type": "integer", "minimum": 0 },
            "heartbeat_sent_count": { "type": "integer", "minimum": 0 },
            "heartbeat_ack_count": { "type": "integer", "minimum": 0 },
            "reconnect_attempts": { "type": "integer", "minimum": 0 },
            "max_reconnect_attempts": { "type": "integer", "minimum": 0 },
            "reconnect_backoff_ms": { "type": "integer", "minimum": 0 },
            "queue_depth": { "type": "integer", "minimum": 0 },
            "max_queue_depth": { "type": "integer", "minimum": 0 },
            "dedupe_size": { "type": "integer", "minimum": 0 },
            "dedupe_window_size": { "type": "integer", "minimum": 0 },
            "accepted_events": { "type": "integer", "minimum": 0 },
            "dropped_events": { "type": "integer", "minimum": 0 },
            "duplicate_events": { "type": "integer", "minimum": 0 },
            "stale_sequence_events": { "type": "integer", "minimum": 0 }
        }
    })
}

fn gateway_projection_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "accepted",
            "topic",
            "reason_code",
            "sequence",
            "event_id",
            "normalized",
            "policy",
            "runtime"
        ],
        "additionalProperties": false,
        "properties": {
            "accepted": { "type": "boolean" },
            "topic": {
                "type": "string",
                "enum": [EVENT_QQ_MESSAGE_AUTHORIZED, EVENT_QQ_EVENT_DROPPED]
            },
            "reason_code": { "type": "string" },
            "sequence": { "type": ["integer", "null"], "minimum": 0 },
            "event_id": { "type": ["string", "null"] },
            "normalized": {
                "anyOf": [
                    normalized_event_schema(),
                    { "type": "null" }
                ]
            },
            "policy": {
                "anyOf": [
                    inbound_policy_decision_schema(),
                    { "type": "null" }
                ]
            },
            "runtime": gateway_runtime_snapshot_schema()
        }
    })
}

#[allow(clippy::too_many_lines)]
fn output_schema_for(operation_id: &str) -> Value {
    match operation_id {
        OP_SEND_CHANNEL | OP_SEND_GROUP | OP_SEND_C2C => send_message_output_schema(),
        OP_GET_GATEWAY => json!({
            "type": "object",
            "required": ["url"],
            "additionalProperties": true,
            "properties": {
                "url": {
                    "type": "string",
                    "format": "uri"
                }
            }
        }),
        OP_HEALTH => json!({
            "type": "object",
            "required": ["status", "base_url", "gateway", "manifest_hash"],
            "additionalProperties": false,
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["ok"]
                },
                "base_url": {
                    "type": "string",
                    "format": "uri"
                },
                "gateway": {
                    "type": ["string", "null"],
                    "format": "uri"
                },
                "manifest_hash": {
                    "type": "string",
                    "pattern": "^sha256:[0-9a-f]{64}$"
                }
            }
        }),
        OP_EVENTS_NORMALIZE => normalized_event_schema(),
        OP_GATEWAY_PROJECT_EVENT => gateway_projection_schema(),
        _ => json!({ "type": "object" }),
    }
}

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

pub struct QqConnector {
    base: BaseConnector,
    client: Option<QqClient>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
}

impl std::fmt::Debug for QqConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QqConnector")
            .field("base", &self.base)
            .field("client_configured", &self.client.is_some())
            .field("verifier_configured", &self.verifier.is_some())
            .field("started_at", &self.started_at)
            .field("chat_coordination_config", &self.chat_coordination_config)
            .finish_non_exhaustive()
    }
}

impl QqConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.qq")),
            client: None,
            verifier: None,
            started_at: Instant::now(),
            chat_coordination_config: default_qq_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
        }
    }

    #[must_use]
    pub const fn instance_id(&self) -> &fcp_prelude::InstanceId {
        &self.base.instance_id
    }

    /// Replace the thread ownership checker used by outbound chat coordination.
    #[must_use]
    pub fn with_thread_ownership_checker(
        mut self,
        checker: Arc<dyn ThreadOwnershipChecker>,
        backend: ChatCoordinationBackend,
    ) -> Self {
        self.thread_ownership_checker = checker;
        self.chat_coordination_config = self.chat_coordination_config.with_backend(backend);
        self
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
            name: "gateway_runtime".into(),
            passed: self.client.is_some(),
            message: Some(match self.client.as_ref() {
                Some(client) if client.config().gateway.enabled => {
                    "Gateway projection runtime configured; WebSocket ownership remains host-driven"
                        .into()
                }
                Some(_) => {
                    "Gateway projection runtime available but disabled by configuration".into()
                }
                None => "Gateway projection runtime missing - configure first".into(),
            }),
            critical: false,
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

    // Keep the QQ operation catalog contiguous so introspection metadata stays auditable.
    #[allow(clippy::too_many_lines)]
    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_SEND_CHANNEL,
                "Send a QQ channel message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                channel_send_input_schema(),
                "Use for QQ channel deliveries when you already know the target channel_id.",
            ),
            operation(
                OP_SEND_GROUP,
                "Send a QQ group message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                group_send_input_schema(),
                "Use for QQ group deliveries to a known group_openid target.",
            ),
            operation(
                OP_SEND_C2C,
                "Send a QQ C2C message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                c2c_send_input_schema(),
                "Use for one-to-one QQ bot messages directed at a specific openid.",
            ),
            operation(
                OP_GET_GATEWAY,
                "Get the QQ gateway websocket URL",
                CAP_GATEWAY_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                empty_input_schema(),
                "Use when a higher-level runtime needs the official QQ gateway URL for event intake.",
            ),
            operation(
                OP_HEALTH,
                "Verify QQ credentials and gateway discovery",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                empty_input_schema(),
                "Use before higher-risk send operations when you need a bounded auth and connectivity check.",
            ),
            operation(
                OP_EVENTS_NORMALIZE,
                "Normalize a raw QQ gateway event into a structured event with routing",
                CAP_EVENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                gateway_event_input_schema(),
                "Use to normalize raw QQ Bot WebSocket gateway events into structured events with routing classification (channel/group/c2c), quote context, and attachment detection.",
            ),
            operation(
                OP_GATEWAY_PROJECT_EVENT,
                "Project a raw QQ gateway event through runtime state and inbound policy",
                CAP_EVENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                gateway_event_input_schema(),
                "Use when a host-owned QQ WebSocket loop needs connector-side sequence, duplicate, and inbound-policy projection before agent-visible event fanout.",
            ),
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])?;

        let output = match req.operation.as_str() {
            OP_SEND_CHANNEL => {
                self.invoke_send_message(client, &req.input, QQ_SEND_CHANNEL_SPEC)
                    .await?
            }
            OP_SEND_GROUP => {
                self.invoke_send_message(client, &req.input, QQ_SEND_GROUP_SPEC)
                    .await?
            }
            OP_SEND_C2C => {
                self.invoke_send_message(client, &req.input, QQ_SEND_C2C_SPEC)
                    .await?
            }
            OP_GET_GATEWAY => client
                .api_request(reqwest::Method::GET, "/gateway", None)
                .await
                .map_err(|e| e.to_fcp_error())?,
            OP_HEALTH => {
                let _access_material = client.access_token().await.map_err(|e| e.to_fcp_error())?;
                let gateway = client
                    .api_request(reqwest::Method::GET, "/gateway", None)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": "ok",
                    "base_url": client.config().base_url,
                    "gateway": gateway.get("url").cloned().unwrap_or(Value::Null),
                    "manifest_hash": Self::manifest_hash(),
                })
            }
            OP_EVENTS_NORMALIZE => {
                let gateway_event = parse_gateway_event(&req.input)?;
                let normalized =
                    normalize_message_event(&gateway_event).map_err(|e| e.to_fcp_error())?;
                serialize_output(&normalized, "normalized event")?
            }
            OP_GATEWAY_PROJECT_EVENT => {
                let gateway_event = parse_gateway_event(&req.input)?;
                let projection = client
                    .project_gateway_event(gateway_event)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serialize_output(&projection, "projected gateway event")?
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

    async fn invoke_send_message(
        &self,
        client: &QqClient,
        input: &Value,
        spec: QqSendOperationSpec,
    ) -> FcpResult<Value> {
        let target_id = required_string(input, spec.target_field)?;
        let path = message_path(spec.path_prefix, target_id, spec.target_field)?;
        let content = required_string(input, "content")?;
        let msg_id = optional_string(input, "msg_id")?;
        let (claim_channel_id, thread_id) = qq_claim_target(spec.target_kind, target_id, msg_id);
        let (zone_id, claimant_agent_id) = self.chat_coordination_context();
        let coordination = self
            .claim_before_qq_send(
                zone_id,
                claim_channel_id,
                thread_id,
                claimant_agent_id.clone(),
            )
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                error = %error,
                operation = spec.log_operation,
                "QQ send denied by chat coordination"
            );
            return Err(error.clone());
        }

        let mut output = client
            .api_request(
                reqwest::Method::POST,
                &path,
                Some((spec.body)(content, msg_id)),
            )
            .await
            .map_err(|e| e.to_fcp_error())?;
        qq_insert_coordination(
            &mut output,
            &coordination,
            self.chat_coordination_config.backend(),
            &claimant_agent_id,
        )?;
        Ok(output)
    }

    fn chat_coordination_context(&self) -> (ZoneId, AgentId) {
        let zone_id = self
            .verifier
            .as_ref()
            .map_or_else(ZoneId::work, |verifier| verifier.zone_id.clone());
        let claimant_agent_id = AgentId::new(self.base.instance_id.as_str().to_owned());
        (zone_id, claimant_agent_id)
    }

    async fn claim_before_qq_send(
        &self,
        zone_id: ZoneId,
        channel_id: ChannelId,
        thread_id: Option<ThreadId>,
        claimant_agent_id: AgentId,
    ) -> ChatCoordinationSendDecision {
        let cx = fcp_async_core::compatibility_cx();
        self.chat_coordination_config
            .claim_before_send(
                &cx,
                self.thread_ownership_checker.as_ref(),
                ChatCoordinationSendRequest::new(
                    zone_id,
                    self.base.id.clone(),
                    channel_id,
                    thread_id,
                    claimant_agent_id,
                ),
            )
            .await
    }
}

impl Default for QqConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(QqConnector);

#[async_trait]
impl FcpConnector for QqConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let chat_coordination_config = parse_qq_chat_coordination_config(
            config.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;
        let config: QqConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid QQ configuration: {error}"),
            })?;
        self.client = Some(QqClient::new(config).map_err(|e| e.to_fcp_error())?);
        self.chat_coordination_config = chat_coordination_config;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
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
        let details = if let Some(client) = self.client.as_ref() {
            let gateway_runtime = client.gateway_runtime_snapshot().await;
            Some(json!({
                "base_url": client.config().base_url,
                "token_base_url": client.config().token_base_url,
                "app_id": client.config().app_id,
                "gateway_runtime": gateway_runtime,
            }))
        } else {
            None
        };
        HealthSnapshot {
            status: if self.client.is_some() {
                HealthState::Ready
            } else {
                HealthState::Starting
            },
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details,
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = self.client.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before QQ self_check",
            ));
        };
        match client.access_token().await {
            Ok(_) => Ok(SelfCheckReport::ok()),
            Err(error) => {
                let fcp_err = error.to_fcp_error();
                Ok(SelfCheckReport::from_error(&fcp_err))
            }
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(client) = self.client.as_ref() {
            client.shutdown();
        }
        self.client = None;
        self.verifier = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations(),
            events: qq_events_info(),
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
        if let Err(error) = validate_simulate_input(req.operation.as_str(), &req.input) {
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }
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
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_SEND_CHANNEL | OP_SEND_GROUP | OP_SEND_C2C => CAP_MESSAGES_WRITE,
        OP_GET_GATEWAY => CAP_GATEWAY_READ,
        OP_HEALTH => CAP_HEALTH_READ,
        OP_EVENTS_NORMALIZE | OP_GATEWAY_PROJECT_EVENT => CAP_EVENTS_READ,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn validate_simulate_input(operation: &str, input: &Value) -> FcpResult<()> {
    match operation {
        OP_SEND_CHANNEL => {
            let channel_id = required_string(input, "channel_id")?;
            let _path = message_path("/channels/", channel_id, "channel_id")?;
            required_string(input, "content")?;
            optional_string(input, "msg_id")?;
        }
        OP_SEND_GROUP => {
            let group_openid = required_string(input, "group_openid")?;
            let _path = message_path("/v2/groups/", group_openid, "group_openid")?;
            required_string(input, "content")?;
            optional_string(input, "msg_id")?;
        }
        OP_SEND_C2C => {
            let openid = required_string(input, "openid")?;
            let _path = message_path("/v2/users/", openid, "openid")?;
            required_string(input, "content")?;
            optional_string(input, "msg_id")?;
        }
        OP_GET_GATEWAY | OP_HEALTH => {}
        OP_EVENTS_NORMALIZE => {
            let event_value = input.get("event").ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "event is required".into(),
            })?;
            let gateway_event: QqGatewayEvent = serde_json::from_value(event_value.clone())
                .map_err(|e| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("invalid gateway event: {e}"),
                })?;
            normalize_message_event(&gateway_event).map_err(|e| e.to_fcp_error())?;
        }
        OP_GATEWAY_PROJECT_EVENT => validate_gateway_project_input(input)?,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown operation: {operation}"),
            });
        }
    }
    Ok(())
}

fn validate_gateway_project_input(input: &Value) -> FcpResult<()> {
    let gateway_event = parse_gateway_event(input)?;
    if gateway_event.op != 0 {
        return Ok(());
    }
    match normalize_message_event(&gateway_event) {
        Ok(_) => Ok(()),
        Err(QqError::InvalidInput(message)) if message.contains("not a normalizable") => Ok(()),
        Err(error) => Err(error.to_fcp_error()),
    }
}

fn parse_gateway_event(input: &Value) -> FcpResult<QqGatewayEvent> {
    let event_value = input.get("event").ok_or_else(|| FcpError::InvalidRequest {
        code: 1005,
        message: "event is required".into(),
    })?;
    serde_json::from_value(event_value.clone()).map_err(|e| FcpError::InvalidRequest {
        code: 1005,
        message: format!("invalid gateway event: {e}"),
    })
}

fn serialize_output<T: serde::Serialize>(value: &T, name: &str) -> FcpResult<Value> {
    serde_json::to_value(value).map_err(|e| FcpError::Internal {
        message: format!("failed to serialize {name}: {e}"),
    })
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| {
            matches!(
                capability.as_str(),
                CAP_MESSAGES_WRITE | CAP_GATEWAY_READ | CAP_HEALTH_READ | CAP_EVENTS_READ
            )
        })
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
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

fn message_path(prefix: &str, target_id: &str, field: &str) -> FcpResult<String> {
    let safe_id = sanitize_path_segment(target_id, field).map_err(|e| e.to_fcp_error())?;
    Ok(format!("{prefix}{safe_id}/messages"))
}

fn qq_claim_target(
    target_kind: &str,
    target_id: &str,
    msg_id: Option<&str>,
) -> (ChannelId, Option<ThreadId>) {
    (
        ChannelId::new(format!("{target_kind}:{target_id}")),
        msg_id.map(|msg_id| ThreadId::new(msg_id.to_owned())),
    )
}

fn qq_insert_coordination(
    output: &mut Value,
    decision: &ChatCoordinationSendDecision,
    backend: ChatCoordinationBackend,
    claimant_agent_id: &AgentId,
) -> FcpResult<()> {
    let output = output.as_object_mut().ok_or_else(|| FcpError::Internal {
        message: "QQ send output was not an object".into(),
    })?;
    output.insert(
        "coordination".into(),
        json!(qq_coordination_audit_records(
            decision,
            backend,
            claimant_agent_id,
        )),
    );
    Ok(())
}

fn qq_events_info() -> Vec<EventInfo> {
    vec![
        EventInfo {
            topic: EVENT_QQ_MESSAGE_AUTHORIZED.into(),
            schema: json!({
                "type": "object",
                "required": ["accepted", "topic", "normalized", "policy", "runtime"],
                "properties": {
                    "accepted": { "const": true },
                    "topic": { "const": EVENT_QQ_MESSAGE_AUTHORIZED },
                    "normalized": { "type": "object" },
                    "policy": { "type": "object" },
                    "runtime": { "type": "object" }
                }
            }),
            requires_ack: false,
        },
        EventInfo {
            topic: EVENT_QQ_EVENT_DROPPED.into(),
            schema: json!({
                "type": "object",
                "required": ["accepted", "topic", "reason_code", "runtime"],
                "properties": {
                    "accepted": { "const": false },
                    "topic": { "const": EVENT_QQ_EVENT_DROPPED },
                    "reason_code": { "type": "string" },
                    "runtime": { "type": "object" }
                }
            }),
            requires_ack: false,
        },
    ]
}

// This factory mirrors the OperationInfo fields to keep each catalog entry explicit.
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
        output_schema: output_schema_for(id),
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: vec![
                "QQ channel sends use channel_id, while group and C2C sends require group_openid or openid."
                    .into(),
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
    use chrono::{Duration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, InstanceId, ZoneId};

    fn build_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &InstanceId,
        cap: &str,
        operation: &str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

        let raw = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("valid constraints cbor")
            .target_instance(instance_id.as_str())
            .sign(signing_key)
            .expect("capability token");
        CapabilityToken::from_raw(raw)
    }

    fn simulate_request(
        signing_key: &Ed25519SigningKey,
        instance_id: &InstanceId,
        cap: &str,
        operation: &'static str,
        input: Value,
    ) -> SimulateRequest {
        SimulateRequest::new(
            ConnectorId::from_static("fcp.qq"),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            build_token(signing_key, instance_id, cap, operation),
        )
    }

    const EXPECTED_MANIFEST_SCHEMA_OPS: &[(&str, &str)] = &[
        (OP_SEND_CHANNEL, "messages_send_channel"),
        (OP_SEND_GROUP, "messages_send_group"),
        (OP_SEND_C2C, "messages_send_c2c"),
        (OP_GET_GATEWAY, "gateway_get"),
        (OP_EVENTS_NORMALIZE, "events_normalize"),
        (OP_GATEWAY_PROJECT_EVENT, "gateway_project_event"),
        (OP_HEALTH, "health"),
    ];

    fn qq_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML).map_err(|err| format!("QQ manifest TOML should parse: {err}"))
    }

    fn manifest_operations(
        manifest: &toml::Value,
    ) -> Result<&toml::map::Map<String, toml::Value>, String> {
        manifest
            .get("provides")
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| "manifest should declare operation tables".to_owned())
    }

    fn operation_schema(
        manifest: &toml::Value,
        operation_key: &str,
        field: &str,
    ) -> Result<serde_json::Value, String> {
        let schema = manifest_operations(manifest)?
            .get(operation_key)
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get(field))
            .ok_or_else(|| format!("{operation_key} should declare {field}"))?;
        if schema.as_table().is_none_or(toml::map::Map::is_empty) {
            return Err(format!(
                "{operation_key}.{field} should be a non-empty schema table"
            ));
        }
        serde_json::to_value(schema)
            .map_err(|err| format!("{operation_key}.{field} should convert to JSON: {err}"))
    }

    fn operation_network_constraints<'a>(
        manifest: &'a toml::Value,
        operation_key: &str,
    ) -> Result<&'a toml::map::Map<String, toml::Value>, String> {
        manifest_operations(manifest)?
            .get(operation_key)
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get("network_constraints"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("{operation_key} should declare network_constraints"))
    }

    fn string_array(
        table: &toml::map::Map<String, toml::Value>,
        key: &str,
    ) -> Result<Vec<String>, String> {
        table
            .get(key)
            .and_then(toml::Value::as_array)
            .ok_or_else(|| format!("{key} should be an array"))?
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{key} entries should be strings"))
            })
            .collect()
    }

    fn integer_array(
        table: &toml::map::Map<String, toml::Value>,
        key: &str,
    ) -> Result<Vec<i64>, String> {
        table
            .get(key)
            .and_then(toml::Value::as_array)
            .ok_or_else(|| format!("{key} should be an array"))?
            .iter()
            .map(|item| {
                item.as_integer()
                    .ok_or_else(|| format!("{key} entries should be integers"))
            })
            .collect()
    }

    fn validator_for(schema: &serde_json::Value) -> Result<jsonschema::Validator, String> {
        jsonschema::Validator::new(schema)
            .map_err(|err| format!("manifest operation schema should compile: {err}"))
    }

    fn assert_schema_accepts(
        schema: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let validator = validator_for(schema)?;
        let errors = validator
            .iter_errors(payload)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "schema should accept {payload}; errors: {errors:?}"
            ))
        }
    }

    fn assert_schema_rejects(
        schema: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let validator = validator_for(schema)?;
        if validator.iter_errors(payload).next().is_some() {
            Ok(())
        } else {
            Err(format!("schema should reject {payload}"))
        }
    }

    fn sample_gateway_event() -> Value {
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-1",
            "d": {
                "id": "msg-1",
                "content": "bot-openid deploy status?",
                "group_openid": "group-1",
                "group_member_openid": "member-1",
                "author": {
                    "id": "member-1",
                    "username": "Alice"
                }
            }
        })
    }

    fn sample_normalized_event() -> Value {
        json!({
            "event_type": "GROUP_AT_MESSAGE_CREATE",
            "message_id": "msg-1",
            "channel_id": null,
            "guild_id": null,
            "group_id": "group-1",
            "sender_id": "member-1",
            "sender_name": "Alice",
            "text": "bot-openid deploy status?",
            "timestamp": null,
            "is_reply": false,
            "reply_to": null,
            "has_attachments": false,
            "routing": "group",
            "raw": {
                "id": "msg-1",
                "content": "bot-openid deploy status?"
            }
        })
    }

    fn sample_runtime_snapshot() -> Value {
        json!({
            "enabled": true,
            "session_id": "session-1",
            "last_sequence": 1,
            "heartbeat_interval_ms": 45_000,
            "heartbeat_sent_count": 0,
            "heartbeat_ack_count": 0,
            "reconnect_attempts": 0,
            "max_reconnect_attempts": 5,
            "reconnect_backoff_ms": 1_000,
            "queue_depth": 1,
            "max_queue_depth": 128,
            "dedupe_size": 1,
            "dedupe_window_size": 1_024,
            "accepted_events": 1,
            "dropped_events": 0,
            "duplicate_events": 0,
            "stale_sequence_events": 0
        })
    }

    fn sample_policy_decision() -> Value {
        json!({
            "allowed": true,
            "reason_code": "group_allowed",
            "routing": "group",
            "sender_id": "member-1",
            "target_id": "group-1",
            "mentioned_bot": true
        })
    }

    async fn ready_connector(signing_key: &Ed25519SigningKey) -> QqConnector {
        let instance_id = InstanceId::new();
        let mut connector = QqConnector::new();
        connector
            .configure(json!({
                "app_id": "test-app",
                "client_secret": "test-secret",
                "base_url": "http://localhost:9999",
                "token_base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();
        connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [7u8; 32],
                capabilities_requested: vec![CapabilityId::from_static(CAP_MESSAGES_WRITE)],
                host: None,
                transport_caps: None,
                requested_instance_id: Some(instance_id),
            })
            .await
            .unwrap();
        connector
    }

    #[test]
    fn connector_default_creates_instance() {
        let connector = QqConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.qq");
    }

    #[test]
    fn introspect_returns_seven_operations() {
        let connector = QqConnector::new();
        let introspection = connector.introspect();
        assert_eq!(introspection.operations.len(), 7);
        assert_eq!(introspection.events.len(), 2);
    }

    #[test]
    fn introspect_operation_ids() {
        let connector = QqConnector::new();
        let introspection = connector.introspect();
        let ids: Vec<&str> = introspection
            .operations
            .iter()
            .map(|op| op.id.as_str())
            .collect();
        assert!(ids.contains(&"qq.messages.send_channel"));
        assert!(ids.contains(&"qq.messages.send_group"));
        assert!(ids.contains(&"qq.messages.send_c2c"));
        assert!(ids.contains(&"qq.gateway.get"));
        assert!(ids.contains(&"qq.health"));
        assert!(ids.contains(&"qq.events.normalize"));
        assert!(ids.contains(&"qq.gateway.project_event"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        let manifest = qq_manifest()?;
        let operations = manifest_operations(&manifest)?;
        let operation_catalog = QqConnector::operations();

        for (operation_id, manifest_key) in EXPECTED_MANIFEST_SCHEMA_OPS {
            assert!(
                operations.contains_key(*manifest_key),
                "manifest should declare operation {manifest_key}"
            );
            let operation = operation_catalog
                .iter()
                .find(|operation| operation.id.as_str() == *operation_id)
                .ok_or_else(|| format!("operation catalog should declare {operation_id}"))?;
            for field in ["input_schema", "output_schema"] {
                let schema = operation_schema(&manifest, manifest_key, field)?;
                let _validator = validator_for(&schema)?;
            }
            assert_eq!(
                operation.input_schema,
                operation_schema(&manifest, manifest_key, "input_schema")?,
                "{operation_id} input schema should match manifest"
            );
            assert_eq!(
                operation.output_schema,
                operation_schema(&manifest, manifest_key, "output_schema")?,
                "{operation_id} output schema should match manifest"
            );
        }

        for operation in operation_catalog {
            let _input_validator = validator_for(&operation.input_schema)?;
            let _output_validator = validator_for(&operation.output_schema)?;
        }

        let channel_input = operation_schema(&manifest, "messages_send_channel", "input_schema")?;
        assert_schema_accepts(
            &channel_input,
            &json!({"channel_id": "channel-1", "content": "hello", "msg_id": ""}),
        )?;
        assert_schema_rejects(&channel_input, &json!({"channel_id": "channel-1"}))?;
        assert_schema_rejects(
            &channel_input,
            &json!({"channel_id": "../admin", "content": "hello"}),
        )?;
        assert_schema_rejects(
            &channel_input,
            &json!({"channel_id": "channel-1", "content": "hello", "extra": true}),
        )?;

        let group_input = operation_schema(&manifest, "messages_send_group", "input_schema")?;
        assert_schema_accepts(
            &group_input,
            &json!({"group_openid": "group-1", "content": "hello"}),
        )?;
        assert_schema_rejects(
            &group_input,
            &json!({"group_openid": "group/1", "content": "hello"}),
        )?;

        let c2c_input = operation_schema(&manifest, "messages_send_c2c", "input_schema")?;
        assert_schema_accepts(&c2c_input, &json!({"openid": "user-1", "content": "hello"}))?;
        assert_schema_rejects(&c2c_input, &json!({"openid": "user-1", "content": "   "}))?;

        for operation_key in ["gateway_get", "health"] {
            let input = operation_schema(&manifest, operation_key, "input_schema")?;
            assert_schema_accepts(&input, &json!({}))?;
            assert_schema_rejects(&input, &json!({"unexpected": true}))?;
        }

        for operation_key in ["events_normalize", "gateway_project_event"] {
            let input = operation_schema(&manifest, operation_key, "input_schema")?;
            assert_schema_accepts(&input, &json!({"event": sample_gateway_event()}))?;
            assert_schema_rejects(&input, &json!({}))?;
            assert_schema_rejects(&input, &json!({"event": {"op": 300}}))?;
            assert_schema_rejects(&input, &json!({"event": {"op": 0, "t": "lowercase_event"}}))?;
            assert_schema_rejects(&input, &json!({"event": {"op": 0}, "unexpected": true}))?;
        }

        for operation_key in [
            "messages_send_channel",
            "messages_send_group",
            "messages_send_c2c",
        ] {
            let output = operation_schema(&manifest, operation_key, "output_schema")?;
            assert_schema_accepts(
                &output,
                &json!({"id": "msg-1", "timestamp": "2026-04-27T19:00:00Z"}),
            )?;
            assert_schema_rejects(&output, &json!([{"id": "msg-1"}]))?;
        }

        let gateway_output = operation_schema(&manifest, "gateway_get", "output_schema")?;
        assert_schema_accepts(&gateway_output, &json!({"url": "wss://gateway.qq.com"}))?;
        assert_schema_rejects(&gateway_output, &json!({}))?;

        let health_output = operation_schema(&manifest, "health", "output_schema")?;
        assert_schema_accepts(
            &health_output,
            &json!({
                "status": "ok",
                "base_url": "https://api.sgroup.qq.com",
                "gateway": "wss://gateway.qq.com",
                "manifest_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }),
        )?;
        assert_schema_rejects(
            &health_output,
            &json!({
                "status": "ok",
                "base_url": "https://api.sgroup.qq.com",
                "gateway": "wss://gateway.qq.com",
                "manifest_hash": "sha256:short"
            }),
        )?;

        let normalize_output = operation_schema(&manifest, "events_normalize", "output_schema")?;
        assert_schema_accepts(&normalize_output, &sample_normalized_event())?;
        assert_schema_rejects(&normalize_output, &json!({"routing": "group"}))?;

        let projection_output =
            operation_schema(&manifest, "gateway_project_event", "output_schema")?;
        assert_schema_accepts(
            &projection_output,
            &json!({
                "accepted": true,
                "topic": EVENT_QQ_MESSAGE_AUTHORIZED,
                "reason_code": "accepted",
                "sequence": 1,
                "event_id": "evt-1",
                "normalized": sample_normalized_event(),
                "policy": sample_policy_decision(),
                "runtime": sample_runtime_snapshot()
            }),
        )?;
        assert_schema_accepts(
            &projection_output,
            &json!({
                "accepted": false,
                "topic": EVENT_QQ_EVENT_DROPPED,
                "reason_code": "heartbeat_ack",
                "sequence": null,
                "event_id": null,
                "normalized": null,
                "policy": null,
                "runtime": sample_runtime_snapshot()
            }),
        )?;
        assert_schema_rejects(
            &projection_output,
            &json!({
                "accepted": false,
                "topic": "qq.unsupported",
                "reason_code": "heartbeat_ack",
                "sequence": null,
                "event_id": null,
                "normalized": null,
                "policy": null,
                "runtime": sample_runtime_snapshot()
            }),
        )?;

        Ok(())
    }

    #[test]
    fn manifest_declares_strict_per_operation_network_constraints() -> Result<(), String> {
        let manifest = qq_manifest()?;
        let operations = manifest_operations(&manifest)?;
        let api_operations = [
            "messages_send_channel",
            "messages_send_group",
            "messages_send_c2c",
            "gateway_get",
            "health",
        ];
        let local_only_operations = ["events_normalize", "gateway_project_event"];

        for operation_key in api_operations {
            let constraints = operation_network_constraints(&manifest, operation_key)?;
            assert_eq!(
                string_array(constraints, "host_allow")?,
                vec!["api.sgroup.qq.com".to_owned(), "bots.qq.com".to_owned()],
                "{operation_key} should only allow QQ API and token hosts"
            );
            assert_eq!(integer_array(constraints, "port_allow")?, vec![443]);
            assert_eq!(constraints["require_sni"].as_bool(), Some(true));
            assert_eq!(constraints["deny_localhost"].as_bool(), Some(true));
            assert_eq!(constraints["deny_private_ranges"].as_bool(), Some(true));
            assert_eq!(constraints["deny_tailnet_ranges"].as_bool(), Some(true));
            assert_eq!(constraints["deny_ip_literals"].as_bool(), Some(true));
            assert_eq!(
                constraints["require_host_canonicalization"].as_bool(),
                Some(true)
            );
            assert_eq!(constraints["dns_max_ips"].as_integer(), Some(16));
            assert_eq!(constraints["max_redirects"].as_integer(), Some(0));
            assert_eq!(constraints["connect_timeout_ms"].as_integer(), Some(10_000));
            assert_eq!(constraints["total_timeout_ms"].as_integer(), Some(30_000));
            assert_eq!(
                constraints["max_response_bytes"].as_integer(),
                Some(1_048_576)
            );
        }

        for operation_key in local_only_operations {
            let constraints = operation_network_constraints(&manifest, operation_key)?;
            assert_eq!(
                string_array(constraints, "host_allow")?,
                vec!["none.invalid".to_owned()],
                "{operation_key} should use the no-egress sentinel"
            );
            assert_eq!(integer_array(constraints, "port_allow")?, vec![0]);
            assert_eq!(constraints["require_sni"].as_bool(), Some(false));
            assert_eq!(constraints["deny_localhost"].as_bool(), Some(true));
            assert_eq!(constraints["deny_private_ranges"].as_bool(), Some(true));
            assert_eq!(constraints["deny_tailnet_ranges"].as_bool(), Some(true));
            assert_eq!(constraints["deny_ip_literals"].as_bool(), Some(true));
            assert_eq!(
                constraints["require_host_canonicalization"].as_bool(),
                Some(true)
            );
            assert_eq!(constraints["dns_max_ips"].as_integer(), Some(0));
            assert_eq!(constraints["max_redirects"].as_integer(), Some(0));
            assert_eq!(constraints["connect_timeout_ms"].as_integer(), Some(1_000));
            assert_eq!(constraints["total_timeout_ms"].as_integer(), Some(30_000));
            assert_eq!(
                constraints["max_response_bytes"].as_integer(),
                Some(1_048_576)
            );
        }

        for (operation_key, operation) in operations {
            assert!(
                operation
                    .as_table()
                    .and_then(|table| table.get("network_constraints"))
                    .is_some(),
                "{operation_key} should declare per-operation network_constraints"
            );
        }

        Ok(())
    }

    #[test]
    fn manifest_hash_is_stable() {
        let a = QqConnector::manifest_hash();
        let b = QqConnector::manifest_hash();
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn doctor_unconfigured_fails_critical() {
        let connector = QqConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
        assert_eq!(result.checks.len(), 4);
        // configuration is critical, should fail
        assert!(!result.checks[0].passed);
        assert!(result.checks[0].critical);
    }

    #[fcp_async_core::runtime::test]
    async fn health_starting_when_unconfigured() {
        let connector = QqConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Starting));
        assert!(health.details.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn health_ready_when_configured() {
        let mut connector = QqConnector::new();
        let config = serde_json::json!({
            "app_id": "test-app",
            "client_secret": "test-secret",
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999"
        });
        connector.configure(config).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
        assert!(health.details.is_some());
        let details = health.details.unwrap();
        assert_eq!(details["app_id"], "test-app");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_without_config_reports_failed() {
        let connector = QqConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_ne!(report.status, fcp_core::SelfCheckStatus::Ok);
    }

    #[fcp_async_core::runtime::test]
    async fn configure_validates_empty_app_id() {
        let mut connector = QqConnector::new();
        let config = serde_json::json!({
            "app_id": "",
            "client_secret": "test-secret",
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999"
        });
        let err = connector.configure(config).await;
        assert!(err.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_validates_bad_host() {
        let mut connector = QqConnector::new();
        let config = serde_json::json!({
            "app_id": "test-app",
            "client_secret": "test-secret",
            "base_url": "https://evil.example.com",
            "token_base_url": "http://localhost:9999"
        });
        let err = connector.configure(config).await;
        assert!(err.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_base_url_query_and_fragment() {
        let mut connector = QqConnector::new();
        let query = serde_json::json!({
            "app_id": "test-app",
            "client_secret": "test-secret",
            "base_url": "https://api.sgroup.qq.com/api?trace=1",
            "token_base_url": "http://localhost:9999"
        });
        let err = connector.configure(query).await.unwrap_err().to_string();
        assert!(err.contains("must not include a query string"));

        let fragment = serde_json::json!({
            "app_id": "test-app",
            "client_secret": "test-secret",
            "base_url": "https://api.sgroup.qq.com/api#fragment",
            "token_base_url": "http://localhost:9999"
        });
        let err = connector.configure(fragment).await.unwrap_err().to_string();
        assert!(err.contains("must not include a fragment"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_token_base_url_userinfo() {
        let mut connector = QqConnector::new();
        let config = serde_json::json!({
            "app_id": "test-app",
            "client_secret": "test-secret",
            "base_url": "http://localhost:9999",
            "token_base_url": "https://bot:secret@bots.qq.com/oauth2/token"
        });
        let err = connector.configure(config).await.unwrap_err().to_string();
        assert!(err.contains("must not include userinfo"));
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_state() {
        let mut connector = QqConnector::new();
        let config = serde_json::json!({
            "app_id": "test-app",
            "client_secret": "test-secret",
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999"
        });
        connector.configure(config).await.unwrap();
        assert!(connector.client.is_some());

        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 5000,
                drain: false,
                reason: Some("test".into()),
            })
            .await
            .unwrap();
        assert!(connector.client.is_none());
        assert!(connector.verifier.is_none());
    }

    #[test]
    fn doctor_configured_passes_critical() {
        let mut connector = QqConnector::new();
        // Manually configure via direct field assignment to avoid async
        let config = QqConfig {
            base_url: "http://localhost:9999".into(),
            token_base_url: "http://localhost:9999".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
            gateway: crate::types::QqGatewayRuntimeConfig::default(),
        };
        connector.client = Some(QqClient::new(config).unwrap());
        let result = connector.doctor();
        assert!(result.passed);
        // handshake check is non-critical, so overall passes
        assert!(!result.checks[3].passed);
        assert!(!result.checks[3].critical);
    }

    #[test]
    fn required_capability_known_ops() {
        assert!(required_capability(OP_SEND_CHANNEL).is_ok());
        assert!(required_capability(OP_SEND_GROUP).is_ok());
        assert!(required_capability(OP_SEND_C2C).is_ok());
        assert!(required_capability(OP_GET_GATEWAY).is_ok());
        assert!(required_capability(OP_HEALTH).is_ok());
        assert!(required_capability(OP_EVENTS_NORMALIZE).is_ok());
        assert!(required_capability(OP_GATEWAY_PROJECT_EVENT).is_ok());
    }

    #[test]
    fn required_capability_unknown_op() {
        let err = required_capability("qq.unknown").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_send_channel_missing_content_denied() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = ready_connector(&signing_key).await;
        let response = connector
            .simulate(simulate_request(
                &signing_key,
                &connector.base.instance_id,
                CAP_MESSAGES_WRITE,
                OP_SEND_CHANNEL,
                json!({"channel_id": "channel-1"}),
            ))
            .await
            .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-1005"));
        assert!(
            response
                .failure_reason
                .as_deref()
                .unwrap_or_default()
                .contains("content")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_send_group_rejects_path_traversal_target() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = ready_connector(&signing_key).await;
        let response = connector
            .simulate(simulate_request(
                &signing_key,
                &connector.base.instance_id,
                CAP_MESSAGES_WRITE,
                OP_SEND_GROUP,
                json!({"group_openid": "../admin", "content": "hello"}),
            ))
            .await
            .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-1005"));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_send_channel_valid_input_allowed() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = ready_connector(&signing_key).await;
        let response = connector
            .simulate(simulate_request(
                &signing_key,
                &connector.base.instance_id,
                CAP_MESSAGES_WRITE,
                OP_SEND_CHANNEL,
                json!({"channel_id": "channel-1", "content": "hello"}),
            ))
            .await
            .unwrap();

        assert!(response.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_events_normalize_missing_event_denied() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = ready_connector(&signing_key).await;
        let response = connector
            .simulate(simulate_request(
                &signing_key,
                &connector.base.instance_id,
                CAP_EVENTS_READ,
                OP_EVENTS_NORMALIZE,
                json!({}),
            ))
            .await
            .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-1005"));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_gateway_project_event_allows_control_frames() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = ready_connector(&signing_key).await;
        let response = connector
            .simulate(simulate_request(
                &signing_key,
                &connector.base.instance_id,
                CAP_EVENTS_READ,
                OP_GATEWAY_PROJECT_EVENT,
                json!({"event": {"op": 10, "d": {"session_id": "session-1"}}}),
            ))
            .await
            .unwrap();

        assert!(response.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_gateway_project_event_allows_non_message_dispatch_drops() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = ready_connector(&signing_key).await;
        let response = connector
            .simulate(simulate_request(
                &signing_key,
                &connector.base.instance_id,
                CAP_EVENTS_READ,
                OP_GATEWAY_PROJECT_EVENT,
                json!({"event": {"op": 0, "s": 1, "t": "READY", "d": {}, "id": "evt-ready"}}),
            ))
            .await
            .unwrap();

        assert!(response.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_gateway_project_event_rejects_malformed_dispatch() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = ready_connector(&signing_key).await;
        let response = connector
            .simulate(simulate_request(
                &signing_key,
                &connector.base.instance_id,
                CAP_EVENTS_READ,
                OP_GATEWAY_PROJECT_EVENT,
                json!({"event": {"op": 0, "s": 1, "d": {}, "id": "evt-missing-type"}}),
            ))
            .await
            .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-1005"));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_events_normalize_still_denies_control_frames() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = ready_connector(&signing_key).await;
        let response = connector
            .simulate(simulate_request(
                &signing_key,
                &connector.base.instance_id,
                CAP_EVENTS_READ,
                OP_EVENTS_NORMALIZE,
                json!({"event": {"op": 10, "d": {"session_id": "session-1"}}}),
            ))
            .await
            .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-1005"));
    }

    #[test]
    fn granted_capabilities_filters_known() {
        let requested = vec![
            CapabilityId::from_static(CAP_MESSAGES_WRITE),
            CapabilityId::from_static(CAP_GATEWAY_READ),
            CapabilityId::from_static(CAP_EVENTS_READ),
            CapabilityId::from_static("qq.unknown.cap"),
        ];
        let granted = granted_capabilities(requested);
        assert_eq!(granted.len(), 3);
    }

    #[test]
    fn required_string_extracts_value() {
        let val = serde_json::json!({"key": "value"});
        assert_eq!(required_string(&val, "key").unwrap(), "value");
    }

    #[test]
    fn required_string_rejects_empty() {
        let val = serde_json::json!({"key": ""});
        assert!(required_string(&val, "key").is_err());
    }

    #[test]
    fn required_string_rejects_missing() {
        let val = serde_json::json!({});
        assert!(required_string(&val, "key").is_err());
    }

    #[test]
    fn required_string_rejects_whitespace_only() {
        let val = serde_json::json!({"key": "   "});
        assert!(required_string(&val, "key").is_err());
    }

    #[test]
    fn message_path_uses_validated_target_id() {
        assert_eq!(
            message_path("/channels/", "channel-42", "channel_id").unwrap(),
            "/channels/channel-42/messages"
        );
        assert_eq!(
            message_path("/v2/groups/", "group-42", "group_openid").unwrap(),
            "/v2/groups/group-42/messages"
        );
        assert_eq!(
            message_path("/v2/users/", "user-42", "openid").unwrap(),
            "/v2/users/user-42/messages"
        );
    }

    #[test]
    fn message_path_rejects_traversal_targets() {
        assert!(message_path("/channels/", "../admin", "channel_id").is_err());
        assert!(message_path("/v2/groups/", "group/other", "group_openid").is_err());
        assert!(message_path("/v2/users/", "user%2Fother", "openid").is_err());
    }

    #[test]
    fn optional_string_rejects_non_string_values() {
        let err = optional_string(&serde_json::json!({"msg_id": 7}), "msg_id").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        assert!(err.to_string().contains("msg_id must be a string"));
    }

    #[test]
    fn optional_string_trims_blank_values_to_none() {
        assert_eq!(
            optional_string(&serde_json::json!({"msg_id": "   "}), "msg_id").unwrap(),
            None
        );
        assert_eq!(
            optional_string(&serde_json::json!({"msg_id": " abc-123 "}), "msg_id").unwrap(),
            Some("abc-123")
        );
    }

    #[test]
    fn streaming_not_supported() {
        // The connector does not support streaming (subscribe/unsubscribe return StreamingNotSupported).
        // Verified via event_caps: streaming=false, replay=false.
        let connector = QqConnector::new();
        let intro = connector.introspect();
        let caps = intro.event_caps.unwrap();
        assert!(!caps.streaming);
        assert!(!caps.replay);
    }

    #[test]
    fn event_caps_disabled() {
        let connector = QqConnector::new();
        let intro = connector.introspect();
        let caps = intro.event_caps.unwrap();
        assert!(!caps.streaming);
        assert!(!caps.replay);
        assert!(!caps.requires_ack);
        assert_eq!(caps.min_buffer_events, 0);
    }

    #[test]
    fn operations_have_correct_capabilities() {
        let ops = QqConnector::operations();
        let send_ops: Vec<_> = ops
            .iter()
            .filter(|op| op.id.as_str().starts_with("qq.messages."))
            .collect();
        for op in &send_ops {
            assert_eq!(op.capability.as_str(), CAP_MESSAGES_WRITE);
            assert_eq!(op.safety_tier, SafetyTier::Risky);
            assert_eq!(op.risk_level, RiskLevel::Medium);
        }
        let gateway = ops
            .iter()
            .find(|op| op.id.as_str() == OP_GET_GATEWAY)
            .unwrap();
        assert_eq!(gateway.capability.as_str(), CAP_GATEWAY_READ);
        assert_eq!(gateway.safety_tier, SafetyTier::Safe);

        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.capability.as_str(), CAP_HEALTH_READ);
        assert_eq!(health.safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn operations_have_agent_hints() {
        let ops = QqConnector::operations();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
            assert!(!op.ai_hints.common_mistakes.is_empty());
        }
    }

    #[test]
    fn metrics_initial_state() {
        let connector = QqConnector::new();
        let metrics = connector.metrics();
        assert_eq!(metrics.requests_total, 0);
        assert_eq!(metrics.requests_error, 0);
    }

    #[test]
    fn events_normalize_operation_has_correct_properties() {
        let ops = QqConnector::operations();
        let normalize_op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_EVENTS_NORMALIZE)
            .expect("events.normalize operation should exist");
        assert_eq!(normalize_op.capability.as_str(), CAP_EVENTS_READ);
        assert_eq!(normalize_op.safety_tier, SafetyTier::Safe);
        assert_eq!(normalize_op.risk_level, RiskLevel::Low);
        assert_eq!(normalize_op.idempotency, IdempotencyClass::Strict);
        assert!(!normalize_op.ai_hints.when_to_use.is_empty());
    }

    #[test]
    fn events_normalize_capability_maps_correctly() {
        let cap = required_capability(OP_EVENTS_NORMALIZE).unwrap();
        assert_eq!(cap.as_str(), CAP_EVENTS_READ);
    }
}
