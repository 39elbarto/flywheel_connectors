//! `Synology Chat` connector implementation.

use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_sdk::prelude::*;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::client::{
    SynologyChatClient, SynologyChatFileUrlRequest, SynologyChatMessageRequest,
    SynologyChatPayload, normalize_inbound_event,
};
use crate::types::{
    InboundWebhookPayload, SynologyChatConfig, SynologyChatDmPolicy, SynologyChatStateModel,
    TokenVerification,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "synology_chat.read";
const CAP_WRITE: &str = "synology_chat.write";
const CAP_WEBHOOK: &str = "synology_chat.webhook";
const OP_SEND_MESSAGE: &str = "synology_chat.send_message";
const OP_SEND_FILE_URL: &str = "synology_chat.send_file_url";
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
    ingress_rate: Mutex<SynologyChatIngressRateState>,
}

#[derive(Debug, Default)]
struct SynologyChatIngressRateState {
    buckets: BTreeMap<String, RateBucket>,
}

#[derive(Debug, Clone)]
struct RateBucket {
    window_started: Instant,
    count: u32,
}

impl SynologyChatIngressRateState {
    fn check(&mut self, key: &str, limit: u32, now: Instant) -> bool {
        const WINDOW: Duration = Duration::from_secs(60);

        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| RateBucket {
                window_started: now,
                count: 0,
            });
        if now.duration_since(bucket.window_started) >= WINDOW {
            bucket.window_started = now;
            bucket.count = 0;
        }
        bucket.count = bucket.count.saturating_add(1);
        bucket.count <= limit
    }
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
            checks.push(DoctorCheck {
                name: "raw_payload_file_url_policy".into(),
                passed: true,
                message:
                    "send_payload remains raw passthrough; use send_file_url for SSRF-checked media URLs"
                        .into(),
                critical: false,
            });
        }

        DoctorResult::new(checks)
    }

    #[must_use]
    pub const fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn nonblank_string_schema() -> Value {
        json!({
            "type": "string",
            "minLength": 1
        })
    }

    fn optional_string_schema() -> Value {
        json!({ "type": "string" })
    }

    fn string_array_schema() -> Value {
        json!({
            "type": "array",
            "items": Self::nonblank_string_schema()
        })
    }

    fn string_or_integer_schema() -> Value {
        json!({ "type": ["string", "integer"] })
    }

    fn nonnegative_integer_schema() -> Value {
        json!({
            "type": "integer",
            "minimum": 0
        })
    }

    fn empty_input_schema() -> Value {
        json!({
            "type": "object",
            "additionalProperties": false,
            "maxProperties": 0
        })
    }

    fn send_message_input_schema() -> Value {
        json!({
            "type": "object",
            "required": ["text"],
            "additionalProperties": false,
            "properties": {
                "text": Self::nonblank_string_schema(),
                "user_id": Self::optional_string_schema(),
                "user_ids": Self::string_array_schema(),
                "bot_name": Self::optional_string_schema()
            }
        })
    }

    fn send_file_url_input_schema() -> Value {
        json!({
            "type": "object",
            "required": ["file_url"],
            "additionalProperties": false,
            "properties": {
                "file_url": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2048,
                    "description": "HTTP or HTTPS media URL for Synology Chat to fetch"
                },
                "user_id": Self::optional_string_schema(),
                "user_ids": Self::string_array_schema(),
                "bot_name": Self::optional_string_schema()
            }
        })
    }

    fn send_payload_input_schema() -> Value {
        json!({
            "type": "object",
            "required": ["payload"],
            "additionalProperties": false,
            "properties": {
                "payload": { "type": "object" }
            }
        })
    }

    fn outgoing_webhook_payload_schema() -> Value {
        json!({
            "type": "object",
            "required": [
                "channel_id",
                "channel_type",
                "user_id",
                "username",
                "post_id",
                "thread_id",
                "timestamp",
                "text"
            ],
            "additionalProperties": true,
            "properties": {
                "token": Self::nonblank_string_schema(),
                "channel_id": Self::string_or_integer_schema(),
                "channel_type": Self::string_or_integer_schema(),
                "channel_name": Self::optional_string_schema(),
                "user_id": Self::string_or_integer_schema(),
                "username": Self::nonblank_string_schema(),
                "post_id": Self::string_or_integer_schema(),
                "thread_id": Self::string_or_integer_schema(),
                "timestamp": {
                    "type": ["string", "integer"],
                    "minimum": 0
                },
                "text": Self::nonblank_string_schema(),
                "trigger_word": Self::optional_string_schema(),
                "file_url": Self::optional_string_schema(),
                "attachments": { "type": "array" },
                "files": { "type": "array" },
                "file": {}
            }
        })
    }

    fn ingest_outgoing_webhook_input_schema() -> Value {
        json!({
            "type": "object",
            "required": ["payload"],
            "additionalProperties": false,
            "properties": {
                "payload": Self::outgoing_webhook_payload_schema(),
                "token": Self::nonblank_string_schema(),
                "headers": { "type": "object" },
                "query": { "type": "object" },
                "body_size_bytes": Self::nonnegative_integer_schema(),
                "body_read_elapsed_ms": Self::nonnegative_integer_schema(),
                "source_id": Self::optional_string_schema(),
                "delivery_id": Self::optional_string_schema()
            }
        })
    }

    fn webhook_normalize_input_schema() -> Value {
        json!({
            "type": "object",
            "required": ["payload"],
            "additionalProperties": false,
            "properties": {
                "payload": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "user_id": {},
                        "username": Self::optional_string_schema(),
                        "post_id": {},
                        "channel_id": {},
                        "channel_name": Self::optional_string_schema(),
                        "channel_type": {},
                        "text": Self::optional_string_schema(),
                        "timestamp": {},
                        "token": Self::optional_string_schema(),
                        "trigger_word": Self::optional_string_schema(),
                        "thread_id": {},
                        "file_url": Self::optional_string_schema()
                    }
                }
            }
        })
    }

    fn dispatch_output_schema() -> Value {
        json!({
            "type": "object",
            "required": ["status", "http_status", "response_kind"],
            "additionalProperties": true,
            "properties": {
                "status": { "enum": ["ok"] },
                "http_status": {
                    "type": "integer",
                    "minimum": 100,
                    "maximum": 599
                },
                "response_kind": {
                    "type": "string",
                    "enum": ["empty", "json", "text"]
                },
                "body": {},
                "raw_body": { "type": "string" }
            }
        })
    }

    fn file_url_policy_output_schema() -> Value {
        json!({
            "type": "object",
            "required": [
                "decision",
                "classification",
                "scheme",
                "host",
                "resolved_ip_count",
                "allowlisted_host"
            ],
            "additionalProperties": false,
            "properties": {
                "decision": { "type": "string" },
                "classification": { "type": "string" },
                "scheme": { "type": "string" },
                "host": { "type": "string" },
                "port": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535
                },
                "resolved_ip_count": Self::nonnegative_integer_schema(),
                "allowlisted_host": { "type": "boolean" }
            }
        })
    }

    fn send_file_url_output_schema() -> Value {
        json!({
            "type": "object",
            "required": ["status", "http_status", "response_kind", "file_url_policy"],
            "additionalProperties": true,
            "properties": {
                "status": { "enum": ["ok"] },
                "http_status": {
                    "type": "integer",
                    "minimum": 100,
                    "maximum": 599
                },
                "response_kind": {
                    "type": "string",
                    "enum": ["empty", "json", "text"]
                },
                "body": {},
                "raw_body": { "type": "string" },
                "file_url_policy": Self::file_url_policy_output_schema()
            }
        })
    }

    fn outgoing_webhook_event_schema() -> Value {
        json!({
            "type": "object",
            "required": [
                "topic",
                "event_type",
                "delivery_id",
                "resource_uri",
                "channel",
                "thread",
                "sender",
                "message",
                "attachments",
                "reply",
                "ingress_policy"
            ],
            "additionalProperties": true,
            "properties": {
                "topic": { "enum": ["synology_chat.outgoing_webhook.received"] },
                "event_type": { "enum": ["outgoing_webhook"] },
                "delivery_id": Self::nonblank_string_schema(),
                "resource_uri": Self::nonblank_string_schema(),
                "channel": {
                    "type": "object",
                    "required": ["id", "type", "resource_uri"],
                    "additionalProperties": true
                },
                "thread": {
                    "type": "object",
                    "required": ["id", "resource_uri", "is_threaded"],
                    "additionalProperties": true
                },
                "sender": {
                    "type": "object",
                    "required": ["user_id", "username", "resource_uri"],
                    "additionalProperties": true
                },
                "message": {
                    "type": "object",
                    "required": ["post_id", "text", "sanitized_text", "timestamp_ms"],
                    "additionalProperties": true
                },
                "attachments": { "type": "array" },
                "reply": {
                    "type": "object",
                    "required": ["mode", "supports_text", "supports_file_url"],
                    "additionalProperties": true
                },
                "ingress_policy": {
                    "type": "object",
                    "required": [
                        "mode",
                        "hosted_listener",
                        "token_source",
                        "token_verification",
                        "body",
                        "sender",
                        "dm",
                        "rate_limit",
                        "sanitization",
                        "source_hash",
                        "raw_payload_logged"
                    ],
                    "additionalProperties": true
                }
            }
        })
    }

    fn ingest_outgoing_webhook_output_schema() -> Value {
        json!({
            "type": "object",
            "required": ["event"],
            "additionalProperties": false,
            "properties": {
                "event": Self::outgoing_webhook_event_schema()
            }
        })
    }

    fn normalized_inbound_event_schema() -> Value {
        json!({
            "type": "object",
            "required": [
                "event_type",
                "channel_id",
                "channel_name",
                "sender_id",
                "sender_name",
                "text",
                "timestamp",
                "trigger_word",
                "is_threaded",
                "thread_id",
                "file_url",
                "token_verified",
                "raw"
            ],
            "additionalProperties": true,
            "properties": {
                "event_type": { "enum": ["inbound_webhook"] },
                "channel_id": { "type": ["string", "null"] },
                "channel_name": { "type": ["string", "null"] },
                "sender_id": { "type": ["string", "null"] },
                "sender_name": { "type": ["string", "null"] },
                "text": { "type": ["string", "null"] },
                "timestamp": { "type": ["string", "null"] },
                "trigger_word": { "type": ["string", "null"] },
                "is_threaded": { "type": "boolean" },
                "thread_id": { "type": ["string", "null"] },
                "file_url": { "type": ["string", "null"] },
                "token_verified": { "type": ["boolean", "null"] },
                "raw": {}
            }
        })
    }

    fn webhook_normalize_output_schema() -> Value {
        json!({
            "type": "object",
            "required": ["event", "token_verification"],
            "additionalProperties": false,
            "properties": {
                "event": Self::normalized_inbound_event_schema(),
                "token_verification": {
                    "type": "string",
                    "enum": [
                        "verified",
                        "mismatch",
                        "missing_from_payload",
                        "not_configured"
                    ]
                }
            }
        })
    }

    fn health_output_schema() -> Value {
        json!({
            "type": "object",
            "required": [
                "status",
                "delivery_target",
                "request_timeout_ms",
                "allow_insecure_ssl",
                "outgoing_token_configured",
                "allowed_file_url_hosts",
                "forwarded_ingress_policy",
                "raw_payload_file_url_policy",
                "receive_path",
                "reply_semantics",
                "manifest_hash"
            ],
            "additionalProperties": true,
            "properties": {
                "status": { "enum": ["ok"] },
                "delivery_target": {
                    "type": "object",
                    "required": [
                        "mode",
                        "scheme",
                        "host",
                        "origin",
                        "path_hint",
                        "incoming_url_redacted"
                    ],
                    "additionalProperties": true,
                    "properties": {
                        "mode": { "enum": ["incoming_webhook"] },
                        "scheme": { "type": "string" },
                        "host": { "type": "string" },
                        "port": {
                            "type": ["integer", "null"],
                            "minimum": 1,
                            "maximum": 65535
                        },
                        "origin": { "type": "string" },
                        "path_hint": { "type": "string" },
                        "incoming_url_redacted": { "type": "string" }
                    }
                },
                "request_timeout_ms": Self::nonnegative_integer_schema(),
                "allow_insecure_ssl": { "type": "boolean" },
                "outgoing_token_configured": { "type": "boolean" },
                "allowed_file_url_hosts": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "forwarded_ingress_policy": {
                    "type": "object",
                    "required": [
                        "sender_policy",
                        "allowed_sender_ids",
                        "dm_policy",
                        "allowed_dm_sender_ids",
                        "body_limit_bytes",
                        "body_timeout_ms",
                        "invalid_token_limit_per_minute",
                        "sender_limit_per_minute",
                        "hosted_listener",
                        "reply_user_id_resolution"
                    ],
                    "additionalProperties": true
                },
                "raw_payload_file_url_policy": { "enum": ["unchecked_passthrough"] },
                "receive_path": {
                    "type": "string",
                    "enum": ["disabled", "forwarded_outgoing_webhook"]
                },
                "reply_semantics": {
                    "type": "string",
                    "enum": ["outbound_only", "outgoing_webhook_response"]
                },
                "manifest_hash": { "type": "string" }
            }
        })
    }

    fn input_schema_for(operation: &str) -> Value {
        match operation {
            OP_SEND_MESSAGE => Self::send_message_input_schema(),
            OP_SEND_FILE_URL => Self::send_file_url_input_schema(),
            OP_SEND_PAYLOAD => Self::send_payload_input_schema(),
            OP_INGEST_OUTGOING_WEBHOOK => Self::ingest_outgoing_webhook_input_schema(),
            OP_WEBHOOK_NORMALIZE => Self::webhook_normalize_input_schema(),
            OP_HEALTH => Self::empty_input_schema(),
            _ => json!({ "type": "object" }),
        }
    }

    fn output_schema_for(operation: &str) -> Value {
        match operation {
            OP_SEND_MESSAGE | OP_SEND_PAYLOAD => Self::dispatch_output_schema(),
            OP_SEND_FILE_URL => Self::send_file_url_output_schema(),
            OP_INGEST_OUTGOING_WEBHOOK => Self::ingest_outgoing_webhook_output_schema(),
            OP_WEBHOOK_NORMALIZE => Self::webhook_normalize_output_schema(),
            OP_HEALTH => Self::health_output_schema(),
            _ => json!({ "type": "object" }),
        }
    }

    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        vec![
            OperationInfo {
                id: OperationId::from_static(OP_SEND_MESSAGE),
                summary: "Send a Synology Chat message".into(),
                description: Some("Deliver a message through a Synology Chat incoming webhook.".into()),
                input_schema: Self::input_schema_for(OP_SEND_MESSAGE),
                output_schema: Self::output_schema_for(OP_SEND_MESSAGE),
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
                    related: vec![CapabilityId::from_static(CAP_READ)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEND_FILE_URL),
                summary: "Send a Synology Chat file URL".into(),
                description: Some("Validate a media or file URL with the connector SSRF policy, then deliver it through the configured Synology Chat incoming webhook.".into()),
                input_schema: Self::input_schema_for(OP_SEND_FILE_URL),
                output_schema: Self::output_schema_for(OP_SEND_FILE_URL),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use this for outbound Synology Chat media or file URL sends; it rejects credentials, fragments, private/internal destinations, and DNS pin bypasses unless the exact host is configured as an override.".into(),
                    common_mistakes: vec![
                        "Do not use send_payload for file_url unless you intentionally need unchecked provider-specific passthrough.".into(),
                        "Private NAS or loopback media hosts must appear in allowed_file_url_hosts exactly.".into(),
                    ],
                    examples: vec!["{\"file_url\":\"https://cdn.example.com/report.pdf\",\"user_id\":\"4\"}".into()],
                    related: vec![CapabilityId::from_static(CAP_WRITE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEND_PAYLOAD),
                summary: "Send a raw Synology Chat webhook payload".into(),
                description: Some("Forward an arbitrary JSON object to a Synology Chat incoming webhook for advanced card or attachment use cases. Raw passthrough is intentionally not inspected for nested file_url fields; use synology_chat.send_file_url when the connector should enforce media URL SSRF policy.".into()),
                input_schema: Self::input_schema_for(OP_SEND_PAYLOAD),
                output_schema: Self::output_schema_for(OP_SEND_PAYLOAD),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use this when the simple text operation is too limited and you need to pass a Synology Chat webhook payload through directly.".into(),
                    common_mistakes: vec![
                        "payload must be a JSON object that the Synology Chat webhook endpoint understands.".into(),
                        "Nested file_url values are raw passthrough and are not SSRF-checked; use synology_chat.send_file_url for checked media sends.".into()
                    ],
                    examples: vec!["{\"payload\":{\"text\":\"Hello\",\"attachments\":[{\"text\":\"Details\"}]}}".into()],
                    related: vec![CapabilityId::from_static(CAP_WRITE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_INGEST_OUTGOING_WEBHOOK),
                summary: "Policy-check and normalize a forwarded Synology Chat outgoing-webhook payload"
                    .into(),
                description: Some(
                    "Apply forwarded body budgets, token alias verification, sender/DM/rate policy, and text sanitization before normalizing a host-forwarded Synology Chat outgoing-webhook payload into a stable event envelope without pretending this connector hosts the listener.".into(),
                ),
                input_schema: Self::input_schema_for(OP_INGEST_OUTGOING_WEBHOOK),
                output_schema: Self::output_schema_for(OP_INGEST_OUTGOING_WEBHOOK),
                capability: CapabilityId::from_static(CAP_WEBHOOK),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this when fcp-host forwards a Synology Chat outgoing-webhook payload and you need channel, thread, sender, attachment, reply, and policy metadata in a stable shape.".into(),
                    common_mistakes: vec![
                        "Passing the raw form-encoded HTTP body instead of the parsed payload object".into(),
                        "Calling this operation without configuring outgoing_token first".into(),
                        "Logging raw source_id, token, or message text instead of the returned policy hashes and sanitization flags".into(),
                    ],
                    examples: vec![
                        "{\"payload\":{\"token\":\"shared-secret\",\"channel_id\":\"34\",\"channel_type\":\"1\",\"channel_name\":\"Labb\",\"user_id\":\"4\",\"username\":\"mikael\",\"post_id\":\"146028888128\",\"thread_id\":\"0\",\"timestamp\":\"1646827836131\",\"text\":\"Tjena\",\"trigger_word\":\"Tjena\"}}".into(),
                        "{\"payload\":{\"channel_id\":\"34\",\"channel_type\":\"1\",\"user_id\":\"4\",\"username\":\"mikael\",\"post_id\":\"146028888128\",\"thread_id\":\"0\",\"timestamp\":\"1646827836131\",\"text\":\"Tjena\"},\"headers\":{\"Authorization\":\"Bearer shared-secret\"},\"body_size_bytes\":512}".into(),
                    ],
                    related: vec![
                        CapabilityId::from_static(CAP_READ),
                        CapabilityId::from_static(CAP_WRITE),
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
                input_schema: Self::input_schema_for(OP_WEBHOOK_NORMALIZE),
                output_schema: Self::output_schema_for(OP_WEBHOOK_NORMALIZE),
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
                        CapabilityId::from_static(CAP_WEBHOOK),
                        CapabilityId::from_static(CAP_READ),
                    ],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_HEALTH),
                summary: "Report connector health".into(),
                description: Some("Return configured webhook target details.".into()),
                input_schema: Self::input_schema_for(OP_HEALTH),
                output_schema: Self::output_schema_for(OP_HEALTH),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this before attempting outbound delivery.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(CAP_WRITE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let required_cap = required_capability(req.operation.as_str())?;
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;
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
            OP_SEND_FILE_URL => {
                let file_url = req
                    .input
                    .get("file_url")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing file_url".into(),
                    })?;
                let user_ids = optional_user_ids(&req.input)?;
                let bot_name = req.input.get("bot_name").and_then(|value| value.as_str());
                let request = SynologyChatFileUrlRequest::new(file_url, &user_ids, bot_name)
                    .map_err(|error| error.to_fcp_error())?;
                let (dispatch, audit) = state
                    .client
                    .send_file_url(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let mut output = dispatch.into_json();
                let audit = serde_json::to_value(audit).map_err(|error| FcpError::Internal {
                    message: format!("Failed to serialize file URL policy audit: {error}"),
                })?;
                if let Some(object) = output.as_object_mut() {
                    object.insert("file_url_policy".into(), audit);
                }
                output
            }
            OP_INGEST_OUTGOING_WEBHOOK => normalize_outgoing_webhook(&req.input, state)?,
            OP_WEBHOOK_NORMALIZE => invoke_webhook_normalize(&req.input, state)?,
            OP_HEALTH => json!({
                "status": "ok",
                "delivery_target": &state.model.delivery_target,
                "request_timeout_ms": state.model.request_timeout_ms,
                "allow_insecure_ssl": state.model.allow_insecure_ssl,
                "outgoing_token_configured": state.model.outgoing_token_configured,
                "allowed_file_url_hosts": &state.model.allowed_file_url_hosts,
                "forwarded_ingress_policy": &state.model.forwarded_ingress_policy,
                "raw_payload_file_url_policy": "unchecked_passthrough",
                "receive_path": &state.model.receive_path,
                "reply_semantics": &state.model.reply_semantics,
                "manifest_hash": Self::manifest_hash(),
            }),
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
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
    let expected_webhook_key =
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

    let body_size_bytes = forwarded_body_size_bytes(input, payload)?;
    let body_read_elapsed_ms = forwarded_body_read_elapsed_ms(input)?;
    let policy = &state.model.forwarded_ingress_policy;
    if body_size_bytes > policy.body_limit_bytes {
        return Err(FcpError::ResourceExhausted {
            resource: format!(
                "synology_chat.forwarded_webhook_body:{body_size_bytes}>{}",
                policy.body_limit_bytes
            ),
        });
    }
    if body_read_elapsed_ms > policy.body_timeout_ms {
        return Err(FcpError::UpstreamTimeout {
            service: "synology_chat.forwarded_webhook_body_read".into(),
        });
    }

    let source_key = input
        .get("source_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown_forwarder");
    let presented_webhook_key = resolve_presented_webhook_token(input, payload)?;
    let Some(presented_webhook_key) = presented_webhook_key else {
        record_invalid_token_attempt(state, source_key)?;
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Outgoing webhook token is missing".into(),
        });
    };
    if !constant_time_secret_eq(expected_webhook_key, &presented_webhook_key.value) {
        record_invalid_token_attempt(state, source_key)?;
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
    let (sanitized_text, sanitization) = sanitize_ingress_text(&text);
    let trigger_word = optional_payload_string(payload, "trigger_word");
    let attachments = normalize_inbound_attachments(payload);
    let is_threaded = !matches!(thread_id.as_str(), "" | "0");
    let policy_decision = enforce_forwarded_ingress_policy(state, &user_id, &channel_type)?;

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
                "sanitized_text": sanitized_text,
                "trigger_word": &trigger_word,
                "timestamp_ms": timestamp_ms,
            },
            "attachments": attachments,
            "reply": {
                "mode": "outgoing_webhook_response",
                "supports_text": true,
                "supports_file_url": true,
                "user_id_resolution": {
                    "mode": "stable_webhook_user_id",
                    "dangerous_name_matching": false,
                    "source": "payload.user_id",
                },
                "audience": {
                    "user_id": &user_id,
                    "username": &username,
                },
            },
            "ingress_policy": {
                "mode": "host_forwarded",
                "hosted_listener": false,
                "token_source": presented_webhook_key.source,
                "token_verification": "verified",
                "body": {
                    "size_bytes": body_size_bytes,
                    "limit_bytes": policy.body_limit_bytes,
                    "read_elapsed_ms": body_read_elapsed_ms,
                    "timeout_ms": policy.body_timeout_ms,
                },
                "sender": policy_decision["sender"].clone(),
                "dm": policy_decision["dm"].clone(),
                "rate_limit": policy_decision["rate_limit"].clone(),
                "sanitization": sanitization,
                "source_hash": hash_identifier(source_key),
                "raw_payload_logged": false,
            },
        }
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PresentedWebhookToken {
    source: &'static str,
    value: String,
}

fn resolve_presented_webhook_token(
    input: &Value,
    payload: &Map<String, Value>,
) -> FcpResult<Option<PresentedWebhookToken>> {
    if payload.contains_key("token") {
        return Ok(Some(PresentedWebhookToken {
            source: "payload.token",
            value: required_payload_string(payload, "token")?,
        }));
    }
    if let Some(value) = optional_input_string(input, "token")? {
        return Ok(Some(PresentedWebhookToken {
            source: "input.token",
            value,
        }));
    }
    if let Some(value) = nested_input_string(input, "query", "token")? {
        return Ok(Some(PresentedWebhookToken {
            source: "query.token",
            value,
        }));
    }
    if let Some(value) = header_value(input, &["x-synology-chat-token", "x-synology-token"])? {
        return Ok(Some(PresentedWebhookToken {
            source: value.0,
            value: value.1,
        }));
    }
    if let Some(authorization) = header_value(input, &["authorization"])? {
        let Some(token) = authorization
            .1
            .strip_prefix("Bearer ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "headers.authorization must use Bearer token syntax".into(),
            });
        };
        return Ok(Some(PresentedWebhookToken {
            source: authorization.0,
            value: token.to_string(),
        }));
    }
    Ok(None)
}

fn optional_input_string(input: &Value, field: &str) -> FcpResult<Option<String>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    string_value(value)
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a non-empty string"),
        })
}

fn nested_input_string(
    input: &Value,
    object_field: &str,
    field: &str,
) -> FcpResult<Option<String>> {
    let Some(object) = input.get(object_field) else {
        return Ok(None);
    };
    let object = object.as_object().ok_or_else(|| FcpError::InvalidRequest {
        code: 1005,
        message: format!("{object_field} must be a JSON object"),
    })?;
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    string_value(value)
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{object_field}.{field} must be a non-empty string"),
        })
}

fn header_value(
    input: &Value,
    candidates: &[&'static str],
) -> FcpResult<Option<(&'static str, String)>> {
    let Some(headers) = input.get("headers") else {
        return Ok(None);
    };
    let headers = headers
        .as_object()
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "headers must be a JSON object".into(),
        })?;
    for candidate in candidates {
        if let Some((_, value)) = headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(candidate))
        {
            let presented_value = string_value(value).ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("headers.{candidate} must be a non-empty string"),
            })?;
            return Ok(Some((candidate, presented_value)));
        }
    }
    Ok(None)
}

fn forwarded_body_size_bytes(input: &Value, payload: &Map<String, Value>) -> FcpResult<u64> {
    if let Some(value) = input.get("body_size_bytes") {
        return value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "body_size_bytes must be a non-negative integer".into(),
        });
    }
    let serialized = serde_json::to_vec(payload).map_err(|error| FcpError::Internal {
        message: format!("Failed to measure forwarded payload size: {error}"),
    })?;
    u64::try_from(serialized.len()).map_err(|_| FcpError::ResourceExhausted {
        resource: "synology_chat.forwarded_webhook_body".into(),
    })
}

fn forwarded_body_read_elapsed_ms(input: &Value) -> FcpResult<u64> {
    input.get("body_read_elapsed_ms").map_or(Ok(0), |value| {
        value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "body_read_elapsed_ms must be a non-negative integer".into(),
        })
    })
}

fn record_invalid_token_attempt(state: &SynologyChatState, source_key: &str) -> FcpResult<()> {
    let key = format!("invalid_token:{}", hash_identifier(source_key));
    let limit = state
        .model
        .forwarded_ingress_policy
        .invalid_token_limit_per_minute;
    if check_rate_limit(state, &key, limit)? {
        Ok(())
    } else {
        Err(FcpError::RateLimited {
            retry_after_ms: 60_000,
            violation: None,
        })
    }
}

fn enforce_forwarded_ingress_policy(
    state: &SynologyChatState,
    user_id: &str,
    channel_type: &str,
) -> FcpResult<Value> {
    let policy = &state.model.forwarded_ingress_policy;
    let sender_allowed = policy.allowed_sender_ids.is_empty()
        || policy
            .allowed_sender_ids
            .iter()
            .any(|allowed| allowed == user_id);
    if !sender_allowed {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Outgoing webhook sender denied by allowlist policy".into(),
        });
    }

    let dm_decision = if is_dm_channel_type(channel_type) {
        match policy.dm_policy {
            SynologyChatDmPolicy::Disabled => {
                return Err(FcpError::Unauthorized {
                    code: 2001,
                    message: "Outgoing webhook direct-message events are disabled".into(),
                });
            }
            SynologyChatDmPolicy::Allowlist => {
                if !policy
                    .allowed_dm_sender_ids
                    .iter()
                    .any(|allowed| allowed == user_id)
                {
                    return Err(FcpError::Unauthorized {
                        code: 2001,
                        message: "Outgoing webhook DM sender denied by allowlist policy".into(),
                    });
                }
                json!({
                    "decision": "allowed",
                    "reason": "dm_allowlist_match",
                    "sender_id_hash": hash_identifier(user_id),
                })
            }
            SynologyChatDmPolicy::Open => json!({
                "decision": "allowed",
                "reason": "dm_open",
                "sender_id_hash": hash_identifier(user_id),
            }),
        }
    } else {
        json!({
            "decision": "not_applicable",
            "reason": "group_or_channel_message",
        })
    };

    let rate_key = format!("sender:{}", hash_identifier(user_id));
    let sender_rate_allowed = check_rate_limit(state, &rate_key, policy.sender_limit_per_minute)?;
    if !sender_rate_allowed {
        return Err(FcpError::RateLimited {
            retry_after_ms: 60_000,
            violation: None,
        });
    }

    Ok(json!({
        "sender": {
            "decision": "allowed",
            "reason": if policy.allowed_sender_ids.is_empty() { "sender_policy_open" } else { "sender_allowlist_match" },
            "sender_id_hash": hash_identifier(user_id),
        },
        "dm": dm_decision,
        "rate_limit": {
            "decision": "allowed",
            "window_seconds": 60,
            "limit": policy.sender_limit_per_minute,
        },
    }))
}

fn check_rate_limit(state: &SynologyChatState, key: &str, limit: u32) -> FcpResult<bool> {
    let mut rate_state = state.ingress_rate.lock().map_err(|_| FcpError::Internal {
        message: "Synology Chat ingress rate limiter lock poisoned".into(),
    })?;
    Ok(rate_state.check(key, limit, Instant::now()))
}

fn is_dm_channel_type(channel_type: &str) -> bool {
    matches!(channel_type, "2")
        || channel_type.eq_ignore_ascii_case("dm")
        || channel_type.eq_ignore_ascii_case("direct")
}

fn constant_time_secret_eq(expected: &str, actual: &str) -> bool {
    let expected = expected.as_bytes();
    let actual = actual.as_bytes();
    let max_len = expected.len().max(actual.len());
    let mut diff = expected.len() ^ actual.len();
    for index in 0..max_len {
        let expected_byte = expected.get(index).copied().unwrap_or(0);
        let actual_byte = actual.get(index).copied().unwrap_or(0);
        diff |= usize::from(expected_byte ^ actual_byte);
    }
    diff == 0
}

fn sanitize_ingress_text(text: &str) -> (String, Value) {
    let mut sanitized = String::with_capacity(text.len());
    let mut replaced_control_chars = 0usize;
    for ch in text.chars() {
        if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
            sanitized.push(' ');
            replaced_control_chars += 1;
        } else {
            sanitized.push(ch);
        }
    }
    let lower = sanitized.to_ascii_lowercase();
    let injection_markers_detected = [
        "ignore previous",
        "system prompt",
        "developer message",
        "jailbreak",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    (
        sanitized,
        json!({
            "control_chars_replaced": replaced_control_chars,
            "prompt_injection_markers_detected": injection_markers_detected,
            "raw_text_logged": false,
        }),
    )
}

fn hash_identifier(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
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
        let webhook_auth_value = config.outgoing_token().map(ToString::to_string);
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
            outgoing_token: webhook_auth_value,
            ingress_rate: Mutex::new(SynologyChatIngressRateState::default()),
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
            "allowed_file_url_hosts": self.state.as_ref().map(|state| &state.model.allowed_file_url_hosts),
            "forwarded_ingress_policy": self.state.as_ref().map(|state| &state.model.forwarded_ingress_policy),
            "raw_payload_file_url_policy": self.state.as_ref().map(|_| "unchecked_passthrough"),
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
                "allowed_file_url_hosts": &state.model.allowed_file_url_hosts,
                "forwarded_ingress_policy": &state.model.forwarded_ingress_policy,
                "raw_payload_file_url_policy": "unchecked_passthrough",
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
        OP_SEND_MESSAGE | OP_SEND_FILE_URL | OP_SEND_PAYLOAD => {
            Ok(CapabilityId::from_static(CAP_WRITE))
        }
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
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, RequestId, ZoneId};

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
        instance_id: &InstanceId,
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
            .target_instance(instance_id.as_str())
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
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
                capability_token: capability_token(
                    &signing_key,
                    CAP_READ,
                    OP_HEALTH,
                    connector.instance_id(),
                ),
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
        assert_eq!(result["forwarded_ingress_policy"]["hosted_listener"], false);
        assert_eq!(result["reply_semantics"], "outbound_only");
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_checks_capability_operation_grant() {
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
            .simulate(SimulateRequest {
                r#type: "simulate".into(),
                id: RequestId::new("synology-simulate"),
                connector_id: ConnectorId::from_static("fcp.synology-chat"),
                operation: OperationId::from_static(OP_SEND_MESSAGE),
                zone_id: ZoneId::work(),
                input: json!({ "text": "hello" }),
                capability_token: capability_token(
                    &signing_key,
                    CAP_READ,
                    OP_SEND_MESSAGE,
                    connector.instance_id(),
                ),
                estimate_cost: false,
                check_availability: false,
                context: None,
                correlation_id: None,
            })
            .await
            .expect("simulate should return a policy result");

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-3003"));
        assert!(response.missing_capabilities.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_reports_state_model_details() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi",
                "request_timeout_ms": 25_000,
                "allow_insecure_ssl": true,
                "outgoing_token": "top-secret",
                "allowed_file_url_hosts": ["media.nas.local"],
                "allowed_webhook_sender_ids": [" 4 ", "4"],
                "allowed_webhook_dm_sender_ids": [" 4 "],
                "webhook_dm_policy": "allowlist"
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
        assert_eq!(details["allowed_file_url_hosts"][0], "media.nas.local");
        assert_eq!(
            details["forwarded_ingress_policy"]["sender_policy"],
            "allowlist"
        );
        assert_eq!(
            details["forwarded_ingress_policy"]["allowed_sender_ids"][0],
            "4"
        );
        assert_eq!(
            details["forwarded_ingress_policy"]["dm_policy"],
            "allowlist"
        );
        assert_eq!(
            details["forwarded_ingress_policy"]["hosted_listener"],
            false
        );
        assert_eq!(
            details["raw_payload_file_url_policy"],
            "unchecked_passthrough"
        );
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
                OP_SEND_FILE_URL.to_string(),
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

    #[test]
    fn resolves_forwarded_webhook_token_aliases_without_payload_token() {
        let input = json!({
            "payload": {
                "channel_id": "34",
                "user_id": "4"
            },
            "headers": {
                "X-Synology-Chat-Token": " shared-secret "
            }
        });
        let payload = input["payload"].as_object().expect("payload object");
        let presented = resolve_presented_webhook_token(&input, payload)
            .expect("token should resolve")
            .expect("token should be present");
        assert_eq!(presented.source, "x-synology-chat-token");
        assert_eq!(presented.value, "shared-secret");

        let query_input = json!({
            "payload": {
                "channel_id": "34",
                "user_id": "4"
            },
            "query": {
                "token": "query-secret"
            }
        });
        let payload = query_input["payload"].as_object().expect("payload object");
        let presented = resolve_presented_webhook_token(&query_input, payload)
            .expect("token should resolve")
            .expect("token should be present");
        assert_eq!(presented.source, "query.token");
        assert_eq!(presented.value, "query-secret");
    }

    #[test]
    fn constant_time_secret_eq_handles_mismatch_and_length_mismatch() {
        assert!(constant_time_secret_eq("shared-secret", "shared-secret"));
        assert!(!constant_time_secret_eq("shared-secret", "shared-secreu"));
        assert!(!constant_time_secret_eq(
            "shared-secret",
            "shared-secret-extra"
        ));
        assert!(!constant_time_secret_eq("shared-secret", ""));
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
                capability_token: capability_token(
                    &signing_key,
                    CAP_READ,
                    OP_WEBHOOK_NORMALIZE,
                    connector.instance_id(),
                ),
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
                capability_token: capability_token(
                    &signing_key,
                    CAP_READ,
                    OP_WEBHOOK_NORMALIZE,
                    connector.instance_id(),
                ),
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
                capability_token: capability_token(
                    &signing_key,
                    CAP_READ,
                    OP_WEBHOOK_NORMALIZE,
                    connector.instance_id(),
                ),
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
                capability_token: capability_token(
                    &signing_key,
                    CAP_READ,
                    OP_WEBHOOK_NORMALIZE,
                    connector.instance_id(),
                ),
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
                capability_token: capability_token(
                    &signing_key,
                    CAP_READ,
                    OP_WEBHOOK_NORMALIZE,
                    connector.instance_id(),
                ),
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
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
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
                capability_token: capability_token(
                    &signing_key,
                    CAP_READ,
                    OP_WEBHOOK_NORMALIZE,
                    connector.instance_id(),
                ),
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
                capability_token: capability_token(
                    &signing_key,
                    CAP_READ,
                    OP_WEBHOOK_NORMALIZE,
                    connector.instance_id(),
                ),
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
