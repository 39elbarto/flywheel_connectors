//! Matrix connector implementation.

use std::collections::BTreeMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::MatrixClient;
use crate::error::MatrixError;
use crate::types::{
    CreateRoomRequest, Event, InvitedSyncRoom, JoinedSyncRoom, LeftSyncRoom, MatrixAuth,
    MatrixEncryptedEventPolicy, MatrixInboundPolicy, SyncResponse,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_JOINED_ROOMS: &str = "matrix.joined_rooms";
const OP_CREATE_ROOM: &str = "matrix.create_room";
const OP_JOIN_ROOM: &str = "matrix.join_room";
const OP_LEAVE_ROOM: &str = "matrix.leave_room";
const OP_SEND_MESSAGE: &str = "matrix.send_message";
const OP_GET_MESSAGES: &str = "matrix.get_messages";
const OP_SYNC: &str = "matrix.sync";
const OP_GET_ROOM_STATE: &str = "matrix.get_room_state";
const OP_LIST_MEMBERS: &str = "matrix.list_members";
const OP_UPLOAD_MEDIA: &str = "matrix.upload_media";
const OP_DOWNLOAD_MEDIA: &str = "matrix.download_media";

const CAP_READ: &str = "matrix.read";
const CAP_WRITE: &str = "matrix.write";
const CAP_MANAGE: &str = "matrix.manage";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MatrixRoomSummary {
    membership: String,
    name: Option<String>,
    topic: Option<String>,
    avatar_url: Option<String>,
    member_count: Option<usize>,
    last_event_ts: Option<u64>,
}

impl MatrixRoomSummary {
    fn with_membership(membership: &str) -> Self {
        Self {
            membership: membership.to_string(),
            ..Self::default()
        }
    }

    fn record_event(&mut self, event: &Event) {
        if let Some(timestamp) = event.origin_server_ts {
            self.last_event_ts = Some(
                self.last_event_ts
                    .map_or(timestamp, |current| current.max(timestamp)),
            );
        }

        match event.r#type.as_str() {
            "m.room.name" => {
                self.name = event
                    .content
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned);
            }
            "m.room.topic" => {
                self.topic = event
                    .content
                    .get("topic")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned);
            }
            "m.room.avatar" => {
                self.avatar_url = event
                    .content
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned);
            }
            _ => {}
        }
    }

    fn snapshot_json(&self, room_id: &str) -> serde_json::Value {
        json!({
            "room_id": room_id,
            "membership": self.membership,
            "name": self.name,
            "topic": self.topic,
            "avatar_url": self.avatar_url,
            "member_count": self.member_count,
            "last_event_ts": self.last_event_ts,
        })
    }
}

#[derive(Debug, Clone, Default)]
struct SyncProjection {
    room_summaries: Vec<serde_json::Value>,
    message_events: Vec<serde_json::Value>,
    membership_changes: Vec<serde_json::Value>,
    state_changes: Vec<serde_json::Value>,
    authorized_message_events: Vec<serde_json::Value>,
    dropped_events: Vec<serde_json::Value>,
    reaction_events: Vec<serde_json::Value>,
    encrypted_events: Vec<serde_json::Value>,
    tracked_updates: BTreeMap<String, MatrixRoomSummary>,
}

#[derive(Debug, Default)]
struct MatrixSyncTelemetry {
    successful_syncs: u64,
    failed_syncs: u64,
    last_status: Option<String>,
    last_error: Option<String>,
    last_duration_ms: Option<u64>,
    last_used_since: Option<String>,
    last_next_batch: Option<String>,
    last_persisted: Option<bool>,
    last_room_summary_count: usize,
    last_message_event_count: usize,
    last_membership_change_count: usize,
    last_state_change_count: usize,
    last_authorized_message_count: usize,
    last_dropped_event_count: usize,
    last_reaction_event_count: usize,
    last_encrypted_event_count: usize,
}

#[derive(Debug, Default)]
struct MatrixSyncState {
    last_sync_token: Option<String>,
    rooms: BTreeMap<String, MatrixRoomSummary>,
    telemetry: MatrixSyncTelemetry,
}

const fn auth_mode_label(auth: &MatrixAuth) -> &'static str {
    match auth {
        MatrixAuth::AccessToken { .. } => "access_token",
        MatrixAuth::CredentialId { .. } => "credential_id",
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

fn homeserver_transport_policy(homeserver_url: &str) -> (bool, String) {
    match reqwest::Url::parse(homeserver_url) {
        Ok(url) if url.scheme() == "https" => (
            true,
            format!(
                "Homeserver transport uses HTTPS for {}",
                url.host_str().unwrap_or("<unknown-host>")
            ),
        ),
        Ok(url) if url.scheme() == "http" && is_loopback_host(url.host_str()) => (
            true,
            format!(
                "Loopback HTTP is acceptable for deterministic verification against {}",
                url.host_str().unwrap_or("localhost")
            ),
        ),
        Ok(url) if url.scheme() == "http" => (
            false,
            format!(
                "Remote homeserver '{}' is configured over plain HTTP; use HTTPS for non-local verification",
                url.host_str().unwrap_or("<unknown-host>")
            ),
        ),
        Ok(url) => (
            false,
            format!(
                "Unsupported homeserver transport scheme '{}'; use HTTPS or loopback HTTP",
                url.scheme()
            ),
        ),
        Err(error) => (
            false,
            format!("Homeserver URL is not parseable for diagnostics: {error}"),
        ),
    }
}

fn doctor_check(
    name: &str,
    passed: bool,
    message: impl Into<String>,
    critical: bool,
) -> serde_json::Value {
    json!({
        "name": name,
        "passed": passed,
        "message": message.into(),
        "critical": critical,
    })
}

/// Matrix connector.
#[derive(Debug)]
pub struct MatrixConnector {
    base: BaseConnector,
    config: Option<crate::types::MatrixConfig>,
    client: Option<MatrixClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    sync_state: RwLock<MatrixSyncState>,
}

impl MatrixConnector {
    /// Create a new connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.matrix")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
            sync_state: RwLock::new(MatrixSyncState::default()),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn provisioning_snapshot(&self) -> Option<serde_json::Value> {
        self.config.as_ref().map(|config| {
            let (transport_ok, transport_message) =
                homeserver_transport_policy(&config.homeserver_url);
            json!({
                "auth_mode": auth_mode_label(&config.auth),
                "homeserver_url": config.homeserver_url.clone(),
                "transport_policy_ok": transport_ok,
                "transport_policy_message": transport_message,
                "credential_injection_required": matches!(&config.auth, MatrixAuth::CredentialId { .. }),
                "sync_delivery_model": "manual_sync_only",
                "inbound_policy": inbound_policy_snapshot(&config.inbound_policy),
                "retry_config": self.retry_config.clone(),
            })
        })
    }

    #[allow(clippy::significant_drop_tightening)]
    fn sync_observability_snapshot(&self) -> serde_json::Value {
        let state = self
            .sync_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let telemetry = &state.telemetry;
        json!({
            "last_sync_token": state.last_sync_token.clone(),
            "tracked_rooms": state.rooms.len(),
            "total_sync_calls": telemetry.successful_syncs + telemetry.failed_syncs,
            "successful_syncs": telemetry.successful_syncs,
            "failed_syncs": telemetry.failed_syncs,
            "last_status": telemetry.last_status.clone(),
            "last_error": telemetry.last_error.clone(),
            "last_duration_ms": telemetry.last_duration_ms,
            "last_used_since": telemetry.last_used_since.clone(),
            "last_next_batch": telemetry.last_next_batch.clone(),
            "last_persisted": telemetry.last_persisted,
            "last_room_summary_count": telemetry.last_room_summary_count,
            "last_message_event_count": telemetry.last_message_event_count,
            "last_membership_change_count": telemetry.last_membership_change_count,
            "last_state_change_count": telemetry.last_state_change_count,
            "last_authorized_message_count": telemetry.last_authorized_message_count,
            "last_dropped_event_count": telemetry.last_dropped_event_count,
            "last_reaction_event_count": telemetry.last_reaction_event_count,
            "last_encrypted_event_count": telemetry.last_encrypted_event_count,
        })
    }

    fn observability_payload(&self) -> serde_json::Value {
        json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.verifier.is_some(),
            "manifest_hash": Self::manifest_hash(),
            "provisioning": self.provisioning_snapshot(),
            "sync_tracking": self.sync_observability_snapshot(),
            "operator_guidance": {
                "dedicated_environment": "Use a non-production homeserver account and disposable rooms when verifying create, join, leave, send_message, and media mutations.",
                "sync_model": "This connector does not run a background receive loop. Invoke matrix.sync explicitly to advance the in-memory cursor and inspect room deltas.",
                "credential_injection": "credential_id mode requires the host or egress proxy to inject a bearer token before self_check can prove live readiness.",
                "redaction": "Do not log raw access tokens or decoded media bytes. Prefer room IDs, event IDs, and retry metadata in diagnostics.",
                "verification_commands": [
                    "rch exec -- cargo check -p fcp-matrix --all-targets",
                    "rch exec -- cargo test -p fcp-matrix"
                ]
            }
        })
    }

    fn attach_self_check_details(&self, mut report: SelfCheckReport) -> SelfCheckReport {
        report.details = Some(self.observability_payload());
        report
    }

    fn classify_self_check_error(error: &MatrixError) -> SelfCheckReport {
        match error {
            MatrixError::Unauthorized(message) => SelfCheckReport::failed(
                "token_invalid_or_expired",
                format!("Matrix homeserver rejected the bearer token: {message}"),
            ),
            MatrixError::Forbidden(message) => {
                SelfCheckReport::failed("homeserver_forbidden", message.clone())
            }
            MatrixError::NotFound(message) => {
                SelfCheckReport::failed("homeserver_endpoint_not_found", message.clone())
            }
            MatrixError::RateLimited { retry_after_ms } => SelfCheckReport::degraded(
                "homeserver_rate_limited",
                format!(
                    "Matrix homeserver throttled the readiness probe; retry after {retry_after_ms}ms"
                ),
            ),
            other if other.is_retryable() => {
                SelfCheckReport::degraded("self_check_retryable", other.to_string())
            }
            other => SelfCheckReport::failed("self_check_failed", other.to_string()),
        }
    }

    fn record_sync_success(
        &self,
        used_since: Option<&str>,
        next_batch: &str,
        persist: bool,
        projection: &SyncProjection,
        duration: Duration,
    ) {
        let mut state = self
            .sync_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.telemetry.successful_syncs = state.telemetry.successful_syncs.saturating_add(1);
        state.telemetry.last_status = Some("success".into());
        state.telemetry.last_error = None;
        state.telemetry.last_duration_ms =
            Some(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
        state.telemetry.last_used_since = used_since.map(ToOwned::to_owned);
        state.telemetry.last_next_batch = Some(next_batch.to_string());
        state.telemetry.last_persisted = Some(persist);
        state.telemetry.last_room_summary_count = projection.room_summaries.len();
        state.telemetry.last_message_event_count = projection.message_events.len();
        state.telemetry.last_membership_change_count = projection.membership_changes.len();
        state.telemetry.last_state_change_count = projection.state_changes.len();
        state.telemetry.last_authorized_message_count = projection.authorized_message_events.len();
        state.telemetry.last_dropped_event_count = projection.dropped_events.len();
        state.telemetry.last_reaction_event_count = projection.reaction_events.len();
        state.telemetry.last_encrypted_event_count = projection.encrypted_events.len();
    }

    fn record_sync_failure(
        &self,
        used_since: Option<&str>,
        persist: bool,
        error: &MatrixError,
        duration: Duration,
    ) {
        let mut state = self
            .sync_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.telemetry.failed_syncs = state.telemetry.failed_syncs.saturating_add(1);
        state.telemetry.last_status = Some("failed".into());
        state.telemetry.last_error = Some(error.to_string());
        state.telemetry.last_duration_ms =
            Some(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
        state.telemetry.last_used_since = used_since.map(ToOwned::to_owned);
        state.telemetry.last_next_batch = None;
        state.telemetry.last_persisted = Some(persist);
        state.telemetry.last_room_summary_count = 0;
        state.telemetry.last_message_event_count = 0;
        state.telemetry.last_membership_change_count = 0;
        state.telemetry.last_state_change_count = 0;
        state.telemetry.last_authorized_message_count = 0;
        state.telemetry.last_dropped_event_count = 0;
        state.telemetry.last_reaction_event_count = 0;
        state.telemetry.last_encrypted_event_count = 0;
    }

    /// Run diagnostics.
    #[must_use]
    pub fn doctor(&self) -> serde_json::Value {
        let mut checks = Vec::new();

        let configured = self.config.is_some();
        checks.push(doctor_check(
            "configuration",
            configured,
            if configured {
                "Configuration loaded"
            } else {
                "Not configured - run configure first"
            },
            true,
        ));

        let client_ok = self.client.is_some();
        checks.push(doctor_check(
            "client_initialized",
            client_ok,
            if client_ok {
                "Matrix client initialized"
            } else {
                "Matrix client missing; re-run configure"
            },
            true,
        ));

        let runtime_ok = self.runtime.is_some();
        checks.push(doctor_check(
            "runtime",
            runtime_ok,
            if runtime_ok {
                "ConnectorRuntime initialized"
            } else {
                "ConnectorRuntime missing; re-run configure"
            },
            true,
        ));

        if let Some(config) = &self.config {
            let (transport_ok, transport_message) =
                homeserver_transport_policy(&config.homeserver_url);
            checks.push(doctor_check(
                "homeserver_transport",
                transport_ok,
                transport_message,
                true,
            ));
            checks.push(doctor_check(
                "auth_mode",
                true,
                format!("Auth mode: {}", auth_mode_label(&config.auth)),
                false,
            ));
            let credential_injection_required =
                matches!(&config.auth, MatrixAuth::CredentialId { .. });
            checks.push(doctor_check(
                "credential_injection",
                !credential_injection_required,
                if credential_injection_required {
                    "Host or egress proxy must inject a bearer token before self_check can prove readiness"
                } else {
                    "Bearer token configured directly"
                },
                false,
            ));
            checks.push(doctor_check(
                "sync_delivery_model",
                true,
                "No background receive loop is running; use matrix.sync to advance the in-memory cursor explicitly",
                false,
            ));
            checks.push(doctor_check(
                "e2ee_delivery_policy",
                true,
                format!(
                    "Encrypted Matrix timeline events are projected as '{}' until verified E2EE/device verification is implemented",
                    encrypted_event_policy_label(config.inbound_policy.encrypted_events)
                ),
                false,
            ));
        }

        let passed = checks.iter().all(|check| {
            !check["critical"].as_bool().unwrap_or(false)
                || check["passed"].as_bool().unwrap_or(false)
        });

        info!(
            event = "matrix.doctor",
            status = if passed { "pass" } else { "fail" },
            check_count = checks.len(),
            "Matrix doctor checks completed"
        );

        json!({
            "passed": passed,
            "checks": checks,
            "sync_tracking": self.sync_observability_snapshot(),
            "details": self.observability_payload(),
        })
    }

    fn tracked_state_json(&self) -> serde_json::Value {
        let state = self
            .sync_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::tracked_state_json_value(state.last_sync_token.as_deref(), &state.rooms)
    }

    fn tracked_state_json_value(
        last_sync_token: Option<&str>,
        rooms: &BTreeMap<String, MatrixRoomSummary>,
    ) -> serde_json::Value {
        json!({
            "last_sync_token": last_sync_token,
            "tracked_rooms": rooms.len(),
            "rooms": rooms.iter().map(|(room_id, summary)| summary.snapshot_json(room_id)).collect::<Vec<_>>(),
        })
    }

    fn preview_tracked_state_json(
        &self,
        next_batch: &str,
        tracked_updates: &BTreeMap<String, MatrixRoomSummary>,
    ) -> serde_json::Value {
        let mut rooms = self
            .sync_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .rooms
            .clone();
        for (room_id, summary) in tracked_updates {
            rooms.insert(room_id.clone(), summary.clone());
        }
        Self::tracked_state_json_value(Some(next_batch), &rooms)
    }
}

impl Default for MatrixConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_JOINED_ROOMS),
            summary: "List joined rooms".into(),
            description: Some("Lists all rooms the authenticated user has joined".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": { "rooms": { "type": "array", "items": { "type": "string" } } }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to discover which rooms the bot is in".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_JOIN_ROOM)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CREATE_ROOM),
            summary: "Create a room".into(),
            description: Some("Creates a new Matrix room".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "topic": { "type": "string" },
                    "invite": { "type": "array", "items": { "type": "string" } },
                    "visibility": { "type": "string", "enum": ["public", "private"] },
                    "preset": { "type": "string", "enum": ["private_chat", "public_chat", "trusted_private_chat"] }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": { "room_id": { "type": "string" } }
            }),
            capability: CapabilityId::from_static(CAP_MANAGE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to create a new conversation space".into(),
                common_mistakes: vec![
                    "Room names are optional; room IDs are auto-generated".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_JOIN_ROOM),
            summary: "Join a room".into(),
            description: Some("Joins a room by ID or alias".into()),
            input_schema: json!({
                "type": "object",
                "required": ["room_id_or_alias"],
                "properties": {
                    "room_id_or_alias": { "type": "string", "description": "Room ID (!...) or alias (#...)" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MANAGE),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to join a room before sending messages".into(),
                common_mistakes: vec!["Room IDs start with !, aliases start with #".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_LEAVE_ROOM)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_LEAVE_ROOM),
            summary: "Leave a room".into(),
            description: Some("Leaves a room".into()),
            input_schema: json!({
                "type": "object",
                "required": ["room_id"],
                "properties": {
                    "room_id": { "type": "string" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MANAGE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to leave a room you no longer need".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_JOIN_ROOM)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEND_MESSAGE),
            summary: "Send a message to a room".into(),
            description: Some("Sends a text message to a Matrix room".into()),
            input_schema: json!({
                "type": "object",
                "required": ["room_id", "body"],
                "properties": {
                    "room_id": { "type": "string" },
                    "body": { "type": "string" },
                    "msgtype": { "type": "string", "default": "m.text", "description": "m.text, m.notice, m.emote" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": { "event_id": { "type": "string" } }
            }),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a message in a Matrix room".into(),
                common_mistakes: vec![
                    "Must be joined to the room first".into(),
                    "Use m.notice for bot messages to avoid notification spam".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_MESSAGES)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_MESSAGES),
            summary: "Get messages from a room".into(),
            description: Some("Retrieves messages from a room with pagination".into()),
            input_schema: json!({
                "type": "object",
                "required": ["room_id"],
                "properties": {
                    "room_id": { "type": "string" },
                    "from": { "type": "string", "description": "Pagination token" },
                    "limit": { "type": "integer", "default": 20 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "messages": { "type": "array" },
                    "end": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read chat history from a room".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SEND_MESSAGE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SYNC),
            summary: "Run a sync cycle".into(),
            description: Some(
                "Long-polls the homeserver sync endpoint, translates room/message/member deltas, and optionally updates the connector's in-memory sync cursor".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "since": { "type": "string", "description": "Optional explicit sync token. Falls back to the tracked token when omitted." },
                    "timeout_ms": { "type": "integer", "default": 30000, "minimum": 0 },
                    "persist": { "type": "boolean", "default": true, "description": "Whether to persist the returned next_batch token and tracked room summaries." }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "used_since": { "type": ["string", "null"] },
                    "next_batch": { "type": "string" },
                    "rooms": { "type": "array" },
                    "message_events": { "type": "array" },
                    "authorized_message_events": { "type": "array" },
                    "dropped_events": { "type": "array" },
                    "reaction_events": { "type": "array" },
                    "encrypted_events": { "type": "array" },
                    "membership_changes": { "type": "array" },
                    "state_changes": { "type": "array" },
                    "inbound_policy": { "type": "object" },
                    "tracked_state": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need a truthful incremental view of room timeline, membership, and state changes from the Matrix sync loop".into(),
                common_mistakes: vec![
                    "Use the returned next_batch token for subsequent sync calls".into(),
                    "Set persist=false if you want to inspect a sync result without advancing tracked state".into(),
                ],
                examples: Vec::new(),
                related: vec![
                    CapabilityId::from_static(OP_GET_ROOM_STATE),
                    CapabilityId::from_static(OP_LIST_MEMBERS),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_ROOM_STATE),
            summary: "Get room state".into(),
            description: Some("Fetches the current state event set for a room and summarizes the tracked room metadata".into()),
            input_schema: json!({
                "type": "object",
                "required": ["room_id"],
                "properties": {
                    "room_id": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "room_id": { "type": "string" },
                    "summary": { "type": "object" },
                    "state_events": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need room metadata such as name, topic, avatar, or other stateful settings".into(),
                common_mistakes: vec!["State events use state_key; empty state_key is common for singleton room settings".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SYNC)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_LIST_MEMBERS),
            summary: "List room members".into(),
            description: Some("Lists membership state events for a room, optionally filtering by membership kind".into()),
            input_schema: json!({
                "type": "object",
                "required": ["room_id"],
                "properties": {
                    "room_id": { "type": "string" },
                    "membership": { "type": "string", "description": "Optional Matrix membership filter such as join, invite, or leave" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "room_id": { "type": "string" },
                    "members": { "type": "array" },
                    "summary": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need the current membership roster or to inspect membership transitions for a room".into(),
                common_mistakes: vec!["Membership filters apply to the returned room member events, not to sync state tracking".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_ROOM_STATE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_UPLOAD_MEDIA),
            summary: "Upload media".into(),
            description: Some("Uploads raw media bytes to the homeserver and returns an MXC content URI".into()),
            input_schema: json!({
                "type": "object",
                "required": ["content_type", "body_base64"],
                "properties": {
                    "content_type": { "type": "string" },
                    "body_base64": { "type": "string", "description": "Base64-encoded file bytes" },
                    "filename": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "content_uri": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to attach files or images before sending Matrix message content that references MXC media".into(),
                common_mistakes: vec![
                    "body_base64 must contain raw bytes, not a data URI".into(),
                    "Use the returned content_uri in subsequent room message content".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_DOWNLOAD_MEDIA)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOWNLOAD_MEDIA),
            summary: "Download media".into(),
            description: Some("Downloads Matrix media by MXC URI or explicit server/media identifiers".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "mxc_uri": { "type": "string", "description": "Convenience MXC URI such as mxc://matrix.org/media123" },
                    "server_name": { "type": "string" },
                    "media_id": { "type": "string" },
                    "allow_remote": { "type": "boolean", "default": true }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "content_type": { "type": ["string", "null"] },
                    "content_disposition": { "type": ["string", "null"] },
                    "size_bytes": { "type": "integer" },
                    "data_base64": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to retrieve a previously uploaded Matrix media object".into(),
                common_mistakes: vec![
                    "Provide either mxc_uri or the explicit server_name/media_id pair".into(),
                    "Large media responses are returned as base64 in the JSON result".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_UPLOAD_MEDIA)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{field}' field"),
        })
}

fn optional_str(input: &serde_json::Value, field: &str) -> FcpResult<Option<String>> {
    match input.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{field}' must be a string"),
            }),
    }
}

fn optional_string_vec(input: &serde_json::Value, field: &str) -> FcpResult<Vec<String>> {
    match input.get(field) {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(value) => {
            serde_json::from_value(value.clone()).map_err(|_| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{field}' must be an array of strings"),
            })
        }
    }
}

fn optional_u32(input: &serde_json::Value, field: &str, default: u32) -> FcpResult<u32> {
    match input.get(field) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(value) => {
            let raw = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{field}' must be an unsigned integer"),
            })?;
            u32::try_from(raw).map_err(|_| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{field}' exceeds maximum supported value"),
            })
        }
    }
}

fn optional_bool(input: &serde_json::Value, field: &str, default: bool) -> FcpResult<bool> {
    match input.get(field) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(value) => value.as_bool().ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Field '{field}' must be a boolean"),
        }),
    }
}

fn parse_mxc_uri(uri: &str) -> FcpResult<(String, String)> {
    let Some(rest) = uri.strip_prefix("mxc://") else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "mxc_uri must start with mxc://".into(),
        });
    };

    let mut parts = rest.splitn(2, '/');
    let server_name = parts.next().unwrap_or_default();
    let media_id = parts.next().unwrap_or_default();
    if server_name.is_empty() || media_id.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "mxc_uri must include both server name and media id".into(),
        });
    }

    Ok((server_name.to_string(), media_id.to_string()))
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    let mut resource_uris = Vec::new();

    match operation {
        OP_JOIN_ROOM => {
            let room = require_str(input, "room_id_or_alias")?;
            if room.starts_with('#') {
                resource_uris.push(format!("matrix:room_alias:{room}"));
            } else {
                resource_uris.push(format!("matrix:room:{room}"));
            }
        }
        OP_LEAVE_ROOM | OP_SEND_MESSAGE | OP_GET_MESSAGES | OP_GET_ROOM_STATE | OP_LIST_MEMBERS => {
            let room_id = require_str(input, "room_id")?;
            resource_uris.push(format!("matrix:room:{room_id}"));
        }
        OP_DOWNLOAD_MEDIA => {
            let (server_name, media_id) = if let Some(uri) = optional_str(input, "mxc_uri")? {
                parse_mxc_uri(&uri)?
            } else {
                (
                    require_str(input, "server_name")?.to_string(),
                    require_str(input, "media_id")?.to_string(),
                )
            };
            resource_uris.push(format!("matrix:media:{server_name}/{media_id}"));
        }
        _ => {}
    }

    Ok(resource_uris)
}

fn normalize_message_event(room_id: &str, event: &Event) -> serde_json::Value {
    json!({
        "room_id": room_id,
        "event_id": event.event_id,
        "sender": event.sender,
        "origin_server_ts": event.origin_server_ts,
        "msgtype": event.content.get("msgtype").and_then(serde_json::Value::as_str),
        "body": event.content.get("body").and_then(serde_json::Value::as_str),
        "url": event.content.get("url").and_then(serde_json::Value::as_str),
    })
}

fn normalize_membership_event(room_id: &str, event: &Event) -> serde_json::Value {
    json!({
        "room_id": room_id,
        "event_id": event.event_id,
        "user_id": event.state_key,
        "sender": event.sender,
        "origin_server_ts": event.origin_server_ts,
        "membership": event.content.get("membership").and_then(serde_json::Value::as_str),
        "displayname": event.content.get("displayname").and_then(serde_json::Value::as_str),
        "avatar_url": event.content.get("avatar_url").and_then(serde_json::Value::as_str),
    })
}

fn normalize_state_event(room_id: &str, event: &Event) -> serde_json::Value {
    json!({
        "room_id": room_id,
        "event_id": event.event_id,
        "event_type": event.r#type,
        "state_key": event.state_key,
        "sender": event.sender,
        "origin_server_ts": event.origin_server_ts,
        "content": event.content,
    })
}

const fn encrypted_event_policy_label(policy: MatrixEncryptedEventPolicy) -> &'static str {
    match policy {
        MatrixEncryptedEventPolicy::FailClosed => "fail_closed",
        MatrixEncryptedEventPolicy::MetadataOnly => "metadata_only",
    }
}

fn inbound_policy_snapshot(policy: &MatrixInboundPolicy) -> serde_json::Value {
    json!({
        "allowed_users": policy.allowed_users.clone(),
        "bot_user_id": policy.bot_user_id.clone(),
        "require_mention": policy.require_mention,
        "free_response_rooms": policy.free_response_rooms.clone(),
        "process_reactions": policy.process_reactions,
        "encrypted_events": encrypted_event_policy_label(policy.encrypted_events),
    })
}

fn sender_allowed(policy: &MatrixInboundPolicy, sender: Option<&str>) -> bool {
    policy.allowed_users.is_empty()
        || sender.is_some_and(|sender| {
            policy
                .allowed_users
                .iter()
                .any(|allowed_sender| allowed_sender == sender)
        })
}

fn room_allows_free_response(policy: &MatrixInboundPolicy, room_id: &str) -> bool {
    policy
        .free_response_rooms
        .iter()
        .any(|allowed_room| allowed_room == room_id)
}

fn event_mentions_bot(event: &Event, policy: &MatrixInboundPolicy) -> bool {
    let Some(bot_user_id) = policy.bot_user_id.as_deref() else {
        return false;
    };

    let mentioned_user_ids = event
        .content
        .get("m.mentions")
        .and_then(|mentions| mentions.get("user_ids"))
        .and_then(serde_json::Value::as_array);
    if mentioned_user_ids.is_some_and(|user_ids| {
        user_ids
            .iter()
            .any(|user_id| user_id.as_str() == Some(bot_user_id))
    }) {
        return true;
    }

    event
        .content
        .get("body")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|body| body.contains(bot_user_id))
}

fn inbound_message_drop_reason(
    room_id: &str,
    event: &Event,
    policy: &MatrixInboundPolicy,
) -> Option<&'static str> {
    let sender = event.sender.as_deref();
    if policy
        .bot_user_id
        .as_deref()
        .is_some_and(|bot| sender == Some(bot))
    {
        return Some("self_event");
    }

    if !sender_allowed(policy, sender) {
        return Some("sender_not_allowed");
    }

    if policy.require_mention
        && !room_allows_free_response(policy, room_id)
        && !event_mentions_bot(event, policy)
    {
        return Some("mention_required");
    }

    None
}

fn policy_metadata_event(room_id: &str, event: &Event, reason: &str) -> serde_json::Value {
    json!({
        "room_id": room_id,
        "event_id": event.event_id,
        "event_type": event.r#type,
        "sender": event.sender,
        "origin_server_ts": event.origin_server_ts,
        "reason": reason,
    })
}

fn normalize_reaction_event(room_id: &str, event: &Event) -> serde_json::Value {
    let relation = event.content.get("m.relates_to");
    json!({
        "room_id": room_id,
        "event_id": event.event_id,
        "sender": event.sender,
        "origin_server_ts": event.origin_server_ts,
        "target_event_id": relation
            .and_then(|value| value.get("event_id"))
            .and_then(serde_json::Value::as_str),
        "rel_type": relation
            .and_then(|value| value.get("rel_type"))
            .and_then(serde_json::Value::as_str),
        "key": relation
            .and_then(|value| value.get("key"))
            .and_then(serde_json::Value::as_str),
    })
}

fn normalize_encrypted_event(
    room_id: &str,
    event: &Event,
    policy: MatrixEncryptedEventPolicy,
) -> serde_json::Value {
    json!({
        "room_id": room_id,
        "event_id": event.event_id,
        "sender": event.sender,
        "origin_server_ts": event.origin_server_ts,
        "algorithm": event
            .content
            .get("algorithm")
            .and_then(serde_json::Value::as_str),
        "session_id": event
            .content
            .get("session_id")
            .and_then(serde_json::Value::as_str),
        "delivery_policy": encrypted_event_policy_label(policy),
    })
}

fn project_inbound_policy_event(
    projection: &mut SyncProjection,
    room_id: &str,
    event: &Event,
    policy: &MatrixInboundPolicy,
) {
    match event.r#type.as_str() {
        "m.room.message" => {
            if let Some(reason) = inbound_message_drop_reason(room_id, event, policy) {
                projection
                    .dropped_events
                    .push(policy_metadata_event(room_id, event, reason));
            } else {
                projection
                    .authorized_message_events
                    .push(normalize_message_event(room_id, event));
            }
        }
        "m.reaction" => {
            if policy.process_reactions {
                projection
                    .reaction_events
                    .push(normalize_reaction_event(room_id, event));
            } else {
                projection.dropped_events.push(policy_metadata_event(
                    room_id,
                    event,
                    "reactions_disabled",
                ));
            }
        }
        "m.room.encrypted" => {
            projection.encrypted_events.push(normalize_encrypted_event(
                room_id,
                event,
                policy.encrypted_events,
            ));
            if matches!(
                policy.encrypted_events,
                MatrixEncryptedEventPolicy::FailClosed
            ) {
                projection.dropped_events.push(policy_metadata_event(
                    room_id,
                    event,
                    "encrypted_event_fail_closed",
                ));
            }
        }
        _ => {}
    }
}

fn summarize_room(room_id: &str, membership: &str, events: &[Event]) -> MatrixRoomSummary {
    let mut summary = MatrixRoomSummary::with_membership(membership);
    let mut joined_members = 0_usize;
    let mut observed_membership = false;

    for event in events {
        summary.record_event(event);
        if event.r#type == "m.room.member" {
            observed_membership = true;
            if event
                .content
                .get("membership")
                .and_then(serde_json::Value::as_str)
                == Some("join")
            {
                joined_members += 1;
            }
        }
    }

    if observed_membership {
        summary.member_count = Some(joined_members);
    }

    let _ = room_id;
    summary
}

fn project_state_events(projection: &mut SyncProjection, room_id: &str, events: &[Event]) -> usize {
    let mut membership_events = 0_usize;

    for event in events {
        if event.r#type == "m.room.member" {
            membership_events += 1;
            projection
                .membership_changes
                .push(normalize_membership_event(room_id, event));
        } else {
            projection
                .state_changes
                .push(normalize_state_event(room_id, event));
        }
    }

    membership_events
}

fn project_timeline_events(
    projection: &mut SyncProjection,
    summary: &mut MatrixRoomSummary,
    room_id: &str,
    events: &[Event],
    policy: &MatrixInboundPolicy,
) -> usize {
    let mut membership_events = 0_usize;

    for event in events {
        summary.record_event(event);
        project_inbound_policy_event(projection, room_id, event, policy);
        match event.r#type.as_str() {
            "m.room.message" => projection
                .message_events
                .push(normalize_message_event(room_id, event)),
            "m.room.member" => {
                membership_events += 1;
                projection
                    .membership_changes
                    .push(normalize_membership_event(room_id, event));
            }
            _ => projection
                .state_changes
                .push(normalize_state_event(room_id, event)),
        }
    }

    membership_events
}

fn build_room_summary(
    room_id: &str,
    summary: &MatrixRoomSummary,
    state_events: usize,
    timeline_events: usize,
    membership_events: usize,
    prev_batch: Option<&str>,
    limited: bool,
) -> serde_json::Value {
    let mut room_summary = summary.snapshot_json(room_id);
    room_summary["state_event_count"] = json!(state_events);
    room_summary["timeline_event_count"] = json!(timeline_events);
    room_summary["membership_event_count"] = json!(membership_events);
    room_summary["prev_batch"] = json!(prev_batch);
    room_summary["limited"] = json!(limited);
    room_summary
}

fn project_joined_room(
    projection: &mut SyncProjection,
    room_id: &str,
    room: &JoinedSyncRoom,
    policy: &MatrixInboundPolicy,
) {
    let mut summary = summarize_room(room_id, "join", &room.state.events);
    let state_events = room.state.events.len();
    let timeline_events = room.timeline.events.len();
    let membership_events = project_state_events(projection, room_id, &room.state.events)
        + project_timeline_events(
            projection,
            &mut summary,
            room_id,
            &room.timeline.events,
            policy,
        );

    projection.room_summaries.push(build_room_summary(
        room_id,
        &summary,
        state_events,
        timeline_events,
        membership_events,
        room.timeline.prev_batch.as_deref(),
        room.timeline.limited,
    ));
    projection
        .tracked_updates
        .insert(room_id.to_string(), summary);
}

fn project_invited_room(projection: &mut SyncProjection, room_id: &str, room: &InvitedSyncRoom) {
    let summary = summarize_room(room_id, "invite", &room.invite_state.events);
    let membership_events = project_state_events(projection, room_id, &room.invite_state.events);

    projection.room_summaries.push(build_room_summary(
        room_id,
        &summary,
        room.invite_state.events.len(),
        0,
        membership_events,
        None,
        false,
    ));
    projection
        .tracked_updates
        .insert(room_id.to_string(), summary);
}

fn project_left_room(
    projection: &mut SyncProjection,
    room_id: &str,
    room: &LeftSyncRoom,
    policy: &MatrixInboundPolicy,
) {
    let mut summary = summarize_room(room_id, "leave", &room.state.events);
    let state_events = room.state.events.len();
    let timeline_events = room.timeline.events.len();
    let membership_events = project_state_events(projection, room_id, &room.state.events)
        + project_timeline_events(
            projection,
            &mut summary,
            room_id,
            &room.timeline.events,
            policy,
        );

    projection.room_summaries.push(build_room_summary(
        room_id,
        &summary,
        state_events,
        timeline_events,
        membership_events,
        room.timeline.prev_batch.as_deref(),
        room.timeline.limited,
    ));
    projection
        .tracked_updates
        .insert(room_id.to_string(), summary);
}

#[cfg(test)]
fn project_sync_response(sync: &SyncResponse) -> SyncProjection {
    project_sync_response_with_policy(sync, &MatrixInboundPolicy::default())
}

fn project_sync_response_with_policy(
    sync: &SyncResponse,
    policy: &MatrixInboundPolicy,
) -> SyncProjection {
    let mut projection = SyncProjection::default();

    for (room_id, room) in &sync.rooms.join {
        project_joined_room(&mut projection, room_id, room, policy);
    }

    for (room_id, room) in &sync.rooms.invite {
        project_invited_room(&mut projection, room_id, room);
    }

    for (room_id, room) in &sync.rooms.leave {
        project_left_room(&mut projection, room_id, room, policy);
    }

    projection
}

fcp_core::impl_fcp_sealed!(MatrixConnector);

#[async_trait]
impl FcpConnector for MatrixConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: crate::types::MatrixConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Matrix config: {e}"),
            })?;

        // Validate homeserver URL scheme and structure.
        if !config.homeserver_url.starts_with("http://")
            && !config.homeserver_url.starts_with("https://")
        {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: "homeserver_url must start with http:// or https://".into(),
            });
        }
        reqwest::Url::parse(&config.homeserver_url).map_err(|e| FcpError::InvalidRequest {
            code: 1002,
            message: format!("homeserver_url is not a valid URL: {e}"),
        })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.timeout_ms)),
        ));

        let timeout = Duration::from_millis(config.timeout_ms);
        let client = match &config.auth {
            MatrixAuth::AccessToken { access_token } => {
                MatrixClient::new(&config.homeserver_url, access_token, timeout)
            }
            MatrixAuth::CredentialId { credential_id } => {
                MatrixClient::new_secretless(&config.homeserver_url, credential_id, timeout)
            }
        }
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Matrix client: {e}"),
        })?;

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
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
        let mut snapshot = if self.config.is_none() {
            HealthSnapshot::degraded("not configured")
        } else if self.client.is_none() || self.runtime.is_none() {
            HealthSnapshot::degraded("connector runtime incomplete")
        } else if let Some(config) = &self.config {
            let (transport_ok, transport_message) =
                homeserver_transport_policy(&config.homeserver_url);
            if !transport_ok {
                HealthSnapshot::degraded(transport_message)
            } else if self
                .client
                .as_ref()
                .is_some_and(MatrixClient::is_secretless)
            {
                HealthSnapshot::degraded("credential injection required")
            } else {
                HealthSnapshot::ready()
            }
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(self.observability_payload());
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(self.attach_self_check_details(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            )));
        };
        let (transport_ok, transport_message) = homeserver_transport_policy(&config.homeserver_url);
        if !transport_ok {
            return Ok(self.attach_self_check_details(SelfCheckReport::failed(
                "homeserver_transport_invalid",
                transport_message,
            )));
        }
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(SelfCheckReport::failed(
                "client_missing",
                "Matrix client not initialized; re-run configure",
            )));
        };
        if self.runtime.is_none() {
            return Ok(self.attach_self_check_details(SelfCheckReport::failed(
                "runtime_missing",
                "ConnectorRuntime not initialized; re-run configure",
            )));
        }
        if client.is_secretless() {
            return Ok(self.attach_self_check_details(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured in credential_id mode; the host or egress proxy must inject a bearer token before live readiness can be proven",
            )));
        }
        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(err) => Self::classify_self_check_error(&err),
        };
        let report = self.attach_self_check_details(report);
        info!(
            event = "matrix.self_check",
            status = ?report.status,
            reason_code = report.reason_code.as_deref().unwrap_or("ok"),
            "Matrix self_check completed"
        );
        Ok(report)
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
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

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl MatrixConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;

        let operation = req.operation.as_str();
        let required_cap = match operation {
            OP_JOINED_ROOMS | OP_GET_MESSAGES | OP_SYNC | OP_GET_ROOM_STATE | OP_LIST_MEMBERS
            | OP_DOWNLOAD_MEDIA => CapabilityId::from_static(CAP_READ),
            OP_SEND_MESSAGE | OP_UPLOAD_MEDIA => CapabilityId::from_static(CAP_WRITE),
            OP_CREATE_ROOM | OP_JOIN_ROOM | OP_LEAVE_ROOM => CapabilityId::from_static(CAP_MANAGE),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        let verifier = self.verifier.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing capability verifier".into(),
        })?;
        let resource_uris = resource_uris_for_operation(operation, &req.input)?;
        // dja9u.1.c: typestate handoff via verify_bound.
        let _bound = verifier.verify_bound(
            req.capability_token,
            &required_cap,
            &req.operation,
            &resource_uris,
        )?;

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Matrix client".into(),
        })?;

        let output = match operation {
            OP_JOINED_ROOMS => {
                let rooms = client.joined_rooms().await.map_err(|e| e.to_fcp_error())?;
                json!({ "rooms": rooms })
            }
            OP_CREATE_ROOM => {
                let name = optional_str(&req.input, "name")?;
                let topic = optional_str(&req.input, "topic")?;
                let invite = optional_string_vec(&req.input, "invite")?;
                let visibility = optional_str(&req.input, "visibility")?;
                let preset = optional_str(&req.input, "preset")?;

                let create_req = CreateRoomRequest {
                    name,
                    topic,
                    room_alias_name: None,
                    invite,
                    visibility,
                    preset,
                };
                let resp = client
                    .create_room(&create_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "room_id": resp.room_id })
            }
            OP_JOIN_ROOM => {
                let room = require_str(&req.input, "room_id_or_alias")?;
                client.join_room(room).await.map_err(|e| e.to_fcp_error())?;
                json!({ "status": "joined" })
            }
            OP_LEAVE_ROOM => {
                let room_id = require_str(&req.input, "room_id")?;
                client
                    .leave_room(room_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "status": "left" })
            }
            OP_SEND_MESSAGE => {
                let room_id = require_str(&req.input, "room_id")?;
                let body = require_str(&req.input, "body")?;
                let msgtype =
                    optional_str(&req.input, "msgtype")?.unwrap_or_else(|| "m.text".to_string());
                let resp = client
                    .send_message(room_id, body, &msgtype)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "event_id": resp.event_id })
            }
            OP_GET_MESSAGES => {
                let room_id = require_str(&req.input, "room_id")?;
                let from = optional_str(&req.input, "from")?;
                let limit = optional_u32(&req.input, "limit", 20)?;
                let resp = client
                    .get_messages(room_id, from.as_deref(), limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "messages": resp.chunk,
                    "end": resp.end,
                })
            }
            OP_SYNC => {
                let explicit_since = optional_str(&req.input, "since")?;
                let timeout_ms = optional_u32(&req.input, "timeout_ms", 30_000)?;
                let persist = optional_bool(&req.input, "persist", true)?;
                let inbound_policy = self
                    .config
                    .as_ref()
                    .map_or_else(MatrixInboundPolicy::default, |config| {
                        config.inbound_policy.clone()
                    });
                let used_since = explicit_since.or_else(|| {
                    self.sync_state
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .last_sync_token
                        .clone()
                });

                let sync_started = Instant::now();
                let response = match client.sync(used_since.as_deref(), timeout_ms).await {
                    Ok(response) => response,
                    Err(error) => {
                        self.record_sync_failure(
                            used_since.as_deref(),
                            persist,
                            &error,
                            sync_started.elapsed(),
                        );
                        return Err(error.to_fcp_error());
                    }
                };
                let projection = project_sync_response_with_policy(&response, &inbound_policy);
                let tracked_state = if persist {
                    {
                        let mut state = self
                            .sync_state
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.last_sync_token = Some(response.next_batch.clone());
                        for (room_id, summary) in &projection.tracked_updates {
                            state.rooms.insert(room_id.clone(), summary.clone());
                        }
                    }
                    self.tracked_state_json()
                } else {
                    self.preview_tracked_state_json(
                        &response.next_batch,
                        &projection.tracked_updates,
                    )
                };
                let duration = sync_started.elapsed();
                self.record_sync_success(
                    used_since.as_deref(),
                    &response.next_batch,
                    persist,
                    &projection,
                    duration,
                );
                info!(
                    event = "matrix.sync",
                    persisted = persist,
                    duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
                    room_summaries = projection.room_summaries.len(),
                    message_events = projection.message_events.len(),
                    authorized_message_events = projection.authorized_message_events.len(),
                    dropped_events = projection.dropped_events.len(),
                    reaction_events = projection.reaction_events.len(),
                    encrypted_events = projection.encrypted_events.len(),
                    membership_changes = projection.membership_changes.len(),
                    state_changes = projection.state_changes.len(),
                    "Matrix sync cycle completed"
                );

                json!({
                    "used_since": used_since,
                    "next_batch": response.next_batch,
                    "persisted": persist,
                    "rooms": projection.room_summaries,
                    "message_events": projection.message_events,
                    "authorized_message_events": projection.authorized_message_events,
                    "dropped_events": projection.dropped_events,
                    "reaction_events": projection.reaction_events,
                    "encrypted_events": projection.encrypted_events,
                    "membership_changes": projection.membership_changes,
                    "state_changes": projection.state_changes,
                    "inbound_policy": inbound_policy_snapshot(&inbound_policy),
                    "tracked_state": tracked_state,
                })
            }
            OP_GET_ROOM_STATE => {
                let room_id = require_str(&req.input, "room_id")?;
                let events = client
                    .get_room_state(room_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let existing_membership = self
                    .sync_state
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .rooms
                    .get(room_id)
                    .map_or_else(
                        || "unknown".to_string(),
                        |summary| summary.membership.clone(),
                    );
                let summary = summarize_room(room_id, &existing_membership, &events);
                self.sync_state
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .rooms
                    .insert(room_id.to_string(), summary.clone());
                json!({
                    "room_id": room_id,
                    "summary": summary.snapshot_json(room_id),
                    "state_events": events,
                })
            }
            OP_LIST_MEMBERS => {
                let room_id = require_str(&req.input, "room_id")?;
                let membership = optional_str(&req.input, "membership")?;
                let events = client
                    .list_members(room_id, membership.as_deref())
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let mut summary =
                    summarize_room(room_id, membership.as_deref().unwrap_or("unknown"), &events);
                summary.member_count = Some(events.len());
                self.sync_state
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .rooms
                    .insert(room_id.to_string(), summary.clone());
                json!({
                    "room_id": room_id,
                    "members": events.iter().map(|event| normalize_membership_event(room_id, event)).collect::<Vec<_>>(),
                    "summary": summary.snapshot_json(room_id),
                })
            }
            OP_UPLOAD_MEDIA => {
                let content_type = require_str(&req.input, "content_type")?;
                let body_base64 = require_str(&req.input, "body_base64")?;
                let filename = optional_str(&req.input, "filename")?;
                let data = base64::engine::general_purpose::STANDARD
                    .decode(body_base64)
                    .map_err(|error| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("body_base64 must be valid base64: {error}"),
                    })?;
                let response = client
                    .upload_media(content_type, data, filename.as_deref())
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "content_uri": response.content_uri,
                })
            }
            OP_DOWNLOAD_MEDIA => {
                let mxc_uri = optional_str(&req.input, "mxc_uri")?;
                let allow_remote = optional_bool(&req.input, "allow_remote", true)?;
                let (server_name, media_id) = if let Some(uri) = mxc_uri {
                    parse_mxc_uri(&uri)?
                } else {
                    (
                        require_str(&req.input, "server_name")?.to_string(),
                        require_str(&req.input, "media_id")?.to_string(),
                    )
                };
                let media = client
                    .download_media(&server_name, &media_id, allow_remote)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "content_type": media.content_type,
                    "content_disposition": media.content_disposition,
                    "size_bytes": media.data.len(),
                    "data_base64": base64::engine::general_purpose::STANDARD.encode(media.data),
                })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

    /// Generate a matched signing key + public key bytes for test handshake/invoke pairs.
    fn test_signing_key() -> Ed25519SigningKey {
        Ed25519SigningKey::generate()
    }

    /// Build a capability token signed by the given key for zone z:work.
    /// Grants `CAP_READ` with all operation names listed so read-path invoke
    /// calls pass verification. For write/manage operations, a separate token
    /// with the matching `capability_id` would be needed.
    fn test_token_for_key(
        signing_key: &Ed25519SigningKey,
        instance_id: &fcp_core::InstanceId,
    ) -> CapabilityToken {
        test_token_for_key_with_resources(signing_key, &["*"], instance_id)
    }

    fn test_token_for_key_with_resources(
        signing_key: &Ed25519SigningKey,
        resource_allow: &[&str],
        instance_id: &fcp_core::InstanceId,
    ) -> CapabilityToken {
        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: resource_allow
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1);
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id(CAP_READ)
            .zone_id("z:work")
            .principal("test-principal")
            .issuer("node:test")
            .validity(now, expires)
            .target_instance(instance_id.as_str())
            .operations(&[
                OP_JOINED_ROOMS,
                OP_GET_MESSAGES,
                OP_SYNC,
                OP_GET_ROOM_STATE,
                OP_LIST_MEMBERS,
                OP_DOWNLOAD_MEDIA,
                OP_SEND_MESSAGE,
                OP_UPLOAD_MEDIA,
                OP_CREATE_ROOM,
                OP_JOIN_ROOM,
                OP_LEAVE_ROOM,
            ])
            .try_constraints_cbor(&cbor)
            .expect("valid test constraints")
            .sign(signing_key)
            .expect("Failed to create test token");
        CapabilityToken::from_raw(cose_token)
    }

    /// Configure and handshake with a real key pair so invoke token verification succeeds.
    async fn configure_and_handshake_with_key(
        c: &mut MatrixConnector,
        homeserver_url: &str,
        signing_key: &Ed25519SigningKey,
        caps: Vec<CapabilityId>,
    ) {
        c.configure(json!({
            "homeserver_url": homeserver_url,
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .unwrap();
        c.handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [0u8; 32],
            capabilities_requested: caps,
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .unwrap();
    }

    fn sync_invoke_request_with_key(
        connector: &MatrixConnector,
        input: serde_json::Value,
        signing_key: &Ed25519SigningKey,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_sync"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_SYNC),
            zone_id: ZoneId::work(),
            input,
            capability_token: test_token_for_key(signing_key, &connector.base.instance_id),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    #[test]
    fn operations_count() {
        assert_eq!(operations_info().len(), 11);
    }

    #[test]
    fn operations_have_hints() {
        for op in &operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn send_message_is_risky() {
        let ops = operations_info();
        let send = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
    }

    #[test]
    fn read_ops_are_safe() {
        let ops = operations_info();
        let rooms = ops
            .iter()
            .find(|op| op.id.as_str() == OP_JOINED_ROOMS)
            .unwrap();
        assert_eq!(rooms.safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn introspection() {
        let c = MatrixConnector::new();
        let intro = c.introspect();
        assert_eq!(intro.operations.len(), 11);
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[test]
    fn sync_and_media_operations_have_expected_safety_tiers() {
        let ops = operations_info();
        let sync = ops.iter().find(|op| op.id.as_str() == OP_SYNC).unwrap();
        let upload = ops
            .iter()
            .find(|op| op.id.as_str() == OP_UPLOAD_MEDIA)
            .unwrap();
        let download = ops
            .iter()
            .find(|op| op.id.as_str() == OP_DOWNLOAD_MEDIA)
            .unwrap();

        assert_eq!(sync.safety_tier, SafetyTier::Safe);
        assert_eq!(upload.safety_tier, SafetyTier::Risky);
        assert_eq!(download.safety_tier, SafetyTier::Safe);
    }

    #[fcp_async_core::runtime::test]
    async fn configure_access_token() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "access_token", "access_token": "syt_abc" }
            }))
            .await;
        assert!(result.is_ok());
        assert!(c.config.is_some());
        assert!(c.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_credential_id() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "credential_id", "credential_id": "cred_1" }
            }))
            .await;
        assert!(result.is_ok());
        assert!(c.client.as_ref().unwrap().is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_invalid() {
        let mut c = MatrixConnector::new();
        assert!(c.configure(json!({})).await.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_non_http_scheme() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "ftp://matrix.org",
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await;
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("http://") || msg.contains("https://"),
            "Error should mention required scheme, got: {msg}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_url() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "not a url at all",
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_javascript_scheme() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "javascript:alert(1)",
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_before_configure() {
        let c = MatrixConnector::new();
        let h = c.health().await;
        assert!(matches!(h.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn health_after_configure() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .unwrap();
        let h = c.health().await;
        assert!(matches!(h.status, HealthState::Ready));
        assert_eq!(
            h.details
                .as_ref()
                .and_then(|details| details["provisioning"]["auth_mode"].as_str()),
            Some("access_token")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_degrades_for_secretless_runtime() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "credential_id", "credential_id": "cred_1" }
        }))
        .await
        .unwrap();

        let h = c.health().await;
        assert!(matches!(
            h.status,
            HealthState::Degraded { ref reason } if reason == "credential injection required"
        ));
        assert_eq!(
            h.details.as_ref().and_then(|details| {
                details["provisioning"]["credential_injection_required"].as_bool()
            }),
            Some(true)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_degrades_for_remote_http_homeserver() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "http://matrix.example.test",
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .unwrap();

        let h = c.health().await;
        assert!(matches!(
            h.status,
            HealthState::Degraded { ref reason } if reason.contains("plain HTTP")
        ));
    }

    #[test]
    fn doctor_before_configure() {
        let c = MatrixConnector::new();
        let d = c.doctor();
        assert!(!d["passed"].as_bool().unwrap());
        assert_eq!(d["details"]["configured"].as_bool(), Some(false));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_after_configure() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .unwrap();
        let d = c.doctor();
        assert!(d["passed"].as_bool().unwrap());
        assert_eq!(
            d["details"]["provisioning"]["auth_mode"].as_str(),
            Some("access_token")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_surfaces_secretless_guidance_without_failing() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "credential_id", "credential_id": "cred_1" }
        }))
        .await
        .unwrap();

        let d = c.doctor();
        assert!(d["passed"].as_bool().unwrap());
        assert_eq!(
            d["details"]["provisioning"]["credential_injection_required"].as_bool(),
            Some(true)
        );
        assert_eq!(
            d["details"]["provisioning"]["sync_delivery_model"].as_str(),
            Some("manual_sync_only")
        );
        assert!(d["checks"].as_array().unwrap().iter().any(|check| {
            check["name"].as_str() == Some("credential_injection")
                && check["passed"].as_bool() == Some(false)
        }));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake() {
        let mut c = MatrixConnector::new();
        let req = HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
                CapabilityId::from_static(CAP_MANAGE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };
        let result = c.handshake(req).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status, "accepted");
    }

    #[test]
    fn manifest_hash_deterministic() {
        let h1 = MatrixConnector::manifest_hash();
        let h2 = MatrixConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_before_configure() {
        let c = MatrixConnector::new();
        let r = c.self_check().await.unwrap();
        assert_eq!(r.status, SelfCheckStatus::Degraded);
        assert_eq!(r.reason_code.as_deref(), Some("not_configured"));
        assert_eq!(
            r.details
                .as_ref()
                .and_then(|details| details["configured"].as_bool()),
            Some(false)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_secretless_runtime_requires_injection() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "credential_id", "credential_id": "cred_1" }
        }))
        .await
        .unwrap();

        let report = c.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("credential_injection_required")
        );
        assert_eq!(
            report.details.as_ref().and_then(|details| {
                details["provisioning"]["credential_injection_required"].as_bool()
            }),
            Some(true)
        );
    }

    #[test]
    fn optional_create_room_fields_reject_invalid_types() {
        let err = optional_string_vec(&json!({ "invite": "not-an-array" }), "invite").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));

        let err = optional_str(&json!({ "visibility": 42 }), "visibility").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn optional_message_pagination_fields_reject_invalid_types() {
        let err = optional_str(&json!({ "from": 5 }), "from").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));

        let err = optional_u32(&json!({ "limit": "many" }), "limit", 20).unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn optional_bool_rejects_invalid_types() {
        let err = optional_bool(&json!({ "persist": "yes" }), "persist", true).unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn parse_mxc_uri_requires_full_identifier() {
        let parsed = parse_mxc_uri("mxc://matrix.org/media123").unwrap();
        assert_eq!(parsed, ("matrix.org".to_string(), "media123".to_string()));
        assert!(parse_mxc_uri("mxc://matrix.org").is_err());
        assert!(parse_mxc_uri("https://matrix.org/media123").is_err());
    }

    #[test]
    fn resource_uris_bind_room_and_media_targets() {
        let join_alias = resource_uris_for_operation(
            OP_JOIN_ROOM,
            &json!({ "room_id_or_alias": "#general:matrix.org" }),
        )
        .unwrap();
        assert_eq!(join_alias, vec!["matrix:room_alias:#general:matrix.org"]);

        let media = resource_uris_for_operation(
            OP_DOWNLOAD_MEDIA,
            &json!({ "mxc_uri": "mxc://matrix.org/media123" }),
        )
        .unwrap();
        assert_eq!(media, vec!["matrix:media:matrix.org/media123"]);
    }

    #[test]
    fn project_sync_response_translates_room_deltas() {
        let sync = SyncResponse {
            next_batch: "batch_2".into(),
            rooms: crate::types::SyncRooms {
                join: BTreeMap::from([(
                    "!room:matrix.org".to_string(),
                    crate::types::JoinedSyncRoom {
                        state: crate::types::SyncEventList {
                            events: vec![
                                Event {
                                    event_id: Some("$state1".into()),
                                    r#type: "m.room.name".into(),
                                    state_key: Some(String::new()),
                                    sender: Some("@bot:matrix.org".into()),
                                    origin_server_ts: Some(100),
                                    content: json!({ "name": "General" }),
                                    room_id: Some("!room:matrix.org".into()),
                                },
                                Event {
                                    event_id: Some("$member1".into()),
                                    r#type: "m.room.member".into(),
                                    state_key: Some("@alice:matrix.org".into()),
                                    sender: Some("@alice:matrix.org".into()),
                                    origin_server_ts: Some(110),
                                    content: json!({ "membership": "join", "displayname": "Alice" }),
                                    room_id: Some("!room:matrix.org".into()),
                                },
                            ],
                        },
                        timeline: crate::types::SyncTimeline {
                            events: vec![Event {
                                event_id: Some("$msg1".into()),
                                r#type: "m.room.message".into(),
                                state_key: None,
                                sender: Some("@alice:matrix.org".into()),
                                origin_server_ts: Some(120),
                                content: json!({ "msgtype": "m.text", "body": "Hello" }),
                                room_id: Some("!room:matrix.org".into()),
                            }],
                            prev_batch: Some("prev".into()),
                            limited: false,
                        },
                    },
                )]),
                ..crate::types::SyncRooms::default()
            },
        };

        let projection = project_sync_response(&sync);
        assert_eq!(projection.room_summaries.len(), 1);
        assert_eq!(projection.message_events.len(), 1);
        assert_eq!(projection.membership_changes.len(), 1);
        assert_eq!(projection.state_changes.len(), 1);
        assert_eq!(
            projection
                .tracked_updates
                .get("!room:matrix.org")
                .and_then(|summary| summary.name.as_deref()),
            Some("General")
        );
        assert_eq!(
            projection
                .tracked_updates
                .get("!room:matrix.org")
                .map(|summary| summary.membership.as_str()),
            Some("join")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn project_sync_response_applies_inbound_policy() {
        let sync = SyncResponse {
            next_batch: "batch_2".into(),
            rooms: crate::types::SyncRooms {
                join: BTreeMap::from([(
                    "!ops:matrix.org".to_string(),
                    crate::types::JoinedSyncRoom {
                        state: crate::types::SyncEventList::default(),
                        timeline: crate::types::SyncTimeline {
                            events: vec![
                                Event {
                                    event_id: Some("$authorized".into()),
                                    r#type: "m.room.message".into(),
                                    state_key: None,
                                    sender: Some("@alice:matrix.org".into()),
                                    origin_server_ts: Some(120),
                                    content: json!({
                                        "msgtype": "m.text",
                                        "body": "hi @bot:matrix.org",
                                        "m.mentions": {
                                            "user_ids": ["@bot:matrix.org"]
                                        }
                                    }),
                                    room_id: Some("!ops:matrix.org".into()),
                                },
                                Event {
                                    event_id: Some("$unmentioned".into()),
                                    r#type: "m.room.message".into(),
                                    state_key: None,
                                    sender: Some("@alice:matrix.org".into()),
                                    origin_server_ts: Some(130),
                                    content: json!({
                                        "msgtype": "m.text",
                                        "body": "ambient room chatter"
                                    }),
                                    room_id: Some("!ops:matrix.org".into()),
                                },
                                Event {
                                    event_id: Some("$denied_sender".into()),
                                    r#type: "m.room.message".into(),
                                    state_key: None,
                                    sender: Some("@mallory:matrix.org".into()),
                                    origin_server_ts: Some(140),
                                    content: json!({
                                        "msgtype": "m.text",
                                        "body": "@bot:matrix.org please act"
                                    }),
                                    room_id: Some("!ops:matrix.org".into()),
                                },
                                Event {
                                    event_id: Some("$reaction".into()),
                                    r#type: "m.reaction".into(),
                                    state_key: None,
                                    sender: Some("@alice:matrix.org".into()),
                                    origin_server_ts: Some(150),
                                    content: json!({
                                        "m.relates_to": {
                                            "rel_type": "m.annotation",
                                            "event_id": "$authorized",
                                            "key": "approve"
                                        }
                                    }),
                                    room_id: Some("!ops:matrix.org".into()),
                                },
                                Event {
                                    event_id: Some("$encrypted".into()),
                                    r#type: "m.room.encrypted".into(),
                                    state_key: None,
                                    sender: Some("@alice:matrix.org".into()),
                                    origin_server_ts: Some(160),
                                    content: json!({
                                        "algorithm": "m.megolm.v1.aes-sha2",
                                        "session_id": "session-1",
                                        "ciphertext": "redacted in policy projection"
                                    }),
                                    room_id: Some("!ops:matrix.org".into()),
                                },
                            ],
                            prev_batch: Some("prev".into()),
                            limited: false,
                        },
                    },
                )]),
                ..crate::types::SyncRooms::default()
            },
        };
        let policy = MatrixInboundPolicy {
            allowed_users: vec!["@alice:matrix.org".into()],
            bot_user_id: Some("@bot:matrix.org".into()),
            require_mention: true,
            free_response_rooms: Vec::new(),
            process_reactions: true,
            encrypted_events: MatrixEncryptedEventPolicy::FailClosed,
        };

        let projection = project_sync_response_with_policy(&sync, &policy);

        assert_eq!(projection.message_events.len(), 3);
        assert_eq!(projection.authorized_message_events.len(), 1);
        assert_eq!(
            projection.authorized_message_events[0]["event_id"].as_str(),
            Some("$authorized")
        );
        assert_eq!(projection.reaction_events.len(), 1);
        assert_eq!(
            projection.reaction_events[0]["target_event_id"].as_str(),
            Some("$authorized")
        );
        assert_eq!(projection.encrypted_events.len(), 1);
        assert_eq!(
            projection.encrypted_events[0]["delivery_policy"].as_str(),
            Some("fail_closed")
        );

        let dropped_reasons = projection
            .dropped_events
            .iter()
            .map(|event| event["reason"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(dropped_reasons.contains(&"mention_required"));
        assert!(dropped_reasons.contains(&"sender_not_allowed"));
        assert!(dropped_reasons.contains(&"encrypted_event_fail_closed"));
        assert!(
            projection
                .dropped_events
                .iter()
                .all(|event| event.get("content").is_none())
        );
    }

    #[test]
    fn summarize_room_keeps_explicit_membership_label() {
        let summary = summarize_room(
            "!room:matrix.org",
            "join",
            &[Event {
                event_id: Some("$member2".into()),
                r#type: "m.room.member".into(),
                state_key: Some("@bob:matrix.org".into()),
                sender: Some("@bob:matrix.org".into()),
                origin_server_ts: Some(200),
                content: json!({ "membership": "leave" }),
                room_id: Some("!room:matrix.org".into()),
            }],
        );

        assert_eq!(summary.membership, "join");
        assert_eq!(summary.member_count, Some(0));
    }

    #[test]
    fn preview_tracked_state_applies_non_persistent_sync_delta() {
        let connector = MatrixConnector::new();
        {
            let mut state = connector
                .sync_state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.last_sync_token = Some("batch_1".into());
            state.rooms.insert(
                "!old:matrix.org".into(),
                MatrixRoomSummary::with_membership("join"),
            );
        }

        let preview = connector.preview_tracked_state_json(
            "batch_2",
            &BTreeMap::from([(
                "!new:matrix.org".to_string(),
                MatrixRoomSummary::with_membership("invite"),
            )]),
        );

        assert_eq!(preview["last_sync_token"], "batch_2");
        assert_eq!(preview["tracked_rooms"], 2);
        assert!(
            preview["rooms"]
                .as_array()
                .unwrap()
                .iter()
                .any(|room| room["room_id"] == "!new:matrix.org" && room["membership"] == "invite")
        );

        let persisted = connector.tracked_state_json();
        assert_eq!(persisted["last_sync_token"], "batch_1");
        assert_eq!(persisted["tracked_rooms"], 1);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_handshake_after_configuration() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .unwrap();

        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: c.id().clone(),
            operation: OperationId::from_static(OP_JOINED_ROOMS),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let err = c.invoke(req).await.unwrap_err();
        assert!(matches!(err, FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_rejects_room_outside_resource_allow() {
        let signing_key = test_signing_key();
        let mut connector = MatrixConnector::new();
        configure_and_handshake_with_key(
            &mut connector,
            "https://matrix.org",
            &signing_key,
            vec![CapabilityId::from_static(CAP_READ)],
        )
        .await;

        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_room_scope"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_GET_MESSAGES),
            zone_id: ZoneId::work(),
            input: json!({ "room_id": "!denied:matrix.org" }),
            capability_token: test_token_for_key_with_resources(
                &signing_key,
                &["matrix:room:!allowed:matrix.org"],
                &connector.base.instance_id,
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let err = connector.invoke(req).await.unwrap_err();
        assert!(matches!(
            err,
            FcpError::ResourceNotAllowed { resource }
                if resource == "matrix:room:!denied:matrix.org"
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unauthorized_is_failed() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/_matrix/client/v3/account/whoami",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(401).set_body_json(serde_json::json!({
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Unrecognised access token."
                })),
            )
            .mount(&mock)
            .await;

        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": mock.uri(),
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .unwrap();

        let report = c.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("token_invalid_or_expired")
        );
        assert!(
            report
                .message
                .as_deref()
                .is_some_and(|message| message.contains("Unrecognised access token."))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn sync_records_success_telemetry() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_matrix/client/v3/sync"))
            .and(wiremock::matchers::query_param("timeout", "1000"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "next_batch": "batch_2",
                    "rooms": {
                        "join": {
                            "!room:matrix.org": {
                                "state": {
                                    "events": [
                                        {
                                            "event_id": "$state1",
                                            "type": "m.room.name",
                                            "state_key": "",
                                            "sender": "@bot:matrix.org",
                                            "origin_server_ts": 100,
                                            "content": { "name": "General" },
                                            "room_id": "!room:matrix.org"
                                        },
                                        {
                                            "event_id": "$member1",
                                            "type": "m.room.member",
                                            "state_key": "@alice:matrix.org",
                                            "sender": "@alice:matrix.org",
                                            "origin_server_ts": 110,
                                            "content": { "membership": "join", "displayname": "Alice" },
                                            "room_id": "!room:matrix.org"
                                        }
                                    ]
                                },
                                "timeline": {
                                    "events": [
                                        {
                                            "event_id": "$msg1",
                                            "type": "m.room.message",
                                            "sender": "@alice:matrix.org",
                                            "origin_server_ts": 120,
                                            "content": { "msgtype": "m.text", "body": "Hello" },
                                            "room_id": "!room:matrix.org"
                                        }
                                    ]
                                }
                            }
                        }
                    }
                })),
            )
            .mount(&mock)
            .await;

        let key = test_signing_key();
        let mut c = MatrixConnector::new();
        configure_and_handshake_with_key(
            &mut c,
            &mock.uri(),
            &key,
            vec![CapabilityId::from_static(CAP_READ)],
        )
        .await;

        let response = c
            .invoke(sync_invoke_request_with_key(
                &c,
                json!({ "timeout_ms": 1000 }),
                &key,
            ))
            .await
            .unwrap();
        let result = response.result.unwrap();
        assert_eq!(result["next_batch"].as_str(), Some("batch_2"));
        assert_eq!(
            result["authorized_message_events"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(result["dropped_events"].as_array().unwrap().len(), 1);
        assert_eq!(result["reaction_events"].as_array().unwrap().len(), 0);
        assert_eq!(result["encrypted_events"].as_array().unwrap().len(), 0);
        assert_eq!(
            result["dropped_events"][0]["reason"].as_str(),
            Some("mention_required")
        );
        assert_eq!(
            result["inbound_policy"]["encrypted_events"].as_str(),
            Some("fail_closed")
        );

        let doctor = c.doctor();
        assert_eq!(
            doctor["sync_tracking"]["successful_syncs"].as_u64(),
            Some(1)
        );
        assert_eq!(doctor["sync_tracking"]["failed_syncs"].as_u64(), Some(0));
        assert_eq!(
            doctor["sync_tracking"]["last_status"].as_str(),
            Some("success")
        );
        assert_eq!(
            doctor["sync_tracking"]["last_next_batch"].as_str(),
            Some("batch_2")
        );
        assert_eq!(
            doctor["sync_tracking"]["last_room_summary_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            doctor["sync_tracking"]["last_message_event_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            doctor["sync_tracking"]["last_membership_change_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            doctor["sync_tracking"]["last_state_change_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            doctor["sync_tracking"]["last_authorized_message_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            doctor["sync_tracking"]["last_dropped_event_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            doctor["sync_tracking"]["last_reaction_event_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            doctor["sync_tracking"]["last_encrypted_event_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            doctor["sync_tracking"]["last_persisted"].as_bool(),
            Some(true)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn sync_records_failure_telemetry() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_matrix/client/v3/sync"))
            .and(wiremock::matchers::query_param("since", "batch_1"))
            .and(wiremock::matchers::query_param("timeout", "1000"))
            .respond_with(
                wiremock::ResponseTemplate::new(429)
                    .insert_header("retry-after", "60")
                    .set_body_string("rate limited"),
            )
            .mount(&mock)
            .await;

        let key = test_signing_key();
        let mut c = MatrixConnector::new();
        configure_and_handshake_with_key(
            &mut c,
            &mock.uri(),
            &key,
            vec![CapabilityId::from_static(CAP_READ)],
        )
        .await;

        let error = c
            .invoke(sync_invoke_request_with_key(
                &c,
                json!({ "since": "batch_1", "timeout_ms": 1000, "persist": false }),
                &key,
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, FcpError::RateLimited { .. }));

        let doctor = c.doctor();
        assert_eq!(
            doctor["sync_tracking"]["successful_syncs"].as_u64(),
            Some(0)
        );
        assert_eq!(doctor["sync_tracking"]["failed_syncs"].as_u64(), Some(1));
        assert_eq!(
            doctor["sync_tracking"]["last_status"].as_str(),
            Some("failed")
        );
        assert_eq!(
            doctor["sync_tracking"]["last_used_since"].as_str(),
            Some("batch_1")
        );
        assert_eq!(
            doctor["sync_tracking"]["last_persisted"].as_bool(),
            Some(false)
        );
        assert!(
            doctor["sync_tracking"]["last_error"]
                .as_str()
                .is_some_and(|message| message.contains("Rate limited"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate() {
        let c = MatrixConnector::new();
        let req = SimulateRequest::new(
            c.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = c.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }
}
