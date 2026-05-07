//! Matrix connector implementation.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use fcp_async_core::channel::{broadcast, watch};
use fcp_async_core::task::JoinHandle;
use fcp_prelude::{
    BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId, EventCaps,
    EventData, EventEnvelope, EventInfo, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, OrderingPolicy, Principal, ReplayBufferInfo, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeResult, ThreadInfo, ThreadKind,
    TrustLevel, ZoneId,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use fcp_sdk::runtime::SupervisorConfig;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::client::MatrixClient;
use crate::crypto::{
    MatrixCryptoEngine, MatrixEncryptedEventProjectionContext, MatrixEncryptedEventRedactionState,
    MatrixTrustGatedDecryptedProjection, MatrixVerifiedDecryptedMessageEvent,
    key_share_after_initial_sync_snapshot, maintenance_driver_snapshot,
    project_trust_gated_decrypted_event, recovery_guidance_snapshot,
    undecrypted_retry_decision_snapshot,
};
use crate::error::MatrixError;
use crate::types::{
    CreateRoomRequest, Event, InvitedSyncRoom, JoinedSyncRoom, LeftSyncRoom, MatrixAuth,
    MatrixConfig, MatrixE2eeConfig, MatrixE2eeDeviceListStatus, MatrixE2eeMaterialStatus,
    MatrixEncryptedEventPolicy, MatrixInboundPolicy, MatrixStatePersistenceBackend,
    MatrixStatePersistenceConfig, MatrixSupervisedSyncConfig, SyncResponse,
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
const OPERATION_ORDER: [&str; 11] = [
    OP_JOINED_ROOMS,
    OP_CREATE_ROOM,
    OP_JOIN_ROOM,
    OP_LEAVE_ROOM,
    OP_SEND_MESSAGE,
    OP_GET_MESSAGES,
    OP_SYNC,
    OP_GET_ROOM_STATE,
    OP_LIST_MEMBERS,
    OP_UPLOAD_MEDIA,
    OP_DOWNLOAD_MEDIA,
];

const CAP_READ: &str = "matrix.read";
const CAP_WRITE: &str = "matrix.write";
const CAP_MANAGE: &str = "matrix.manage";

const EVENT_MESSAGE_AUTHORIZED: &str = "matrix.message.authorized";
const EVENT_MESSAGE_DECRYPTED: &str = "matrix.message.decrypted";
const EVENT_DROPPED: &str = "matrix.event.dropped";
const EVENT_REACTION: &str = "matrix.reaction";
const EVENT_ENCRYPTED: &str = "matrix.encrypted";
const MATRIX_EVENT_BUFFER_CAPACITY: usize = 200;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MatrixRoomSummary {
    membership: String,
    name: Option<String>,
    topic: Option<String>,
    avatar_url: Option<String>,
    member_count: Option<usize>,
    last_event_ts: Option<u64>,
    joined_user_ids: BTreeSet<String>,
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
            "m.room.member" => {
                if let Some(user_id) = event.state_key.as_deref() {
                    match event
                        .content
                        .get("membership")
                        .and_then(serde_json::Value::as_str)
                    {
                        Some("join") => {
                            self.joined_user_ids.insert(user_id.to_string());
                        }
                        Some("ban" | "invite" | "knock" | "leave") => {
                            self.joined_user_ids.remove(user_id);
                        }
                        _ => {}
                    }
                    self.member_count = Some(self.joined_user_ids.len());
                }
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
    decrypted_message_events: Vec<serde_json::Value>,
    dropped_events: Vec<serde_json::Value>,
    reaction_events: Vec<serde_json::Value>,
    encrypted_events: Vec<serde_json::Value>,
    tracked_updates: BTreeMap<String, MatrixRoomSummary>,
    dynamic_direct_message_rooms: BTreeSet<String>,
    thread_participation_roots: BTreeSet<String>,
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
    last_decrypted_message_count: usize,
    last_dropped_event_count: usize,
    last_reaction_event_count: usize,
    last_encrypted_event_count: usize,
    last_emitted_event_count: usize,
}

#[derive(Debug, Default)]
struct MatrixSyncState {
    last_sync_cursor: Option<String>,
    rooms: BTreeMap<String, MatrixRoomSummary>,
    dynamic_direct_message_rooms: BTreeSet<String>,
    thread_participation_roots: BTreeSet<String>,
    emitted_event_keys: BTreeSet<String>,
    telemetry: MatrixSyncTelemetry,
}

#[derive(Debug, Default)]
struct MatrixSupervisedSyncStatus {
    configured_enabled: bool,
    running: bool,
    total_polls: u64,
    successful_polls: u64,
    failed_polls: u64,
    emitted_events: u64,
    consecutive_failures: u32,
    last_status: Option<String>,
    last_error: Option<String>,
    last_used_since: Option<String>,
    last_next_batch: Option<String>,
    last_duration_ms: Option<u64>,
    last_stop_reason: Option<String>,
}

#[derive(Debug, Default)]
struct MatrixSupervisedSyncControl {
    shutdown_tx: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct MatrixSupervisedSyncWorker {
    connector_id: ConnectorId,
    instance_id: InstanceId,
    client: MatrixClient,
    policy: MatrixInboundPolicy,
    e2ee: MatrixE2eeConfig,
    state_persistence: MatrixStatePersistenceConfig,
    config: MatrixSupervisedSyncConfig,
    sync_state: Arc<RwLock<MatrixSyncState>>,
    status: Arc<RwLock<MatrixSupervisedSyncStatus>>,
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    next_event_seq: Arc<AtomicU64>,
    subscribed_topics: Arc<RwLock<Vec<String>>>,
}

const fn auth_mode_label(auth: &MatrixAuth) -> &'static str {
    match auth {
        MatrixAuth::AccessToken { .. } => "access_token",
        MatrixAuth::CredentialId { .. } => "credential_id",
    }
}

const fn state_persistence_backend_label(backend: MatrixStatePersistenceBackend) -> &'static str {
    match backend {
        MatrixStatePersistenceBackend::InMemory => "in_memory",
        MatrixStatePersistenceBackend::HostManagedSnapshot => "host_managed_snapshot",
    }
}

fn redacted_identifier_snapshot(value: Option<&str>) -> serde_json::Value {
    value.map_or_else(
        || json!({ "configured": false }),
        |value| {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            json!({
                "configured": true,
                "sha256": format!("sha256:{}", hex::encode(hasher.finalize())),
            })
        },
    )
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

fn default_matrix_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_matrix_chat_coordination_config(
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

fn matrix_coordination_audit_records(
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

/// Matrix connector.
pub struct MatrixConnector {
    base: BaseConnector,
    config: Option<MatrixConfig>,
    client: Option<MatrixClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    sync_state: Arc<RwLock<MatrixSyncState>>,
    supervised_sync_status: Arc<RwLock<MatrixSupervisedSyncStatus>>,
    supervised_sync_control: Mutex<MatrixSupervisedSyncControl>,
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    next_event_seq: Arc<AtomicU64>,
    subscribed_topics: Arc<RwLock<Vec<String>>>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
}

impl std::fmt::Debug for MatrixConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixConnector")
            .field("base", &self.base)
            .field("config", &self.config)
            .field("client", &self.client)
            .field("runtime", &self.runtime)
            .field("retry_config", &self.retry_config)
            .field("started_at", &self.started_at)
            .field("verifier", &self.verifier)
            .field("sync_state", &self.sync_state)
            .field("supervised_sync_status", &self.supervised_sync_status)
            .field("supervised_sync_control", &self.supervised_sync_control)
            .field("event_tx", &self.event_tx)
            .field("next_event_seq", &self.next_event_seq)
            .field("subscribed_topics", &self.subscribed_topics)
            .field("chat_coordination_config", &self.chat_coordination_config)
            .field("thread_ownership_checker", &"<thread-ownership-checker>")
            .finish()
    }
}

impl MatrixConnector {
    /// Create a new connector.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(MATRIX_EVENT_BUFFER_CAPACITY);
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.matrix")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
            sync_state: Arc::new(RwLock::new(MatrixSyncState::default())),
            supervised_sync_status: Arc::new(RwLock::new(MatrixSupervisedSyncStatus::default())),
            supervised_sync_control: Mutex::new(MatrixSupervisedSyncControl::default()),
            event_tx,
            next_event_seq: Arc::new(AtomicU64::new(1)),
            subscribed_topics: Arc::new(RwLock::new(Vec::new())),
            chat_coordination_config: default_matrix_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
        }
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

    /// Subscribe to Matrix event envelopes emitted by persisted manual sync calls.
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<FcpResult<EventEnvelope>> {
        self.event_tx.subscribe()
    }

    /// Return the connector instance ID used for bound capability tokens and emitted events.
    #[must_use]
    pub const fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
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
                "sync_delivery_model": "manual_or_supervised_sync_event_fanout",
                "inbound_policy": inbound_policy_snapshot(&config.inbound_policy),
                "e2ee": e2ee_status_snapshot_for_config(config),
                "state_persistence": state_persistence_snapshot(&config.state_persistence),
                "supervised_sync": supervised_sync_config_snapshot(&config.supervised_sync),
                "retry_config": self.retry_config.clone(),
            })
        })
    }

    fn subscribed_topics_snapshot(&self) -> Vec<String> {
        self.subscribed_topics
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    #[allow(clippy::significant_drop_tightening)]
    fn sync_observability_snapshot(&self) -> serde_json::Value {
        let state = self
            .sync_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let telemetry = &state.telemetry;
        json!({
            "last_sync_token": state.last_sync_cursor.clone(),
            "tracked_rooms": state.rooms.len(),
            "dynamic_direct_message_rooms": state.dynamic_direct_message_rooms.iter().cloned().collect::<Vec<_>>(),
            "thread_participation_roots": state.thread_participation_roots.iter().cloned().collect::<Vec<_>>(),
            "emitted_event_dedupe_keys": state.emitted_event_keys.len(),
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
            "last_decrypted_message_count": telemetry.last_decrypted_message_count,
            "last_dropped_event_count": telemetry.last_dropped_event_count,
            "last_reaction_event_count": telemetry.last_reaction_event_count,
            "last_encrypted_event_count": telemetry.last_encrypted_event_count,
            "last_emitted_event_count": telemetry.last_emitted_event_count,
        })
    }

    fn supervised_sync_snapshot(&self) -> serde_json::Value {
        let status = self
            .supervised_sync_status
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        json!({
            "configured_enabled": status.configured_enabled,
            "running": status.running,
            "total_polls": status.total_polls,
            "successful_polls": status.successful_polls,
            "failed_polls": status.failed_polls,
            "emitted_events": status.emitted_events,
            "consecutive_failures": status.consecutive_failures,
            "last_status": status.last_status.clone(),
            "last_error": status.last_error.clone(),
            "last_used_since": status.last_used_since.clone(),
            "last_next_batch": status.last_next_batch.clone(),
            "last_duration_ms": status.last_duration_ms,
            "last_stop_reason": status.last_stop_reason.clone(),
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
            "e2ee": e2ee_status_snapshot_for_optional_config(self.config.as_ref()),
            "state_persistence": self.config.as_ref().map(|config| {
                state_persistence_snapshot(&config.state_persistence)
            }),
            "supervised_sync": self.supervised_sync_snapshot(),
            "event_stream": {
                "delivery_model": "manual_or_supervised_sync_persisted_events",
                "buffer_capacity": MATRIX_EVENT_BUFFER_CAPACITY,
                "subscribed_topics": self.subscribed_topics_snapshot(),
            },
            "operator_guidance": {
                "dedicated_environment": "Use a non-production homeserver account and disposable rooms when verifying create, join, leave, send_message, and media mutations.",
                "sync_model": "Manual matrix.sync remains the fallback. If supervised_sync.enabled=true, a validated event subscription starts a bounded background sync worker that shares the same policy projection and EventEnvelope fanout.",
                "credential_injection": "credential_id mode requires the host or egress proxy to inject a bearer token before self_check can prove live readiness.",
                "state_persistence": "Durable Matrix state is host-managed: persist tracked_state outside the connector and restore it through state_persistence on configure. Connector-local disk writes remain disabled.",
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
        emitted_event_count: usize,
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
        state.telemetry.last_decrypted_message_count = projection.decrypted_message_events.len();
        state.telemetry.last_dropped_event_count = projection.dropped_events.len();
        state.telemetry.last_reaction_event_count = projection.reaction_events.len();
        state.telemetry.last_encrypted_event_count = projection.encrypted_events.len();
        state.telemetry.last_emitted_event_count = emitted_event_count;
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
        state.telemetry.last_decrypted_message_count = 0;
        state.telemetry.last_dropped_event_count = 0;
        state.telemetry.last_reaction_event_count = 0;
        state.telemetry.last_encrypted_event_count = 0;
        state.telemetry.last_emitted_event_count = 0;
    }

    fn build_event_envelope(
        &self,
        topic: &'static str,
        batch: &str,
        payload: &serde_json::Value,
    ) -> EventEnvelope {
        build_matrix_event_envelope(
            &self.base.id,
            &self.base.instance_id,
            &self.next_event_seq,
            topic,
            batch,
            payload,
        )
    }

    fn emit_projected_events(&self, batch: &str, projection: &SyncProjection) -> usize {
        let subscribed_topics = self.subscribed_topics_snapshot();
        if subscribed_topics.is_empty() {
            return 0;
        }

        let topic_groups = [
            (
                EVENT_MESSAGE_AUTHORIZED,
                projection.authorized_message_events.as_slice(),
            ),
            (
                EVENT_MESSAGE_DECRYPTED,
                projection.decrypted_message_events.as_slice(),
            ),
            (EVENT_DROPPED, projection.dropped_events.as_slice()),
            (EVENT_REACTION, projection.reaction_events.as_slice()),
            (EVENT_ENCRYPTED, projection.encrypted_events.as_slice()),
        ];

        let mut state = self
            .sync_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut emitted = 0_usize;
        for (topic, payloads) in topic_groups {
            if !subscribed_topics
                .iter()
                .any(|subscribed| subscribed == topic)
            {
                continue;
            }
            for payload in payloads {
                let dedupe_key = matrix_event_dedupe_key(topic, payload);
                if state.emitted_event_keys.contains(&dedupe_key) {
                    continue;
                }
                let envelope = self.build_event_envelope(topic, batch, payload);
                if self.event_tx.send(Ok(envelope)).is_ok() {
                    state.emitted_event_keys.insert(dedupe_key);
                    self.base.record_event();
                    emitted = emitted.saturating_add(1);
                }
            }
        }

        drop(state);
        emitted
    }

    /// Run diagnostics.
    #[must_use]
    #[allow(clippy::too_many_lines)]
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
                "state_persistence",
                true,
                if config.state_persistence.enabled {
                    "Host-managed Matrix state snapshot restore configured; connector-local disk writes remain disabled and runtime tracking continues in memory"
                } else {
                    "State persistence disabled; configure resets Matrix sync cursor, dynamic DM rooms, and participated thread roots"
                },
                false,
            ));
            if config.state_persistence.enabled {
                checks.push(doctor_check(
                    "state_persistence_scope",
                    true,
                    "Restored state is explicitly scoped to zone/account/device metadata and scope identifiers are redacted in diagnostics",
                    false,
                ));
            }
            checks.push(doctor_check(
                "sync_delivery_model",
                true,
                if config.supervised_sync.enabled {
                    "Manual matrix.sync fallback remains available; a validated event subscription starts the supervised sync worker"
                } else {
                    "Supervised sync disabled; use matrix.sync with persist=true to advance the in-memory cursor and fan out subscribed events"
                },
                false,
            ));
            let supervised_status = self
                .supervised_sync_status
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            checks.push(doctor_check(
                "supervised_sync",
                !config.supervised_sync.enabled || supervised_status.running,
                if config.supervised_sync.enabled {
                    if supervised_status.running {
                        "Supervised sync worker is running"
                    } else {
                        "Supervised sync is enabled but idle until subscribe confirms an event topic"
                    }
                } else {
                    "Supervised sync disabled by configuration"
                },
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
            checks.push(doctor_check(
                "e2ee_verified_decryption",
                !config.e2ee.verified_decryption_requested,
                if config.e2ee.verified_decryption_requested {
                    "Verified Matrix E2EE decryption was requested, but audited crypto/device trust support is not implemented; encrypted payloads remain blocked"
                } else {
                    "Verified Matrix E2EE decryption not requested; encrypted payloads remain fail-closed or metadata-only according to inbound policy"
                },
                false,
            ));
            checks.push(doctor_check(
                "migration_recovery",
                !config.e2ee.verified_decryption_requested
                    || (config.e2ee.recovery.status == MatrixE2eeMaterialStatus::Verified
                        && config.e2ee.room_key_backup.status == MatrixE2eeMaterialStatus::Verified),
                if config.e2ee.verified_decryption_requested {
                    "E2EE migration remains a structured skip until recovery material, room-key backup, device trust, and audited crypto verification are all available"
                } else {
                    "No encrypted-state migration requested; plain sync state can be restored from host-managed snapshots"
                },
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
        Self::tracked_state_json_value(
            state.last_sync_cursor.as_deref(),
            &state.rooms,
            &state.dynamic_direct_message_rooms,
            &state.thread_participation_roots,
        )
    }

    fn tracked_state_json_value(
        last_sync_token: Option<&str>,
        rooms: &BTreeMap<String, MatrixRoomSummary>,
        dynamic_direct_message_rooms: &BTreeSet<String>,
        thread_participation_roots: &BTreeSet<String>,
    ) -> serde_json::Value {
        json!({
            "last_sync_token": last_sync_token,
            "tracked_rooms": rooms.len(),
            "rooms": rooms.iter().map(|(room_id, summary)| summary.snapshot_json(room_id)).collect::<Vec<_>>(),
            "dynamic_direct_message_rooms": dynamic_direct_message_rooms.iter().cloned().collect::<Vec<_>>(),
            "thread_participation_roots": thread_participation_roots.iter().cloned().collect::<Vec<_>>(),
        })
    }

    fn preview_tracked_state_json(
        &self,
        next_batch: &str,
        projection: &SyncProjection,
    ) -> serde_json::Value {
        let mut rooms = self
            .sync_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .rooms
            .clone();
        for (room_id, summary) in &projection.tracked_updates {
            rooms.insert(room_id.clone(), summary.clone());
        }
        let state = self
            .sync_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut dynamic_direct_message_rooms = state.dynamic_direct_message_rooms.clone();
        dynamic_direct_message_rooms
            .extend(projection.dynamic_direct_message_rooms.iter().cloned());
        let mut thread_participation_roots = state.thread_participation_roots.clone();
        thread_participation_roots.extend(projection.thread_participation_roots.iter().cloned());
        drop(state);
        Self::tracked_state_json_value(
            Some(next_batch),
            &rooms,
            &dynamic_direct_message_rooms,
            &thread_participation_roots,
        )
    }

    fn validate_supervised_sync_config(config: &MatrixSupervisedSyncConfig) -> FcpResult<()> {
        if !config.enabled {
            return Ok(());
        }
        let mut errors = Vec::new();
        if config.poll_interval_ms == 0 {
            errors.push("supervised_sync.poll_interval_ms must be > 0".to_string());
        }
        if config.timeout_ms == 0 {
            errors.push("supervised_sync.timeout_ms must be > 0".to_string());
        }
        if let Err(supervisor_errors) = config.supervisor.validate() {
            errors.extend(
                supervisor_errors
                    .into_iter()
                    .map(|error| format!("supervised_sync.supervisor.{error}")),
            );
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(FcpError::InvalidRequest {
                code: 1005,
                message: errors.join("; "),
            })
        }
    }

    fn reset_supervised_sync_status(&self, config: &MatrixSupervisedSyncConfig) {
        let mut status = self
            .supervised_sync_status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *status = MatrixSupervisedSyncStatus {
            configured_enabled: config.enabled,
            running: false,
            last_status: Some(
                if config.enabled {
                    "configured"
                } else {
                    "disabled"
                }
                .into(),
            ),
            ..MatrixSupervisedSyncStatus::default()
        };
    }

    fn start_supervised_sync_if_enabled(&self) -> FcpResult<()> {
        let Some(config) = &self.config else {
            return Ok(());
        };
        if !config.supervised_sync.enabled {
            return Ok(());
        }
        let client = self.client.clone().ok_or_else(|| FcpError::Internal {
            message: "Matrix supervised sync enabled without initialized client".into(),
        })?;

        let mut control = self
            .supervised_sync_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if control
            .task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            return Ok(());
        }
        control.task = None;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker = MatrixSupervisedSyncWorker {
            connector_id: self.base.id.clone(),
            instance_id: self.base.instance_id.clone(),
            client,
            policy: config.inbound_policy.clone(),
            e2ee: config.e2ee.clone(),
            state_persistence: config.state_persistence.clone(),
            config: config.supervised_sync.clone(),
            sync_state: Arc::clone(&self.sync_state),
            status: Arc::clone(&self.supervised_sync_status),
            event_tx: self.event_tx.clone(),
            next_event_seq: Arc::clone(&self.next_event_seq),
            subscribed_topics: Arc::clone(&self.subscribed_topics),
        };
        let task = fcp_async_core::task::spawn(async move {
            worker.run(shutdown_rx).await;
        });
        control.shutdown_tx = Some(shutdown_tx);
        control.task = Some(task);
        drop(control);
        Ok(())
    }

    async fn stop_supervised_sync(&self, reason: &str) {
        let (shutdown_tx, task) = {
            let mut control = self
                .supervised_sync_control
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (control.shutdown_tx.take(), control.task.take())
        };

        if let Some(shutdown_tx) = shutdown_tx {
            let _ = shutdown_tx.send(true);
        }

        if let Some(task) = task {
            let timeout = self
                .config
                .as_ref()
                .map_or(Duration::from_secs(5), |config| {
                    config.supervised_sync.supervisor.shutdown_timeout()
                });
            if fcp_async_core::time::timeout(timeout, task).await.is_err() {
                warn!(
                    event = "matrix.supervised_sync.stop_timeout",
                    reason, "Matrix supervised sync worker did not stop before timeout"
                );
            }
        }

        let mut status = self
            .supervised_sync_status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.running = false;
        status.last_status = Some("stopped".into());
        status.last_stop_reason = Some(reason.to_string());
    }
}

impl Default for MatrixConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl MatrixSupervisedSyncWorker {
    async fn run(self, shutdown: watch::Receiver<bool>) {
        self.mark_started();
        let outcome = self.run_loop(shutdown).await;
        self.mark_stopped(&outcome);
        info!(
            event = "matrix.supervised_sync.stopped",
            outcome, "Matrix supervised sync worker stopped"
        );
    }

    async fn run_loop(&self, mut shutdown: watch::Receiver<bool>) -> String {
        let mut consecutive_failures = 0_u32;

        loop {
            if *shutdown.borrow() {
                return "shutdown".into();
            }

            let (used_since, effective_policy) = {
                let state = self
                    .sync_state
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (
                    state.last_sync_cursor.clone(),
                    inbound_policy_with_state(&self.policy, &state),
                )
            };
            let sync_started = Instant::now();

            match self
                .client
                .sync(used_since.as_deref(), self.config.timeout_ms)
                .await
            {
                Ok(response) => {
                    consecutive_failures = 0;
                    let projection = project_sync_response_with_full_context(
                        &response,
                        &effective_policy,
                        &self.e2ee,
                        &self.state_persistence,
                    );
                    self.persist_projection(&response, &projection);
                    let emitted = self.emit_projected_events(&response.next_batch, &projection);
                    self.record_success(
                        used_since.as_deref(),
                        &response.next_batch,
                        &projection,
                        emitted,
                        sync_started.elapsed(),
                    );
                    if fcp_async_core::shutdown::sleep_or_shutdown(
                        Duration::from_millis(self.config.poll_interval_ms),
                        &mut shutdown,
                    )
                    .await
                    .is_err()
                    {
                        return "shutdown".into();
                    }
                }
                Err(error) => {
                    self.record_failure(used_since.as_deref(), &error, sync_started.elapsed());
                    if !error.is_retryable() {
                        return format!("fatal:{error}");
                    }
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if consecutive_failures >= self.config.supervisor.max_consecutive_failures {
                        return format!("max_failures:{consecutive_failures}");
                    }
                    let delay = supervised_sync_backoff(
                        &self.config.supervisor,
                        &error,
                        consecutive_failures,
                    );
                    if fcp_async_core::shutdown::sleep_or_shutdown(delay, &mut shutdown)
                        .await
                        .is_err()
                    {
                        return "shutdown".into();
                    }
                }
            }
        }
    }

    fn mark_started(&self) {
        let mut status = self
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.configured_enabled = true;
        status.running = true;
        status.last_status = Some("running".into());
        status.last_error = None;
        status.last_stop_reason = None;
    }

    fn mark_stopped(&self, reason: &str) {
        let mut status = self
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.running = false;
        status.last_status = Some("stopped".into());
        status.last_stop_reason = Some(reason.to_string());
    }

    fn persist_projection(&self, response: &SyncResponse, projection: &SyncProjection) {
        let mut state = self
            .sync_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        persist_projection_state(&mut state, &response.next_batch, projection);
    }

    fn emit_projected_events(&self, batch: &str, projection: &SyncProjection) -> usize {
        let subscribed_topics = self
            .subscribed_topics
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if subscribed_topics.is_empty() {
            return 0;
        }

        let topic_groups = [
            (
                EVENT_MESSAGE_AUTHORIZED,
                projection.authorized_message_events.as_slice(),
            ),
            (
                EVENT_MESSAGE_DECRYPTED,
                projection.decrypted_message_events.as_slice(),
            ),
            (EVENT_DROPPED, projection.dropped_events.as_slice()),
            (EVENT_REACTION, projection.reaction_events.as_slice()),
            (EVENT_ENCRYPTED, projection.encrypted_events.as_slice()),
        ];

        let mut state = self
            .sync_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut emitted = 0_usize;
        for (topic, payloads) in topic_groups {
            if !subscribed_topics
                .iter()
                .any(|subscribed| subscribed == topic)
            {
                continue;
            }
            for payload in payloads {
                let dedupe_key = matrix_event_dedupe_key(topic, payload);
                if state.emitted_event_keys.contains(&dedupe_key) {
                    continue;
                }
                let envelope = build_matrix_event_envelope(
                    &self.connector_id,
                    &self.instance_id,
                    &self.next_event_seq,
                    topic,
                    batch,
                    payload,
                );
                if self.event_tx.send(Ok(envelope)).is_ok() {
                    state.emitted_event_keys.insert(dedupe_key);
                    emitted = emitted.saturating_add(1);
                }
            }
        }

        drop(state);
        emitted
    }

    fn record_success(
        &self,
        used_since: Option<&str>,
        next_batch: &str,
        projection: &SyncProjection,
        emitted_event_count: usize,
        duration: Duration,
    ) {
        {
            let mut state = self
                .sync_state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.telemetry.successful_syncs = state.telemetry.successful_syncs.saturating_add(1);
            state.telemetry.last_status = Some("supervised_success".into());
            state.telemetry.last_error = None;
            state.telemetry.last_duration_ms =
                Some(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
            state.telemetry.last_used_since = used_since.map(ToOwned::to_owned);
            state.telemetry.last_next_batch = Some(next_batch.to_string());
            state.telemetry.last_persisted = Some(true);
            state.telemetry.last_room_summary_count = projection.room_summaries.len();
            state.telemetry.last_message_event_count = projection.message_events.len();
            state.telemetry.last_membership_change_count = projection.membership_changes.len();
            state.telemetry.last_state_change_count = projection.state_changes.len();
            state.telemetry.last_authorized_message_count =
                projection.authorized_message_events.len();
            state.telemetry.last_decrypted_message_count =
                projection.decrypted_message_events.len();
            state.telemetry.last_dropped_event_count = projection.dropped_events.len();
            state.telemetry.last_reaction_event_count = projection.reaction_events.len();
            state.telemetry.last_encrypted_event_count = projection.encrypted_events.len();
            state.telemetry.last_emitted_event_count = emitted_event_count;
        }

        let mut status = self
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.total_polls = status.total_polls.saturating_add(1);
        status.successful_polls = status.successful_polls.saturating_add(1);
        status.consecutive_failures = 0;
        status.emitted_events = status
            .emitted_events
            .saturating_add(u64::try_from(emitted_event_count).unwrap_or(u64::MAX));
        status.last_status = Some("success".into());
        status.last_error = None;
        status.last_used_since = used_since.map(ToOwned::to_owned);
        status.last_next_batch = Some(next_batch.to_string());
        status.last_duration_ms = Some(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
    }

    fn record_failure(&self, used_since: Option<&str>, error: &MatrixError, duration: Duration) {
        {
            let mut state = self
                .sync_state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.telemetry.failed_syncs = state.telemetry.failed_syncs.saturating_add(1);
            state.telemetry.last_status = Some("supervised_failed".into());
            state.telemetry.last_error = Some(error.to_string());
            state.telemetry.last_duration_ms =
                Some(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
            state.telemetry.last_used_since = used_since.map(ToOwned::to_owned);
            state.telemetry.last_next_batch = None;
            state.telemetry.last_persisted = Some(true);
            state.telemetry.last_room_summary_count = 0;
            state.telemetry.last_message_event_count = 0;
            state.telemetry.last_membership_change_count = 0;
            state.telemetry.last_state_change_count = 0;
            state.telemetry.last_authorized_message_count = 0;
            state.telemetry.last_decrypted_message_count = 0;
            state.telemetry.last_dropped_event_count = 0;
            state.telemetry.last_reaction_event_count = 0;
            state.telemetry.last_encrypted_event_count = 0;
            state.telemetry.last_emitted_event_count = 0;
        }

        let mut status = self
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.total_polls = status.total_polls.saturating_add(1);
        status.failed_polls = status.failed_polls.saturating_add(1);
        status.consecutive_failures = status.consecutive_failures.saturating_add(1);
        status.last_status = Some("failed".into());
        status.last_error = Some(error.to_string());
        status.last_used_since = used_since.map(ToOwned::to_owned);
        status.last_next_batch = None;
        status.last_duration_ms = Some(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
    }
}

fn supervised_sync_backoff(
    config: &SupervisorConfig,
    error: &MatrixError,
    consecutive_failures: u32,
) -> Duration {
    let attempt = consecutive_failures.saturating_sub(1);
    let backoff_ms = config.compute_backoff(attempt);
    let retry_after_ms = error
        .retry_after()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok());
    Duration::from_millis(
        retry_after_ms.map_or(backoff_ms, |retry_after| retry_after.max(backoff_ms)),
    )
}

#[derive(Debug, Default, Deserialize)]
struct MatrixManifestOperationCatalog {
    #[serde(default)]
    provides: MatrixManifestProvides,
}

#[derive(Debug, Default, Deserialize)]
struct MatrixManifestProvides {
    #[serde(default)]
    operations: BTreeMap<String, fcp_manifest::OperationSection>,
}

fn manifest_operation_catalog() -> Result<BTreeMap<String, fcp_manifest::OperationSection>, String>
{
    toml::from_str::<MatrixManifestOperationCatalog>(MANIFEST_TOML)
        .map(|manifest| manifest.provides.operations)
        .map_err(|error| format!("embedded Matrix manifest operation catalog is invalid: {error}"))
}

/// Build the typed operations catalog from `manifest.toml`.
///
/// # Panics
///
/// Panics if the embedded Matrix manifest operation catalog cannot be parsed or
/// contains an invalid operation identifier.
#[must_use]
pub fn operations_info() -> Vec<OperationInfo> {
    try_operations_info().expect("embedded Matrix manifest operations must parse")
}

fn try_operations_info() -> Result<Vec<OperationInfo>, String> {
    let mut operations: Vec<_> = manifest_operation_catalog()?.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    operations
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(&id, operation))
        .collect()
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|candidate| *candidate == operation_id)
        .unwrap_or(OPERATION_ORDER.len())
}

fn operation_info_from_manifest(
    id: &str,
    operation: fcp_manifest::OperationSection,
) -> Result<OperationInfo, String> {
    let summary = matrix_operation_summary(id, &operation.description);
    let operation_id = OperationId::new(id.to_string())
        .map_err(|error| format!("manifest operation `{id}` has invalid ID: {error}"))?;
    Ok(OperationInfo {
        id: operation_id,
        summary,
        description: Some(operation.description),
        input_schema: operation.input_schema,
        output_schema: operation.output_schema,
        capability: operation.capability,
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints,
        rate_limit: operation
            .rate_limit
            .map(|rate_limit| rate_limit.as_inner().clone()),
        requires_approval: Some(operation.requires_approval.into()),
    })
}

fn matrix_operation_summary(operation_id: &str, fallback: &str) -> String {
    match operation_id {
        OP_JOINED_ROOMS => "List joined rooms",
        OP_CREATE_ROOM => "Create a room",
        OP_JOIN_ROOM => "Join a room",
        OP_LEAVE_ROOM => "Leave a room",
        OP_SEND_MESSAGE => "Send a message to a room",
        OP_GET_MESSAGES => "Get messages from a room",
        OP_SYNC => "Run a sync cycle",
        OP_GET_ROOM_STATE => "Get room state",
        OP_LIST_MEMBERS => "List room members",
        OP_UPLOAD_MEDIA => "Upload media",
        OP_DOWNLOAD_MEDIA => "Download media",
        _ => fallback,
    }
    .to_owned()
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

fn matrix_send_thread_id(input: &Value) -> FcpResult<Option<String>> {
    optional_str(input, "thread_root_event_id")
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
    let thread_root_event_id = matrix_thread_root_event_id(event);
    let relation_type = matrix_relation_type(event);
    json!({
        "room_id": room_id,
        "event_id": event.event_id,
        "sender": event.sender,
        "origin_server_ts": event.origin_server_ts,
        "msgtype": event.content.get("msgtype").and_then(serde_json::Value::as_str),
        "body": event.content.get("body").and_then(serde_json::Value::as_str),
        "url": event.content.get("url").and_then(serde_json::Value::as_str),
        "rel_type": relation_type,
        "thread_root_event_id": thread_root_event_id,
    })
}

fn normalize_authorized_message_event(
    room_id: &str,
    event: &Event,
    policy: &MatrixInboundPolicy,
    context: MatrixRoomPolicyContext,
) -> serde_json::Value {
    let mut value = normalize_message_event(room_id, event);
    let raw_body = event
        .content
        .get("body")
        .and_then(serde_json::Value::as_str);
    let mentioned_bot = event_mentions_bot(event, policy);
    value["delivery_body"] = json!(strip_bot_mention(raw_body, policy));
    value["mentioned_bot"] = json!(mentioned_bot);
    value["delivery_context"] = json!({
        "require_mention": policy.require_mention,
        "mention_present": mentioned_bot,
        "free_response_room": room_allows_free_response(policy, room_id),
        "direct_message_room": room_is_configured_direct_message(policy, room_id),
        "dynamic_direct_message": context.dynamic_direct_message,
        "thread_participated": event_is_participated_thread(policy, event),
        "bot_mentions_stripped": policy.workflow.strip_bot_mentions && mentioned_bot,
    });
    value["media"] = json!(normalize_media_context(event, policy));
    value
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
        "direct_message_rooms": policy.direct_message_rooms.clone(),
        "dynamic_direct_message_detection": policy.workflow.dynamic_direct_message_detection,
        "direct_message_member_limit": policy.workflow.direct_message_member_limit,
        "thread_participation_roots": policy.thread_participation_roots.clone(),
        "strip_bot_mentions": policy.workflow.strip_bot_mentions,
        "process_reactions": policy.process_reactions,
        "approval_reaction_keys": policy.workflow.approval_reaction_keys.clone(),
        "media_max_bytes": policy.workflow.media_max_bytes,
        "encrypted_events": encrypted_event_policy_label(policy.encrypted_events),
    })
}

fn extend_policy_vec(values: &mut Vec<String>, updates: &BTreeSet<String>) {
    for value in updates {
        if !values.iter().any(|existing| existing == value) {
            values.push(value.clone());
        }
    }
}

fn inbound_policy_with_state(
    policy: &MatrixInboundPolicy,
    state: &MatrixSyncState,
) -> MatrixInboundPolicy {
    let mut effective = policy.clone();
    extend_policy_vec(
        &mut effective.direct_message_rooms,
        &state.dynamic_direct_message_rooms,
    );
    extend_policy_vec(
        &mut effective.thread_participation_roots,
        &state.thread_participation_roots,
    );
    effective
}

fn persist_projection_state(
    state: &mut MatrixSyncState,
    next_batch: &str,
    projection: &SyncProjection,
) {
    state.last_sync_cursor = Some(next_batch.to_string());
    for (room_id, summary) in &projection.tracked_updates {
        state.rooms.insert(room_id.clone(), summary.clone());
    }
    state
        .dynamic_direct_message_rooms
        .extend(projection.dynamic_direct_message_rooms.iter().cloned());
    state
        .thread_participation_roots
        .extend(projection.thread_participation_roots.iter().cloned());
}

fn sync_state_from_persistence_config(config: &MatrixStatePersistenceConfig) -> MatrixSyncState {
    let mut state = MatrixSyncState::default();
    if config.enabled {
        state
            .last_sync_cursor
            .clone_from(&config.restore.last_sync_token);
        state
            .dynamic_direct_message_rooms
            .extend(config.restore.dynamic_direct_message_rooms.iter().cloned());
        state
            .thread_participation_roots
            .extend(config.restore.thread_participation_roots.iter().cloned());
    }
    state
}

fn supervised_sync_config_snapshot(config: &MatrixSupervisedSyncConfig) -> serde_json::Value {
    json!({
        "enabled": config.enabled,
        "poll_interval_ms": config.poll_interval_ms,
        "timeout_ms": config.timeout_ms,
        "base_backoff_ms": config.supervisor.base_backoff_ms,
        "max_backoff_ms": config.supervisor.max_backoff_ms,
        "jitter_enabled": config.supervisor.jitter_enabled,
        "max_consecutive_failures": config.supervisor.max_consecutive_failures,
        "shutdown_timeout_ms": config.supervisor.shutdown_timeout_ms,
    })
}

fn state_persistence_snapshot(config: &MatrixStatePersistenceConfig) -> serde_json::Value {
    json!({
        "enabled": config.enabled,
        "backend": state_persistence_backend_label(config.backend),
        "connector_local_durable_writes": false,
        "effective_runtime_state": if config.enabled {
            "host_managed_snapshot_restore_then_in_memory_tracking"
        } else {
            "in_memory_only"
        },
        "zone_scope": redacted_identifier_snapshot(config.zone_id.as_deref()),
        "account_scope": redacted_identifier_snapshot(config.account_user_id.as_deref()),
        "device_scope": redacted_identifier_snapshot(config.device_id.as_deref()),
        "restore": {
            "last_sync_token_configured": config.restore.last_sync_token.is_some(),
            "dynamic_direct_message_room_count": config.restore.dynamic_direct_message_rooms.len(),
            "thread_participation_root_count": config.restore.thread_participation_roots.len(),
        },
        "limits": {
            "max_tracked_rooms": config.limits.max_tracked_rooms,
            "max_thread_participation_roots": config.limits.max_thread_participation_roots,
        },
        "operator_note": if config.enabled {
            "Host must persist the redaction-safe tracked_state returned by matrix.sync and pass it back through this restore config on next configure; this connector does not write Matrix state to local disk."
        } else {
            "Durable state persistence disabled; configure resets Matrix sync cursor, dynamic DM classifications, and participated thread roots."
        },
    })
}

const fn e2ee_material_status_label(status: MatrixE2eeMaterialStatus) -> &'static str {
    match status {
        MatrixE2eeMaterialStatus::Unknown => "unknown",
        MatrixE2eeMaterialStatus::Missing => "missing",
        MatrixE2eeMaterialStatus::PresentUnverified => "present_unverified",
        MatrixE2eeMaterialStatus::Verified => "verified",
    }
}

const fn e2ee_device_list_status_label(status: MatrixE2eeDeviceListStatus) -> &'static str {
    match status {
        MatrixE2eeDeviceListStatus::Unknown => "unknown",
        MatrixE2eeDeviceListStatus::Missing => "missing",
        MatrixE2eeDeviceListStatus::Stale => "stale",
        MatrixE2eeDeviceListStatus::Fresh => "fresh",
    }
}

fn matrix_user_id_valid(user_id: &str) -> bool {
    user_id.starts_with('@')
        && user_id.contains(':')
        && !user_id.chars().any(char::is_whitespace)
        && user_id.len() > 3
}

fn matrix_device_id_valid(device_id: &str) -> bool {
    !device_id.is_empty() && device_id.len() <= 255 && !device_id.chars().any(char::is_whitespace)
}

fn matrix_scope_id_valid(scope_id: &str) -> bool {
    !scope_id.trim().is_empty() && !scope_id.chars().any(char::is_whitespace)
}

fn matrix_restore_token_valid(token: &str) -> bool {
    !token.trim().is_empty() && token.len() <= 4_096 && !token.chars().any(char::is_whitespace)
}

fn matrix_room_id_valid(room_id: &str) -> bool {
    room_id.starts_with('!') && room_id.contains(':') && !room_id.chars().any(char::is_whitespace)
}

fn matrix_thread_root_valid(thread_root: &str) -> bool {
    thread_root.starts_with('$') && !thread_root.chars().any(char::is_whitespace)
}

fn validate_e2ee_config(config: &MatrixE2eeConfig) -> FcpResult<()> {
    let mut errors = Vec::new();

    if let Some(user_id) = config.account_user_id.as_deref()
        && !matrix_user_id_valid(user_id)
    {
        errors.push("e2ee.account_user_id must be a Matrix user ID like @user:server".to_string());
    }

    if let Some(device_id) = config.device_id.as_deref()
        && !matrix_device_id_valid(device_id)
    {
        errors.push(
            "e2ee.device_id must be non-empty, <=255 characters, and contain no whitespace"
                .to_string(),
        );
    }
    if config.verified_decryption_requested && config.account_user_id.is_none() {
        errors.push(
            "e2ee.account_user_id is required when verified_decryption_requested=true".to_string(),
        );
    }
    if config.verified_decryption_requested && config.device_id.is_none() {
        errors
            .push("e2ee.device_id is required when verified_decryption_requested=true".to_string());
    }
    if config
        .trust_state
        .tracked_users
        .iter()
        .any(|user_id| !matrix_user_id_valid(user_id))
    {
        errors.push("e2ee.trust_state.tracked_users must contain Matrix user IDs".to_string());
    }
    if config
        .trust_state
        .tracked_rooms
        .iter()
        .any(|room_id| !matrix_room_id_valid(room_id))
    {
        errors.push("e2ee.trust_state.tracked_rooms must contain Matrix room IDs".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1006,
            message: errors.join("; "),
        })
    }
}

fn validate_state_persistence_config(
    config: &MatrixStatePersistenceConfig,
    e2ee: &MatrixE2eeConfig,
) -> FcpResult<()> {
    let mut errors = Vec::new();
    validate_state_persistence_limits(config, &mut errors);
    validate_state_persistence_restore(config, &mut errors);
    if config.enabled {
        validate_state_persistence_scope(config, e2ee, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1007,
            message: errors.join("; "),
        })
    }
}

fn validate_state_persistence_limits(
    config: &MatrixStatePersistenceConfig,
    errors: &mut Vec<String>,
) {
    if config.limits.max_tracked_rooms == 0 {
        errors.push("state_persistence.limits.max_tracked_rooms must be > 0".to_string());
    }
    if config.limits.max_thread_participation_roots == 0 {
        errors.push(
            "state_persistence.limits.max_thread_participation_roots must be > 0".to_string(),
        );
    }
    if config.restore.dynamic_direct_message_rooms.len() > config.limits.max_tracked_rooms {
        errors.push(
            "state_persistence.restore.dynamic_direct_message_rooms exceeds state_persistence.limits.max_tracked_rooms"
                .to_string(),
        );
    }
    if config.restore.thread_participation_roots.len()
        > config.limits.max_thread_participation_roots
    {
        errors.push(
            "state_persistence.restore.thread_participation_roots exceeds state_persistence.limits.max_thread_participation_roots"
                .to_string(),
        );
    }
}

fn validate_state_persistence_restore(
    config: &MatrixStatePersistenceConfig,
    errors: &mut Vec<String>,
) {
    if config
        .restore
        .dynamic_direct_message_rooms
        .iter()
        .any(|room_id| !matrix_room_id_valid(room_id))
    {
        errors.push(
            "state_persistence.restore.dynamic_direct_message_rooms must contain Matrix room IDs"
                .to_string(),
        );
    }
    if config
        .restore
        .thread_participation_roots
        .iter()
        .any(|root| !matrix_thread_root_valid(root))
    {
        errors.push(
            "state_persistence.restore.thread_participation_roots must contain Matrix event IDs"
                .to_string(),
        );
    }
    if let Some(token) = config.restore.last_sync_token.as_deref()
        && !matrix_restore_token_valid(token)
    {
        errors.push(
            "state_persistence.restore.last_sync_token must be non-empty, <=4096 bytes, and contain no whitespace"
                .to_string(),
        );
    }
}

fn validate_state_persistence_scope(
    config: &MatrixStatePersistenceConfig,
    e2ee: &MatrixE2eeConfig,
    errors: &mut Vec<String>,
) {
    if config.backend != MatrixStatePersistenceBackend::HostManagedSnapshot {
        errors.push(
            "state_persistence.enabled requires state_persistence.backend=host_managed_snapshot"
                .to_string(),
        );
    }
    match config.zone_id.as_deref() {
        Some(zone_id) if matrix_scope_id_valid(zone_id) => {}
        _ => errors.push(
            "state_persistence.zone_id is required when state persistence is enabled".to_string(),
        ),
    }
    match config.account_user_id.as_deref() {
        Some(account_user_id) if matrix_user_id_valid(account_user_id) => {}
        _ => errors.push(
            "state_persistence.account_user_id must be a Matrix user ID when state persistence is enabled"
                .to_string(),
        ),
    }
    match config.device_id.as_deref() {
        Some(device_id) if matrix_device_id_valid(device_id) => {}
        _ => {
            errors.push(
                "state_persistence.device_id must be non-empty, <=255 characters, and contain no whitespace when state persistence is enabled"
                    .to_string(),
            );
        }
    }
    if let (Some(state_account), Some(e2ee_account)) = (
        config.account_user_id.as_deref(),
        e2ee.account_user_id.as_deref(),
    ) && state_account != e2ee_account
    {
        errors.push(
            "state_persistence.account_user_id must match e2ee.account_user_id when both are configured"
                .to_string(),
        );
    }
    if let (Some(state_device), Some(e2ee_device)) =
        (config.device_id.as_deref(), e2ee.device_id.as_deref())
        && state_device != e2ee_device
    {
        errors.push(
            "state_persistence.device_id must match e2ee.device_id when both are configured"
                .to_string(),
        );
    }
}

fn validate_inbound_policy(policy: &MatrixInboundPolicy) -> FcpResult<()> {
    let mut errors = Vec::new();

    if policy.workflow.dynamic_direct_message_detection && policy.bot_user_id.is_none() {
        errors.push(
            "inbound_policy.dynamic_direct_message_detection requires inbound_policy.bot_user_id"
                .to_string(),
        );
    }
    if policy.workflow.dynamic_direct_message_detection
        && policy.workflow.direct_message_member_limit < 2
    {
        errors.push(
            "inbound_policy.direct_message_member_limit must be at least 2 when dynamic direct-message detection is enabled"
                .to_string(),
        );
    }
    if policy
        .workflow
        .approval_reaction_keys
        .iter()
        .any(|key| key.trim().is_empty())
    {
        errors.push("inbound_policy.approval_reaction_keys cannot contain empty keys".to_string());
    }
    if policy.workflow.media_max_bytes == Some(0) {
        errors.push("inbound_policy.media_max_bytes must be greater than 0 when set".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1006,
            message: errors.join("; "),
        })
    }
}

const fn e2ee_undecrypted_classification(config: &MatrixE2eeConfig) -> &'static str {
    if config.undecrypted_retry.max_attempts == 0 {
        "final_failure"
    } else {
        "retryable_until_budget_exhausted"
    }
}

fn e2ee_status_snapshot_for_config(config: &MatrixConfig) -> serde_json::Value {
    let e2ee = &config.e2ee;
    let crypto = MatrixCryptoEngine::new();
    let decision = crypto.encrypted_event_decision(config.inbound_policy.encrypted_events, e2ee);
    let trust_state = crypto.trust_state_snapshot(e2ee, &config.state_persistence);
    let maintenance = maintenance_driver_snapshot(e2ee);
    let requested_unavailable =
        e2ee.verified_decryption_requested && !decision.verified_decryption_available;
    json!({
        "verified_decryption_requested": e2ee.verified_decryption_requested,
        "verified_decryption_available": decision.verified_decryption_available,
        "decryption_status": if requested_unavailable { decision.decryption_status } else { "not_requested" },
        "denial_reason": if requested_unavailable {
            Some(decision.reason_message)
        } else {
            None
        },
        "encrypted_event_delivery_policy": decision.delivery_policy,
        "crypto_backend": crypto.status_snapshot(e2ee),
        "trust_state": trust_state,
        "maintenance": maintenance,
        "recovery_guidance": recovery_guidance_snapshot(e2ee),
        "ciphertext_redacted": true,
        "account_identity": {
            "configured": e2ee.account_user_id.is_some(),
            "valid_shape": e2ee.account_user_id.as_deref().map(matrix_user_id_valid),
            "verification": "not_verified",
        },
        "device_identity": {
            "configured": e2ee.device_id.is_some(),
            "valid_shape": e2ee.device_id.as_deref().map(matrix_device_id_valid),
            "trust_required": e2ee.trust.require_verified_device_trust,
            "trust_status": e2ee_material_status_label(e2ee.trust_state.own_device),
            "trust_verified": e2ee.trust_state.own_device == MatrixE2eeMaterialStatus::Verified,
        },
        "device_keys": {
            "status": e2ee_material_status_label(e2ee.trust_state.device_keys),
            "verified": e2ee.trust_state.device_keys == MatrixE2eeMaterialStatus::Verified,
        },
        "device_list": {
            "status": e2ee_device_list_status_label(e2ee.trust_state.device_list.status),
            "last_refresh_age_ms": e2ee.trust_state.device_list.last_refresh_age_ms,
            "fresh": e2ee.trust_state.device_list.status == MatrixE2eeDeviceListStatus::Fresh,
        },
        "cross_signing": {
            "required": e2ee.trust.require_cross_signing,
            "status": e2ee_material_status_label(e2ee.trust_state.cross_signing),
            "verified": e2ee.trust_state.cross_signing == MatrixE2eeMaterialStatus::Verified,
        },
        "recovery": {
            "status": e2ee_material_status_label(e2ee.recovery.status),
            "verified": false,
        },
        "room_key_backup": {
            "required": e2ee.trust.require_room_key_backup,
            "status": e2ee_material_status_label(e2ee.room_key_backup.status),
            "backup_version": e2ee.room_key_backup.backup_version.clone(),
            "verified": false,
        },
        "undecrypted_retry": {
            "max_attempts": e2ee.undecrypted_retry.max_attempts,
            "retry_after_ms": e2ee.undecrypted_retry.retry_after_ms,
            "classification": e2ee_undecrypted_classification(e2ee),
            "driver": "host_persisted_retry_budget",
        },
        "key_share_after_initial_sync": key_share_after_initial_sync_snapshot(
            config.state_persistence.restore.last_sync_token.is_some(),
            e2ee.trust_state.tracked_rooms.len(),
        ),
        "structured_skip": {
            "reason_code": decision.reason_code,
            "covers": [
                "verified_decrypt_success",
                "wrong_device_denial",
                "wrong_room_key_denial",
                "backup_mismatch_denial"
            ]
        },
    })
}

fn e2ee_status_snapshot_for_optional_config(config: Option<&MatrixConfig>) -> serde_json::Value {
    config.map_or_else(
        || {
            json!({
                "configured": false,
                "verified_decryption_requested": false,
                "verified_decryption_available": false,
                "decryption_status": "not_configured",
                "ciphertext_redacted": true,
            })
        },
        |config| {
            let mut snapshot = e2ee_status_snapshot_for_config(config);
            snapshot["configured"] = json!(true);
            snapshot
        },
    )
}

const fn matrix_event_topics() -> [&'static str; 5] {
    [
        EVENT_MESSAGE_AUTHORIZED,
        EVENT_MESSAGE_DECRYPTED,
        EVENT_DROPPED,
        EVENT_REACTION,
        EVENT_ENCRYPTED,
    ]
}

fn confirm_matrix_event_topics(topics: &[String]) -> FcpResult<Vec<String>> {
    let known = matrix_event_topics();
    if topics.is_empty()
        || topics
            .iter()
            .any(|topic| matches!(topic.as_str(), "*" | "matrix.*"))
    {
        return Ok(known.into_iter().map(str::to_string).collect());
    }

    let mut confirmed = Vec::new();
    for topic in topics {
        if known.contains(&topic.as_str()) && !confirmed.iter().any(|seen| seen == topic) {
            confirmed.push(topic.clone());
        }
    }

    if confirmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("No supported Matrix event topics requested: {topics:?}"),
        });
    }

    Ok(confirmed)
}

fn matrix_event_caps() -> EventCaps {
    EventCaps {
        streaming: true,
        replay: false,
        min_buffer_events: u32::try_from(MATRIX_EVENT_BUFFER_CAPACITY).unwrap_or(u32::MAX),
        requires_ack: false,
    }
}

fn matrix_event_schema(topic: &str) -> serde_json::Value {
    let description = match topic {
        EVENT_MESSAGE_AUTHORIZED => "Policy-authorized Matrix room message",
        EVENT_MESSAGE_DECRYPTED => "Trust-gated verified decrypted Matrix room message",
        EVENT_DROPPED => "Matrix timeline event dropped before agent delivery",
        EVENT_REACTION => "Matrix reaction event",
        EVENT_ENCRYPTED => "Matrix encrypted event metadata",
        _ => "Matrix event",
    };

    json!({
        "type": "object",
        "description": description,
        "required": ["room_id"],
        "properties": {
            "room_id": { "type": "string" },
            "event_id": { "type": ["string", "null"] },
            "sender": { "type": ["string", "null"] },
            "origin_server_ts": { "type": ["integer", "null"] }
        },
        "additionalProperties": true
    })
}

fn matrix_events_info() -> Vec<EventInfo> {
    matrix_event_topics()
        .into_iter()
        .map(|topic| EventInfo {
            topic: topic.to_string(),
            schema: matrix_event_schema(topic),
            requires_ack: false,
        })
        .collect()
}

fn matrix_event_principal(payload: &serde_json::Value) -> Principal {
    let sender = payload
        .get("sender")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    Principal {
        kind: "matrix_user".into(),
        id: sender.to_string(),
        trust: TrustLevel::Untrusted,
        display: None,
    }
}

fn matrix_event_resource_uris(payload: &serde_json::Value) -> Vec<String> {
    let mut uris = Vec::new();
    if let Some(room_id) = payload.get("room_id").and_then(serde_json::Value::as_str) {
        uris.push(format!("matrix:room:{room_id}"));
    }
    if let Some(event_id) = payload.get("event_id").and_then(serde_json::Value::as_str) {
        uris.push(format!("matrix:event:{event_id}"));
    }
    if let Some(target_event_id) = payload
        .get("target_event_id")
        .and_then(serde_json::Value::as_str)
    {
        uris.push(format!("matrix:event:{target_event_id}"));
    }
    if let Some(mxc_uri) = payload
        .get("media")
        .and_then(|media| media.get("mxc_uri"))
        .and_then(serde_json::Value::as_str)
        && let Some(rest) = mxc_uri.strip_prefix("mxc://")
        && !rest.is_empty()
    {
        uris.push(format!("matrix:media:{rest}"));
    }
    uris
}

fn matrix_event_thread_info(payload: &serde_json::Value) -> Option<ThreadInfo> {
    let thread_root_event_id = payload
        .get("thread_root_event_id")
        .and_then(serde_json::Value::as_str)?;
    let room_id = payload.get("room_id").and_then(serde_json::Value::as_str)?;
    Some(ThreadInfo::new(thread_root_event_id, ThreadKind::Reply).with_parent_id(room_id))
}

fn matrix_event_dedupe_key(topic: &str, payload: &serde_json::Value) -> String {
    let room_id = payload
        .get("room_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let event_id = payload
        .get("event_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !event_id.is_empty() {
        return format!("{topic}|{room_id}|{event_id}");
    }

    let fallback = serde_json::to_string(payload).unwrap_or_else(|_| "unserializable".into());
    format!("{topic}|{room_id}|{fallback}")
}

#[derive(Debug, Clone, Copy, Default)]
struct MatrixRoomPolicyContext {
    dynamic_direct_message: bool,
}

#[derive(Clone, Copy)]
struct MatrixProjectionPolicyContext<'a> {
    policy: &'a MatrixInboundPolicy,
    e2ee: &'a MatrixE2eeConfig,
    state_persistence: &'a MatrixStatePersistenceConfig,
}

fn build_matrix_event_envelope(
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
    next_event_seq: &AtomicU64,
    topic: &'static str,
    batch: &str,
    payload: &serde_json::Value,
) -> EventEnvelope {
    let seq = next_event_seq.fetch_add(1, AtomicOrdering::Relaxed);
    let event_id = payload
        .get("event_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("event");
    let event_data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        ZoneId::community(),
        matrix_event_principal(payload),
        payload.clone(),
    )
    .with_resource_uris(matrix_event_resource_uris(payload));
    let event_data = if let Some(thread_info) = matrix_event_thread_info(payload) {
        event_data.with_thread_info(thread_info)
    } else {
        event_data
    };
    let mut envelope = EventEnvelope::new(topic, event_data)
        .with_seq(seq)
        .with_cursor(format!("{batch}:{event_id}:{seq}"))
        .with_ordering(OrderingPolicy::PerKey);

    if let Some(room_id) = payload.get("room_id").and_then(serde_json::Value::as_str) {
        envelope = envelope.with_stream_key(room_id);
    }

    envelope
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

fn room_is_direct_message(
    policy: &MatrixInboundPolicy,
    room_id: &str,
    context: MatrixRoomPolicyContext,
) -> bool {
    context.dynamic_direct_message
        || policy
            .direct_message_rooms
            .iter()
            .any(|direct_room| direct_room == room_id)
}

fn room_is_configured_direct_message(policy: &MatrixInboundPolicy, room_id: &str) -> bool {
    policy
        .direct_message_rooms
        .iter()
        .any(|direct_room| direct_room == room_id)
}

fn matrix_relation(event: &Event) -> Option<&serde_json::Value> {
    event.content.get("m.relates_to")
}

fn matrix_relation_type(event: &Event) -> Option<&str> {
    matrix_relation(event)
        .and_then(|relation| relation.get("rel_type"))
        .and_then(serde_json::Value::as_str)
}

fn matrix_thread_root_event_id(event: &Event) -> Option<&str> {
    let relation = matrix_relation(event)?;
    if relation.get("rel_type").and_then(serde_json::Value::as_str) != Some("m.thread") {
        return None;
    }
    relation.get("event_id").and_then(serde_json::Value::as_str)
}

fn event_is_participated_thread(policy: &MatrixInboundPolicy, event: &Event) -> bool {
    let Some(thread_root_event_id) = matrix_thread_root_event_id(event) else {
        return false;
    };
    policy
        .thread_participation_roots
        .iter()
        .any(|known_root| known_root == thread_root_event_id)
}

fn room_is_dynamic_direct_message(
    policy: &MatrixInboundPolicy,
    summary: &MatrixRoomSummary,
) -> bool {
    if !policy.workflow.dynamic_direct_message_detection
        || policy.workflow.direct_message_member_limit == 0
    {
        return false;
    }
    let Some(bot_user_id) = policy.bot_user_id.as_deref() else {
        return false;
    };
    let joined_members = summary.joined_user_ids.len();
    joined_members >= 2
        && joined_members <= policy.workflow.direct_message_member_limit
        && summary.joined_user_ids.contains(bot_user_id)
}

fn record_thread_participation(
    projection: &mut SyncProjection,
    policy: &mut MatrixInboundPolicy,
    event: &Event,
) {
    let Some(bot_user_id) = policy.bot_user_id.as_deref() else {
        return;
    };
    if event.sender.as_deref() != Some(bot_user_id) {
        return;
    }
    let Some(thread_root_event_id) = matrix_thread_root_event_id(event) else {
        return;
    };
    projection
        .thread_participation_roots
        .insert(thread_root_event_id.to_string());
    if !policy
        .thread_participation_roots
        .iter()
        .any(|known| known == thread_root_event_id)
    {
        policy
            .thread_participation_roots
            .push(thread_root_event_id.to_string());
    }
}

fn event_allows_unmentioned_delivery(
    policy: &MatrixInboundPolicy,
    room_id: &str,
    event: &Event,
    context: MatrixRoomPolicyContext,
) -> bool {
    room_allows_free_response(policy, room_id)
        || room_is_direct_message(policy, room_id, context)
        || event_is_participated_thread(policy, event)
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
        || event
            .content
            .get("formatted_body")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|body| body.contains(bot_user_id))
}

fn strip_bot_mention(body: Option<&str>, policy: &MatrixInboundPolicy) -> Option<String> {
    let body = body?;
    if !policy.workflow.strip_bot_mentions {
        return Some(body.to_string());
    }
    let Some(bot_user_id) = policy.bot_user_id.as_deref() else {
        return Some(body.to_string());
    };
    let stripped = body
        .replace(bot_user_id, "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    Some(stripped)
}

fn matrix_media_size(event: &Event) -> Option<u64> {
    event.content.get("info").and_then(|info| {
        info.get("size")
            .and_then(serde_json::Value::as_u64)
            .or_else(|| info.get("size_bytes").and_then(serde_json::Value::as_u64))
    })
}

fn matrix_media_msgtype(event: &Event) -> Option<&str> {
    event
        .content
        .get("msgtype")
        .and_then(serde_json::Value::as_str)
}

fn matrix_message_is_media(event: &Event) -> bool {
    matches!(
        matrix_media_msgtype(event),
        Some("m.image" | "m.file" | "m.audio" | "m.video")
    ) || event.content.get("url").is_some()
}

fn matrix_media_drop_reason(event: &Event, policy: &MatrixInboundPolicy) -> Option<&'static str> {
    let max_bytes = policy.workflow.media_max_bytes?;
    let size = matrix_media_size(event)?;
    (size > max_bytes).then_some("media_too_large")
}

fn normalize_media_context(
    event: &Event,
    policy: &MatrixInboundPolicy,
) -> Option<serde_json::Value> {
    if !matrix_message_is_media(event) {
        return None;
    }
    let size_bytes = matrix_media_size(event);
    let max_bytes = policy.workflow.media_max_bytes;
    let within_size_limit = max_bytes.zip(size_bytes).map(|(max, size)| size <= max);
    Some(json!({
        "msgtype": matrix_media_msgtype(event),
        "mxc_uri": event.content.get("url").and_then(serde_json::Value::as_str),
        "filename": event
            .content
            .get("filename")
            .and_then(serde_json::Value::as_str)
            .or_else(|| event.content.get("body").and_then(serde_json::Value::as_str)),
        "content_type": event
            .content
            .get("info")
            .and_then(|info| info.get("mimetype"))
            .and_then(serde_json::Value::as_str),
        "size_bytes": size_bytes,
        "width": event
            .content
            .get("info")
            .and_then(|info| info.get("w"))
            .and_then(serde_json::Value::as_u64),
        "height": event
            .content
            .get("info")
            .and_then(|info| info.get("h"))
            .and_then(serde_json::Value::as_u64),
        "duration_ms": event
            .content
            .get("info")
            .and_then(|info| info.get("duration"))
            .and_then(serde_json::Value::as_u64),
        "media_max_bytes": max_bytes,
        "within_size_limit": within_size_limit,
        "raw_bytes_redacted": true,
    }))
}

fn inbound_message_drop_reason(
    room_id: &str,
    event: &Event,
    policy: &MatrixInboundPolicy,
    context: MatrixRoomPolicyContext,
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
        && !event_allows_unmentioned_delivery(policy, room_id, event, context)
        && !event_mentions_bot(event, policy)
    {
        return Some("mention_required");
    }

    if let Some(reason) = matrix_media_drop_reason(event, policy) {
        return Some(reason);
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

fn reaction_key(event: &Event) -> Option<&str> {
    event
        .content
        .get("m.relates_to")
        .and_then(|value| value.get("key"))
        .and_then(serde_json::Value::as_str)
}

fn reaction_target_event_id(event: &Event) -> Option<&str> {
    event
        .content
        .get("m.relates_to")
        .and_then(|value| value.get("event_id"))
        .and_then(serde_json::Value::as_str)
}

fn reaction_drop_reason(event: &Event, policy: &MatrixInboundPolicy) -> Option<&'static str> {
    if !policy.process_reactions {
        return Some("reactions_disabled");
    }
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
    if reaction_target_event_id(event).is_none() || reaction_key(event).is_none() {
        return Some("malformed_reaction");
    }
    None
}

fn normalize_reaction_event(
    room_id: &str,
    event: &Event,
    policy: &MatrixInboundPolicy,
) -> serde_json::Value {
    let relation = event.content.get("m.relates_to");
    let key = reaction_key(event);
    let approval_allowed = key.is_some_and(|key| {
        policy
            .workflow
            .approval_reaction_keys
            .iter()
            .any(|approval_key| approval_key == key)
    });
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
        "approval": {
            "approved": approval_allowed,
            "reaction_key": key,
            "allowed_keys": policy.workflow.approval_reaction_keys.clone(),
            "denial_reason": if approval_allowed {
                None
            } else {
                Some("reaction_key_not_configured_for_approval")
            },
        },
    })
}

fn encrypted_event_redaction_state(event: &Event) -> MatrixEncryptedEventRedactionState {
    if event
        .content
        .get("unsigned")
        .and_then(|value| value.get("redacted_because"))
        .is_some()
        || event.content.get("redacted_because").is_some()
    {
        MatrixEncryptedEventRedactionState::Redacted
    } else {
        MatrixEncryptedEventRedactionState::Clear
    }
}

fn encrypted_projection_context(
    room_id: &str,
    event: &Event,
    retry_attempts_used: u32,
) -> MatrixEncryptedEventProjectionContext {
    MatrixEncryptedEventProjectionContext {
        room_id: room_id.to_string(),
        event_id: event.event_id.clone(),
        sender: event.sender.clone(),
        origin_server_ts: event.origin_server_ts,
        algorithm: event
            .content
            .get("algorithm")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        session_id: event
            .content
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        redaction_state: encrypted_event_redaction_state(event),
        retry_attempts_used,
    }
}

fn normalize_encrypted_event(
    room_id: &str,
    event: &Event,
    policy: MatrixEncryptedEventPolicy,
    e2ee: &MatrixE2eeConfig,
    state_persistence: &MatrixStatePersistenceConfig,
    decrypted_projection: &MatrixTrustGatedDecryptedProjection,
) -> serde_json::Value {
    let crypto = MatrixCryptoEngine::new();
    let decision = crypto.encrypted_event_decision(policy, e2ee);
    let undecrypted_retry = undecrypted_retry_decision_snapshot(
        event.event_id.as_deref(),
        room_id,
        0,
        &e2ee.undecrypted_retry,
    );
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
        "delivery_policy": decision.delivery_policy,
        "ciphertext_redacted": true,
        "verified_decryption_requested": e2ee.verified_decryption_requested,
        "verified_decryption_available": decision.verified_decryption_available,
        "decryption_status": decision.decryption_status,
        "decryption_reason": decision.reason_code,
        "crypto_backend": crypto.status_snapshot(e2ee),
        "trust_state": crypto.trust_state_snapshot(e2ee, state_persistence),
        "maintenance": maintenance_driver_snapshot(e2ee),
        "recovery_guidance": recovery_guidance_snapshot(e2ee),
        "account_user_id_configured": e2ee.account_user_id.is_some(),
        "device_id_configured": e2ee.device_id.is_some(),
        "device_trust_verified": e2ee.trust_state.own_device == MatrixE2eeMaterialStatus::Verified,
        "device_keys_status": e2ee_material_status_label(e2ee.trust_state.device_keys),
        "device_list_status": e2ee_device_list_status_label(e2ee.trust_state.device_list.status),
        "cross_signing_status": e2ee_material_status_label(e2ee.trust_state.cross_signing),
        "recovery_status": e2ee_material_status_label(e2ee.recovery.status),
        "room_key_backup_status": e2ee_material_status_label(e2ee.room_key_backup.status),
        "undecrypted_retry": undecrypted_retry,
        "decrypted_projection": decrypted_projection.metadata_event.clone(),
    })
}

fn project_encrypted_event_with_candidate(
    projection: &mut SyncProjection,
    room_id: &str,
    event: &Event,
    projection_policy: MatrixProjectionPolicyContext<'_>,
    candidate: Option<&MatrixVerifiedDecryptedMessageEvent>,
) {
    let context = encrypted_projection_context(room_id, event, 0);
    let decrypted_projection = project_trust_gated_decrypted_event(
        &context,
        candidate,
        projection_policy.e2ee,
        projection_policy.state_persistence,
        &[],
    );
    projection.encrypted_events.push(normalize_encrypted_event(
        room_id,
        event,
        projection_policy.policy.encrypted_events,
        projection_policy.e2ee,
        projection_policy.state_persistence,
        &decrypted_projection,
    ));
    if let Some(event) = decrypted_projection.authorized_event {
        projection.decrypted_message_events.push(event);
    } else if projection_policy.e2ee.verified_decryption_requested
        && let Some(reason) = decrypted_projection.dropped_reason
    {
        projection
            .dropped_events
            .push(policy_metadata_event(room_id, event, reason));
    }
}

fn project_inbound_policy_event(
    projection: &mut SyncProjection,
    room_id: &str,
    event: &Event,
    projection_policy: MatrixProjectionPolicyContext<'_>,
    context: MatrixRoomPolicyContext,
) {
    match event.r#type.as_str() {
        "m.room.message" => {
            if let Some(reason) =
                inbound_message_drop_reason(room_id, event, projection_policy.policy, context)
            {
                projection
                    .dropped_events
                    .push(policy_metadata_event(room_id, event, reason));
            } else {
                projection
                    .authorized_message_events
                    .push(normalize_authorized_message_event(
                        room_id,
                        event,
                        projection_policy.policy,
                        context,
                    ));
            }
        }
        "m.reaction" => {
            if let Some(reason) = reaction_drop_reason(event, projection_policy.policy) {
                projection
                    .dropped_events
                    .push(policy_metadata_event(room_id, event, reason));
            } else {
                projection.reaction_events.push(normalize_reaction_event(
                    room_id,
                    event,
                    projection_policy.policy,
                ));
            }
        }
        "m.room.encrypted" => {
            project_encrypted_event_with_candidate(
                projection,
                room_id,
                event,
                projection_policy,
                None,
            );
            if matches!(
                projection_policy.policy.encrypted_events,
                MatrixEncryptedEventPolicy::FailClosed
            ) {
                projection.dropped_events.push(policy_metadata_event(
                    room_id,
                    event,
                    "encrypted_event_fail_closed",
                ));
            }
        }
        "m.receipt" => {
            projection.dropped_events.push(policy_metadata_event(
                room_id,
                event,
                "read_receipt_not_delivered",
            ));
        }
        "m.room.redaction" => {
            projection.dropped_events.push(policy_metadata_event(
                room_id,
                event,
                "redaction_event_not_delivered",
            ));
        }
        _ => {}
    }
}

fn summarize_room(room_id: &str, membership: &str, events: &[Event]) -> MatrixRoomSummary {
    let mut summary = MatrixRoomSummary::with_membership(membership);
    let mut observed_membership = false;

    for event in events {
        summary.record_event(event);
        if event.r#type == "m.room.member" {
            observed_membership = true;
        }
    }

    if observed_membership {
        summary.member_count = Some(summary.joined_user_ids.len());
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
    projection_policy: MatrixProjectionPolicyContext<'_>,
    context: MatrixRoomPolicyContext,
) -> usize {
    let mut membership_events = 0_usize;
    let mut room_policy = projection_policy.policy.clone();

    for event in events {
        summary.record_event(event);
        record_thread_participation(projection, &mut room_policy, event);
        let effective_projection_policy = MatrixProjectionPolicyContext {
            policy: &room_policy,
            e2ee: projection_policy.e2ee,
            state_persistence: projection_policy.state_persistence,
        };
        project_inbound_policy_event(
            projection,
            room_id,
            event,
            effective_projection_policy,
            context,
        );
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
    projection_policy: MatrixProjectionPolicyContext<'_>,
) {
    let mut summary = summarize_room(room_id, "join", &room.state.events);
    let context = MatrixRoomPolicyContext {
        dynamic_direct_message: room_is_dynamic_direct_message(projection_policy.policy, &summary),
    };
    if context.dynamic_direct_message {
        projection
            .dynamic_direct_message_rooms
            .insert(room_id.to_string());
    }
    let state_events = room.state.events.len();
    let timeline_events = room.timeline.events.len();
    let membership_events = project_state_events(projection, room_id, &room.state.events)
        + project_timeline_events(
            projection,
            &mut summary,
            room_id,
            &room.timeline.events,
            projection_policy,
            context,
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
    projection_policy: MatrixProjectionPolicyContext<'_>,
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
            projection_policy,
            MatrixRoomPolicyContext::default(),
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

#[cfg(test)]
fn project_sync_response_with_policy(
    sync: &SyncResponse,
    policy: &MatrixInboundPolicy,
) -> SyncProjection {
    project_sync_response_with_context(sync, policy, &MatrixE2eeConfig::default())
}

#[cfg(test)]
fn project_sync_response_with_context(
    sync: &SyncResponse,
    policy: &MatrixInboundPolicy,
    e2ee: &MatrixE2eeConfig,
) -> SyncProjection {
    project_sync_response_with_full_context(
        sync,
        policy,
        e2ee,
        &MatrixStatePersistenceConfig::default(),
    )
}

fn project_sync_response_with_full_context(
    sync: &SyncResponse,
    policy: &MatrixInboundPolicy,
    e2ee: &MatrixE2eeConfig,
    state_persistence: &MatrixStatePersistenceConfig,
) -> SyncProjection {
    let mut projection = SyncProjection::default();
    let projection_policy = MatrixProjectionPolicyContext {
        policy,
        e2ee,
        state_persistence,
    };

    for (room_id, room) in &sync.rooms.join {
        project_joined_room(&mut projection, room_id, room, projection_policy);
    }

    for (room_id, room) in &sync.rooms.invite {
        project_invited_room(&mut projection, room_id, room);
    }

    for (room_id, room) in &sync.rooms.leave {
        project_left_room(&mut projection, room_id, room, projection_policy);
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
        let chat_coordination_config = parse_matrix_chat_coordination_config(
            config.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;
        let config: MatrixConfig =
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
        validate_inbound_policy(&config.inbound_policy)?;
        validate_e2ee_config(&config.e2ee)?;
        validate_state_persistence_config(&config.state_persistence, &config.e2ee)?;
        Self::validate_supervised_sync_config(&config.supervised_sync)?;

        self.stop_supervised_sync("reconfigure").await;

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
        let supervised_sync_config = config.supervised_sync.clone();
        let restored_sync_state = sync_state_from_persistence_config(&config.state_persistence);

        self.client = Some(client);
        self.config = Some(config);
        self.chat_coordination_config = chat_coordination_config;
        *self
            .sync_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = restored_sync_state;
        self.subscribed_topics
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.next_event_seq.store(1, AtomicOrdering::Relaxed);
        self.reset_supervised_sync_status(&supervised_sync_config);
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
            event_caps: Some(matrix_event_caps()),
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
            } else if config.e2ee.verified_decryption_requested {
                HealthSnapshot::degraded(
                    "verified Matrix E2EE decryption requested but unavailable",
                )
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
        if config.e2ee.verified_decryption_requested {
            return Ok(self.attach_self_check_details(SelfCheckReport::failed(
                "e2ee_verified_decryption_unavailable",
                "Verified Matrix E2EE decryption was requested, but this connector has no audited crypto/device-trust implementation yet; refusing decrypted or ciphertext delivery",
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
        self.stop_supervised_sync("shutdown").await;
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.subscribed_topics
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: matrix_events_info(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(matrix_event_caps()),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        self.base.check_ready()?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let Some(capability_token) = req.capability_token else {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: "Matrix event subscription requires a matrix.read capability token".into(),
            });
        };
        verifier.verify_bound(
            capability_token,
            &CapabilityId::from_static(CAP_READ),
            &OperationId::from_static(OP_SYNC),
            &[],
        )?;

        let confirmed_topics = confirm_matrix_event_topics(&req.topics)?;
        self.subscribed_topics
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&confirmed_topics);
        let cursor = self
            .sync_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last_sync_cursor
            .clone();
        let cursors = cursor.map_or_else(HashMap::new, |cursor| {
            confirmed_topics
                .iter()
                .map(|topic| (topic.clone(), cursor.clone()))
                .collect()
        });
        self.start_supervised_sync_if_enabled()?;

        Ok(SubscribeResponse {
            r#type: "response".into(),
            id: req.id,
            result: SubscribeResult {
                confirmed_topics,
                cursors,
                replay_supported: false,
                buffer: Some(ReplayBufferInfo {
                    min_events: u32::try_from(MATRIX_EVENT_BUFFER_CAPACITY).unwrap_or(u32::MAX),
                    overflow: "drop_oldest".into(),
                }),
            },
        })
    }

    async fn unsubscribe(&self, req: UnsubscribeRequest) -> FcpResult<()> {
        self.base.check_ready()?;
        let mut subscribed_topics = self
            .subscribed_topics
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if req.topics.is_empty()
            || req
                .topics
                .iter()
                .any(|topic| matches!(topic.as_str(), "*" | "matrix.*"))
        {
            subscribed_topics.clear();
        } else {
            subscribed_topics
                .retain(|topic| !req.topics.iter().any(|requested| requested == topic));
        }
        drop(subscribed_topics);
        Ok(())
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
                let thread_root_event_id = matrix_send_thread_id(&req.input)?;
                let (zone_id, claimant_agent_id) = self.chat_coordination_context();
                let coordination = self
                    .claim_before_matrix_send(
                        zone_id,
                        room_id,
                        thread_root_event_id.as_deref(),
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(
                        event = "matrix.chat_coordination.denied",
                        operation = OP_SEND_MESSAGE,
                        "Matrix send_message denied by chat coordination"
                    );
                    return Err(error.clone());
                }
                let resp = client
                    .send_message(room_id, body, &msgtype)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "event_id": resp.event_id,
                    "coordination": matrix_coordination_audit_records(
                        &coordination,
                        self.chat_coordination_config.backend(),
                        &claimant_agent_id
                    ),
                })
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
                let (configured_policy, e2ee_config, state_persistence_config) =
                    self.config.as_ref().map_or_else(
                        || {
                            (
                                MatrixInboundPolicy::default(),
                                MatrixE2eeConfig::default(),
                                MatrixStatePersistenceConfig::default(),
                            )
                        },
                        |config| {
                            (
                                config.inbound_policy.clone(),
                                config.e2ee.clone(),
                                config.state_persistence.clone(),
                            )
                        },
                    );
                let (state_since, inbound_policy) = {
                    let state = self
                        .sync_state
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    (
                        state.last_sync_cursor.clone(),
                        inbound_policy_with_state(&configured_policy, &state),
                    )
                };
                let used_since = explicit_since.or(state_since);

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
                let projection = project_sync_response_with_full_context(
                    &response,
                    &inbound_policy,
                    &e2ee_config,
                    &state_persistence_config,
                );
                let tracked_state = if persist {
                    {
                        let mut state = self
                            .sync_state
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        persist_projection_state(&mut state, &response.next_batch, &projection);
                    }
                    self.tracked_state_json()
                } else {
                    self.preview_tracked_state_json(&response.next_batch, &projection)
                };
                let duration = sync_started.elapsed();
                let emitted_event_count = if persist {
                    self.emit_projected_events(&response.next_batch, &projection)
                } else {
                    0
                };
                self.record_sync_success(
                    used_since.as_deref(),
                    &response.next_batch,
                    persist,
                    &projection,
                    emitted_event_count,
                    duration,
                );
                info!(
                    event = "matrix.sync",
                    persisted = persist,
                    duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
                    room_summaries = projection.room_summaries.len(),
                    message_events = projection.message_events.len(),
                    authorized_message_events = projection.authorized_message_events.len(),
                    decrypted_message_events = projection.decrypted_message_events.len(),
                    dropped_events = projection.dropped_events.len(),
                    reaction_events = projection.reaction_events.len(),
                    encrypted_events = projection.encrypted_events.len(),
                    emitted_event_count,
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
                    "decrypted_message_events": projection.decrypted_message_events,
                    "dropped_events": projection.dropped_events,
                    "reaction_events": projection.reaction_events,
                    "encrypted_events": projection.encrypted_events,
                    "emitted_event_count": emitted_event_count,
                    "membership_changes": projection.membership_changes,
                    "state_changes": projection.state_changes,
                    "inbound_policy": inbound_policy_snapshot(&inbound_policy),
                    "policy_context_updates": {
                        "dynamic_direct_message_rooms": projection.dynamic_direct_message_rooms.iter().cloned().collect::<Vec<_>>(),
                        "thread_participation_roots": projection.thread_participation_roots.iter().cloned().collect::<Vec<_>>(),
                    },
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

    fn chat_coordination_context(&self) -> (ZoneId, AgentId) {
        let zone_id = self
            .verifier
            .as_ref()
            .map_or_else(ZoneId::work, |verifier| verifier.zone_id.clone());
        let claimant_agent_id = AgentId::new(self.base.instance_id.as_str().to_owned());
        (zone_id, claimant_agent_id)
    }

    async fn claim_before_matrix_send(
        &self,
        zone_id: ZoneId,
        room_id: &str,
        thread_root_event_id: Option<&str>,
        claimant_agent_id: AgentId,
    ) -> ChatCoordinationSendDecision {
        let channel_id = ChannelId::new(room_id.trim().to_owned());
        let thread_id = thread_root_event_id
            .map(str::trim)
            .filter(|event_id| !event_id.is_empty())
            .map(|event_id| ThreadId::new(event_id.to_owned()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MatrixWorkflowPolicy;
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
        test_token_for_key_with_capability_and_resources(
            signing_key,
            CAP_READ,
            resource_allow,
            instance_id,
        )
    }

    fn test_write_token_for_key(
        signing_key: &Ed25519SigningKey,
        instance_id: &fcp_core::InstanceId,
    ) -> CapabilityToken {
        test_token_for_key_with_capability_and_resources(
            signing_key,
            CAP_WRITE,
            &["*"],
            instance_id,
        )
    }

    fn test_token_for_key_with_capability_and_resources(
        signing_key: &Ed25519SigningKey,
        capability_id: &str,
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
        let signed_capability = CapabilityTokenBuilder::new()
            .capability_id(capability_id)
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
        CapabilityToken::from_raw(signed_capability)
    }

    struct IndeterminateThreadOwnershipChecker {
        reason: &'static str,
    }

    #[async_trait]
    impl ThreadOwnershipChecker for IndeterminateThreadOwnershipChecker {
        async fn claim(
            &self,
            _cx: &fcp_async_core::Cx,
            _key: ClaimKey,
            _agent_id: AgentId,
        ) -> ClaimOutcome {
            ClaimOutcome::Indeterminate(self.reason.to_string())
        }
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

    fn send_message_invoke_request_with_key(
        connector: &MatrixConnector,
        input: serde_json::Value,
        signing_key: &Ed25519SigningKey,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_send"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_SEND_MESSAGE),
            zone_id: ZoneId::work(),
            input,
            capability_token: test_write_token_for_key(signing_key, &connector.base.instance_id),
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
    fn manifest_declares_matrix_operation_metadata() {
        let operations =
            manifest_operation_catalog().expect("embedded manifest operation catalog should parse");
        assert_eq!(operations.len(), OPERATION_ORDER.len());

        let manifest_ids = operations
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let runtime_ids = OPERATION_ORDER.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(manifest_ids, runtime_ids);

        for operation_id in OPERATION_ORDER {
            let operation = operations
                .get(operation_id)
                .expect("operation should be declared in manifest");
            assert!(operation.input_schema.is_object());
            assert!(operation.output_schema.is_object());
            assert!(!operation.ai_hints.when_to_use.is_empty());
            let network_constraints = operation
                .network_constraints
                .as_ref()
                .expect("Matrix operation should declare network metadata");
            assert!(
                network_constraints.host_allow.is_empty(),
                "Matrix homeserver host is runtime-configured"
            );
            assert!(
                network_constraints.port_allow.is_empty(),
                "Matrix homeserver port is runtime-configured"
            );
            assert!(network_constraints.require_sni);
            assert!(!network_constraints.deny_localhost);
        }

        let send = operations
            .get(OP_SEND_MESSAGE)
            .expect("send operation should be declared");
        assert_eq!(send.capability.as_str(), CAP_WRITE);
        assert_eq!(send.input_schema["required"], json!(["room_id", "body"]));
        assert_eq!(
            send.input_schema["properties"]["thread_root_event_id"]["type"],
            json!("string")
        );

        let sync = operations.get(OP_SYNC).expect("sync operation");
        assert_eq!(sync.capability.as_str(), CAP_READ);
        assert_eq!(
            sync.output_schema["properties"]["tracked_state"]["type"],
            json!("object")
        );

        let download = operations
            .get(OP_DOWNLOAD_MEDIA)
            .expect("download media operation");
        assert_eq!(
            download.output_schema["properties"]["data_base64"]["type"],
            json!("string")
        );
    }

    #[test]
    fn operations_info_uses_manifest_operation_metadata() {
        let operations =
            manifest_operation_catalog().expect("embedded manifest operation catalog should parse");
        let runtime_operations = operations_info();
        assert_eq!(runtime_operations.len(), operations.len());

        for (index, operation_id) in OPERATION_ORDER.iter().enumerate() {
            let manifest_operation = operations
                .get(*operation_id)
                .expect("operation should be declared in manifest");
            let runtime_operation = runtime_operations
                .get(index)
                .expect("operation should use manifest order");
            assert_eq!(runtime_operation.id.as_str(), *operation_id);
            assert_eq!(
                runtime_operation.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(
                runtime_operation.capability.as_str(),
                manifest_operation.capability.as_str()
            );
            assert_eq!(runtime_operation.risk_level, manifest_operation.risk_level);
            assert_eq!(
                runtime_operation.safety_tier,
                manifest_operation.safety_tier
            );
            assert_eq!(
                runtime_operation.idempotency,
                manifest_operation.idempotency
            );
            assert_eq!(
                &runtime_operation.input_schema,
                &manifest_operation.input_schema
            );
            assert_eq!(
                &runtime_operation.output_schema,
                &manifest_operation.output_schema
            );
            assert_eq!(
                runtime_operation.ai_hints.when_to_use,
                manifest_operation.ai_hints.when_to_use
            );
        }
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
        assert!(intro.event_caps.as_ref().unwrap().streaming);
        assert_eq!(intro.events.len(), 5);
        let topics = intro
            .events
            .iter()
            .map(|event| event.topic.as_str())
            .collect::<Vec<_>>();
        assert!(topics.contains(&EVENT_MESSAGE_AUTHORIZED));
        assert!(topics.contains(&EVENT_MESSAGE_DECRYPTED));
        assert!(topics.contains(&EVENT_DROPPED));
        assert!(topics.contains(&EVENT_REACTION));
        assert!(topics.contains(&EVENT_ENCRYPTED));
    }

    #[test]
    fn matrix_event_topic_confirmation_defaults_and_filters() {
        assert_eq!(
            confirm_matrix_event_topics(&[]).unwrap(),
            vec![
                EVENT_MESSAGE_AUTHORIZED.to_string(),
                EVENT_MESSAGE_DECRYPTED.to_string(),
                EVENT_DROPPED.to_string(),
                EVENT_REACTION.to_string(),
                EVENT_ENCRYPTED.to_string(),
            ]
        );
        assert_eq!(
            confirm_matrix_event_topics(&[
                EVENT_REACTION.to_string(),
                "matrix.unknown".to_string(),
                EVENT_REACTION.to_string(),
            ])
            .unwrap(),
            vec![EVENT_REACTION.to_string()]
        );
        assert!(confirm_matrix_event_topics(&["matrix.unknown".to_string()]).is_err());
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
    async fn configure_rejects_invalid_e2ee_identities() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "access_token", "access_token": "tok" },
                "e2ee": {
                    "verified_decryption_requested": true,
                    "account_user_id": "not-a-matrix-user",
                    "device_id": "device with spaces"
                }
            }))
            .await;

        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("e2ee.account_user_id"));
        assert!(error.contains("e2ee.device_id"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_requested_e2ee_without_stable_account_and_device_scope() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "access_token", "access_token": "tok" },
                "e2ee": {
                    "verified_decryption_requested": true,
                    "trust_state": {
                        "tracked_users": ["@alice:matrix.org"],
                        "tracked_rooms": ["!secure:matrix.org"]
                    }
                }
            }))
            .await;

        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("e2ee.account_user_id is required"));
        assert!(error.contains("e2ee.device_id is required"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_e2ee_trust_state_tracking_scope() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "access_token", "access_token": "tok" },
                "e2ee": {
                    "account_user_id": "@bot:matrix.org",
                    "device_id": "DEVICE123",
                    "trust_state": {
                        "tracked_users": ["alice"],
                        "tracked_rooms": ["secure-room"]
                    }
                }
            }))
            .await;

        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("e2ee.trust_state.tracked_users"));
        assert!(error.contains("e2ee.trust_state.tracked_rooms"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_inbound_workflow_policy() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "access_token", "access_token": "tok" },
                "inbound_policy": {
                    "dynamic_direct_message_detection": true,
                    "direct_message_member_limit": 1,
                    "approval_reaction_keys": ["approve", ""],
                    "media_max_bytes": 0
                }
            }))
            .await;

        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("dynamic_direct_message_detection"));
        assert!(error.contains("direct_message_member_limit"));
        assert!(error.contains("approval_reaction_keys"));
        assert!(error.contains("media_max_bytes"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_state_persistence_config() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "access_token", "access_token": "tok" },
                "e2ee": {
                    "account_user_id": "@bot:matrix.org",
                    "device_id": "DEVICE123"
                },
                "state_persistence": {
                    "enabled": true,
                    "backend": "in_memory",
                    "zone_id": "z:work",
                    "account_user_id": "@other:matrix.org",
                    "device_id": "OTHERDEVICE",
                    "restore": {
                        "last_sync_token": "bad token",
                        "dynamic_direct_message_rooms": ["not-a-room"],
                        "thread_participation_roots": ["not-a-thread"]
                    },
                    "limits": {
                        "max_tracked_rooms": 0,
                        "max_thread_participation_roots": 0
                    }
                }
            }))
            .await;

        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("state_persistence.enabled requires"));
        assert!(error.contains("state_persistence.account_user_id must match"));
        assert!(error.contains("state_persistence.device_id must match"));
        assert!(error.contains("state_persistence.restore.last_sync_token"));
        assert!(error.contains("state_persistence.restore.dynamic_direct_message_rooms"));
        assert!(error.contains("state_persistence.restore.thread_participation_roots"));
        assert!(error.contains("state_persistence.limits.max_tracked_rooms"));
        assert!(error.contains("state_persistence.limits.max_thread_participation_roots"));
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

    #[fcp_async_core::runtime::test]
    async fn health_degrades_when_verified_e2ee_decryption_requested() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "e2ee": {
                "verified_decryption_requested": true,
                "account_user_id": "@bot:matrix.org",
                "device_id": "DEVICE123"
            }
        }))
        .await
        .unwrap();

        let h = c.health().await;
        assert!(matches!(
            h.status,
            HealthState::Degraded { ref reason }
                if reason == "verified Matrix E2EE decryption requested but unavailable"
        ));
        assert_eq!(
            h.details
                .as_ref()
                .and_then(|details| details["e2ee"]["decryption_status"].as_str()),
            Some("denied_unavailable")
        );
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
            Some("manual_or_supervised_sync_event_fanout")
        );
        assert!(d["checks"].as_array().unwrap().iter().any(|check| {
            check["name"].as_str() == Some("credential_injection")
                && check["passed"].as_bool() == Some(false)
        }));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_surfaces_e2ee_requested_unavailable_without_marking_critical_failure() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "inbound_policy": {
                "encrypted_events": "metadata_only"
            },
            "e2ee": {
                "verified_decryption_requested": true,
                "account_user_id": "@bot:matrix.org",
                "device_id": "DEVICE123",
                "recovery": { "status": "present_unverified" },
                "room_key_backup": {
                    "status": "missing",
                    "backup_version": "1"
                }
            }
        }))
        .await
        .unwrap();

        let d = c.doctor();
        assert!(d["passed"].as_bool().unwrap());
        assert_eq!(
            d["details"]["e2ee"]["decryption_status"].as_str(),
            Some("denied_unavailable")
        );
        assert_eq!(
            d["details"]["e2ee"]["encrypted_event_delivery_policy"].as_str(),
            Some("metadata_only")
        );
        assert_eq!(
            d["details"]["e2ee"]["recovery"]["status"].as_str(),
            Some("present_unverified")
        );
        assert_eq!(
            d["details"]["e2ee"]["room_key_backup"]["status"].as_str(),
            Some("missing")
        );
        assert_eq!(
            d["details"]["e2ee"]["crypto_backend"]["dependency"].as_str(),
            Some("matrix-sdk-crypto")
        );
        assert_eq!(
            d["details"]["e2ee"]["crypto_backend"]["dependency_version"].as_str(),
            Some(crate::crypto::MATRIX_SDK_CRYPTO_VERSION)
        );
        assert_eq!(
            d["details"]["e2ee"]["crypto_backend"]["network_io_model"].as_str(),
            Some(crate::crypto::MATRIX_CRYPTO_NETWORK_IO_MODEL)
        );
        assert_eq!(
            d["details"]["e2ee"]["crypto_backend"]["adapter_state"].as_str(),
            Some("boundary_only")
        );
        assert_eq!(
            d["details"]["e2ee"]["trust_state"]["device_list"]["status"].as_str(),
            Some("unknown")
        );
        assert_eq!(
            d["details"]["e2ee"]["trust_state"]["readiness"]["trust_state_ready"].as_bool(),
            Some(false)
        );
        let trust_reasons = d["details"]["e2ee"]["trust_state"]["readiness"]["denial_reason_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(trust_reasons.contains(&"device_keys_unverified"));
        assert!(trust_reasons.contains(&"device_list_not_fresh"));
        assert!(trust_reasons.contains(&"cross_signing_unverified"));
        assert!(
            !d["details"]["e2ee"]["crypto_backend"]
                .to_string()
                .contains("@bot:matrix.org")
        );
        assert!(
            !d["details"]["e2ee"]["crypto_backend"]
                .to_string()
                .contains("DEVICE123")
        );
        assert!(d["checks"].as_array().unwrap().iter().any(|check| {
            check["name"].as_str() == Some("e2ee_verified_decryption")
                && check["passed"].as_bool() == Some(false)
                && check["critical"].as_bool() == Some(false)
        }));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_surfaces_ready_secretless_trust_state_without_enabling_decrypted_delivery() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "e2ee": {
                "verified_decryption_requested": true,
                "account_user_id": "@bot:matrix.org",
                "device_id": "DEVICE123",
                "trust_state": {
                    "own_device": "verified",
                    "device_keys": "verified",
                    "device_list": {
                        "status": "fresh",
                        "last_refresh_age_ms": 10
                    },
                    "cross_signing": "verified",
                    "tracked_users": ["@alice:matrix.org"],
                    "tracked_rooms": ["!secure:matrix.org"]
                },
                "recovery": { "status": "verified" },
                "room_key_backup": {
                    "status": "verified",
                    "backup_version": "1"
                }
            },
            "state_persistence": {
                "enabled": true,
                "backend": "host_managed_snapshot",
                "zone_id": "z:work",
                "account_user_id": "@bot:matrix.org",
                "device_id": "DEVICE123"
            }
        }))
        .await
        .unwrap();

        let d = c.doctor();
        assert!(d["passed"].as_bool().unwrap());
        assert_eq!(
            d["details"]["e2ee"]["trust_state"]["readiness"]["trust_state_ready"].as_bool(),
            Some(true)
        );
        assert_eq!(
            d["details"]["e2ee"]["trust_state"]["readiness"]["decrypted_delivery_enabled"]
                .as_bool(),
            Some(false)
        );
        assert_eq!(
            d["details"]["e2ee"]["trust_state"]["tracked"]["user_count"].as_u64(),
            Some(1)
        );
        let details = d["details"]["e2ee"]["trust_state"].to_string();
        assert!(!details.contains("@bot:matrix.org"));
        assert!(!details.contains("DEVICE123"));
        assert!(!details.contains("@alice:matrix.org"));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_surfaces_state_persistence_scope_without_leaking_identifiers() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "e2ee": {
                "account_user_id": "@bot:matrix.org",
                "device_id": "DEVICE123"
            },
            "state_persistence": {
                "enabled": true,
                "backend": "host_managed_snapshot",
                "zone_id": "z:work",
                "account_user_id": "@bot:matrix.org",
                "device_id": "DEVICE123",
                "restore": {
                    "last_sync_token": "batch_restore",
                    "dynamic_direct_message_rooms": ["!dm:matrix.org"],
                    "thread_participation_roots": ["$thread-root"]
                }
            }
        }))
        .await
        .unwrap();

        let d = c.doctor();
        assert!(d["passed"].as_bool().unwrap());
        assert_eq!(
            d["details"]["state_persistence"]["enabled"].as_bool(),
            Some(true)
        );
        assert_eq!(
            d["details"]["state_persistence"]["backend"].as_str(),
            Some("host_managed_snapshot")
        );
        assert_eq!(
            d["details"]["state_persistence"]["restore"]["last_sync_token_configured"].as_bool(),
            Some(true)
        );
        assert_eq!(
            d["sync_tracking"]["last_sync_token"].as_str(),
            Some("batch_restore")
        );
        assert!(d["checks"].as_array().unwrap().iter().any(|check| {
            check["name"].as_str() == Some("state_persistence_scope")
                && check["passed"].as_bool() == Some(true)
        }));

        let details = d["details"]["state_persistence"].to_string();
        assert!(!details.contains("@bot:matrix.org"));
        assert!(!details.contains("DEVICE123"));
        assert!(!details.contains("batch_restore"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_resets_sync_state_when_state_persistence_disabled() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "state_persistence": {
                "enabled": true,
                "backend": "host_managed_snapshot",
                "zone_id": "z:work",
                "account_user_id": "@bot:matrix.org",
                "device_id": "DEVICE123",
                "restore": {
                    "last_sync_token": "batch_restore",
                    "dynamic_direct_message_rooms": ["!dm:matrix.org"],
                    "thread_participation_roots": ["$thread-root"]
                }
            }
        }))
        .await
        .unwrap();
        assert_eq!(
            c.tracked_state_json()["last_sync_token"].as_str(),
            Some("batch_restore")
        );

        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok2" }
        }))
        .await
        .unwrap();
        let tracked = c.tracked_state_json();
        assert_eq!(tracked["last_sync_token"].as_str(), None);
        assert_eq!(
            tracked["dynamic_direct_message_rooms"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            tracked["thread_participation_roots"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
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

    #[fcp_async_core::runtime::test]
    async fn self_check_denies_requested_decryption_without_verified_crypto() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "e2ee": {
                "verified_decryption_requested": true,
                "account_user_id": "@bot:matrix.org",
                "device_id": "DEVICE123"
            }
        }))
        .await
        .unwrap();

        let report = c.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("e2ee_verified_decryption_unavailable")
        );
        assert_eq!(
            report
                .details
                .as_ref()
                .and_then(|details| details["e2ee"]["verified_decryption_available"].as_bool()),
            Some(false)
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
                join: BTreeMap::from([
                    (
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
                                        event_id: Some("$thread_bypass".into()),
                                        r#type: "m.room.message".into(),
                                        state_key: None,
                                        sender: Some("@alice:matrix.org".into()),
                                        origin_server_ts: Some(145),
                                        content: json!({
                                            "msgtype": "m.text",
                                            "body": "thread follow-up without another mention",
                                            "m.relates_to": {
                                                "rel_type": "m.thread",
                                                "event_id": "$thread-root"
                                            }
                                        }),
                                        room_id: Some("!ops:matrix.org".into()),
                                    },
                                    Event {
                                        event_id: Some("$thread_unlisted".into()),
                                        r#type: "m.room.message".into(),
                                        state_key: None,
                                        sender: Some("@alice:matrix.org".into()),
                                        origin_server_ts: Some(146),
                                        content: json!({
                                            "msgtype": "m.text",
                                            "body": "unlisted thread follow-up",
                                            "m.relates_to": {
                                                "rel_type": "m.thread",
                                                "event_id": "$other-thread-root"
                                            }
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
                    ),
                    (
                        "!dm:matrix.org".to_string(),
                        crate::types::JoinedSyncRoom {
                            state: crate::types::SyncEventList::default(),
                            timeline: crate::types::SyncTimeline {
                                events: vec![Event {
                                    event_id: Some("$dm_unmentioned".into()),
                                    r#type: "m.room.message".into(),
                                    state_key: None,
                                    sender: Some("@alice:matrix.org".into()),
                                    origin_server_ts: Some(170),
                                    content: json!({
                                        "msgtype": "m.text",
                                        "body": "dm without mention"
                                    }),
                                    room_id: Some("!dm:matrix.org".into()),
                                }],
                                prev_batch: Some("prev-dm".into()),
                                limited: false,
                            },
                        },
                    ),
                ]),
                ..crate::types::SyncRooms::default()
            },
        };
        let policy = MatrixInboundPolicy {
            allowed_users: vec!["@alice:matrix.org".into()],
            bot_user_id: Some("@bot:matrix.org".into()),
            require_mention: true,
            free_response_rooms: Vec::new(),
            direct_message_rooms: vec!["!dm:matrix.org".into()],
            thread_participation_roots: vec!["$thread-root".into()],
            process_reactions: true,
            workflow: MatrixWorkflowPolicy {
                dynamic_direct_message_detection: false,
                direct_message_member_limit: 2,
                strip_bot_mentions: true,
                approval_reaction_keys: vec!["approve".into()],
                media_max_bytes: None,
            },
            encrypted_events: MatrixEncryptedEventPolicy::FailClosed,
        };

        let projection = project_sync_response_with_policy(&sync, &policy);

        assert_eq!(projection.message_events.len(), 6);
        let authorized_event_ids = projection
            .authorized_message_events
            .iter()
            .map(|event| event["event_id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(projection.authorized_message_events.len(), 3);
        assert!(authorized_event_ids.contains(&"$authorized"));
        assert!(authorized_event_ids.contains(&"$thread_bypass"));
        assert!(authorized_event_ids.contains(&"$dm_unmentioned"));
        let authorized_event = projection
            .authorized_message_events
            .iter()
            .find(|event| event["event_id"].as_str() == Some("$authorized"))
            .unwrap();
        assert_eq!(authorized_event["delivery_body"].as_str(), Some("hi"));
        assert_eq!(
            authorized_event["delivery_context"]["mention_present"].as_bool(),
            Some(true)
        );
        let thread_event = projection
            .authorized_message_events
            .iter()
            .find(|event| event["event_id"].as_str() == Some("$thread_bypass"))
            .unwrap();
        assert_eq!(
            thread_event["thread_root_event_id"].as_str(),
            Some("$thread-root")
        );
        assert_eq!(thread_event["rel_type"].as_str(), Some("m.thread"));
        assert_eq!(projection.reaction_events.len(), 1);
        assert_eq!(
            projection.reaction_events[0]["target_event_id"].as_str(),
            Some("$authorized")
        );
        assert_eq!(
            projection.reaction_events[0]["approval"]["approved"].as_bool(),
            Some(true)
        );
        assert_eq!(projection.encrypted_events.len(), 1);
        assert_eq!(
            projection.encrypted_events[0]["delivery_policy"].as_str(),
            Some("fail_closed")
        );
        assert_eq!(
            projection.encrypted_events[0]["ciphertext_redacted"].as_bool(),
            Some(true)
        );
        assert_eq!(
            projection.encrypted_events[0]["decryption_status"].as_str(),
            Some("not_attempted")
        );
        assert_eq!(
            projection.encrypted_events[0]["decryption_reason"].as_str(),
            Some("verified_e2ee_decryption_not_requested")
        );
        assert!(projection.encrypted_events[0].get("ciphertext").is_none());

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
    #[allow(clippy::too_many_lines)]
    fn project_sync_response_tracks_workflow_context_and_media_bounds() {
        let sync = SyncResponse {
            next_batch: "batch_workflow".into(),
            rooms: crate::types::SyncRooms {
                join: BTreeMap::from([
                    (
                        "!dm-auto:matrix.org".to_string(),
                        crate::types::JoinedSyncRoom {
                            state: crate::types::SyncEventList {
                                events: vec![
                                    Event {
                                        event_id: Some("$bot-member".into()),
                                        r#type: "m.room.member".into(),
                                        state_key: Some("@bot:matrix.org".into()),
                                        sender: Some("@bot:matrix.org".into()),
                                        origin_server_ts: Some(1),
                                        content: json!({ "membership": "join" }),
                                        room_id: Some("!dm-auto:matrix.org".into()),
                                    },
                                    Event {
                                        event_id: Some("$alice-member".into()),
                                        r#type: "m.room.member".into(),
                                        state_key: Some("@alice:matrix.org".into()),
                                        sender: Some("@alice:matrix.org".into()),
                                        origin_server_ts: Some(2),
                                        content: json!({ "membership": "join" }),
                                        room_id: Some("!dm-auto:matrix.org".into()),
                                    },
                                ],
                            },
                            timeline: crate::types::SyncTimeline {
                                events: vec![
                                    Event {
                                        event_id: Some("$dm-unmentioned".into()),
                                        r#type: "m.room.message".into(),
                                        state_key: None,
                                        sender: Some("@alice:matrix.org".into()),
                                        origin_server_ts: Some(3),
                                        content: json!({
                                            "msgtype": "m.text",
                                            "body": "direct workflow without mention"
                                        }),
                                        room_id: Some("!dm-auto:matrix.org".into()),
                                    },
                                    Event {
                                        event_id: Some("$media-ok".into()),
                                        r#type: "m.room.message".into(),
                                        state_key: None,
                                        sender: Some("@alice:matrix.org".into()),
                                        origin_server_ts: Some(4),
                                        content: json!({
                                            "msgtype": "m.image",
                                            "body": "diagram.png",
                                            "url": "mxc://matrix.org/media-ok",
                                            "info": {
                                                "mimetype": "image/png",
                                                "size": 512,
                                                "w": 640,
                                                "h": 480
                                            }
                                        }),
                                        room_id: Some("!dm-auto:matrix.org".into()),
                                    },
                                    Event {
                                        event_id: Some("$media-large".into()),
                                        r#type: "m.room.message".into(),
                                        state_key: None,
                                        sender: Some("@alice:matrix.org".into()),
                                        origin_server_ts: Some(5),
                                        content: json!({
                                            "msgtype": "m.file",
                                            "body": "archive.zip",
                                            "url": "mxc://matrix.org/media-large",
                                            "info": {
                                                "mimetype": "application/zip",
                                                "size": 2048
                                            }
                                        }),
                                        room_id: Some("!dm-auto:matrix.org".into()),
                                    },
                                ],
                                prev_batch: None,
                                limited: false,
                            },
                        },
                    ),
                    (
                        "!ops:matrix.org".to_string(),
                        crate::types::JoinedSyncRoom {
                            state: crate::types::SyncEventList::default(),
                            timeline: crate::types::SyncTimeline {
                                events: vec![
                                    Event {
                                        event_id: Some("$bot-thread".into()),
                                        r#type: "m.room.message".into(),
                                        state_key: None,
                                        sender: Some("@bot:matrix.org".into()),
                                        origin_server_ts: Some(10),
                                        content: json!({
                                            "msgtype": "m.text",
                                            "body": "bot joined the thread",
                                            "m.relates_to": {
                                                "rel_type": "m.thread",
                                                "event_id": "$support-thread"
                                            }
                                        }),
                                        room_id: Some("!ops:matrix.org".into()),
                                    },
                                    Event {
                                        event_id: Some("$thread-followup".into()),
                                        r#type: "m.room.message".into(),
                                        state_key: None,
                                        sender: Some("@alice:matrix.org".into()),
                                        origin_server_ts: Some(11),
                                        content: json!({
                                            "msgtype": "m.text",
                                            "body": "follow-up without another mention",
                                            "m.relates_to": {
                                                "rel_type": "m.thread",
                                                "event_id": "$support-thread"
                                            }
                                        }),
                                        room_id: Some("!ops:matrix.org".into()),
                                    },
                                    Event {
                                        event_id: Some("$reaction-eyes".into()),
                                        r#type: "m.reaction".into(),
                                        state_key: None,
                                        sender: Some("@alice:matrix.org".into()),
                                        origin_server_ts: Some(12),
                                        content: json!({
                                            "m.relates_to": {
                                                "rel_type": "m.annotation",
                                                "event_id": "$thread-followup",
                                                "key": "eyes"
                                            }
                                        }),
                                        room_id: Some("!ops:matrix.org".into()),
                                    },
                                    Event {
                                        event_id: Some("$reaction-denied".into()),
                                        r#type: "m.reaction".into(),
                                        state_key: None,
                                        sender: Some("@mallory:matrix.org".into()),
                                        origin_server_ts: Some(13),
                                        content: json!({
                                            "m.relates_to": {
                                                "rel_type": "m.annotation",
                                                "event_id": "$thread-followup",
                                                "key": "approve"
                                            }
                                        }),
                                        room_id: Some("!ops:matrix.org".into()),
                                    },
                                    Event {
                                        event_id: Some("$receipt".into()),
                                        r#type: "m.receipt".into(),
                                        state_key: None,
                                        sender: Some("@alice:matrix.org".into()),
                                        origin_server_ts: Some(14),
                                        content: json!({ "$thread-followup": { "m.read": {} } }),
                                        room_id: Some("!ops:matrix.org".into()),
                                    },
                                    Event {
                                        event_id: Some("$redaction".into()),
                                        r#type: "m.room.redaction".into(),
                                        state_key: None,
                                        sender: Some("@alice:matrix.org".into()),
                                        origin_server_ts: Some(15),
                                        content: json!({ "redacts": "$thread-followup" }),
                                        room_id: Some("!ops:matrix.org".into()),
                                    },
                                ],
                                prev_batch: None,
                                limited: false,
                            },
                        },
                    ),
                ]),
                ..crate::types::SyncRooms::default()
            },
        };
        let policy = MatrixInboundPolicy {
            allowed_users: vec!["@alice:matrix.org".into()],
            bot_user_id: Some("@bot:matrix.org".into()),
            require_mention: true,
            workflow: MatrixWorkflowPolicy {
                dynamic_direct_message_detection: true,
                media_max_bytes: Some(1024),
                approval_reaction_keys: vec!["approve".into()],
                ..MatrixWorkflowPolicy::default()
            },
            ..MatrixInboundPolicy::default()
        };

        let projection = project_sync_response_with_policy(&sync, &policy);

        assert!(
            projection
                .dynamic_direct_message_rooms
                .contains("!dm-auto:matrix.org")
        );
        assert!(
            projection
                .thread_participation_roots
                .contains("$support-thread")
        );

        let dm_message = projection
            .authorized_message_events
            .iter()
            .find(|event| event["event_id"].as_str() == Some("$dm-unmentioned"))
            .unwrap();
        assert_eq!(
            dm_message["delivery_context"]["dynamic_direct_message"].as_bool(),
            Some(true)
        );

        let media_message = projection
            .authorized_message_events
            .iter()
            .find(|event| event["event_id"].as_str() == Some("$media-ok"))
            .unwrap();
        assert_eq!(
            media_message["media"]["mxc_uri"].as_str(),
            Some("mxc://matrix.org/media-ok")
        );
        assert_eq!(
            media_message["media"]["within_size_limit"].as_bool(),
            Some(true)
        );

        let thread_message = projection
            .authorized_message_events
            .iter()
            .find(|event| event["event_id"].as_str() == Some("$thread-followup"))
            .unwrap();
        assert_eq!(
            thread_message["delivery_context"]["thread_participated"].as_bool(),
            Some(true)
        );

        let reaction = projection
            .reaction_events
            .iter()
            .find(|event| event["event_id"].as_str() == Some("$reaction-eyes"))
            .unwrap();
        assert_eq!(reaction["approval"]["approved"].as_bool(), Some(false));
        assert_eq!(
            reaction["approval"]["denial_reason"].as_str(),
            Some("reaction_key_not_configured_for_approval")
        );

        let dropped_reasons = projection
            .dropped_events
            .iter()
            .map(|event| event["reason"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(dropped_reasons.contains(&"media_too_large"));
        assert!(dropped_reasons.contains(&"self_event"));
        assert!(dropped_reasons.contains(&"sender_not_allowed"));
        assert!(dropped_reasons.contains(&"read_receipt_not_delivered"));
        assert!(dropped_reasons.contains(&"redaction_event_not_delivered"));
    }

    #[test]
    fn encrypted_event_projection_records_requested_decryption_denial_and_retry_metadata() {
        let sync = SyncResponse {
            next_batch: "batch_2".into(),
            rooms: crate::types::SyncRooms {
                join: BTreeMap::from([(
                    "!secure:matrix.org".to_string(),
                    crate::types::JoinedSyncRoom {
                        state: crate::types::SyncEventList::default(),
                        timeline: crate::types::SyncTimeline {
                            events: vec![Event {
                                event_id: Some("$encrypted".into()),
                                r#type: "m.room.encrypted".into(),
                                state_key: None,
                                sender: Some("@alice:matrix.org".into()),
                                origin_server_ts: Some(160),
                                content: json!({
                                    "algorithm": "m.megolm.v1.aes-sha2",
                                    "session_id": "session-1",
                                    "ciphertext": "must not leak"
                                }),
                                room_id: Some("!secure:matrix.org".into()),
                            }],
                            prev_batch: None,
                            limited: false,
                        },
                    },
                )]),
                ..crate::types::SyncRooms::default()
            },
        };
        let policy = MatrixInboundPolicy {
            encrypted_events: MatrixEncryptedEventPolicy::MetadataOnly,
            ..MatrixInboundPolicy::default()
        };
        let e2ee = MatrixE2eeConfig {
            verified_decryption_requested: true,
            account_user_id: Some("@bot:matrix.org".into()),
            device_id: Some("DEVICE123".into()),
            recovery: crate::types::MatrixE2eeRecoveryConfig {
                status: MatrixE2eeMaterialStatus::PresentUnverified,
            },
            room_key_backup: crate::types::MatrixE2eeBackupConfig {
                status: MatrixE2eeMaterialStatus::Missing,
                backup_version: Some("1".into()),
            },
            undecrypted_retry: crate::types::MatrixUndecryptedRetryConfig {
                max_attempts: 2,
                retry_after_ms: 500,
            },
            ..MatrixE2eeConfig::default()
        };

        let projection = project_sync_response_with_context(&sync, &policy, &e2ee);
        let encrypted = &projection.encrypted_events[0];
        assert_eq!(encrypted["delivery_policy"].as_str(), Some("metadata_only"));
        assert_eq!(
            encrypted["decryption_status"].as_str(),
            Some("denied_unavailable")
        );
        assert_eq!(
            encrypted["decryption_reason"].as_str(),
            Some("matrix_e2ee_verified_crypto_unimplemented")
        );
        assert_eq!(
            encrypted["crypto_backend"]["dependency"].as_str(),
            Some("matrix-sdk-crypto")
        );
        assert_eq!(
            encrypted["crypto_backend"]["outgoing_requests"]["total_pending"].as_u64(),
            Some(0)
        );
        assert_eq!(
            encrypted["crypto_backend"]["network_io_model"].as_str(),
            Some(crate::crypto::MATRIX_CRYPTO_NETWORK_IO_MODEL)
        );
        assert_eq!(
            encrypted["account_user_id_configured"].as_bool(),
            Some(true)
        );
        assert_eq!(encrypted["device_id_configured"].as_bool(), Some(true));
        assert_eq!(
            encrypted["recovery_status"].as_str(),
            Some("present_unverified")
        );
        assert_eq!(
            encrypted["room_key_backup_status"].as_str(),
            Some("missing")
        );
        assert_eq!(
            encrypted["undecrypted_retry"]["classification"].as_str(),
            Some("retryable_until_budget_exhausted")
        );
        assert_eq!(
            encrypted["undecrypted_retry"]["max_attempts"].as_u64(),
            Some(2)
        );
        assert_eq!(
            encrypted["undecrypted_retry"]["retry_after_ms"].as_u64(),
            Some(500)
        );
        assert!(encrypted.get("ciphertext").is_none());
    }

    #[test]
    fn encrypted_event_projection_emits_verified_decrypted_message_only_after_trust_gate() {
        let event = Event {
            event_id: Some("$encrypted".into()),
            r#type: "m.room.encrypted".into(),
            state_key: None,
            sender: Some("@alice:matrix.example".into()),
            origin_server_ts: Some(160),
            content: json!({
                "algorithm": crate::crypto::MATRIX_MEGOLM_ALGORITHM,
                "session_id": "SESSION1",
                "ciphertext": "must not leak"
            }),
            room_id: Some("!room:matrix.example".into()),
        };
        let policy = MatrixInboundPolicy {
            encrypted_events: MatrixEncryptedEventPolicy::MetadataOnly,
            ..MatrixInboundPolicy::default()
        };
        let e2ee = MatrixE2eeConfig {
            verified_decryption_requested: true,
            account_user_id: Some("@bot:matrix.example".into()),
            device_id: Some("DEVICE123".into()),
            trust_state: crate::types::MatrixE2eeTrustStateConfig {
                own_device: MatrixE2eeMaterialStatus::Verified,
                device_keys: MatrixE2eeMaterialStatus::Verified,
                device_list: crate::types::MatrixE2eeDeviceListConfig {
                    status: MatrixE2eeDeviceListStatus::Fresh,
                    last_refresh_age_ms: Some(10),
                },
                cross_signing: MatrixE2eeMaterialStatus::Verified,
                tracked_users: vec!["@alice:matrix.example".into()],
                tracked_rooms: vec!["!room:matrix.example".into()],
            },
            recovery: crate::types::MatrixE2eeRecoveryConfig {
                status: MatrixE2eeMaterialStatus::Verified,
            },
            room_key_backup: crate::types::MatrixE2eeBackupConfig {
                status: MatrixE2eeMaterialStatus::Verified,
                backup_version: Some("1".into()),
            },
            ..MatrixE2eeConfig::default()
        };
        let state = MatrixStatePersistenceConfig {
            account_user_id: Some("@bot:matrix.example".into()),
            device_id: Some("DEVICE123".into()),
            ..MatrixStatePersistenceConfig::default()
        };
        let projection_policy = MatrixProjectionPolicyContext {
            policy: &policy,
            e2ee: &e2ee,
            state_persistence: &state,
        };
        let candidate = MatrixVerifiedDecryptedMessageEvent {
            room_id: "!room:matrix.example".into(),
            sender: "@alice:matrix.example".into(),
            sender_device_id: "ALICEDEVICE".into(),
            sender_device_trust: crate::crypto::MatrixProjectionVerificationStatus::Verified,
            cross_signing_trust: crate::crypto::MatrixProjectionVerificationStatus::Verified,
            session_id: "SESSION1".into(),
            session_room_id: "!room:matrix.example".into(),
            session_trust: crate::crypto::MatrixProjectionVerificationStatus::Verified,
            algorithm: crate::crypto::MATRIX_MEGOLM_ALGORITHM.into(),
            replay_key: "SESSION1:$encrypted:0".into(),
            msgtype: "m.text".into(),
            body: "trusted plaintext".into(),
            format: None,
            formatted_body: None,
            redaction_state: MatrixEncryptedEventRedactionState::Clear,
        };
        let mut projection = SyncProjection::default();

        project_encrypted_event_with_candidate(
            &mut projection,
            "!room:matrix.example",
            &event,
            projection_policy,
            Some(&candidate),
        );

        assert_eq!(projection.decrypted_message_events.len(), 1);
        assert_eq!(
            projection.decrypted_message_events[0]["body"].as_str(),
            Some("trusted plaintext")
        );
        assert_eq!(
            projection.encrypted_events[0]["decrypted_projection"]["decryption_status"].as_str(),
            Some("authorized_decrypted")
        );
        let encrypted_text = projection.encrypted_events[0].to_string();
        assert!(!encrypted_text.contains("must not leak"));
        assert!(!encrypted_text.contains("trusted plaintext"));
        assert!(projection.dropped_events.is_empty());
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
            state.last_sync_cursor = Some("batch_1".into());
            state.rooms.insert(
                "!old:matrix.org".into(),
                MatrixRoomSummary::with_membership("join"),
            );
        }

        let projection = SyncProjection {
            tracked_updates: BTreeMap::from([(
                "!new:matrix.org".to_string(),
                MatrixRoomSummary::with_membership("invite"),
            )]),
            dynamic_direct_message_rooms: BTreeSet::from(["!dm:matrix.org".to_string()]),
            thread_participation_roots: BTreeSet::from(["$thread-root".to_string()]),
            ..SyncProjection::default()
        };
        let preview = connector.preview_tracked_state_json("batch_2", &projection);

        assert_eq!(preview["last_sync_token"], "batch_2");
        assert_eq!(preview["tracked_rooms"], 2);
        assert!(
            preview["rooms"]
                .as_array()
                .unwrap()
                .iter()
                .any(|room| room["room_id"] == "!new:matrix.org" && room["membership"] == "invite")
        );
        assert_eq!(
            preview["dynamic_direct_message_rooms"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            preview["thread_participation_roots"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let persisted = connector.tracked_state_json();
        assert_eq!(persisted["last_sync_token"], "batch_1");
        assert_eq!(persisted["tracked_rooms"], 1);
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_enabled_supervised_sync() {
        let mut connector = MatrixConnector::new();
        let error = connector
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "access_token", "access_token": "tok" },
                "supervised_sync": {
                    "enabled": true,
                    "poll_interval_ms": 0,
                    "timeout_ms": 0,
                    "supervisor": {
                        "base_backoff_ms": 0,
                        "max_backoff_ms": 1,
                        "max_consecutive_failures": 0
                    }
                }
            }))
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("supervised_sync.poll_interval_ms must be > 0"));
        assert!(message.contains("supervised_sync.timeout_ms must be > 0"));
        assert!(message.contains("supervised_sync.supervisor.base_backoff_ms must be > 0"));
        assert!(
            message.contains("supervised_sync.supervisor.max_consecutive_failures must be > 0")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_reports_supervised_sync_enabled_idle_without_failing() {
        let mut connector = MatrixConnector::new();
        connector
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "access_token", "access_token": "tok" },
                "supervised_sync": {
                    "enabled": true,
                    "poll_interval_ms": 50,
                    "timeout_ms": 25,
                    "supervisor": {
                        "base_backoff_ms": 10,
                        "max_backoff_ms": 20,
                        "jitter_enabled": false,
                        "max_consecutive_failures": 2
                    }
                }
            }))
            .await
            .unwrap();

        let doctor = connector.doctor();
        assert!(doctor["passed"].as_bool().unwrap());
        assert_eq!(
            doctor["details"]["supervised_sync"]["configured_enabled"].as_bool(),
            Some(true)
        );
        assert_eq!(
            doctor["details"]["supervised_sync"]["running"].as_bool(),
            Some(false)
        );
        assert!(doctor["checks"].as_array().unwrap().iter().any(|check| {
            check["name"].as_str() == Some("supervised_sync")
                && check["passed"].as_bool() == Some(false)
                && check["critical"].as_bool() == Some(false)
                && check["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("idle until subscribe"))
        }));
    }

    #[test]
    fn supervised_sync_backoff_uses_retry_after_floor_and_cap() {
        let supervisor = SupervisorConfig {
            base_backoff_ms: 10,
            max_backoff_ms: 40,
            jitter_enabled: false,
            ..SupervisorConfig::default()
        };

        assert_eq!(
            supervised_sync_backoff(&supervisor, &MatrixError::Runtime("again".into()), 1),
            Duration::from_millis(10)
        );
        assert_eq!(
            supervised_sync_backoff(&supervisor, &MatrixError::Runtime("again".into()), 4),
            Duration::from_millis(40)
        );
        assert_eq!(
            supervised_sync_backoff(
                &supervisor,
                &MatrixError::RateLimited {
                    retry_after_ms: 250
                },
                2,
            ),
            Duration::from_millis(250)
        );
    }

    async fn wait_for_supervised_status(
        connector: &MatrixConnector,
        label: &str,
        predicate: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        let started = Instant::now();
        loop {
            let status = connector.doctor()["details"]["supervised_sync"].clone();
            if predicate(&status) {
                return status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "timed out waiting for supervised sync status {label}: {status}"
            );
            fcp_async_core::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_interrupts_supervised_sync_poll_sleep() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_matrix/client/v3/sync"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "next_batch": "batch_shutdown",
                    "rooms": {}
                })),
            )
            .mount(&mock)
            .await;

        let key = test_signing_key();
        let mut connector = MatrixConnector::new();
        connector
            .configure(json!({
                "homeserver_url": mock.uri(),
                "auth": { "mode": "access_token", "access_token": "tok" },
                "supervised_sync": {
                    "enabled": true,
                    "poll_interval_ms": 60_000,
                    "timeout_ms": 10,
                    "supervisor": {
                        "base_backoff_ms": 10,
                        "max_backoff_ms": 20,
                        "jitter_enabled": false,
                        "max_consecutive_failures": 3,
                        "shutdown_timeout_ms": 1000
                    }
                }
            }))
            .await
            .unwrap();
        connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: key.verifying_key().to_bytes(),
                nonce: [0u8; 32],
                capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            })
            .await
            .unwrap();
        connector
            .subscribe(SubscribeRequest {
                r#type: "subscribe".into(),
                id: RequestId::new("sub_poll_shutdown"),
                topics: vec![EVENT_MESSAGE_AUTHORIZED.into()],
                since: None,
                max_events_per_sec: None,
                batch_ms: None,
                window_size: None,
                capability_token: Some(test_token_for_key(&key, &connector.base.instance_id)),
            })
            .await
            .unwrap();

        wait_for_supervised_status(&connector, "successful poll", |status| {
            status["successful_polls"].as_u64() == Some(1)
                && status["running"].as_bool() == Some(true)
        })
        .await;
        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 1_000,
                drain: true,
                reason: Some("poll sleep cancellation test".into()),
            })
            .await
            .unwrap();
        let status = connector.doctor()["details"]["supervised_sync"].clone();
        assert_eq!(status["running"].as_bool(), Some(false));
        assert_eq!(status["last_stop_reason"].as_str(), Some("shutdown"));
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_interrupts_supervised_sync_retry_sleep() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_matrix/client/v3/sync"))
            .respond_with(
                wiremock::ResponseTemplate::new(429)
                    .insert_header("retry-after", "60")
                    .set_body_json(serde_json::json!({
                        "errcode": "M_LIMIT_EXCEEDED",
                        "error": "retry later"
                    })),
            )
            .mount(&mock)
            .await;

        let key = test_signing_key();
        let mut connector = MatrixConnector::new();
        connector
            .configure(json!({
                "homeserver_url": mock.uri(),
                "auth": { "mode": "access_token", "access_token": "tok" },
                "supervised_sync": {
                    "enabled": true,
                    "poll_interval_ms": 10,
                    "timeout_ms": 10,
                    "supervisor": {
                        "base_backoff_ms": 60_000,
                        "max_backoff_ms": 60_000,
                        "jitter_enabled": false,
                        "max_consecutive_failures": 3,
                        "shutdown_timeout_ms": 1000
                    }
                }
            }))
            .await
            .unwrap();
        connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: key.verifying_key().to_bytes(),
                nonce: [0u8; 32],
                capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            })
            .await
            .unwrap();
        connector
            .subscribe(SubscribeRequest {
                r#type: "subscribe".into(),
                id: RequestId::new("sub_retry_shutdown"),
                topics: vec![EVENT_MESSAGE_AUTHORIZED.into()],
                since: None,
                max_events_per_sec: None,
                batch_ms: None,
                window_size: None,
                capability_token: Some(test_token_for_key(&key, &connector.base.instance_id)),
            })
            .await
            .unwrap();

        wait_for_supervised_status(&connector, "retry sleep", |status| {
            status["failed_polls"].as_u64() == Some(1) && status["running"].as_bool() == Some(true)
        })
        .await;
        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 1_000,
                drain: true,
                reason: Some("retry sleep cancellation test".into()),
            })
            .await
            .unwrap();
        let status = connector.doctor()["details"]["supervised_sync"].clone();
        assert_eq!(status["running"].as_bool(), Some(false));
        assert_eq!(status["last_stop_reason"].as_str(), Some("shutdown"));
    }

    #[fcp_async_core::runtime::test]
    async fn event_fanout_deduplicates_manual_and_supervised_sync_payloads() {
        let connector = MatrixConnector::new();
        connector
            .subscribed_topics
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(EVENT_MESSAGE_AUTHORIZED.to_string());
        let mut events = connector.subscribe_events();
        let mut projection = SyncProjection::default();
        projection.authorized_message_events.push(json!({
            "room_id": "!room:matrix.org",
            "event_id": "$duplicate",
            "sender": "@alice:matrix.org",
            "origin_server_ts": 120,
            "msgtype": "m.text",
            "body": "only once"
        }));

        assert_eq!(connector.emit_projected_events("batch_1", &projection), 1);
        let event = fcp_async_core::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("timeout waiting for first event")
            .expect("broadcast receive")
            .expect("event payload");
        assert_eq!(event.cursor, "batch_1:$duplicate:1");

        assert_eq!(connector.emit_projected_events("batch_2", &projection), 0);
        assert!(
            fcp_async_core::time::timeout(Duration::from_millis(50), events.recv())
                .await
                .is_err()
        );
        assert_eq!(
            connector.sync_observability_snapshot()["emitted_event_dedupe_keys"].as_u64(),
            Some(1)
        );
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
    async fn send_message_granted_claim_sends_with_coordination_audit() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .and(wiremock::matchers::path_regex(
                r"^/_matrix/client/v3/rooms/%21room%3Amatrix\.org/send/m\.room\.message/.+$",
            ))
            .and(wiremock::matchers::body_json(json!({
                "msgtype": "m.notice",
                "body": "hello from Matrix"
            })))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "event_id": "$sent_event"
                })),
            )
            .expect(1)
            .mount(&mock)
            .await;

        let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
        let mut connector = MatrixConnector::new()
            .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
        let signing_key = test_signing_key();
        connector
            .configure(json!({
                "homeserver_url": mock.uri(),
                "auth": { "mode": "access_token", "access_token": "tok" },
                "chat_coordination": { "backend": "in_memory" }
            }))
            .await
            .unwrap();
        connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [0u8; 32],
                capabilities_requested: vec![CapabilityId::from_static(CAP_WRITE)],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            })
            .await
            .unwrap();

        let response = connector
            .invoke(send_message_invoke_request_with_key(
                &connector,
                json!({
                    "room_id": "!room:matrix.org",
                    "body": "hello from Matrix",
                    "msgtype": "m.notice",
                    "thread_root_event_id": "$root_event"
                }),
                &signing_key,
            ))
            .await
            .unwrap();
        let result = response.result.expect("send_message should return result");
        assert_eq!(result["event_id"].as_str(), Some("$sent_event"));
        let coordination = result["coordination"]
            .as_array()
            .expect("coordination audit should be an array");
        let events = coordination
            .iter()
            .filter_map(|record| record.get("event").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(
            events,
            vec!["claim_attempt", "claim_outcome", "send_executed"]
        );
        assert_eq!(coordination[1]["outcome"].as_str(), Some("granted"));
        assert_eq!(coordination[2]["backend"].as_str(), Some("in_memory"));
        let coordination_text = Value::Array(coordination.clone()).to_string();
        assert!(!coordination_text.contains("!room:matrix.org"));
        assert!(!coordination_text.contains("$root_event"));
        assert!(!coordination_text.contains("hello from Matrix"));
        assert!(!coordination_text.contains(connector.base.instance_id.as_str()));
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_denies_duplicate_owner_before_http_send() {
        let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
        let key = ClaimKey::for_chat_message(
            ZoneId::work(),
            ConnectorId::from_static("fcp.matrix"),
            ChannelId::new("!room:matrix.org"),
            Some(ThreadId::new("$root_event")),
            DmMode::TreatAsThread,
        )
        .expect("threaded Matrix send should produce a claim key");
        assert!(matches!(
            checker.claim_now(key, AgentId::new("agent:alpha"), Instant::now()),
            ClaimOutcome::Granted(_)
        ));

        let mut connector = MatrixConnector::new()
            .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
        let signing_key = test_signing_key();
        connector
            .configure(json!({
                "homeserver_url": "http://127.0.0.1:9",
                "auth": { "mode": "access_token", "access_token": "tok" },
                "timeout_ms": 100,
                "chat_coordination": { "backend": "in_memory" }
            }))
            .await
            .unwrap();
        connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [0u8; 32],
                capabilities_requested: vec![CapabilityId::from_static(CAP_WRITE)],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            })
            .await
            .unwrap();

        let error = connector
            .invoke(send_message_invoke_request_with_key(
                &connector,
                json!({
                    "room_id": "!room:matrix.org",
                    "body": "must not reach Matrix",
                    "thread_root_event_id": "$root_event"
                }),
                &signing_key,
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, FcpError::Unauthorized { code: 4090, .. }));
        assert!(
            error
                .to_string()
                .contains("thread_owned_by_peer:agent:alpha")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_fail_open_sends_with_degraded_coordination_audit() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .and(wiremock::matchers::path_regex(
                r"^/_matrix/client/v3/rooms/%21room%3Amatrix\.org/send/m\.room\.message/.+$",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "event_id": "$degraded_event"
                })),
            )
            .expect(1)
            .mount(&mock)
            .await;

        let mut connector = MatrixConnector::new().with_thread_ownership_checker(
            Arc::new(IndeterminateThreadOwnershipChecker {
                reason: "agent_mail_unavailable",
            }),
            ChatCoordinationBackend::AgentMail,
        );
        let signing_key = test_signing_key();
        connector
            .configure(json!({
                "homeserver_url": mock.uri(),
                "auth": { "mode": "access_token", "access_token": "tok" },
                "chat_coordination": {
                    "backend": "agent_mail",
                    "fail_open": true
                }
            }))
            .await
            .unwrap();
        connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [0u8; 32],
                capabilities_requested: vec![CapabilityId::from_static(CAP_WRITE)],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            })
            .await
            .unwrap();

        let response = connector
            .invoke(send_message_invoke_request_with_key(
                &connector,
                json!({
                    "room_id": "!room:matrix.org",
                    "body": "degraded send"
                }),
                &signing_key,
            ))
            .await
            .unwrap();
        let result = response.result.expect("send_message should return result");
        assert_eq!(result["event_id"].as_str(), Some("$degraded_event"));
        let coordination = result["coordination"]
            .as_array()
            .expect("coordination audit should be an array");
        assert_eq!(coordination[1]["outcome"].as_str(), Some("indeterminate"));
        assert_eq!(
            coordination[1]["reason"].as_str(),
            Some("agent_mail_unavailable")
        );
        assert_eq!(coordination[2]["event"].as_str(), Some("send_executed"));
        assert_eq!(
            coordination[2]["reason"].as_str(),
            Some("agent_mail_unavailable")
        );
        assert_eq!(coordination[2]["backend"].as_str(), Some("agent_mail"));
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_fail_closed_denies_indeterminate_before_http_send() {
        let mut connector = MatrixConnector::new().with_thread_ownership_checker(
            Arc::new(IndeterminateThreadOwnershipChecker {
                reason: "agent_mail_unavailable",
            }),
            ChatCoordinationBackend::AgentMail,
        );
        let signing_key = test_signing_key();
        connector
            .configure(json!({
                "homeserver_url": "http://127.0.0.1:9",
                "auth": { "mode": "access_token", "access_token": "tok" },
                "timeout_ms": 100,
                "chat_coordination": {
                    "backend": "agent_mail",
                    "fail_open": false
                }
            }))
            .await
            .unwrap();
        connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [0u8; 32],
                capabilities_requested: vec![CapabilityId::from_static(CAP_WRITE)],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            })
            .await
            .unwrap();

        let error = connector
            .invoke(send_message_invoke_request_with_key(
                &connector,
                json!({
                    "room_id": "!room:matrix.org",
                    "body": "must not reach Matrix"
                }),
                &signing_key,
            ))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            FcpError::ConnectorUnavailable { code: 5090, .. }
        ));
        assert!(
            error
                .to_string()
                .contains("thread_ownership_indeterminate:agent_mail_unavailable")
        );
    }

    #[test]
    fn matrix_send_claim_key_derives_room_thread_and_dm_mode() {
        let config = default_matrix_chat_coordination_config();
        let action = config.action_for_message(
            ZoneId::work(),
            ConnectorId::from_static("fcp.matrix"),
            ChannelId::new("!room:matrix.org"),
            Some(ThreadId::new("$root_event")),
        );
        let threaded_key = match action {
            ChatCoordinationAction::Claim { key } => Some(key),
            ChatCoordinationAction::Skip { .. } => None,
        };
        assert!(
            threaded_key.is_some(),
            "threaded Matrix send should produce a coordination claim"
        );
        let threaded_key = threaded_key.expect("claim asserted");
        assert_eq!(threaded_key.channel_id().as_str(), "!room:matrix.org");
        assert_eq!(threaded_key.thread_id().as_str(), "$root_event");

        let threadless = config.action_for_message(
            ZoneId::work(),
            ConnectorId::from_static("fcp.matrix"),
            ChannelId::new("!room:matrix.org"),
            None,
        );
        let threadless_key = match threadless {
            ChatCoordinationAction::Claim { key } => Some(key),
            ChatCoordinationAction::Skip { .. } => None,
        };
        assert!(
            threadless_key.is_some(),
            "default Matrix dm_mode should claim threadless sends"
        );
        let threadless_key = threadless_key.expect("claim asserted");
        assert_eq!(threadless_key.thread_id().as_str(), "!room:matrix.org");

        let skipped = config.with_dm_mode(DmMode::Skip).action_for_message(
            ZoneId::work(),
            ConnectorId::from_static("fcp.matrix"),
            ChannelId::new("!room:matrix.org"),
            None,
        );
        assert!(matches!(
            skipped,
            ChatCoordinationAction::Skip {
                reason: ChatCoordinationSkipReason::ThreadlessDmSkipped
            }
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
            doctor["sync_tracking"]["last_emitted_event_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            doctor["sync_tracking"]["last_persisted"].as_bool(),
            Some(true)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn sync_emits_authorized_event_for_active_subscription() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_matrix/client/v3/sync"))
            .and(wiremock::matchers::query_param("timeout", "1000"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "next_batch": "batch_stream",
                    "rooms": {
                        "join": {
                            "!room:matrix.org": {
                                "state": { "events": [] },
                                "timeline": {
                                    "events": [
                                        {
                                            "event_id": "$msg_stream",
                                                "type": "m.room.message",
                                                "sender": "@alice:matrix.org",
                                                "origin_server_ts": 120,
                                                "content": {
                                                    "msgtype": "m.text",
                                                    "body": "Hello from Matrix",
                                                    "m.relates_to": {
                                                        "rel_type": "m.thread",
                                                        "event_id": "$root_stream"
                                                    }
                                                },
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
        c.configure(json!({
            "homeserver_url": mock.uri(),
            "auth": { "mode": "access_token", "access_token": "tok" },
            "inbound_policy": { "require_mention": false }
        }))
        .await
        .unwrap();
        c.handshake(HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: key.verifying_key().to_bytes(),
            nonce: [0u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .unwrap();

        let mut event_rx = c.subscribe_events();
        let subscribe_response = c
            .subscribe(SubscribeRequest {
                r#type: "subscribe".into(),
                id: RequestId::new("sub_matrix"),
                topics: vec![EVENT_MESSAGE_AUTHORIZED.into()],
                since: None,
                max_events_per_sec: None,
                batch_ms: None,
                window_size: None,
                capability_token: Some(test_token_for_key(&key, &c.base.instance_id)),
            })
            .await
            .unwrap();
        assert_eq!(
            subscribe_response.result.confirmed_topics,
            vec![EVENT_MESSAGE_AUTHORIZED.to_string()]
        );

        let response = c
            .invoke(sync_invoke_request_with_key(
                &c,
                json!({ "timeout_ms": 1000 }),
                &key,
            ))
            .await
            .unwrap();
        let result = response.result.unwrap();
        assert_eq!(result["emitted_event_count"].as_u64(), Some(1));

        let event = fcp_async_core::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("timeout waiting for Matrix sync event")
            .expect("broadcast receive")
            .expect("event payload");
        assert_eq!(event.topic, EVENT_MESSAGE_AUTHORIZED);
        assert_eq!(event.seq, 1);
        assert_eq!(event.cursor, "batch_stream:$msg_stream:1");
        assert_eq!(event.stream_key.as_deref(), Some("!room:matrix.org"));
        assert_eq!(event.ordering, Some(OrderingPolicy::PerKey));
        assert_eq!(event.data.principal.kind, "matrix_user");
        assert_eq!(event.data.principal.id, "@alice:matrix.org");
        assert_eq!(event.data.principal.trust, TrustLevel::Untrusted);
        assert_eq!(event.data.zone_id, ZoneId::community());
        assert_eq!(
            event.data.payload["body"].as_str(),
            Some("Hello from Matrix")
        );
        assert!(
            event
                .data
                .resource_uris
                .iter()
                .any(|uri| uri == "matrix:room:!room:matrix.org")
        );
        assert!(
            event
                .data
                .resource_uris
                .iter()
                .any(|uri| uri == "matrix:event:$msg_stream")
        );
        assert_eq!(
            event.data.payload["thread_root_event_id"].as_str(),
            Some("$root_stream")
        );
        assert_eq!(
            event.data.thread_info,
            Some(
                ThreadInfo::new("$root_stream", ThreadKind::Reply)
                    .with_parent_id("!room:matrix.org")
            )
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
