//! `Nostr` relay connector.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, AuthCaps, BaseConnector, CapabilityGrant, CapabilityId,
    CapabilityVerifier, ConnectorId, ConnectorMetrics, EventCaps, EventData, EventEnvelope,
    EventInfo, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    HealthState, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, OrderingPolicy, Principal, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    SubscribeResult, TrustLevel, UnsubscribeRequest, ZoneId,
};
use fcp_sdk::prelude::*;
use fcp_sdk::{
    AgentId, ChannelId, ChatCoordinationAuditRecord, ChatCoordinationBackend,
    ChatCoordinationConfig, ChatCoordinationSendDecision, ChatCoordinationSendRequest, DmMode,
    InMemoryThreadOwnershipChecker, ThreadId, ThreadOwnershipChecker,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::client::{
    InboundDmGuardSnapshot, InboundDmGuardState, InboundDmRateLimits, InboundDmSubscriptionOutcome,
    NostrClient, NostrRelayClient, inbound_dm_subscription_event_payload,
};
use crate::types::{
    CAP_DM_WRITE, CAP_EVENTS_READ, CAP_HEALTH_READ, CAP_NOTES_WRITE, CAP_PROFILE_READ,
    CAP_PROFILE_WRITE, CAP_RELAYS_READ, EVENT_INBOUND_DM, NIP04_KIND_ENCRYPTED_DM, NostrConfig,
    NostrProfile, OP_HEALTH, OP_LIST_RELAYS, OP_PROFILE_IMPORT, OP_PROFILE_PUBLISH,
    OP_PROFILE_STATE, OP_PUBLISH_NOTE, OP_QUERY_EVENTS, OP_RELAYS_HEALTH, OP_SEND_DM, build_filter,
    note_kind, note_tags, parse_dm_send_input, parse_profile_import_input,
    parse_profile_publish_input, required_string,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

fn default_nostr_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_nostr_chat_coordination_config(
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

fn event_id_string_schema() -> Value {
    json!({
        "type": "string",
        "pattern": "^[0-9A-Fa-f]{64}$"
    })
}

fn https_url_schema() -> Value {
    json!({
        "type": "string",
        "format": "uri",
        "pattern": "^https://"
    })
}

fn nostr_address_schema() -> Value {
    json!({
        "type": "string",
        "maxLength": 320,
        "pattern": r"^[^\s@]+@[^\s@]+$"
    })
}

fn profile_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "name": { "type": "string", "maxLength": 256 },
            "display_name": { "type": "string", "maxLength": 256 },
            "displayName": { "type": "string", "maxLength": 256 },
            "about": { "type": "string", "maxLength": 2000 },
            "picture": https_url_schema(),
            "banner": https_url_schema(),
            "website": https_url_schema(),
            "nip05": nostr_address_schema(),
            "lud16": nostr_address_schema()
        }
    })
}

fn publish_note_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["content"],
        "additionalProperties": false,
        "properties": {
            "content": nonblank_string_schema(),
            "kind": { "type": "integer", "enum": [1] },
            "tags": {
                "type": "array",
                "items": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        }
    })
}

fn send_dm_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "anyOf": [
            { "required": ["recipient"] },
            { "required": ["recipient_pubkey"] },
            { "required": ["target"] }
        ],
        "allOf": [
            {
                "anyOf": [
                    { "required": ["plaintext"] },
                    { "required": ["content"] }
                ]
            }
        ],
        "properties": {
            "recipient": nonblank_string_schema(),
            "recipient_pubkey": nonblank_string_schema(),
            "target": nonblank_string_schema(),
            "plaintext": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "pattern": "\\S"
            },
            "content": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "pattern": "\\S"
            },
            "reply_to_event_id": event_id_string_schema(),
            "reply_to": event_id_string_schema(),
            "allow_self_send": { "type": "boolean" }
        }
    })
}

fn profile_publish_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["profile"],
        "additionalProperties": false,
        "properties": {
            "profile": profile_schema(),
            "last_published_at": {
                "type": "integer",
                "minimum": 0
            }
        }
    })
}

fn profile_import_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "pubkey": nonblank_string_schema(),
            "local_profile": profile_schema()
        }
    })
}

fn query_events_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "authors": {
                "type": "array",
                "items": nonblank_string_schema()
            },
            "kinds": {
                "type": "array",
                "items": {
                    "type": "integer",
                    "minimum": 0
                }
            },
            "ids": {
                "type": "array",
                "items": event_id_string_schema()
            },
            "since": { "type": "integer" },
            "until": { "type": "integer" },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000
            }
        }
    })
}

fn relay_array_schema() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "string",
            "format": "uri"
        }
    })
}

fn relay_diagnostics_schema() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": true
        }
    })
}

fn relay_resilience_schema() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": true
        }
    })
}

fn relay_metrics_schema() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": true
        }
    })
}

fn coordination_output_schema() -> Value {
    json!({
        "type": "array",
        "description": "Redaction-safe chat coordination audit records for the send attempt",
        "items": { "type": "object" }
    })
}

fn nostr_event_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "pubkey", "created_at", "kind"],
        "additionalProperties": true,
        "properties": {
            "id": event_id_string_schema(),
            "pubkey": event_id_string_schema(),
            "created_at": { "type": "integer" },
            "kind": { "type": "integer" },
            "content": { "type": "string" },
            "tags": {
                "type": "array",
                "items": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            },
            "sig": event_id_string_schema()
        }
    })
}

fn profile_state_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "load_result",
            "persistence",
            "connector_public_key_hex",
            "last_published_at",
            "last_published_event_id",
            "last_publish_results",
            "last_profile",
            "updated_at_secs"
        ],
        "additionalProperties": false,
        "properties": {
            "load_result": { "type": "string" },
            "persistence": {
                "type": "string",
                "enum": ["zone_dir", "memory_only_no_zone_dir"]
            },
            "connector_public_key_hex": event_id_string_schema(),
            "last_published_at": { "type": ["integer", "null"] },
            "last_published_event_id": { "type": ["string", "null"] },
            "last_publish_results": {
                "type": "object",
                "additionalProperties": { "type": "string" }
            },
            "last_profile": { "type": ["object", "null"] },
            "updated_at_secs": { "type": ["integer", "null"] }
        }
    })
}

#[allow(clippy::too_many_lines)]
fn output_schema_for(operation_id: &str) -> Value {
    match operation_id {
        OP_PUBLISH_NOTE => json!({
            "type": "object",
            "required": [
                "event",
                "accepted_relays",
                "rejected_relays",
                "coordination",
                "relay_resilience",
                "relay_metrics"
            ],
            "additionalProperties": false,
            "properties": {
                "event": nostr_event_schema(),
                "accepted_relays": relay_diagnostics_schema(),
                "rejected_relays": relay_diagnostics_schema(),
                "coordination": coordination_output_schema(),
                "relay_resilience": relay_resilience_schema(),
                "relay_metrics": relay_metrics_schema()
            }
        }),
        OP_SEND_DM => json!({
            "type": "object",
            "required": [
                "event_id",
                "event_kind",
                "sender_pubkey_hex",
                "recipient_pubkey_hex",
                "recipient_format",
                "tags",
                "created_at",
                "accepted_relays",
                "rejected_relays",
                "coordination",
                "relay_resilience",
                "relay_metrics"
            ],
            "additionalProperties": false,
            "properties": {
                "event_id": event_id_string_schema(),
                "event_kind": { "type": "integer", "enum": [4] },
                "sender_pubkey_hex": event_id_string_schema(),
                "recipient_pubkey_hex": event_id_string_schema(),
                "recipient_format": { "type": "string" },
                "tags": {
                    "type": "array",
                    "items": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                },
                "created_at": { "type": "integer" },
                "accepted_relays": relay_diagnostics_schema(),
                "rejected_relays": relay_diagnostics_schema(),
                "coordination": coordination_output_schema(),
                "relay_resilience": relay_resilience_schema(),
                "relay_metrics": relay_metrics_schema()
            }
        }),
        OP_PROFILE_PUBLISH => json!({
            "type": "object",
            "required": [
                "event",
                "event_kind",
                "profile",
                "display_profile",
                "accepted_relays",
                "rejected_relays",
                "persist_recommended",
                "persisted",
                "persistence_result",
                "profile_state",
                "relay_resilience",
                "relay_metrics"
            ],
            "additionalProperties": false,
            "properties": {
                "event": nostr_event_schema(),
                "event_kind": { "type": "integer", "enum": [0] },
                "profile": { "type": "object", "additionalProperties": true },
                "display_profile": { "type": "object", "additionalProperties": true },
                "accepted_relays": relay_diagnostics_schema(),
                "rejected_relays": relay_diagnostics_schema(),
                "persist_recommended": { "type": "boolean" },
                "persisted": { "type": "boolean" },
                "persistence_result": { "type": "string" },
                "profile_state": profile_state_output_schema(),
                "relay_resilience": relay_resilience_schema(),
                "relay_metrics": relay_metrics_schema()
            }
        }),
        OP_PROFILE_STATE => profile_state_output_schema(),
        OP_PROFILE_IMPORT => json!({
            "type": "object",
            "required": [
                "ok",
                "pubkey_hex",
                "relays_queried",
                "relay_results",
                "invalid_candidates",
                "relay_resilience",
                "relay_metrics"
            ],
            "additionalProperties": false,
            "properties": {
                "ok": { "type": "boolean" },
                "pubkey_hex": event_id_string_schema(),
                "error": { "type": "string" },
                "profile": { "type": "object", "additionalProperties": true },
                "display_profile": { "type": "object", "additionalProperties": true },
                "merged_profile": { "type": "object", "additionalProperties": true },
                "event": nostr_event_schema(),
                "source_relay": { "type": "string", "format": "uri" },
                "relays_queried": relay_array_schema(),
                "relay_results": relay_diagnostics_schema(),
                "dropped_profile_fields": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "invalid_candidates": relay_diagnostics_schema(),
                "relay_resilience": relay_resilience_schema(),
                "relay_metrics": relay_metrics_schema()
            }
        }),
        OP_QUERY_EVENTS => json!({
            "type": "object",
            "required": [
                "subscription_id",
                "filter",
                "results",
                "relay_resilience",
                "relay_metrics"
            ],
            "additionalProperties": false,
            "properties": {
                "subscription_id": { "type": "string" },
                "filter": { "type": "object", "additionalProperties": true },
                "results": relay_diagnostics_schema(),
                "relay_resilience": relay_resilience_schema(),
                "relay_metrics": relay_metrics_schema()
            }
        }),
        OP_LIST_RELAYS => json!({
            "type": "object",
            "required": ["relays", "public_key_hex"],
            "additionalProperties": false,
            "properties": {
                "relays": relay_array_schema(),
                "public_key_hex": event_id_string_schema()
            }
        }),
        OP_HEALTH => json!({
            "type": "object",
            "required": [
                "public_key_hex",
                "relay_health",
                "relay_resilience",
                "relay_metrics"
            ],
            "additionalProperties": false,
            "properties": {
                "public_key_hex": event_id_string_schema(),
                "relay_health": relay_diagnostics_schema(),
                "relay_resilience": relay_resilience_schema(),
                "relay_metrics": relay_metrics_schema()
            }
        }),
        OP_RELAYS_HEALTH => json!({
            "type": "object",
            "required": [
                "public_key_hex",
                "relay_scores",
                "scored_count",
                "relay_resilience",
                "relay_metrics"
            ],
            "additionalProperties": false,
            "properties": {
                "public_key_hex": event_id_string_schema(),
                "relay_scores": relay_diagnostics_schema(),
                "scored_count": { "type": "integer", "minimum": 0 },
                "relay_resilience": relay_resilience_schema(),
                "relay_metrics": relay_metrics_schema()
            }
        }),
        _ => json!({ "type": "object" }),
    }
}

// ─── Doctor types (V3 requirement) ───────────────────────────────────────

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

// ─── Connector ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct NostrSubscriptionTaskSet {
    topics: BTreeSet<String>,
    tasks: Vec<fcp_async_core::task::JoinHandle<()>>,
}

impl NostrSubscriptionTaskSet {
    fn abort_all(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

const INBOUND_DM_STATE_FILE: &str = "nostr_inbound_dm_state.json";
const INBOUND_DM_STATE_VERSION: u32 = 1;
const PROFILE_STATE_FILE: &str = "nostr_profile_state.json";
const PROFILE_STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NostrInboundDmStateFile {
    version: u32,
    connector_public_key_hex: String,
    guard: InboundDmGuardSnapshot,
    updated_at_secs: u64,
}

#[derive(Debug)]
struct NostrInboundDmStateStore {
    path: Option<PathBuf>,
    connector_public_key_hex: String,
    guard: Mutex<InboundDmGuardState>,
    load_result: String,
}

impl NostrInboundDmStateStore {
    fn new(
        zone_dir: Option<&str>,
        connector_public_key_hex: &str,
        seen_event_capacity: usize,
        rate_limits: InboundDmRateLimits,
    ) -> Self {
        let path = zone_dir
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .map(|path| path.join(INBOUND_DM_STATE_FILE));
        let (guard, load_result) = path.as_deref().map_or_else(
            || {
                (
                    InboundDmGuardState::new(seen_event_capacity, rate_limits),
                    "memory_only_no_zone_dir".to_string(),
                )
            },
            |path| {
                Self::load(
                    path,
                    connector_public_key_hex,
                    seen_event_capacity,
                    rate_limits,
                )
            },
        );
        Self {
            path,
            connector_public_key_hex: connector_public_key_hex.to_string(),
            guard: Mutex::new(guard),
            load_result,
        }
    }

    fn load(
        path: &Path,
        connector_public_key_hex: &str,
        seen_event_capacity: usize,
        rate_limits: InboundDmRateLimits,
    ) -> (InboundDmGuardState, String) {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return (
                    InboundDmGuardState::new(seen_event_capacity, rate_limits),
                    "state_missing_default".into(),
                );
            }
            Err(error) => {
                return (
                    InboundDmGuardState::new(seen_event_capacity, rate_limits),
                    format!("state_read_failed: {error}"),
                );
            }
        };
        let state = match serde_json::from_slice::<NostrInboundDmStateFile>(&bytes) {
            Ok(state) => state,
            Err(error) => {
                return (
                    InboundDmGuardState::new(seen_event_capacity, rate_limits),
                    format!("state_parse_failed: {error}"),
                );
            }
        };
        if state.version != INBOUND_DM_STATE_VERSION {
            return (
                InboundDmGuardState::new(seen_event_capacity, rate_limits),
                format!("state_version_{}_reset", state.version),
            );
        }
        if state.connector_public_key_hex != connector_public_key_hex {
            return (
                InboundDmGuardState::new(seen_event_capacity, rate_limits),
                "state_identity_mismatch_reset".into(),
            );
        }
        (
            InboundDmGuardState::from_snapshot_with_config(
                state.guard,
                seen_event_capacity,
                rate_limits,
            ),
            "state_loaded".into(),
        )
    }

    fn lock_guard(&self) -> MutexGuard<'_, InboundDmGuardState> {
        self.guard
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn prepare_subscription(&self) -> Value {
        let persistence_result = {
            let mut guard = self.lock_guard();
            guard.mark_reconnect();
            let persistence_result = self.persist_locked(&guard);
            drop(guard);
            persistence_result
        };
        let guard = self.lock_guard();
        json!({
            "load_result": self.load_result,
            "persistence_result": persistence_result,
            "cursor_before": guard.cursor(),
            "cursor_after": guard.cursor(),
            "reconnect_generation": guard.reconnect_generation(),
            "restart_generation": guard.restart_generation(),
            "seen_state": guard.last_transition()["seen_state"].clone(),
        })
    }

    fn effective_since(&self, requested_since: Option<i64>) -> Option<i64> {
        let cursor = self.lock_guard().cursor();
        match (requested_since, cursor) {
            (Some(requested), Some(cursor)) => Some(requested.max(cursor)),
            (Some(requested), None) => Some(requested),
            (None, Some(cursor)) => Some(cursor),
            (None, None) => None,
        }
    }

    fn persist(&self, guard: &InboundDmGuardState) -> String {
        self.persist_locked(guard)
    }

    fn persist_locked(&self, guard: &InboundDmGuardState) -> String {
        let Some(path) = &self.path else {
            return "memory_only_no_zone_dir".into();
        };
        let state = NostrInboundDmStateFile {
            version: INBOUND_DM_STATE_VERSION,
            connector_public_key_hex: self.connector_public_key_hex.clone(),
            guard: guard.snapshot(),
            updated_at_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs()),
        };
        let bytes = match serde_json::to_vec_pretty(&state) {
            Ok(bytes) => bytes,
            Err(error) => return format!("state_serialize_failed: {error}"),
        };
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            && let Err(error) = fs::create_dir_all(parent)
        {
            return format!("state_dir_create_failed: {error}");
        }
        let tmp_path = path.with_extension("json.tmp");
        if let Err(error) = fs::write(&tmp_path, bytes) {
            return format!("state_write_failed: {error}");
        }
        if let Err(error) = fs::rename(&tmp_path, path) {
            return format!("state_commit_failed: {error}");
        }
        "state_persisted".into()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NostrProfileStateFile {
    version: u32,
    connector_public_key_hex: String,
    last_published_at: Option<u64>,
    last_published_event_id: Option<String>,
    last_publish_results: BTreeMap<String, String>,
    last_profile: Option<NostrProfile>,
    updated_at_secs: u64,
}

#[derive(Debug)]
struct NostrProfileStateStore {
    path: Option<PathBuf>,
    connector_public_key_hex: String,
    state: Mutex<NostrProfileStateFile>,
    load_result: String,
}

impl NostrProfileStateStore {
    fn new(zone_dir: Option<&str>, connector_public_key_hex: &str) -> Self {
        let path = zone_dir
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .map(|path| path.join(PROFILE_STATE_FILE));
        let (state, load_result) = path.as_deref().map_or_else(
            || {
                (
                    Self::empty_state(connector_public_key_hex),
                    "memory_only_no_zone_dir".to_string(),
                )
            },
            |path| Self::load(path, connector_public_key_hex),
        );
        Self {
            path,
            connector_public_key_hex: connector_public_key_hex.to_string(),
            state: Mutex::new(state),
            load_result,
        }
    }

    fn empty_state(connector_public_key_hex: &str) -> NostrProfileStateFile {
        NostrProfileStateFile {
            version: PROFILE_STATE_VERSION,
            connector_public_key_hex: connector_public_key_hex.to_string(),
            last_published_at: None,
            last_published_event_id: None,
            last_publish_results: BTreeMap::new(),
            last_profile: None,
            updated_at_secs: 0,
        }
    }

    fn load(path: &Path, connector_public_key_hex: &str) -> (NostrProfileStateFile, String) {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return (
                    Self::empty_state(connector_public_key_hex),
                    "state_missing_default".into(),
                );
            }
            Err(error) => {
                return (
                    Self::empty_state(connector_public_key_hex),
                    format!("state_read_failed: {error}"),
                );
            }
        };
        let state = match serde_json::from_slice::<NostrProfileStateFile>(&bytes) {
            Ok(state) => state,
            Err(error) => {
                return (
                    Self::empty_state(connector_public_key_hex),
                    format!("state_parse_failed: {error}"),
                );
            }
        };
        if state.version != PROFILE_STATE_VERSION {
            return (
                Self::empty_state(connector_public_key_hex),
                format!("state_version_{}_reset", state.version),
            );
        }
        if state.connector_public_key_hex != connector_public_key_hex {
            return (
                Self::empty_state(connector_public_key_hex),
                "state_identity_mismatch_reset".into(),
            );
        }
        (state, "state_loaded".into())
    }

    fn lock_state(&self) -> MutexGuard<'_, NostrProfileStateFile> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn last_published_at(&self) -> Option<u64> {
        self.lock_state().last_published_at
    }

    fn snapshot(&self) -> Value {
        let state = self.lock_state();
        json!({
            "load_result": self.load_result,
            "persistence": if self.path.is_some() { "zone_dir" } else { "memory_only_no_zone_dir" },
            "connector_public_key_hex": self.connector_public_key_hex.clone(),
            "last_published_at": state.last_published_at,
            "last_published_event_id": state.last_published_event_id.clone(),
            "last_publish_results": state.last_publish_results.clone(),
            "last_profile": state.last_profile.clone(),
            "updated_at_secs": state.updated_at_secs,
        })
    }

    fn persist_publish(&self, event: &Value, profile: NostrProfile, output: &Value) -> String {
        let event_id = event.get("id").and_then(Value::as_str).map(str::to_string);
        let created_at = event.get("created_at").and_then(Value::as_u64);
        let mut results = BTreeMap::new();
        if let Some(accepted) = output.get("accepted_relays").and_then(Value::as_array) {
            for relay in accepted {
                if let Some(relay_url) = relay.get("relay").and_then(Value::as_str) {
                    results.insert(relay_url.to_string(), "ok".to_string());
                }
            }
        }
        if let Some(rejected) = output.get("rejected_relays").and_then(Value::as_array) {
            for relay in rejected {
                if let Some(relay_url) = relay.get("relay").and_then(Value::as_str) {
                    results
                        .entry(relay_url.to_string())
                        .or_insert_with(|| "failed".to_string());
                }
            }
        }
        let updated_at_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let state_to_persist = {
            let mut state = self.lock_state();
            state.last_published_at = created_at;
            state.last_published_event_id = event_id;
            state.last_publish_results = results;
            state.last_profile = Some(profile);
            state.updated_at_secs = updated_at_secs;
            state.clone()
        };
        self.persist_state(&state_to_persist)
    }

    fn persist_state(&self, state: &NostrProfileStateFile) -> String {
        let Some(path) = &self.path else {
            return "memory_only_no_zone_dir".into();
        };
        let bytes = match serde_json::to_vec_pretty(state) {
            Ok(bytes) => bytes,
            Err(error) => return format!("state_serialize_failed: {error}"),
        };
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            && let Err(error) = fs::create_dir_all(parent)
        {
            return format!("state_dir_create_failed: {error}");
        }
        let tmp_path = path.with_extension("json.tmp");
        if let Err(error) = fs::write(&tmp_path, bytes) {
            return format!("state_write_failed: {error}");
        }
        if let Err(error) = fs::rename(&tmp_path, path) {
            return format!("state_commit_failed: {error}");
        }
        "state_persisted".into()
    }
}

fn nostr_coordination_material_hash(scope: &str, material: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scope.len().to_be_bytes());
    hasher.update(scope.as_bytes());
    hasher.update(material.len().to_be_bytes());
    hasher.update(material.as_bytes());
    hex::encode(hasher.finalize())
}

fn nostr_coordination_dm_channel_id(recipient_pubkey_hex: &str) -> ChannelId {
    ChannelId::new(format!(
        "nostr:dm:{}",
        nostr_coordination_material_hash("dm-recipient", recipient_pubkey_hex)
    ))
}

fn nostr_coordination_public_identity_channel_id(public_key_hex: &str) -> ChannelId {
    ChannelId::new(format!(
        "nostr:public-identity:{}",
        nostr_coordination_material_hash("public-identity", public_key_hex)
    ))
}

fn nostr_coordination_public_thread_channel_id() -> ChannelId {
    ChannelId::new("nostr:public-thread")
}

fn nostr_coordination_thread_id(event_id_hex: &str) -> ThreadId {
    ThreadId::new(format!(
        "nostr:event:{}",
        nostr_coordination_material_hash("event-thread", event_id_hex)
    ))
}

fn nostr_note_thread_event_id(input: &Value) -> Option<String> {
    let tags = input.get("tags")?.as_array()?;
    let mut first_event_id = None;
    for tag in tags {
        let Some(parts) = tag.as_array() else {
            continue;
        };
        if parts.first().and_then(Value::as_str) != Some("e") {
            continue;
        }
        let Some(event_id) = parts.get(1).and_then(Value::as_str) else {
            continue;
        };
        if !is_nostr_event_id(event_id) {
            continue;
        }
        let normalized = event_id.to_ascii_lowercase();
        if parts.get(3).and_then(Value::as_str) == Some("root") {
            return Some(normalized);
        }
        first_event_id.get_or_insert(normalized);
    }
    first_event_id
}

fn is_nostr_event_id(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn nostr_coordination_audit_records(
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

fn nostr_insert_coordination(
    output: &mut Value,
    decision: &ChatCoordinationSendDecision,
    backend: ChatCoordinationBackend,
    claimant_agent_id: &AgentId,
) -> FcpResult<()> {
    let object = output.as_object_mut().ok_or_else(|| FcpError::Internal {
        message: "Serialized Nostr publish response was not an object".into(),
    })?;
    object.insert(
        "coordination".into(),
        json!(nostr_coordination_audit_records(
            decision,
            backend,
            claimant_agent_id,
        )),
    );
    Ok(())
}

pub struct NostrConnector {
    base: BaseConnector,
    client: Option<NostrClient>,
    verifier: Option<CapabilityVerifier>,
    zone_id: Option<ZoneId>,
    inbound_state: Option<Arc<NostrInboundDmStateStore>>,
    profile_state: Option<Arc<NostrProfileStateStore>>,
    subscriptions: Mutex<BTreeMap<String, NostrSubscriptionTaskSet>>,
    subscription_diagnostics: Arc<Mutex<Vec<Value>>>,
    subscription_events: Arc<Mutex<Vec<EventEnvelope>>>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
    started_at: Instant,
}

impl std::fmt::Debug for NostrConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrConnector")
            .field("base", &self.base)
            .field("client", &self.client)
            .field("verifier", &self.verifier)
            .field("zone_id", &self.zone_id)
            .field("inbound_state", &self.inbound_state)
            .field("profile_state", &self.profile_state)
            .field("subscriptions", &self.subscriptions)
            .field("subscription_diagnostics", &self.subscription_diagnostics)
            .field("subscription_events", &self.subscription_events)
            .field("chat_coordination_config", &self.chat_coordination_config)
            .field("thread_ownership_checker", &"<thread-ownership-checker>")
            .field("started_at", &self.started_at)
            .finish()
    }
}

impl NostrConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.nostr")),
            client: None,
            verifier: None,
            zone_id: None,
            inbound_state: None,
            profile_state: None,
            subscriptions: Mutex::new(BTreeMap::new()),
            subscription_diagnostics: Arc::new(Mutex::new(Vec::new())),
            subscription_events: Arc::new(Mutex::new(Vec::new())),
            chat_coordination_config: default_nostr_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
            started_at: Instant::now(),
        }
    }

    /// Replace the thread-ownership checker used by outbound chat coordination.
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

    const fn event_caps() -> EventCaps {
        EventCaps {
            streaming: true,
            replay: false,
            min_buffer_events: 0,
            requires_ack: false,
        }
    }

    fn event_info() -> Vec<EventInfo> {
        vec![EventInfo {
            topic: EVENT_INBOUND_DM.into(),
            schema: json!({
                "type": "object",
                "required": [
                    "stream_id",
                    "relay",
                    "event_id",
                    "sender",
                    "recipient",
                    "event_kind",
                    "created_at",
                    "plaintext"
                ],
                "properties": {
                    "stream_id": { "type": "string" },
                    "relay": { "type": "string" },
                    "event_id": { "type": "string" },
                    "sender": { "type": "string", "minLength": 64, "maxLength": 64 },
                    "recipient": { "type": "string", "minLength": 64, "maxLength": 64 },
                    "event_kind": { "type": "integer", "enum": [4] },
                    "created_at": { "type": "integer" },
                    "plaintext": { "type": "string" }
                },
                "additionalProperties": false
            }),
            requires_ack: false,
        }]
    }

    fn subscription_states(&self) -> MutexGuard<'_, BTreeMap<String, NostrSubscriptionTaskSet>> {
        self.subscriptions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn subscription_diagnostics_mut(&self) -> MutexGuard<'_, Vec<Value>> {
        self.subscription_diagnostics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn subscription_events_mut(&self) -> MutexGuard<'_, Vec<EventEnvelope>> {
        self.subscription_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn clear_subscriptions(&self, reason: &'static str) {
        let mut states = self.subscription_states();
        let drained = std::mem::take(&mut *states);
        drop(states);
        for (stream_id, state) in drained {
            self.subscription_diagnostics_mut().push(json!({
                "stream_id": stream_id,
                "relay": null,
                "stage": "cancellation",
                "event_kind": null,
                "event_id": null,
                "filter_kinds": [4],
                "filter_p_tag": [],
                "subscribe_result": null,
                "unsubscribe_result": "aborted",
                "cancellation_reason": reason,
                "core_decision": null,
                "rejection_reason": null,
                "decrypt_result": null,
                "shutdown_result": "task_abort_requested",
                "elapsed_ms": 0,
            }));
            state.abort_all();
        }
    }

    #[must_use]
    pub fn active_subscription_count(&self) -> usize {
        self.subscription_states().len()
    }

    #[must_use]
    pub fn subscription_diagnostics(&self) -> Vec<Value> {
        self.subscription_diagnostics_mut().clone()
    }

    #[must_use]
    pub fn subscription_events(&self) -> Vec<EventEnvelope> {
        self.subscription_events_mut().clone()
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
                "ConnectorRuntime active".into()
            } else {
                "ConnectorRuntime not initialized".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: self.verifier.is_some(),
            message: Some(if self.verifier.is_some() {
                "Handshake completed".into()
            } else {
                "No handshake - run handshake after configure".into()
            }),
            critical: false,
        });

        if let Some(client) = &self.client {
            checks.push(DoctorCheck {
                name: "relays".into(),
                passed: !client.relays.is_empty(),
                message: Some(format!("{} relay(s) configured", client.relay_count())),
                critical: true,
            });

            checks.push(DoctorCheck {
                name: "key_material".into(),
                passed: true,
                message: Some(format!(
                    "Public key: {}...{}",
                    &client.public_key_hex()[..8],
                    &client.public_key_hex()[56..]
                )),
                critical: true,
            });
        }

        DoctorResult::from_checks(checks)
    }

    #[allow(clippy::too_many_lines)]
    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_PUBLISH_NOTE,
                "Publish a signed public Nostr note",
                "Sign one public kind-1 Nostr note with the configured secp256k1 secret key and publish it to every configured relay. Encrypted DMs use the separate `nostr.dm.send` operation and `nostr.dm.write` capability.",
                CAP_NOTES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                publish_note_input_schema(),
                "Use when you need to publish one public note through the connector's bound keypair to every configured relay.",
                &[
                    "This operation remains kind-1 public-note only; encrypted DMs require `nostr.dm.send`.",
                    "`kind` is fixed to `1` for this public-note operation.",
                    "`secret_key_hex` accepts either raw 64-character hex or NIP-19 `nsec`; secrets are redacted in Debug and error paths.",
                    "Publishing fans out to every configured relay; there is no per-request relay override.",
                ],
                &[
                    r#"{"input":{"content":"Release notes are ready for review.","kind":1,"tags":[["t","release"]]},"output":{"accepted_relays":[{"relay":"wss://relay.example.com","ok":true}],"rejected_relays":[]}}"#,
                ],
                &[CAP_HEALTH_READ, CAP_RELAYS_READ, CAP_EVENTS_READ],
            ),
            operation(
                OP_SEND_DM,
                "Send a NIP-04 encrypted Nostr direct message",
                "Normalize a recipient pubkey from raw hex, NIP-19 `npub`, or `nostr:npub`; encrypt plaintext with the connector-bound secp256k1 secret key using NIP-04 AES-256-CBC; sign a kind-4 event with a `p` tag; and publish it to every configured relay.",
                CAP_DM_WRITE,
                RiskLevel::High,
                SafetyTier::Risky,
                IdempotencyClass::None,
                send_dm_input_schema(),
                "Use for outbound encrypted direct messages when the caller has explicit `nostr.dm.write` authority.",
                &[
                    "`recipient`, `recipient_pubkey`, and `target` accept raw hex, NIP-19 `npub`, and `nostr:npub`; aliases must agree if multiple are provided.",
                    "`plaintext` and `content` are accepted as input aliases, capped at 4096 bytes, and never returned in operation output.",
                    "Self-send is rejected unless `allow_self_send` is explicitly true.",
                    "The operation returns event id, kind, public sender/recipient metadata, and per-relay delivery diagnostics; it omits plaintext and encrypted content.",
                ],
                &[
                    r#"{"input":{"recipient_pubkey":"1111111111111111111111111111111111111111111111111111111111111111","plaintext":"Can you review the incident summary?"},"output":{"event_kind":4,"accepted_relays":[{"relay":"wss://relay.example.com","ok":true}]}}"#,
                ],
                &[CAP_HEALTH_READ, CAP_RELAYS_READ],
            ),
            operation(
                OP_PROFILE_PUBLISH,
                "Publish NIP-01 profile metadata",
                "Validate NIP-01 profile metadata, require safe https profile URLs, sign a kind-0 replaceable event with the connector-bound key, publish it to every configured relay, and persist publish state only after at least one relay accepts.",
                CAP_PROFILE_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                profile_publish_input_schema(),
                "Use when the connector's bound identity should publish or replace its public Nostr profile.",
                &[
                    "This is a separate kind-0 profile operation; `nostr.notes.publish` remains kind-1 only.",
                    "Profile URLs must use https and must not target loopback, private, link-local, .local, or .internal hosts.",
                    "State is persisted only after at least one configured relay accepts the event.",
                    "`last_published_at` can provide host state, but connector-persisted state also enforces monotonic timestamps.",
                ],
                &[
                    r#"{"input":{"profile":{"display_name":"FCP Operations","about":"Automation status and handoff notes","website":"https://example.com/fcp"}},"output":{"event_kind":0,"persisted":true,"accepted_relays":[{"relay":"wss://relay.example.com","ok":true}]}}"#,
                ],
                &[CAP_PROFILE_READ, CAP_RELAYS_READ, CAP_HEALTH_READ],
            ),
            operation(
                OP_PROFILE_STATE,
                "Read local Nostr profile publish state",
                "Return connector-owned NIP-01 profile publish state from the handshake zone directory when available. This is local state only and never queries relays.",
                CAP_PROFILE_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                empty_input_schema(),
                "Use to inspect the last profile event id, timestamp, profile fields, and per-relay publish result persisted by this connector instance.",
                &[
                    "This operation does not import profile data from relays; use `nostr.profile.import` for bounded relay reads.",
                    "No secret key material is persisted or returned.",
                ],
                &[
                    r#"{"input":{},"output":{"persistence":"zone_dir","last_published_event_id":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","last_profile":{"display_name":"FCP Operations"}}}"#,
                ],
                &[CAP_PROFILE_WRITE, CAP_RELAYS_READ],
            ),
            operation(
                OP_PROFILE_IMPORT,
                "Import a verified NIP-01 profile from configured relays",
                "Query configured relays for the newest verified kind-0 profile event for a public key, reject invalid signatures/shapes, drop unsafe imported URLs, and optionally merge imported fields into a caller-supplied local profile without overwriting local values.",
                CAP_PROFILE_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                profile_import_input_schema(),
                "Use before profile editing or display to read the latest public kind-0 profile state through the connector's relay set.",
                &[
                    "Import uses the configured relay list; there is no per-request relay override.",
                    "Unsafe URL fields from imported content are omitted and reported rather than returned for display/fetch use.",
                    "If `pubkey` is omitted, the connector imports its own bound public key profile.",
                ],
                &[
                    r#"{"input":{"pubkey":"2222222222222222222222222222222222222222222222222222222222222222","local_profile":{"display_name":"Local fallback"}},"output":{"ok":true,"pubkey_hex":"2222222222222222222222222222222222222222222222222222222222222222","relays_queried":["wss://relay.example.com"]}}"#,
                ],
                &[CAP_EVENTS_READ, CAP_RELAYS_READ, CAP_PROFILE_WRITE],
            ),
            operation(
                OP_QUERY_EVENTS,
                "Query bounded public Nostr events from configured relays",
                "Run one bounded REQ/EOSE query across configured relays and collect matching public events. The connector does not maintain long-lived subscriptions, replay cursors, or cross-relay dedupe.",
                CAP_EVENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                query_events_input_schema(),
                "Use for bounded public-event queries when you already know the relay set and do not need a long-lived subscription.",
                &[
                    "This is a bounded public-event query surface, not DM sync.",
                    "If `limit` is omitted the connector uses `default_query_limit`.",
                    "`authors` accepts raw hex, NIP-19 `npub`, and `nostr:npub`; filters sent to relays use canonical hex.",
                    "Results are returned per relay and may contain duplicates across relays.",
                ],
                &[
                    r#"{"input":{"authors":["3333333333333333333333333333333333333333333333333333333333333333"],"kinds":[1],"limit":20},"output":{"subscription_id":"sub-001","results":[{"relay":"wss://relay.example.com","events":[]}]}}"#,
                ],
                &[CAP_RELAYS_READ, CAP_HEALTH_READ],
            ),
            operation(
                OP_LIST_RELAYS,
                "List configured relays",
                "Return the configured relay allowlist and the x-only public key derived from the bound secp256k1 secret key. This is local inspection only; it does not discover or mutate relays.",
                CAP_RELAYS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                empty_input_schema(),
                "Use to inspect which relays and public key this connector instance is bound to.",
                &[
                    "This does not discover relays from NIP metadata or mutate relay policy.",
                    "The relay list is static configuration for this request-response slice.",
                ],
                &[
                    r#"{"input":{},"output":{"relays":["wss://relay.example.com"],"public_key_hex":"4444444444444444444444444444444444444444444444444444444444444444"}}"#,
                ],
                &[CAP_HEALTH_READ, CAP_EVENTS_READ],
            ),
            operation(
                OP_HEALTH,
                "Verify relay connectivity and local signing identity",
                "Open and close each configured relay and report reachability alongside the derived public key. This verifies relay reachability and local key derivation, not encrypted DM support or publish success policy.",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                empty_input_schema(),
                "Use before publishing to confirm the configured relay set is reachable and the bound signing identity is coherent.",
                &[
                    "Health checks websocket reachability only; it does not prove encrypted DM support.",
                    "Health does not score, rank, or deduplicate relays.",
                ],
                &[
                    r#"{"input":{},"output":{"public_key_hex":"5555555555555555555555555555555555555555555555555555555555555555","relay_health":[{"relay":"wss://relay.example.com","ok":true}]}}"#,
                ],
                &[CAP_RELAYS_READ, CAP_NOTES_WRITE],
            ),
            operation(
                OP_RELAYS_HEALTH,
                "Score relay health with latency and NIP support metrics",
                "Connect to each configured relay, measure connection latency, and probe for NIP-04 (encrypted DM) and NIP-44 (gift-wrapped) event kind support. Returns per-relay health scores. This is a more detailed alternative to the basic `nostr.health` operation.",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                empty_input_schema(),
                "Use when you need detailed per-relay metrics including latency and NIP support, rather than just reachability.",
                &[
                    "This operation probes relay kind support by issuing bounded REQs; some relays may rate-limit probing.",
                    "NIP-44 support is inferred from kind=1059 (gift-wrapped) event indexing, not direct NIP-44 negotiation.",
                    "Latency measures WebSocket connection time only, not query round-trip time.",
                ],
                &[
                    r#"{"input":{},"output":{"public_key_hex":"6666666666666666666666666666666666666666666666666666666666666666","relay_scores":[{"relay":"wss://relay.example.com","score":100}],"scored_count":1}}"#,
                ],
                &[CAP_RELAYS_READ, CAP_NOTES_WRITE, CAP_EVENTS_READ],
            ),
        ]
    }

    fn chat_coordination_agent_id(&self) -> AgentId {
        AgentId::new(self.base.instance_id.as_str().to_owned())
    }

    async fn claim_before_nostr_send(
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

    async fn invoke_publish_note_with_coordination(
        &self,
        zone_id: &ZoneId,
        input: &Value,
        client: &NostrClient,
    ) -> FcpResult<Value> {
        let _ = required_string(input, "content")?;
        let _ = note_kind(input)?;
        let _ = note_tags(input)?;
        let thread_id = nostr_note_thread_event_id(input)
            .as_deref()
            .map(nostr_coordination_thread_id);
        let channel_id = if thread_id.is_some() {
            nostr_coordination_public_thread_channel_id()
        } else {
            nostr_coordination_public_identity_channel_id(client.public_key_hex())
        };
        let claimant_agent_id = self.chat_coordination_agent_id();
        let coordination = self
            .claim_before_nostr_send(
                zone_id.clone(),
                channel_id,
                thread_id,
                claimant_agent_id.clone(),
            )
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                operation = OP_PUBLISH_NOTE,
                "Nostr notes.publish denied by chat coordination"
            );
            return Err(error.clone());
        }
        let mut output = Box::pin(client.publish_note(input)).await?;
        nostr_insert_coordination(
            &mut output,
            &coordination,
            self.chat_coordination_config.backend(),
            &claimant_agent_id,
        )?;
        Ok(output)
    }

    async fn invoke_send_dm_with_coordination(
        &self,
        zone_id: &ZoneId,
        input: &Value,
        client: &NostrClient,
    ) -> FcpResult<Value> {
        let request = parse_dm_send_input(input, client.public_key_hex())?;
        let thread_id = request
            .reply_to_event_id()
            .map(nostr_coordination_thread_id);
        let claimant_agent_id = self.chat_coordination_agent_id();
        let coordination = self
            .claim_before_nostr_send(
                zone_id.clone(),
                nostr_coordination_dm_channel_id(request.recipient_pubkey()),
                thread_id,
                claimant_agent_id.clone(),
            )
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                operation = OP_SEND_DM,
                "Nostr dm.send denied by chat coordination"
            );
            return Err(error.clone());
        }
        let mut output = Box::pin(client.send_dm(input)).await?;
        nostr_insert_coordination(
            &mut output,
            &coordination,
            self.chat_coordination_config.backend(),
            &claimant_agent_id,
        )?;
        Ok(output)
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])?;

        let output = match req.operation.as_str() {
            OP_PUBLISH_NOTE => {
                self.invoke_publish_note_with_coordination(&req.zone_id, &req.input, client)
                    .await?
            }
            OP_SEND_DM => {
                self.invoke_send_dm_with_coordination(&req.zone_id, &req.input, client)
                    .await?
            }
            OP_PROFILE_PUBLISH => {
                let profile_state = self.profile_state.as_ref().ok_or(FcpError::NotHandshaken)?;
                let publish_input = parse_profile_publish_input(&req.input)?;
                let mut output =
                    Box::pin(client.publish_profile(&req.input, profile_state.last_published_at()))
                        .await?;
                let accepted_count = output
                    .get("accepted_relays")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                let persistence_result = if accepted_count > 0 {
                    let event = output.get("event").cloned().unwrap_or(Value::Null);
                    profile_state.persist_publish(&event, publish_input.profile().clone(), &output)
                } else {
                    "not_persisted_no_relay_acceptance".to_string()
                };
                if let Some(object) = output.as_object_mut() {
                    object.insert("persisted".into(), json!(accepted_count > 0));
                    object.insert("persistence_result".into(), json!(persistence_result));
                    object.insert("profile_state".into(), profile_state.snapshot());
                }
                output
            }
            OP_PROFILE_STATE => self
                .profile_state
                .as_ref()
                .ok_or(FcpError::NotHandshaken)?
                .snapshot(),
            OP_PROFILE_IMPORT => Box::pin(client.import_profile(&req.input)).await?,
            OP_QUERY_EVENTS => Box::pin(client.query_events(&req.input)).await?,
            OP_LIST_RELAYS => json!({
                "relays": client.relay_urls(),
                "public_key_hex": client.public_key_hex(),
            }),
            OP_HEALTH => client.health_details().await?,
            OP_RELAYS_HEALTH => Box::pin(client.relay_health_scores()).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("unknown operation: {}", req.operation),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }

    fn validate_inbound_subscription_request(req: &SubscribeRequest) -> FcpResult<Option<i64>> {
        if req.topics.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("subscribe requires explicit `{EVENT_INBOUND_DM}` topic"),
            });
        }
        if let Some(topic) = req
            .topics
            .iter()
            .find(|topic| topic.as_str() != EVENT_INBOUND_DM)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "unsupported Nostr stream `{topic}`; only `{EVENT_INBOUND_DM}` is implemented"
                ),
            });
        }
        req.since
            .as_deref()
            .map(|since| {
                since.parse::<i64>().map_err(|_| FcpError::InvalidRequest {
                    code: 1003,
                    message: "`since` for Nostr inbound DM subscriptions must be a unix timestamp"
                        .into(),
                })
            })
            .transpose()
    }

    fn validate_unsubscribe_request(req: &UnsubscribeRequest) -> FcpResult<()> {
        if req.topics.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("unsubscribe requires explicit `{EVENT_INBOUND_DM}` topic"),
            });
        }
        if let Some(topic) = req
            .topics
            .iter()
            .find(|topic| topic.as_str() != EVENT_INBOUND_DM)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "unsupported Nostr stream `{topic}`; only `{EVENT_INBOUND_DM}` is implemented"
                ),
            });
        }
        Ok(())
    }

    fn build_inbound_subscription_envelope(
        connector_id: ConnectorId,
        instance_id: fcp_prelude::InstanceId,
        zone_id: ZoneId,
        accepted: &crate::client::InboundDmAccepted,
        relay: &str,
        stream_id: &str,
    ) -> EventEnvelope {
        let payload = inbound_dm_subscription_event_payload(accepted, relay, stream_id);
        let principal = Principal {
            kind: "nostr".into(),
            id: accepted.sender_pubkey_hex.clone(),
            trust: TrustLevel::Paired,
            display: None,
        };
        EventEnvelope::new(
            EVENT_INBOUND_DM,
            EventData::new(connector_id, instance_id, zone_id, principal, payload),
        )
        .with_stream_key(accepted.sender_pubkey_hex.clone())
        .with_cursor(accepted.event_id.clone())
        .with_ordering(OrderingPolicy::PerKey)
    }
}

impl Default for NostrConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(NostrConnector);

#[allow(clippy::too_many_lines)]
#[async_trait]
impl FcpConnector for NostrConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let chat_coordination_config = parse_nostr_chat_coordination_config(
            config.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;
        let config: NostrConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid Nostr configuration: {error}"),
            })?;
        self.clear_subscriptions("reconfigured");
        let client = NostrClient::new(&config)?;
        self.client = Some(client);
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
        self.zone_id = None;
        self.inbound_state = None;
        self.profile_state = None;
        self.chat_coordination_config = chat_coordination_config;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        self.base.set_handshaken(true);
        self.zone_id = Some(req.zone.clone());
        self.inbound_state = Some(Arc::new(NostrInboundDmStateStore::new(
            req.zone_dir.as_deref(),
            client.public_key_hex(),
            client.inbound_dm_seen_event_capacity(),
            client.inbound_dm_rate_limits(),
        )));
        self.profile_state = Some(Arc::new(NostrProfileStateStore::new(
            req.zone_dir.as_deref(),
            client.public_key_hex(),
        )));
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
            event_caps: Some(Self::event_caps()),
            auth_caps: Some(nostr_auth_caps()),
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
            details: self.client.as_ref().map(|client| {
                json!({
                    "relay_count": client.relay_count(),
                    "public_key_hex": client.public_key_hex(),
                })
            }),
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = self.client.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before Nostr self_check",
            ));
        };
        match client.health_details().await {
            Ok(_) => Ok(SelfCheckReport::ok()),
            Err(error) => Ok(SelfCheckReport::from_error(&error)),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.clear_subscriptions("shutdown");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.verifier = None;
        self.zone_id = None;
        self.inbound_state = None;
        self.profile_state = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations(),
            events: Self::event_info(),
            resource_types: Vec::new(),
            auth_caps: Some(nostr_auth_caps()),
            event_caps: Some(Self::event_caps()),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = Box::pin(self.invoke_inner(req)).await;
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
        let Some(client) = self.client.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        };
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
        if let Err(error) = validate_simulation_input(req.operation.as_str(), &req.input, client) {
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let _verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let zone_id = self.zone_id.clone().ok_or(FcpError::NotHandshaken)?;
        let requested_since = Self::validate_inbound_subscription_request(&req)?;
        let inbound_state = self.inbound_state.clone().ok_or(FcpError::NotHandshaken)?;
        let state_prepare = inbound_state.prepare_subscription();
        let since = inbound_state.effective_since(requested_since);
        let stream_id = req.id.0.clone();

        let mut states = self.subscription_states();
        if states.contains_key(&stream_id) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("subscription `{stream_id}` already exists"),
            });
        }

        let diagnostics = Arc::clone(&self.subscription_diagnostics);
        let events = Arc::clone(&self.subscription_events);
        let connector_id = self.base.id.clone();
        let instance_id = self.base.instance_id.clone();
        let public_key_hex = client.public_key_hex().to_string();
        let secret_key = *client.secret_key();
        let request_timeout = client.request_timeout;
        let inbound_policy = client.inbound_dm_policy().clone();
        self.subscription_diagnostics_mut().push(json!({
            "stream_id": stream_id,
            "relay": null,
            "stage": "state_prepare",
            "event_kind": NIP04_KIND_ENCRYPTED_DM,
            "event_id": null,
            "filter_kinds": [NIP04_KIND_ENCRYPTED_DM],
            "filter_p_tag": [public_key_hex],
            "subscribe_result": "state_ready",
            "unsubscribe_result": null,
            "cancellation_reason": null,
            "core_decision": null,
            "rejection_reason": null,
            "decrypt_result": null,
            "shutdown_result": null,
            "cursor_before": state_prepare["cursor_before"].clone(),
            "cursor_after": state_prepare["cursor_after"].clone(),
            "seen_state": state_prepare["seen_state"].clone(),
            "reconnect_generation": state_prepare["reconnect_generation"].clone(),
            "restart_generation": state_prepare["restart_generation"].clone(),
            "persistence_result": state_prepare["persistence_result"].clone(),
            "state_load_result": state_prepare["load_result"].clone(),
            "requested_since": requested_since,
            "effective_since": since,
            "elapsed_ms": 0,
        }));
        let mut tasks = Vec::with_capacity(client.relays.len());
        for relay in client.relays.clone() {
            let diagnostics = Arc::clone(&diagnostics);
            let events = Arc::clone(&events);
            let inbound_state = Arc::clone(&inbound_state);
            let stream_id_for_task = stream_id.clone();
            let public_key_for_task = public_key_hex.clone();
            let policy_for_task = inbound_policy.clone();
            let connector_id = connector_id.clone();
            let instance_id = instance_id.clone();
            let zone_id = zone_id.clone();
            let task = fcp_async_core::task::spawn(async move {
                let relay_client = NostrRelayClient::new(&relay, request_timeout);
                let outcome = relay_client
                    .subscribe_inbound_dms_once(
                        &stream_id_for_task,
                        &public_key_for_task,
                        since,
                        &secret_key,
                        &policy_for_task,
                        &inbound_state.guard,
                        |guard| inbound_state.persist(guard),
                    )
                    .await;
                record_subscription_outcome(
                    outcome,
                    &diagnostics,
                    &events,
                    &connector_id,
                    &instance_id,
                    &zone_id,
                );
            });
            tasks.push(task);
        }

        states.insert(
            stream_id,
            NostrSubscriptionTaskSet {
                topics: req.topics.iter().cloned().collect(),
                tasks,
            },
        );
        drop(states);
        Ok(SubscribeResponse {
            r#type: "response".into(),
            id: req.id,
            result: SubscribeResult {
                confirmed_topics: vec![EVENT_INBOUND_DM.into()],
                cursors: HashMap::new(),
                replay_supported: false,
                buffer: None,
            },
        })
    }

    async fn unsubscribe(&self, req: UnsubscribeRequest) -> FcpResult<()> {
        self.base.check_ready()?;
        Self::validate_unsubscribe_request(&req)?;
        let requested_topics = req.topics.iter().cloned().collect::<BTreeSet<_>>();
        let mut states = self.subscription_states();
        let matching_streams = states
            .iter()
            .filter(|(_, state)| {
                state
                    .topics
                    .iter()
                    .any(|topic| requested_topics.contains(topic))
            })
            .map(|(stream_id, _)| stream_id.clone())
            .collect::<Vec<_>>();
        for stream_id in matching_streams {
            if let Some(state) = states.remove(&stream_id) {
                self.subscription_diagnostics_mut().push(json!({
                    "stream_id": stream_id,
                    "relay": null,
                    "stage": "unsubscribe",
                    "event_kind": null,
                    "event_id": null,
                    "filter_kinds": [4],
                    "filter_p_tag": [self.client.as_ref().map_or("", NostrClient::public_key_hex)],
                    "subscribe_result": null,
                    "unsubscribe_result": "aborted",
                    "cancellation_reason": "unsubscribe",
                    "core_decision": null,
                    "rejection_reason": null,
                    "decrypt_result": null,
                    "shutdown_result": "task_abort_requested",
                    "elapsed_ms": 0,
                }));
                state.abort_all();
            }
        }
        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_PUBLISH_NOTE => CAP_NOTES_WRITE,
        OP_SEND_DM => CAP_DM_WRITE,
        OP_PROFILE_PUBLISH => CAP_PROFILE_WRITE,
        OP_PROFILE_STATE | OP_PROFILE_IMPORT => CAP_PROFILE_READ,
        OP_QUERY_EVENTS => CAP_EVENTS_READ,
        OP_LIST_RELAYS => CAP_RELAYS_READ,
        OP_HEALTH | OP_RELAYS_HEALTH => CAP_HEALTH_READ,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn validate_simulation_input(
    operation: &str,
    input: &Value,
    client: &NostrClient,
) -> FcpResult<()> {
    match operation {
        OP_PUBLISH_NOTE => {
            let _ = required_string(input, "content")?;
            let _ = note_kind(input)?;
            let _ = note_tags(input)?;
            Ok(())
        }
        OP_SEND_DM => {
            let _ = parse_dm_send_input(input, client.public_key_hex())?;
            Ok(())
        }
        OP_PROFILE_PUBLISH => {
            let _ = parse_profile_publish_input(input)?;
            Ok(())
        }
        OP_PROFILE_STATE | OP_LIST_RELAYS | OP_HEALTH | OP_RELAYS_HEALTH => Ok(()),
        OP_PROFILE_IMPORT => {
            let _ = parse_profile_import_input(input, client.public_key_hex())?;
            Ok(())
        }
        OP_QUERY_EVENTS => {
            let _ = build_filter(input, client.default_query_limit)?;
            Ok(())
        }
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("unknown operation: {operation}"),
        }),
    }
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| {
            matches!(
                capability.as_str(),
                CAP_NOTES_WRITE
                    | CAP_DM_WRITE
                    | CAP_PROFILE_WRITE
                    | CAP_PROFILE_READ
                    | CAP_EVENTS_READ
                    | CAP_RELAYS_READ
                    | CAP_HEALTH_READ
            )
        })
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

fn nostr_auth_caps() -> AuthCaps {
    AuthCaps {
        methods: vec![
            "secp256k1_secret_key_hex".to_string(),
            "nip19_nsec".to_string(),
            "nip19_npub".to_string(),
            "nostr_uri_npub".to_string(),
        ],
        oauth: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn operation(
    id: &'static str,
    summary: &str,
    description: &str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: Value,
    when_to_use: &str,
    common_mistakes: &[&str],
    examples: &[&str],
    related: &[&'static str],
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(description.into()),
        input_schema,
        output_schema: output_schema_for(id),
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: common_mistakes
                .iter()
                .map(|item| (*item).to_string())
                .collect(),
            examples: examples.iter().map(|item| (*item).to_string()).collect(),
            related: related
                .iter()
                .map(|capability| CapabilityId::from_static(capability))
                .collect(),
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn record_subscription_outcome(
    outcome: InboundDmSubscriptionOutcome,
    diagnostics: &Arc<Mutex<Vec<Value>>>,
    events: &Arc<Mutex<Vec<EventEnvelope>>>,
    connector_id: &ConnectorId,
    instance_id: &fcp_prelude::InstanceId,
    zone_id: &ZoneId,
) {
    let relay = outcome.relay.clone();
    let stream_id = outcome.stream_id.clone();
    diagnostics
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .extend(outcome.diagnostics);

    let mut event_sink = events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for accepted in outcome.accepted {
        event_sink.push(NostrConnector::build_inbound_subscription_envelope(
            connector_id.clone(),
            instance_id.clone(),
            zone_id.clone(),
            &accepted,
            &relay,
            &stream_id,
        ));
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::NostrKeyMaterial;
    use crate::types::NIP01_KIND_PROFILE;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{
        CapabilityConstraints, CapabilityToken, ConnectorId, RequestId, SelfCheckStatus, ZoneId,
    };
    use fcp_sdk::prelude::FcpConnector;
    use std::sync::atomic::Ordering;
    use uuid::Uuid;

    fn test_config() -> Value {
        json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111"
        })
    }

    fn handshake_request_for(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [9u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_HEALTH_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn handshake_request() -> HandshakeRequest {
        handshake_request_for([7u8; 32])
    }

    fn unique_zone_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fcp-nostr-{label}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("test zone dir should be created");
        dir
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
        instance_id: &str,
    ) -> CapabilityToken {
        let now = Utc::now();
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
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .target_instance(instance_id)
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    fn invoke_request(
        signing_key: &Ed25519SigningKey,
        operation: &'static str,
        capability: &'static str,
        instance_id: &str,
        input: Value,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new(format!("test-{operation}")),
            connector_id: ConnectorId::from_static("fcp.nostr"),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: capability_token(signing_key, capability, operation, instance_id),
            holder_proof: None,
            context: None,
            idempotency_key: Some(format!("idem-{operation}")),
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    const EXPECTED_MANIFEST_SCHEMA_OPS: &[(&str, &str)] = &[
        (OP_PUBLISH_NOTE, "notes_publish"),
        (OP_SEND_DM, "dm_send"),
        (OP_PROFILE_PUBLISH, "profile_publish"),
        (OP_PROFILE_STATE, "profile_state"),
        (OP_PROFILE_IMPORT, "profile_import"),
        (OP_QUERY_EVENTS, "events_query"),
        (OP_LIST_RELAYS, "relays_list"),
        (OP_HEALTH, "health"),
        (OP_RELAYS_HEALTH, "relays_health"),
    ];

    fn nostr_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML)
            .map_err(|err| format!("Nostr manifest TOML should parse: {err}"))
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

    fn operation_ai_hints<'a>(
        manifest: &'a toml::Value,
        operation_key: &str,
    ) -> Result<&'a toml::map::Map<String, toml::Value>, String> {
        manifest_operations(manifest)?
            .get(operation_key)
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get("ai_hints"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("{operation_key} should declare ai_hints"))
    }

    fn hint_string_array(
        hints: &toml::map::Map<String, toml::Value>,
        field: &str,
    ) -> Result<Vec<String>, String> {
        let values = hints
            .get(field)
            .and_then(toml::Value::as_array)
            .ok_or_else(|| format!("ai_hints.{field} should be an array"))?;
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|text| !text.trim().is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| format!("ai_hints.{field} entries should be non-empty strings"))
            })
            .collect()
    }

    const RELAY_NETWORK_CONSTRAINT_OPS: &[&str] = &[
        "notes_publish",
        "dm_send",
        "profile_publish",
        "profile_import",
        "events_query",
        "health",
        "relays_health",
    ];
    const LOCAL_ONLY_NETWORK_CONSTRAINT_OPS: &[&str] = &["profile_state", "relays_list"];

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

    fn constraint_strings(
        constraints: &toml::map::Map<String, toml::Value>,
        field: &str,
    ) -> Result<Vec<String>, String> {
        let values = constraints
            .get(field)
            .and_then(toml::Value::as_array)
            .ok_or_else(|| format!("{field} should be a string array"))?;
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{field} should contain only strings"))
            })
            .collect()
    }

    fn constraint_integers(
        constraints: &toml::map::Map<String, toml::Value>,
        field: &str,
    ) -> Result<Vec<i64>, String> {
        let values = constraints
            .get(field)
            .and_then(toml::Value::as_array)
            .ok_or_else(|| format!("{field} should be an integer array"))?;
        values
            .iter()
            .map(|value| {
                value
                    .as_integer()
                    .ok_or_else(|| format!("{field} should contain only integers"))
            })
            .collect()
    }

    fn constraint_bool(
        constraints: &toml::map::Map<String, toml::Value>,
        field: &str,
    ) -> Result<bool, String> {
        constraints
            .get(field)
            .and_then(toml::Value::as_bool)
            .ok_or_else(|| format!("{field} should be a boolean"))
    }

    fn constraint_integer(
        constraints: &toml::map::Map<String, toml::Value>,
        field: &str,
    ) -> Result<i64, String> {
        constraints
            .get(field)
            .and_then(toml::Value::as_integer)
            .ok_or_else(|| format!("{field} should be an integer"))
    }

    fn assert_common_network_constraints(
        constraints: &toml::map::Map<String, toml::Value>,
        require_sni: bool,
        dns_max_ips: i64,
        connect_timeout_ms: i64,
    ) -> Result<(), String> {
        assert_eq!(
            constraint_strings(constraints, "ip_allow")?,
            Vec::<String>::new()
        );
        assert_eq!(
            constraint_strings(constraints, "cidr_deny")?,
            Vec::<String>::new()
        );
        assert_eq!(
            constraint_strings(constraints, "spki_pins")?,
            Vec::<String>::new()
        );
        for field in [
            "deny_localhost",
            "deny_private_ranges",
            "deny_tailnet_ranges",
            "deny_ip_literals",
            "require_host_canonicalization",
        ] {
            assert!(
                constraint_bool(constraints, field)?,
                "{field} should be true"
            );
        }
        assert_eq!(constraint_bool(constraints, "require_sni")?, require_sni);
        assert_eq!(constraint_integer(constraints, "dns_max_ips")?, dns_max_ips);
        assert_eq!(constraint_integer(constraints, "max_redirects")?, 0);
        assert_eq!(
            constraint_integer(constraints, "connect_timeout_ms")?,
            connect_timeout_ms
        );
        assert_eq!(constraint_integer(constraints, "total_timeout_ms")?, 30_000);
        assert_eq!(
            constraint_integer(constraints, "max_response_bytes")?,
            1_048_576
        );
        Ok(())
    }

    fn assert_relay_network_constraints(
        constraints: &toml::map::Map<String, toml::Value>,
    ) -> Result<(), String> {
        assert_eq!(
            constraint_strings(constraints, "host_allow")?,
            vec!["${nostr_relay_host}".to_owned()]
        );
        assert_eq!(constraint_integers(constraints, "port_allow")?, vec![443]);
        assert_common_network_constraints(constraints, true, 16, 10_000)
    }

    fn assert_no_egress_network_constraints(
        constraints: &toml::map::Map<String, toml::Value>,
    ) -> Result<(), String> {
        assert_eq!(
            constraint_strings(constraints, "host_allow")?,
            vec!["none.invalid".to_owned()]
        );
        assert_eq!(constraint_integers(constraints, "port_allow")?, vec![0]);
        assert_common_network_constraints(constraints, false, 0, 1_000)
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

    fn hex_64(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    fn sample_event(kind: u64) -> Value {
        json!({
            "id": hex_64('a'),
            "pubkey": hex_64('b'),
            "created_at": 1_715_000_000_u64,
            "kind": kind,
            "content": "hello",
            "tags": [["p", hex_64('c')]],
            "sig": hex_64('d')
        })
    }

    fn sample_relay_diagnostics() -> Value {
        json!([
            {
                "relay": "wss://relay.example.com",
                "ok": true,
                "latency_ms": 12
            }
        ])
    }

    fn sample_relay_resilience() -> Value {
        json!([
            {
                "relay_url": "wss://relay.example.com",
                "circuit_state": "closed",
                "success_count": 1,
                "failure_count": 0,
                "skipped_count": 0,
                "average_latency_ms": 12
            }
        ])
    }

    fn sample_relay_metrics() -> Value {
        json!([
            {
                "labels": {
                    "connector": "nostr",
                    "operation": OP_HEALTH,
                    "relay": "wss://relay.example.com",
                    "circuit_state": "closed"
                },
                "success_count": 1,
                "failure_count": 0,
                "skipped_count": 0,
                "average_latency_ms": 12
            }
        ])
    }

    fn sample_coordination() -> Value {
        json!([
            {
                "event": "claim_attempt",
                "backend": "in_memory",
                "claim_key": "claim:abc123",
                "channel_id": "channel:def456",
                "claimant_agent_id": "agent:abc123"
            },
            {
                "event": "claim_outcome",
                "backend": "in_memory",
                "claim_key": "claim:abc123",
                "channel_id": "channel:def456",
                "claimant_agent_id": "agent:abc123",
                "owner_agent_id": "agent:abc123",
                "outcome": "granted"
            },
            {
                "event": "send_executed",
                "backend": "in_memory",
                "claim_key": "claim:abc123",
                "channel_id": "channel:def456",
                "claimant_agent_id": "agent:abc123",
                "outcome": "executed"
            }
        ])
    }

    fn sample_profile_state() -> Value {
        json!({
            "load_result": "state_loaded",
            "persistence": "zone_dir",
            "connector_public_key_hex": hex_64('e'),
            "last_published_at": 1_715_000_000_u64,
            "last_published_event_id": hex_64('f'),
            "last_publish_results": {
                "wss://relay.example.com": "ok"
            },
            "last_profile": {
                "name": "alice"
            },
            "updated_at_secs": 1_715_000_001_u64
        })
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        let manifest = nostr_manifest()?;
        let operations = manifest_operations(&manifest)?;
        let operation_catalog = NostrConnector::operations();

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

        let notes_input = operation_schema(&manifest, "notes_publish", "input_schema")?;
        assert_schema_accepts(
            &notes_input,
            &json!({"content": "hello nostr", "kind": 1, "tags": [["t", "fcp"]]}),
        )?;
        assert_schema_rejects(&notes_input, &json!({}))?;
        assert_schema_rejects(&notes_input, &json!({"content": "   "}))?;
        assert_schema_rejects(&notes_input, &json!({"content": "hello", "kind": 4}))?;
        assert_schema_rejects(&notes_input, &json!({"content": "hello", "extra": true}))?;

        let dm_input = operation_schema(&manifest, "dm_send", "input_schema")?;
        assert_schema_accepts(
            &dm_input,
            &json!({"recipient": hex_64('1'), "plaintext": "hello"}),
        )?;
        assert_schema_accepts(
            &dm_input,
            &json!({"target": hex_64('2'), "content": "hello", "allow_self_send": true}),
        )?;
        assert_schema_rejects(&dm_input, &json!({"recipient": hex_64('1')}))?;
        assert_schema_rejects(
            &dm_input,
            &json!({"recipient": hex_64('1'), "plaintext": ""}),
        )?;
        assert_schema_rejects(
            &dm_input,
            &json!({"recipient": hex_64('1'), "plaintext": "hello", "reply_to": "short"}),
        )?;
        assert_schema_rejects(
            &dm_input,
            &json!({"recipient": hex_64('1'), "plaintext": "hello", "extra": true}),
        )?;

        let profile_publish_input = operation_schema(&manifest, "profile_publish", "input_schema")?;
        assert_schema_accepts(
            &profile_publish_input,
            &json!({
                "profile": {
                    "name": "alice",
                    "displayName": "Alice",
                    "picture": "https://example.com/alice.png",
                    "nip05": "alice@example.com"
                },
                "last_published_at": 1_715_000_000_u64
            }),
        )?;
        assert_schema_rejects(&profile_publish_input, &json!({}))?;
        assert_schema_rejects(
            &profile_publish_input,
            &json!({"profile": {"picture": "http://example.com/alice.png"}}),
        )?;
        assert_schema_rejects(
            &profile_publish_input,
            &json!({"profile": {"name": "alice", "extra": true}}),
        )?;

        let profile_import_input = operation_schema(&manifest, "profile_import", "input_schema")?;
        assert_schema_accepts(&profile_import_input, &json!({}))?;
        assert_schema_accepts(
            &profile_import_input,
            &json!({"pubkey": hex_64('3'), "local_profile": {"website": "https://example.com"}}),
        )?;
        assert_schema_rejects(&profile_import_input, &json!({"pubkey": "   "}))?;
        assert_schema_rejects(
            &profile_import_input,
            &json!({"local_profile": {"website": "http://example.com"}}),
        )?;
        assert_schema_rejects(&profile_import_input, &json!({"unexpected": true}))?;

        let events_input = operation_schema(&manifest, "events_query", "input_schema")?;
        assert_schema_accepts(
            &events_input,
            &json!({
                "authors": [hex_64('4')],
                "kinds": [1, 4],
                "ids": [hex_64('5')],
                "since": -1,
                "until": 1_715_000_000_i64,
                "limit": 10
            }),
        )?;
        assert_schema_rejects(&events_input, &json!({"ids": ["short"]}))?;
        assert_schema_rejects(&events_input, &json!({"limit": 0}))?;
        assert_schema_rejects(&events_input, &json!({"extra": true}))?;

        for operation_key in ["profile_state", "relays_list", "health", "relays_health"] {
            let input = operation_schema(&manifest, operation_key, "input_schema")?;
            assert_schema_accepts(&input, &json!({}))?;
            assert_schema_rejects(&input, &json!({"extra": true}))?;
        }

        let notes_output = operation_schema(&manifest, "notes_publish", "output_schema")?;
        assert_schema_accepts(
            &notes_output,
            &json!({
                "event": sample_event(1),
                "accepted_relays": sample_relay_diagnostics(),
                "rejected_relays": [],
                "coordination": sample_coordination(),
                "relay_resilience": sample_relay_resilience(),
                "relay_metrics": sample_relay_metrics()
            }),
        )?;
        assert_schema_rejects(&notes_output, &json!({"accepted_relays": []}))?;

        let dm_output = operation_schema(&manifest, "dm_send", "output_schema")?;
        assert_schema_accepts(
            &dm_output,
            &json!({
                "event_id": hex_64('6'),
                "event_kind": 4,
                "sender_pubkey_hex": hex_64('7'),
                "recipient_pubkey_hex": hex_64('8'),
                "recipient_format": "hex",
                "tags": [["p", hex_64('8')]],
                "created_at": 1_715_000_000_u64,
                "accepted_relays": sample_relay_diagnostics(),
                "rejected_relays": [],
                "coordination": sample_coordination(),
                "relay_resilience": sample_relay_resilience(),
                "relay_metrics": sample_relay_metrics()
            }),
        )?;
        assert_schema_rejects(
            &dm_output,
            &json!({
                "event_id": hex_64('6'),
                "event_kind": 1,
                "sender_pubkey_hex": hex_64('7'),
                "recipient_pubkey_hex": hex_64('8'),
                "recipient_format": "hex",
                "tags": [],
                "created_at": 1_715_000_000_u64,
                "accepted_relays": [],
                "rejected_relays": [],
                "coordination": [],
                "relay_resilience": [],
                "relay_metrics": []
            }),
        )?;

        let profile_publish_output =
            operation_schema(&manifest, "profile_publish", "output_schema")?;
        assert_schema_accepts(
            &profile_publish_output,
            &json!({
                "event": sample_event(0),
                "event_kind": 0,
                "profile": {"name": "alice"},
                "display_profile": {"name": "alice"},
                "accepted_relays": sample_relay_diagnostics(),
                "rejected_relays": [],
                "persist_recommended": true,
                "persisted": true,
                "persistence_result": "state_persisted",
                "profile_state": sample_profile_state(),
                "relay_resilience": sample_relay_resilience(),
                "relay_metrics": sample_relay_metrics()
            }),
        )?;

        let profile_state_output = operation_schema(&manifest, "profile_state", "output_schema")?;
        assert_schema_accepts(&profile_state_output, &sample_profile_state())?;
        assert_schema_rejects(
            &profile_state_output,
            &json!({"load_result": "state_loaded"}),
        )?;

        let profile_import_output = operation_schema(&manifest, "profile_import", "output_schema")?;
        assert_schema_accepts(
            &profile_import_output,
            &json!({
                "ok": false,
                "pubkey_hex": hex_64('9'),
                "error": "no verified kind-0 profile found",
                "relays_queried": ["wss://relay.example.com"],
                "relay_results": sample_relay_diagnostics(),
                "invalid_candidates": [],
                "relay_resilience": sample_relay_resilience(),
                "relay_metrics": sample_relay_metrics()
            }),
        )?;

        let events_output = operation_schema(&manifest, "events_query", "output_schema")?;
        assert_schema_accepts(
            &events_output,
            &json!({
                "subscription_id": "sub-1",
                "filter": {"limit": 10},
                "results": sample_relay_diagnostics(),
                "relay_resilience": sample_relay_resilience(),
                "relay_metrics": sample_relay_metrics()
            }),
        )?;

        let relays_output = operation_schema(&manifest, "relays_list", "output_schema")?;
        assert_schema_accepts(
            &relays_output,
            &json!({"relays": ["wss://relay.example.com"], "public_key_hex": hex_64('a')}),
        )?;

        let health_output = operation_schema(&manifest, "health", "output_schema")?;
        assert_schema_accepts(
            &health_output,
            &json!({
                "public_key_hex": hex_64('b'),
                "relay_health": sample_relay_diagnostics(),
                "relay_resilience": sample_relay_resilience(),
                "relay_metrics": sample_relay_metrics()
            }),
        )?;

        let relays_health_output = operation_schema(&manifest, "relays_health", "output_schema")?;
        assert_schema_accepts(
            &relays_health_output,
            &json!({
                "public_key_hex": hex_64('c'),
                "relay_scores": sample_relay_diagnostics(),
                "scored_count": 1,
                "relay_resilience": sample_relay_resilience(),
                "relay_metrics": sample_relay_metrics()
            }),
        )?;
        assert_schema_rejects(
            &relays_health_output,
            &json!({
                "public_key_hex": hex_64('c'),
                "relay_scores": [],
                "scored_count": -1,
                "relay_resilience": [],
                "relay_metrics": []
            }),
        )?;

        Ok(())
    }

    #[test]
    fn manifest_ai_hints_cover_all_operations_and_runtime_examples() -> Result<(), String> {
        let manifest = nostr_manifest()?;
        let operation_catalog = NostrConnector::operations();

        for (operation_id, manifest_key) in EXPECTED_MANIFEST_SCHEMA_OPS {
            let hints = operation_ai_hints(&manifest, manifest_key)?;
            let when_to_use = hints
                .get("when_to_use")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("{manifest_key}.ai_hints.when_to_use missing"))?;
            if when_to_use.trim().is_empty() {
                return Err(format!("{manifest_key}.ai_hints.when_to_use is empty"));
            }

            let common_mistakes = hint_string_array(hints, "common_mistakes")?;
            if common_mistakes.len() < 2 {
                return Err(format!(
                    "{manifest_key}.ai_hints.common_mistakes should have at least 2 entries"
                ));
            }

            let examples = hint_string_array(hints, "examples")?;
            for example in &examples {
                serde_json::from_str::<Value>(example).map_err(|err| {
                    format!("{manifest_key}.ai_hints example should parse as JSON: {err}")
                })?;
                let lower = example.to_ascii_lowercase();
                for forbidden in ["secret", "token", "password", "private_key", "nsec"] {
                    if lower.contains(forbidden) {
                        return Err(format!(
                            "{manifest_key}.ai_hints example contains forbidden sample text `{forbidden}`"
                        ));
                    }
                }
            }

            let operation = operation_catalog
                .iter()
                .find(|operation| operation.id.as_str() == *operation_id)
                .ok_or_else(|| format!("operation catalog should declare {operation_id}"))?;
            if operation.ai_hints.when_to_use.trim().is_empty() {
                return Err(format!("{operation_id} runtime when_to_use is empty"));
            }
            if operation.ai_hints.common_mistakes.is_empty() {
                return Err(format!("{operation_id} runtime common_mistakes is empty"));
            }
            if operation.ai_hints.examples.is_empty() {
                return Err(format!("{operation_id} runtime examples are empty"));
            }
            for example in &operation.ai_hints.examples {
                serde_json::from_str::<Value>(example).map_err(|err| {
                    format!("{operation_id} runtime example should parse as JSON: {err}")
                })?;
            }
        }

        Ok(())
    }

    #[test]
    fn manifest_declares_runtime_scoped_network_constraints() -> Result<(), String> {
        let manifest = nostr_manifest()?;
        let operations = manifest_operations(&manifest)?;
        assert_eq!(
            operations.len(),
            RELAY_NETWORK_CONSTRAINT_OPS.len() + LOCAL_ONLY_NETWORK_CONSTRAINT_OPS.len(),
            "manifest operation count should match the audited constraint split"
        );

        for operation_key in RELAY_NETWORK_CONSTRAINT_OPS {
            let constraints = operation_network_constraints(&manifest, operation_key)?;
            assert_relay_network_constraints(constraints)?;
        }
        for operation_key in LOCAL_ONLY_NETWORK_CONSTRAINT_OPS {
            let constraints = operation_network_constraints(&manifest, operation_key)?;
            assert_no_egress_network_constraints(constraints)?;
        }

        Ok(())
    }

    // ── Doctor tests ─────────────────────────────────────────────────

    #[test]
    fn doctor_unconfigured_reports_failure() {
        let connector = NostrConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
        let config_check = result
            .checks
            .iter()
            .find(|c| c.name == "configuration")
            .unwrap();
        assert!(!config_check.passed);
        assert!(
            config_check
                .message
                .as_deref()
                .unwrap()
                .contains("Not configured")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured_reports_success() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector.doctor();
        assert!(result.passed);
        let config_check = result
            .checks
            .iter()
            .find(|c| c.name == "configuration")
            .unwrap();
        assert!(config_check.passed);
        let relays_check = result.checks.iter().find(|c| c.name == "relays").unwrap();
        assert!(relays_check.passed);
        let key_check = result
            .checks
            .iter()
            .find(|c| c.name == "key_material")
            .unwrap();
        assert!(key_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_shows_handshake_not_done() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector.doctor();
        let hs_check = result
            .checks
            .iter()
            .find(|c| c.name == "handshake")
            .unwrap();
        assert!(!hs_check.passed);
        assert!(
            hs_check
                .message
                .as_deref()
                .unwrap()
                .contains("No handshake")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_shows_handshake_done() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(handshake_request()).await.unwrap();
        let result = connector.doctor();
        let hs_check = result
            .checks
            .iter()
            .find(|c| c.name == "handshake")
            .unwrap();
        assert!(hs_check.passed);
    }

    // ── Health tests ─────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn health_starting_when_unconfigured() {
        let connector = NostrConnector::new();
        let snapshot = connector.health().await;
        assert!(matches!(snapshot.status, HealthState::Starting));
        assert!(snapshot.details.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn health_ready_when_configured() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        let snapshot = connector.health().await;
        assert!(matches!(snapshot.status, HealthState::Ready));
        let details = snapshot.details.unwrap();
        assert_eq!(details["relay_count"], 1);
        assert!(details["public_key_hex"].is_string());
    }

    // ── Self-check tests ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn self_check_fails_when_unconfigured() {
        let connector = NostrConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
    }

    // ── Introspect tests ─────────────────────────────────────────────

    #[test]
    fn introspection_reports_key_and_address_formats() {
        let intro = NostrConnector::new().introspect();
        let auth = intro.auth_caps.expect("auth caps should be present");
        assert_eq!(
            auth.methods,
            vec![
                "secp256k1_secret_key_hex",
                "nip19_nsec",
                "nip19_npub",
                "nostr_uri_npub"
            ]
        );
        let publish = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_PUBLISH_NOTE)
            .expect("publish operation should exist");
        assert!(
            publish
                .description
                .as_deref()
                .unwrap_or_default()
                .contains("separate `nostr.dm.send` operation")
        );
        assert!(publish.ai_hints.common_mistakes.iter().any(|hint| {
            hint.contains("raw 64-character hex") && hint.contains("NIP-19 `nsec`")
        }));
        let query = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_QUERY_EVENTS)
            .expect("query operation should exist");
        assert!(
            query
                .ai_hints
                .common_mistakes
                .iter()
                .any(|hint| { hint.contains("raw hex") && hint.contains("NIP-19 `npub`") })
        );
        let related: Vec<_> = publish
            .ai_hints
            .related
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        assert_eq!(
            related,
            vec![CAP_HEALTH_READ, CAP_RELAYS_READ, CAP_EVENTS_READ]
        );
        let dm = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_DM)
            .expect("DM send operation should exist");
        assert_eq!(dm.capability.as_str(), CAP_DM_WRITE);
        assert!(matches!(dm.risk_level, RiskLevel::High));
        assert!(matches!(dm.safety_tier, SafetyTier::Risky));
        assert!(matches!(dm.idempotency, IdempotencyClass::None));
        assert!(
            dm.description
                .as_deref()
                .unwrap_or_default()
                .contains("NIP-04 AES-256-CBC")
        );
        assert!(
            dm.ai_hints
                .common_mistakes
                .iter()
                .any(|hint| hint.contains("never returned") && hint.contains("4096 bytes"))
        );
    }

    #[test]
    fn introspect_has_profile_operations_separate_from_note_publish() {
        let intro = NostrConnector::new().introspect();
        assert_eq!(intro.operations.len(), 9);
        let ids: Vec<_> = intro.operations.iter().map(|op| op.id.as_str()).collect();
        assert!(ids.contains(&OP_PUBLISH_NOTE));
        assert!(ids.contains(&OP_SEND_DM));
        assert!(ids.contains(&OP_PROFILE_PUBLISH));
        assert!(ids.contains(&OP_PROFILE_STATE));
        assert!(ids.contains(&OP_PROFILE_IMPORT));
        assert!(ids.contains(&OP_QUERY_EVENTS));
        assert!(ids.contains(&OP_LIST_RELAYS));
        assert!(ids.contains(&OP_HEALTH));
        assert!(ids.contains(&OP_RELAYS_HEALTH));

        let note_publish = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_PUBLISH_NOTE)
            .unwrap();
        assert_eq!(note_publish.capability.as_str(), CAP_NOTES_WRITE);
        let profile_publish = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_PROFILE_PUBLISH)
            .unwrap();
        assert_eq!(profile_publish.capability.as_str(), CAP_PROFILE_WRITE);
        assert!(
            profile_publish
                .description
                .as_deref()
                .unwrap()
                .contains("kind-0")
        );
        assert!(
            profile_publish
                .ai_hints
                .common_mistakes
                .iter()
                .any(|hint| { hint.contains("`nostr.notes.publish` remains kind-1 only") })
        );
        let profile_state = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_PROFILE_STATE)
            .unwrap();
        assert_eq!(profile_state.capability.as_str(), CAP_PROFILE_READ);
        assert!(matches!(profile_state.safety_tier, SafetyTier::Safe));
        let profile_import = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_PROFILE_IMPORT)
            .unwrap();
        assert_eq!(profile_import.capability.as_str(), CAP_PROFILE_READ);
        assert!(matches!(
            profile_import.idempotency,
            IdempotencyClass::Strict
        ));
    }

    #[test]
    fn introspect_event_caps_streams_inbound_dm_without_replay() {
        let intro = NostrConnector::new().introspect();
        let caps = intro.event_caps.unwrap();
        assert!(caps.streaming);
        assert!(!caps.replay);
        assert_eq!(intro.events[0].topic, EVENT_INBOUND_DM);
    }

    // ── Simulate tests ───────────────────────────────────────────────

    #[test]
    fn simulate_denies_when_not_configured() {
        let connector = NostrConnector::new();
        let response = fcp_async_core::runtime::block_on_sync(async {
            connector
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.nostr"),
                    OperationId::from_static(OP_PUBLISH_NOTE),
                    ZoneId::community(),
                    json!({ "content": "hello" }),
                    CapabilityToken::test_token(),
                ))
                .await
        })
        .expect("runtime should complete");
        let response = response.expect("simulate should succeed");
        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-5002"));
        assert_eq!(
            response.failure_reason.as_deref(),
            Some("Connector is not configured")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_checks_capability_operation_grant() {
        let mut connector = NostrConnector::new();
        connector
            .configure(test_config())
            .await
            .expect("configure should succeed");
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request_for(
                signing_key.verifying_key().to_bytes(),
            ))
            .await
            .expect("handshake should succeed");

        let response = connector
            .simulate(SimulateRequest::new(
                ConnectorId::from_static("fcp.nostr"),
                OperationId::from_static(OP_PUBLISH_NOTE),
                ZoneId::work(),
                json!({ "content": "hello" }),
                capability_token(
                    &signing_key,
                    CAP_EVENTS_READ,
                    OP_PUBLISH_NOTE,
                    connector.base.instance_id.as_str(),
                ),
            ))
            .await
            .expect("simulate should return a policy result");

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-3003"));
        assert!(response.missing_capabilities.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_dm_send_denies_duplicate_claim_before_relay_publish() -> Result<(), String> {
        let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
        let checker_for_connector: Arc<dyn ThreadOwnershipChecker> = checker.clone();
        let mut connector = NostrConnector::new().with_thread_ownership_checker(
            checker_for_connector,
            ChatCoordinationBackend::InMemory,
        );
        connector
            .configure(json!({
                "relay_urls": ["wss://relay.example.com"],
                "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
                "chat_coordination": { "backend": "in_memory" }
            }))
            .await
            .expect("configure should accept Nostr coordination config");
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request_for(
                signing_key.verifying_key().to_bytes(),
            ))
            .await
            .expect("handshake should succeed");

        let recipient_pubkey = NostrKeyMaterial::from_secret_key_input(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .expect("recipient fixture key should parse")
        .public_key_hex()
        .to_owned();
        let claim_key = fcp_sdk::ClaimKey::for_chat_message(
            ZoneId::work(),
            ConnectorId::from_static("fcp.nostr"),
            nostr_coordination_dm_channel_id(&recipient_pubkey),
            None,
            DmMode::TreatAsThread,
        )
        .expect("DM coordination should use conversation as thread");
        assert!(matches!(
            checker.claim_now(claim_key, AgentId::new("peer-agent"), Instant::now(),),
            fcp_sdk::ClaimOutcome::Granted(_)
        ));

        let error = connector
            .invoke(invoke_request(
                &signing_key,
                OP_SEND_DM,
                CAP_DM_WRITE,
                connector.base.instance_id.as_str(),
                json!({
                    "recipient": recipient_pubkey,
                    "plaintext": "secret Nostr body"
                }),
            ))
            .await
            .expect_err("duplicate active claim should deny before relay WebSocket publish");

        match error {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 4090);
                assert!(message.starts_with("thread_owned_by_peer:"));
                assert!(
                    !message.contains("secret Nostr body"),
                    "coordination denial must not leak plaintext"
                );
            }
            other => {
                return Err(format!(
                    "expected Unauthorized duplicate-claim denial, got {other:?}"
                ));
            }
        }

        Ok(())
    }

    // ── Configure / handshake / shutdown lifecycle tests ─────────────

    #[fcp_async_core::runtime::test]
    async fn reconfigure_requires_a_fresh_handshake() {
        let mut connector = NostrConnector::new();
        connector
            .configure(test_config())
            .await
            .expect("configure should succeed");
        connector
            .handshake(handshake_request())
            .await
            .expect("handshake should succeed");
        assert!(connector.base.handshaken.load(Ordering::Relaxed));

        connector
            .configure(test_config())
            .await
            .expect("reconfigure should succeed");

        assert!(!connector.base.handshaken.load(Ordering::Relaxed));
        assert!(connector.verifier.is_none());

        let response = connector
            .simulate(SimulateRequest::new(
                ConnectorId::from_static("fcp.nostr"),
                OperationId::from_static(OP_HEALTH),
                ZoneId::work(),
                json!({}),
                CapabilityToken::test_token(),
            ))
            .await
            .expect("simulate should return");
        assert!(!response.would_succeed);
        let expected = FcpError::NotHandshaken.error_code();
        assert_eq!(response.denial_code.as_deref(), Some(expected.as_str()));
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_base_ready_flags() {
        let mut connector = NostrConnector::new();
        connector
            .configure(test_config())
            .await
            .expect("configure should succeed");
        connector
            .handshake(handshake_request())
            .await
            .expect("handshake should succeed");

        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 1_000,
                drain: false,
                reason: Some("test".into()),
            })
            .await
            .expect("shutdown should succeed");

        assert!(!connector.base.configured.load(Ordering::Relaxed));
        assert!(!connector.base.handshaken.load(Ordering::Relaxed));
        assert!(connector.verifier.is_none());
        assert!(connector.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_json() {
        let mut connector = NostrConnector::new();
        let err = connector
            .configure(json!({ "bad": "config" }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_empty_relays() {
        let mut connector = NostrConnector::new();
        let err = connector
            .configure(json!({
                "relay_urls": [],
                "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111"
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_grants_requested_capabilities() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        let resp = connector
            .handshake(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: [7u8; 32],
                nonce: [9u8; 32],
                capabilities_requested: vec![
                    CapabilityId::from_static(CAP_HEALTH_READ),
                    CapabilityId::from_static(CAP_NOTES_WRITE),
                    CapabilityId::from_static(CAP_DM_WRITE),
                    CapabilityId::from_static(CAP_PROFILE_WRITE),
                    CapabilityId::from_static(CAP_PROFILE_READ),
                    CapabilityId::from_static("unknown.cap"),
                ],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            })
            .await
            .unwrap();
        let granted: Vec<_> = resp
            .capabilities_granted
            .iter()
            .map(|g| g.capability.as_str())
            .collect();
        assert!(granted.contains(&CAP_HEALTH_READ));
        assert!(granted.contains(&CAP_NOTES_WRITE));
        assert!(granted.contains(&CAP_DM_WRITE));
        assert!(granted.contains(&CAP_PROFILE_WRITE));
        assert!(granted.contains(&CAP_PROFILE_READ));
        assert!(!granted.contains(&"unknown.cap"));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_advertises_inbound_dm_streaming_without_replay() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        let resp = connector.handshake(handshake_request()).await.unwrap();
        let caps = resp.event_caps.expect("Nostr should advertise event caps");
        assert!(caps.streaming);
        assert!(!caps.replay);
        assert_eq!(caps.min_buffer_events, 0);
        assert!(!caps.requires_ack);
    }

    #[test]
    fn inbound_state_store_reports_reload_failure_without_leaking_secrets() {
        let zone_dir = unique_zone_dir("bad-state");
        let state_path = zone_dir.join(INBOUND_DM_STATE_FILE);
        std::fs::write(&state_path, "not valid json").expect("bad state fixture should write");
        let public_key = "aa".repeat(32);
        let store = NostrInboundDmStateStore::new(
            zone_dir.to_str(),
            &public_key,
            4096,
            InboundDmRateLimits::default(),
        );
        let prepared = store.prepare_subscription();
        assert!(
            prepared["load_result"]
                .as_str()
                .unwrap()
                .starts_with("state_parse_failed"),
            "parse failure should be visible in diagnostics"
        );
        assert_eq!(prepared["persistence_result"], "state_persisted");
        let persisted = std::fs::read_to_string(state_path).expect("state should be rewritten");
        assert!(persisted.contains(&public_key));
        assert!(
            !persisted.contains("1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert!(!persisted.contains("plaintext"));
    }

    #[test]
    fn profile_state_persists_public_publish_metadata_without_secret_material() {
        let zone_dir = unique_zone_dir("profile-state");
        let public_key = "aa".repeat(32);
        let store = NostrProfileStateStore::new(zone_dir.to_str(), &public_key);
        let event = json!({
            "id": "bb".repeat(32),
            "created_at": 1_700_000_010_u64,
            "kind": NIP01_KIND_PROFILE,
        });
        let output = json!({
            "accepted_relays": [{"relay": "wss://relay.example.com/", "response": ["OK", "event", true, ""]}],
            "rejected_relays": [{"relay": "wss://down.example.com/", "error": "timeout"}],
        });
        let profile = NostrProfile {
            name: Some("alice".into()),
            ..NostrProfile::default()
        };

        let persist = store.persist_publish(&event, profile, &output);
        assert_eq!(persist, "state_persisted");
        let snapshot = store.snapshot();
        assert_eq!(snapshot["last_published_at"], 1_700_000_010_u64);
        assert_eq!(
            snapshot["last_publish_results"]["wss://relay.example.com/"],
            "ok"
        );
        assert_eq!(
            snapshot["last_publish_results"]["wss://down.example.com/"],
            "failed"
        );

        let persisted =
            std::fs::read_to_string(zone_dir.join(PROFILE_STATE_FILE)).expect("state should exist");
        assert!(persisted.contains("alice"));
        assert!(
            !persisted.contains("1111111111111111111111111111111111111111111111111111111111111111")
        );
    }

    #[test]
    fn introspection_advertises_only_inbound_dm_stream_without_replay() {
        let connector = NostrConnector::new();
        let introspection = connector.introspect();
        let caps = introspection
            .event_caps
            .expect("Nostr introspection should include event caps");
        assert!(caps.streaming);
        assert!(!caps.replay);
        assert_eq!(caps.min_buffer_events, 0);
        assert_eq!(introspection.events.len(), 1);
        assert_eq!(introspection.events[0].topic, EVENT_INBOUND_DM);
        assert!(!introspection.events[0].requires_ack);
        assert!(
            introspection
                .operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_QUERY_EVENTS),
            "bounded public query remains a request-response operation"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn subscribe_rejects_empty_and_unsupported_streams_before_relay_tasks() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(handshake_request()).await.unwrap();

        let empty = connector
            .subscribe(SubscribeRequest {
                r#type: "subscribe".into(),
                id: RequestId::new("empty-subscribe"),
                topics: Vec::new(),
                since: None,
                max_events_per_sec: None,
                batch_ms: None,
                window_size: None,
                capability_token: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(empty, FcpError::InvalidRequest { .. }));

        let unsupported = connector
            .subscribe(SubscribeRequest {
                r#type: "subscribe".into(),
                id: RequestId::new("public-query-stream"),
                topics: vec![OP_QUERY_EVENTS.into()],
                since: None,
                max_events_per_sec: None,
                batch_ms: None,
                window_size: None,
                capability_token: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(unsupported, FcpError::InvalidRequest { .. }));
        assert_eq!(connector.active_subscription_count(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn unsubscribe_is_idempotent_for_supported_topic_and_rejects_broadening() {
        let mut connector = NostrConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(handshake_request()).await.unwrap();

        connector
            .unsubscribe(UnsubscribeRequest {
                r#type: "unsubscribe".into(),
                id: RequestId::new("unsubscribe-empty-state"),
                topics: vec![EVENT_INBOUND_DM.into()],
                capability_token: None,
            })
            .await
            .unwrap();
        connector
            .unsubscribe(UnsubscribeRequest {
                r#type: "unsubscribe".into(),
                id: RequestId::new("unsubscribe-empty-state-again"),
                topics: vec![EVENT_INBOUND_DM.into()],
                capability_token: None,
            })
            .await
            .unwrap();

        let unsupported = connector
            .unsubscribe(UnsubscribeRequest {
                r#type: "unsubscribe".into(),
                id: RequestId::new("unsubscribe-public-query"),
                topics: vec![OP_QUERY_EVENTS.into()],
                capability_token: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(unsupported, FcpError::InvalidRequest { .. }));
    }

    // ── Connector ID / default tests ─────────────────────────────────

    #[test]
    fn connector_id_is_fcp_nostr() {
        let connector = NostrConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.nostr");
    }

    #[test]
    fn default_creates_new() {
        let connector = NostrConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.nostr");
        assert!(connector.client.is_none());
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let h1 = NostrConnector::manifest_hash();
        let h2 = NostrConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    // ── Required capability tests ────────────────────────────────────

    #[test]
    fn required_capability_publish() {
        let cap = required_capability(OP_PUBLISH_NOTE).unwrap();
        assert_eq!(cap.as_str(), CAP_NOTES_WRITE);
    }

    #[test]
    fn required_capability_dm_send() {
        let cap = required_capability(OP_SEND_DM).unwrap();
        assert_eq!(cap.as_str(), CAP_DM_WRITE);
    }

    #[test]
    fn required_capability_profile_operations() {
        let publish = required_capability(OP_PROFILE_PUBLISH).unwrap();
        let state = required_capability(OP_PROFILE_STATE).unwrap();
        let import = required_capability(OP_PROFILE_IMPORT).unwrap();
        assert_eq!(publish.as_str(), CAP_PROFILE_WRITE);
        assert_eq!(state.as_str(), CAP_PROFILE_READ);
        assert_eq!(import.as_str(), CAP_PROFILE_READ);
    }

    #[test]
    fn required_capability_query() {
        let cap = required_capability(OP_QUERY_EVENTS).unwrap();
        assert_eq!(cap.as_str(), CAP_EVENTS_READ);
    }

    #[test]
    fn required_capability_unknown() {
        assert!(required_capability("unknown.op").is_err());
    }

    // ── Doctor serialization test ────────────────────────────────────

    #[test]
    fn doctor_result_serializes() {
        let result = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: Some("all good".into()),
            critical: true,
        }]);
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["passed"], true);
        assert_eq!(json["checks"][0]["name"], "test");
    }

    #[test]
    fn doctor_result_fails_on_critical_failure() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "pass".into(),
                passed: true,
                message: None,
                critical: false,
            },
            DoctorCheck {
                name: "fail".into(),
                passed: false,
                message: Some("broken".into()),
                critical: true,
            },
        ]);
        assert!(!result.passed);
    }

    #[test]
    fn doctor_result_passes_with_non_critical_failure() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "pass_critical".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "fail_non_critical".into(),
                passed: false,
                message: Some("optional".into()),
                critical: false,
            },
        ]);
        assert!(result.passed);
    }

    // ── Relay health operation tests ────────────────────────────────────

    #[test]
    fn required_capability_relays_health() {
        let cap = required_capability(OP_RELAYS_HEALTH).unwrap();
        assert_eq!(cap.as_str(), CAP_HEALTH_READ);
    }

    #[test]
    fn introspect_relays_health_operation_properties() {
        let intro = NostrConnector::new().introspect();
        let op = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_RELAYS_HEALTH)
            .expect("relays.health operation should exist");
        assert_eq!(op.capability.as_str(), CAP_HEALTH_READ);
        assert!(matches!(op.risk_level, RiskLevel::Low));
        assert!(matches!(op.safety_tier, SafetyTier::Safe));
        assert!(matches!(op.idempotency, IdempotencyClass::Strict));
        assert!(
            op.description
                .as_deref()
                .unwrap_or_default()
                .contains("NIP-04")
        );
        assert!(
            op.description
                .as_deref()
                .unwrap_or_default()
                .contains("NIP-44")
        );
    }

    #[test]
    fn introspect_relays_health_has_related_caps() {
        let intro = NostrConnector::new().introspect();
        let op = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_RELAYS_HEALTH)
            .unwrap();
        let related: Vec<_> = op
            .ai_hints
            .related
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        assert!(related.contains(&CAP_RELAYS_READ));
        assert!(related.contains(&CAP_EVENTS_READ));
    }

    #[test]
    fn simulate_relays_health_denies_when_not_configured() {
        let connector = NostrConnector::new();
        let response = fcp_async_core::runtime::block_on_sync(async {
            connector
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.nostr"),
                    OperationId::from_static(OP_RELAYS_HEALTH),
                    ZoneId::community(),
                    json!({}),
                    CapabilityToken::test_token(),
                ))
                .await
        })
        .expect("runtime should complete");
        let response = response.expect("simulate should succeed");
        assert!(!response.would_succeed);
    }
}
