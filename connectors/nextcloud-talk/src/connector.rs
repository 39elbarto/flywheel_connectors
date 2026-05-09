//! Nextcloud Talk connector implementation.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, EventInfo, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use hmac::{Hmac, Mac};
use reqwest::Url;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::client::NextcloudTalkClient;
use crate::config::{NextcloudTalkConfig, NextcloudTalkSecretRef};
use crate::types::{
    AddParticipantRequest, AttendeeId, ChatMessagesQuery, ConversationListQuery, ConversationToken,
    CreateConversationRequest, MessageId, ParticipantListQuery, ReactionRequest, ReadMarkerRequest,
    RemoveParticipantRequest, SendChatMessageRequest, ShareFileRequest,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OP_HEALTH: &str = "nextcloud_talk.health";
const OP_LIST_CONVERSATIONS: &str = "nextcloud_talk.list_conversations";
const OP_GET_CONVERSATION: &str = "nextcloud_talk.get_conversation";
const OP_CREATE_CONVERSATION: &str = "nextcloud_talk.create_conversation";
const OP_GET_MESSAGES: &str = "nextcloud_talk.get_messages";
const OP_POLL_CONVERSATION_EVENTS: &str = "nextcloud_talk.poll_conversation_events";
const OP_INGEST_WEBHOOK: &str = "nextcloud_talk.ingest_webhook";
const OP_SEND_MESSAGE: &str = "nextcloud_talk.send_message";
const OP_DELETE_MESSAGE: &str = "nextcloud_talk.delete_message";
const OP_SET_READ_MARKER: &str = "nextcloud_talk.set_read_marker";
const OP_LIST_PARTICIPANTS: &str = "nextcloud_talk.list_participants";
const OP_ADD_PARTICIPANT: &str = "nextcloud_talk.add_participant";
const OP_REMOVE_PARTICIPANT: &str = "nextcloud_talk.remove_participant";
const OP_GET_CALL_STATE: &str = "nextcloud_talk.get_call_state";
const OP_ADD_REACTION: &str = "nextcloud_talk.add_reaction";
const OP_DELETE_REACTION: &str = "nextcloud_talk.delete_reaction";
const OP_SHARE_FILE: &str = "nextcloud_talk.share_file";
const CAP_READ: &str = "nextcloud_talk.read";
const CAP_WRITE: &str = "nextcloud_talk.write";
const CAP_MANAGE: &str = "nextcloud_talk.manage";
const CAP_WEBHOOK: &str = "nextcloud_talk.webhook";
const EVENT_WEBHOOK_MESSAGE: &str = "nextcloud_talk.webhook.message";
type HmacSha256 = Hmac<Sha256>;

fn default_nextcloud_talk_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_nextcloud_talk_chat_coordination_config(
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
            normalized.push(ChannelId::new(channel_id.to_ascii_lowercase()));
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

fn nextcloud_talk_coordination_audit_records(
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

/// Connector doctor response.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

/// A single doctor check.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        Self { passed, checks }
    }
}

impl DoctorCheck {
    fn new(name: impl Into<String>, passed: bool, message: Option<String>, critical: bool) -> Self {
        Self {
            name: name.into(),
            passed,
            message,
            critical,
            details: None,
        }
    }

    fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Nextcloud Talk connector state.
pub struct NextcloudTalkConnector {
    base: BaseConnector,
    config: Option<NextcloudTalkConfig>,
    client: Option<NextcloudTalkClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
    webhook_replay: Mutex<NextcloudTalkWebhookReplayState>,
    webhook_rate: Mutex<NextcloudTalkWebhookRateState>,
}

impl NextcloudTalkConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.nextcloud-talk")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
            chat_coordination_config: default_nextcloud_talk_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
            webhook_replay: Mutex::new(NextcloudTalkWebhookReplayState::default()),
            webhook_rate: Mutex::new(NextcloudTalkWebhookRateState::default()),
        }
    }

    /// Replace the thread ownership checker used by outbound chat coordination.
    #[must_use]
    pub fn with_thread_ownership_checker(
        mut self,
        checker: Arc<dyn ThreadOwnershipChecker>,
    ) -> Self {
        self.thread_ownership_checker = checker;
        self
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Run connector diagnostics without performing network calls.
    #[allow(clippy::too_many_lines)]
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        checks.push(DoctorCheck::new(
            "configuration",
            self.config.is_some(),
            Some(if self.config.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            true,
        ));

        checks.push(DoctorCheck::new(
            "client_initialized",
            self.client.is_some(),
            Some(if self.client.is_some() {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            true,
        ));

        checks.push(DoctorCheck::new(
            "runtime",
            self.runtime.is_some(),
            Some(if self.runtime.is_some() {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing; re-run configure".into()
            }),
            true,
        ));

        if let Some(config) = &self.config {
            let policy = config.server_url_policy_report();
            let policy_details = policy.as_ref().map_or_else(
                |error| json!({ "allowed": false, "error": error.to_string() }),
                |report| {
                    json!({
                        "url": report.url,
                        "host": report.host,
                        "classification": report.classification,
                        "allowed": report.allowed,
                        "reason": report.reason,
                        "network_constraints": runtime_network_constraints_projection(config),
                    })
                },
            );
            let policy_allowed = policy.as_ref().is_ok_and(|report| report.allowed);
            checks.push(
                DoctorCheck::new(
                    "server_url",
                    policy_allowed,
                    Some(format!("Target server: {}", config.normalized_server_url())),
                    true,
                )
                .with_details(policy_details),
            );
            checks.push(
                DoctorCheck::new(
                    "account_setup",
                    true,
                    Some(format!("Account: {}", config.account_label())),
                    false,
                )
                .with_details(setup_details(config)),
            );
            checks.push(
                DoctorCheck::new(
                    "ocs_auth_source",
                    true,
                    Some(format!("OCS auth mode: {}", config.auth.mode_label())),
                    false,
                )
                .with_details(json!({
                    "mode": config.auth.mode_label(),
                    "secret_redacted": true,
                })),
            );
            checks.push(
                DoctorCheck::new(
                    "webhook_readiness",
                    config.webhook.readiness_label() != "webhook_missing_secret",
                    Some(webhook_readiness_message(config)),
                    false,
                )
                .with_details(webhook_details(config)),
            );
            checks.push(
                DoctorCheck::new(
                    "inbound_policy",
                    true,
                    Some(format!(
                        "DM policy: {}; group policy: {}; room allowlist entries: {}",
                        config.inbound_policy.dm_policy,
                        config.inbound_policy.group_policy,
                        config.inbound_policy.rooms.len()
                    )),
                    false,
                )
                .with_details(inbound_policy_details(config)),
            );
        }

        checks.push(DoctorCheck::new(
            "capability_verifier",
            self.verifier.is_some(),
            Some(if self.verifier.is_some() {
                "Handshake completed".into()
            } else {
                "Handshake not performed yet".into()
            }),
            false,
        ));

        DoctorResult::from_checks(checks)
    }
}

impl Default for NextcloudTalkConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WebhookReplayKey {
    account_id: String,
    room_token: String,
    message_id: String,
}

impl WebhookReplayKey {
    fn new(account_id: &str, room_token: &str, message_id: &str) -> FcpResult<Self> {
        if account_id.trim().is_empty()
            || room_token.trim().is_empty()
            || message_id.trim().is_empty()
        {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "webhook replay key requires account_id, room_token, and message_id"
                    .into(),
            });
        }
        Ok(Self {
            account_id: account_id.trim().to_string(),
            room_token: room_token.trim().to_string(),
            message_id: message_id.trim().to_string(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebhookReplayDecision {
    Claimed,
    Duplicate,
    Inflight,
}

impl WebhookReplayDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Duplicate => "duplicate",
            Self::Inflight => "inflight",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebhookReplayEntryState {
    InFlight,
    Committed,
}

#[derive(Debug, Clone)]
struct WebhookReplayEntry {
    state: WebhookReplayEntryState,
    expires_at: Instant,
    sequence: u64,
}

#[derive(Debug, Default)]
struct NextcloudTalkWebhookReplayState {
    entries: BTreeMap<WebhookReplayKey, WebhookReplayEntry>,
    next_sequence: u64,
}

impl NextcloudTalkWebhookReplayState {
    fn claim(
        &mut self,
        key: WebhookReplayKey,
        now: Instant,
        ttl: Duration,
        max_entries: usize,
    ) -> WebhookReplayDecision {
        self.prune(now, max_entries);
        if let Some(entry) = self.entries.get(&key) {
            return match entry.state {
                WebhookReplayEntryState::Committed => WebhookReplayDecision::Duplicate,
                WebhookReplayEntryState::InFlight => WebhookReplayDecision::Inflight,
            };
        }

        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.entries.insert(
            key,
            WebhookReplayEntry {
                state: WebhookReplayEntryState::InFlight,
                expires_at: now + ttl,
                sequence,
            },
        );
        self.prune(now, max_entries);
        WebhookReplayDecision::Claimed
    }

    fn commit(&mut self, key: &WebhookReplayKey, now: Instant, ttl: Duration) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.state = WebhookReplayEntryState::Committed;
            entry.expires_at = now + ttl;
        }
    }

    fn release(&mut self, key: &WebhookReplayKey) {
        self.entries.remove(key);
    }

    fn prune(&mut self, now: Instant, max_entries: usize) {
        self.entries.retain(|_, entry| entry.expires_at > now);
        while self.entries.len() > max_entries {
            let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.sequence)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&oldest_key);
        }
    }
}

#[derive(Debug, Default)]
struct NextcloudTalkWebhookRateState {
    buckets: BTreeMap<String, WebhookRateBucket>,
}

#[derive(Debug, Clone)]
struct WebhookRateBucket {
    window_started: Instant,
    count: u32,
}

impl NextcloudTalkWebhookRateState {
    fn check(&mut self, key: &str, limit: u32, now: Instant) -> bool {
        const WINDOW: Duration = Duration::from_mins(1);

        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| WebhookRateBucket {
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

fn setup_details(config: &NextcloudTalkConfig) -> serde_json::Value {
    json!({
        "account_id": config.account_id(),
        "account_name_configured": config.account_name.is_some(),
        "ocs_auth_mode": config.auth.mode_label(),
        "webhook_mode": if config.webhook.enabled { "webhook" } else { "manual_poll" },
        "webhook_readiness": config.webhook.readiness_label(),
        "credential_sources": {
            "ocs": config.auth.mode_label(),
            "webhook_bot_secret": config.webhook.secret_source_label(),
        },
    })
}

fn webhook_details(config: &NextcloudTalkConfig) -> serde_json::Value {
    json!({
        "enabled": config.webhook.enabled,
        "mode": if config.webhook.enabled { "webhook" } else { "manual_poll" },
        "public_path": config.webhook.public_path,
        "public_url_configured": config.webhook.public_url.is_some(),
        "bot_secret_source": config.webhook.secret_source_label(),
        "bot_secret_fingerprint": config
            .webhook
            .bot_secret
            .as_ref()
            .map(secret_fingerprint),
        "secret_redacted": true,
        "backend_allowlist": effective_backend_allowlist(config),
        "host_forwarded_ingress": true,
        "hosted_listener": false,
        "body": {
            "max_body_bytes": config.webhook.max_body_bytes,
            "timeout_ms": config.webhook.body_timeout_ms,
        },
        "rate_limits": {
            "auth_failure_limit_per_minute": config.webhook.auth_failure_limit_per_minute,
            "sender_limit_per_minute": config.webhook.sender_limit_per_minute,
        },
        "replay": {
            "mode": "in_memory",
            "ttl_secs": config.webhook.replay_ttl_secs,
            "max_entries": config.webhook.replay_max_entries,
            "persistent_storage_configured": false,
        },
    })
}

fn webhook_readiness_message(config: &NextcloudTalkConfig) -> String {
    match (
        config.webhook.enabled,
        config
            .webhook
            .bot_secret
            .as_ref()
            .map(NextcloudTalkSecretRef::source_label),
    ) {
        (false, _) => "Manual-poll mode; webhook receiver is not enabled".to_string(),
        (true, Some(source)) => format!("Webhook mode ready; bot secret source: {source}"),
        (true, None) => "Webhook mode requested but bot secret is missing".to_string(),
    }
}

fn inbound_policy_details(config: &NextcloudTalkConfig) -> serde_json::Value {
    json!({
        "dm_policy": config.inbound_policy.dm_policy,
        "group_policy": config.inbound_policy.group_policy,
        "allow_from_count": config.inbound_policy.allow_from.len(),
        "group_allow_from_count": config.inbound_policy.group_allow_from.len(),
        "rooms_count": config.inbound_policy.rooms.len(),
        "disabled_rooms_count": config.inbound_policy.disabled_rooms.len(),
        "mention_required_rooms_count": config.inbound_policy.mention_required_rooms.len(),
        "mention_required_default": "host_forwarded_group_messages",
        "command_authorization": "host_forwarded_input_flag",
    })
}

fn runtime_network_constraints_projection(config: &NextcloudTalkConfig) -> serde_json::Value {
    json!({
        "host_allow": effective_host_allowlist(config),
        "port_allow": [80, 443],
        "cidr_deny": [],
        "deny_localhost": !config.network.allow_private_networks,
        "deny_private_ranges": !config.network.allow_private_networks,
        "deny_tailnet_ranges": !config.network.allow_tailnet_networks,
        "require_sni": true,
        "deny_ip_literals": false,
        "require_host_canonicalization": true,
        "max_redirects": 5,
        "connect_timeout_ms": 10_000,
        "total_timeout_ms": config.request_timeout_ms,
    })
}

fn effective_host_allowlist(config: &NextcloudTalkConfig) -> Vec<String> {
    if !config.network.allowed_hosts.is_empty() {
        return config.network.allowed_hosts.clone();
    }
    config
        .server_url_policy_report()
        .map_or_else(|_| Vec::new(), |report| vec![report.host])
}

fn effective_backend_allowlist(config: &NextcloudTalkConfig) -> Vec<String> {
    if !config.webhook.backend_allowlist.is_empty() {
        return config.webhook.backend_allowlist.clone();
    }
    vec![config.normalized_server_url()]
}

fn secret_fingerprint(secret_ref: &NextcloudTalkSecretRef) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret_ref.fingerprint_material().as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("sha256:{}", &digest[..16])
}

fn attach_self_check_details(
    mut report: SelfCheckReport,
    config: Option<&NextcloudTalkConfig>,
) -> SelfCheckReport {
    report.details = Some(config.map_or_else(
        || json!({ "configured": false }),
        |config| {
            json!({
            "setup": setup_details(config),
            "webhook": webhook_details(config),
            "inbound_policy": inbound_policy_details(config),
            "network_policy": runtime_network_constraints_projection(config),
            })
        },
    ));
    report
}

#[allow(clippy::too_many_arguments)]
fn op_info(
    id: &'static str,
    summary: &str,
    description: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    when_to_use: &str,
    common_mistakes: &[&str],
    related: &[&'static str],
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(description.into()),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: common_mistakes.iter().map(ToString::to_string).collect(),
            examples: Vec::new(),
            related: related
                .iter()
                .copied()
                .map(CapabilityId::from_static)
                .collect(),
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

/// Build the typed operation catalog for the connector.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            OP_HEALTH,
            "Probe Nextcloud Talk reachability and capability surface",
            "Performs a read-only capabilities probe against the configured Nextcloud server and confirms that the Talk app is exposed.",
            json!({ "type": "object", "properties": {} }),
            json!({
                "type": "object",
                "properties": {
                    "server_url": { "type": "string" },
                    "version": { "type": ["string", "null"] },
                    "has_talk": { "type": "boolean" },
                    "features": { "type": "array", "items": { "type": "string" } },
                    "config": { "type": ["object", "array", "string", "number", "boolean", "null"] }
                }
            }),
            CAP_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            "Use this before room, participant, or chat operations to verify the configured server is reachable and exposes the Talk app.",
            &[
                "Passing a base URL with a query string or fragment",
                "Using a server that has Nextcloud but not the Talk app enabled",
            ],
            &[OP_LIST_CONVERSATIONS, OP_GET_MESSAGES],
        ),
        op_info(
            OP_LIST_CONVERSATIONS,
            "List conversations",
            "Lists the authenticated principal's visible Nextcloud Talk conversations.",
            json!({
                "type": "object",
                "properties": {
                    "include_status": { "type": "boolean" },
                    "modified_since": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "conversations": { "type": "array", "items": { "type": "object" } }
                }
            }),
            CAP_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            "Use this to enumerate rooms before looking up details, chat history, or call state.",
            &["Forgetting that archived or inaccessible rooms may not be returned"],
            &[OP_GET_CONVERSATION, OP_GET_MESSAGES],
        ),
        op_info(
            OP_GET_CONVERSATION,
            "Get conversation details",
            "Fetches metadata for a single Nextcloud Talk conversation token.",
            json!({
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "conversation": { "type": "object" }
                }
            }),
            CAP_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            "Use this when you already know the conversation token and need current metadata or permissions.",
            &["Passing a display name instead of the room token"],
            &[OP_LIST_CONVERSATIONS, OP_LIST_PARTICIPANTS],
        ),
        op_info(
            OP_CREATE_CONVERSATION,
            "Create conversation",
            "Creates a new Nextcloud Talk conversation.",
            json!({
                "type": "object",
                "required": ["room_type"],
                "properties": {
                    "room_type": { "type": "integer", "minimum": 1, "maximum": 6 },
                    "invite": { "type": "string" },
                    "source": { "type": "string" },
                    "room_name": { "type": "string" },
                    "object_type": { "type": "string" },
                    "object_id": { "type": "string" },
                    "password": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "conversation": { "type": "object" }
                }
            }),
            CAP_MANAGE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            "Use this to create a room before inviting participants or sending messages.",
            &["Using the wrong numeric room_type for the desired conversation shape"],
            &[OP_ADD_PARTICIPANT, OP_SEND_MESSAGE],
        ),
        op_info(
            OP_GET_MESSAGES,
            "Get chat messages",
            "Fetches chat history for a conversation and supports long-poll style retrieval.",
            json!({
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "look_into_future": { "type": "boolean" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                    "last_known_message_id": { "type": "integer" },
                    "last_common_read_id": { "type": "integer" },
                    "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 60 },
                    "set_read_marker": { "type": "boolean" },
                    "include_last_known": { "type": "boolean" },
                    "no_status_update": { "type": "boolean" },
                    "mark_notifications_as_read": { "type": "boolean" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "messages": { "type": "array", "items": { "type": "object" } },
                    "last_given": { "type": ["integer", "null"] },
                    "last_common_read": { "type": ["integer", "null"] },
                    "not_modified": { "type": "boolean" }
                }
            }),
            CAP_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            "Use this to read recent chat activity or to long-poll for new messages.",
            &[
                "Setting limit or timeout outside the documented API bounds",
                "Using a room display name instead of the conversation token",
            ],
            &[OP_SEND_MESSAGE, OP_SET_READ_MARKER],
        ),
        op_info(
            OP_POLL_CONVERSATION_EVENTS,
            "Poll conversation events",
            "Transforms Nextcloud Talk long-poll chat retrieval into explicit event envelopes plus cursor metadata for inbound room synchronization.",
            json!({
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "look_into_future": { "type": "boolean" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                    "last_known_message_id": { "type": "integer" },
                    "last_common_read_id": { "type": "integer" },
                    "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 60 },
                    "set_read_marker": { "type": "boolean" },
                    "include_last_known": { "type": "boolean" },
                    "no_status_update": { "type": "boolean" },
                    "mark_notifications_as_read": { "type": "boolean" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "events": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "conversation_token": { "type": "string" },
                                "message_id": { "type": "integer" },
                                "message": { "type": "object" }
                            }
                        }
                    },
                    "cursor": {
                        "type": "object",
                        "properties": {
                            "last_known_message_id": { "type": ["integer", "null"] },
                            "last_common_read_id": { "type": ["integer", "null"] }
                        }
                    },
                    "not_modified": { "type": "boolean" }
                }
            }),
            CAP_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            "Use this as the explicit inbound polling fallback for room activity when you need event-like envelopes and a resumable cursor.",
            &[
                "Forgetting to persist the returned cursor between polling iterations",
                "Expecting this passive polling surface to also advance read markers or notification state",
                "Expecting non-chat room state changes that the Talk HTTP API does not emit as messages",
            ],
            &[OP_GET_MESSAGES, OP_SET_READ_MARKER],
        ),
        op_info(
            OP_INGEST_WEBHOOK,
            "Ingest a host-forwarded Nextcloud Talk webhook",
            "Verifies a host-forwarded Nextcloud Talk bot webhook without opening a listener: required headers, backend allowlist, HMAC-SHA256 random+body signature, body budget, timeout budget, replay claim/commit/release, and inbound sender/room policy are enforced before emitting an event envelope.",
            json!({
                "type": "object",
                "required": ["headers", "body"],
                "properties": {
                    "headers": {
                        "type": "object",
                        "required": [
                            "x-nextcloud-talk-signature",
                            "x-nextcloud-talk-random",
                            "x-nextcloud-talk-backend"
                        ]
                    },
                    "body": { "type": "string", "minLength": 1 },
                    "body_size_bytes": { "type": "integer", "minimum": 0 },
                    "body_read_elapsed_ms": { "type": "integer", "minimum": 0 },
                    "source_id": { "type": "string" },
                    "delivery_id": { "type": "string" },
                    "room_kind": { "type": "string", "enum": ["group", "dm"] },
                    "mention_text": { "type": "string" },
                    "require_mention": { "type": "boolean" },
                    "command_authorized": { "type": "boolean" },
                    "dispatch_outcome": { "type": "string", "enum": ["commit", "retryable_error", "nonretryable_error"] }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" },
                    "event": { "type": ["object", "null"] },
                    "signature": { "type": "object" },
                    "replay": { "type": "object" },
                    "policy": { "type": "object" }
                }
            }),
            CAP_WEBHOOK,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            "Use this only when fcp-host has already accepted the HTTP request and is forwarding raw headers plus raw body to the connector for Nextcloud Talk bot webhook verification.",
            &[
                "Do not expose an in-connector listener; this operation is the host-forwarded ingress boundary",
                "Do not send a parsed payload instead of the exact raw body because the HMAC covers random+body bytes",
                "Do not expect credential_id secrets to verify locally until the host injects the secret material",
            ],
            &[OP_POLL_CONVERSATION_EVENTS],
        ),
        op_info(
            OP_SEND_MESSAGE,
            "Send chat message",
            "Posts a message into a Nextcloud Talk conversation.",
            json!({
                "type": "object",
                "required": ["token", "message"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "message": { "type": "string", "minLength": 1 },
                    "actor_display_name": { "type": "string" },
                    "reply_to": { "type": "integer" },
                    "reference_id": { "type": "string" },
                    "silent": { "type": "boolean" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "message": { "type": "object" }
                }
            }),
            CAP_WRITE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            "Use this when you need to post a new message into a conversation.",
            &["Forgetting to target the room token rather than the room name"],
            &[OP_GET_MESSAGES, OP_ADD_REACTION],
        ),
        op_info(
            OP_DELETE_MESSAGE,
            "Delete chat message",
            "Deletes a specific chat message in a conversation.",
            json!({
                "type": "object",
                "required": ["token", "message_id"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "message_id": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "message": { "type": "object" }
                }
            }),
            CAP_MANAGE,
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            "Use this to remove a previously sent message when the caller has permission to do so.",
            &["Assuming deletion is always allowed for every room member"],
            &[OP_GET_MESSAGES],
        ),
        op_info(
            OP_SET_READ_MARKER,
            "Set read marker",
            "Updates the read marker for a conversation.",
            json!({
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "last_read_message": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "conversation": { "type": "object" }
                }
            }),
            CAP_WRITE,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            "Use this after reading a room to advance the caller's read state.",
            &["Passing a message ID from a different conversation"],
            &[OP_GET_MESSAGES],
        ),
        op_info(
            OP_LIST_PARTICIPANTS,
            "List participants",
            "Lists conversation participants and optional presence details.",
            json!({
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "include_status": { "type": "boolean" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "participants": { "type": "array", "items": { "type": "object" } }
                }
            }),
            CAP_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            "Use this to inspect room membership, roles, and current participant status.",
            &["Forgetting that guests and federated users use different actor types"],
            &[OP_ADD_PARTICIPANT, OP_REMOVE_PARTICIPANT],
        ),
        op_info(
            OP_ADD_PARTICIPANT,
            "Add participant",
            "Adds a user, group, email, or guest target to a conversation.",
            json!({
                "type": "object",
                "required": ["token", "new_participant"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "new_participant": { "type": "string", "minLength": 1 },
                    "source": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "result": { "type": ["object", "array", "string", "number", "boolean", "null"] }
                }
            }),
            CAP_MANAGE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            "Use this when you need to invite or attach an additional participant to a conversation.",
            &["Choosing the wrong source for non-user participants"],
            &[OP_LIST_PARTICIPANTS],
        ),
        op_info(
            OP_REMOVE_PARTICIPANT,
            "Remove participant",
            "Removes an attendee from a conversation by attendee ID.",
            json!({
                "type": "object",
                "required": ["token", "attendee_id"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "attendee_id": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" },
                    "attendee_id": { "type": "integer" }
                }
            }),
            CAP_MANAGE,
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            "Use this to remove a room participant when moderation or lifecycle policy requires it.",
            &["Passing an actor ID instead of the numeric attendee_id"],
            &[OP_LIST_PARTICIPANTS],
        ),
        op_info(
            OP_GET_CALL_STATE,
            "Get call state",
            "Lists currently connected call participants for a conversation.",
            json!({
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "participants": { "type": "array", "items": { "type": "object" } }
                }
            }),
            CAP_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            "Use this to inspect live call presence for a room.",
            &["Assuming every conversation currently has an active call"],
            &[OP_GET_CONVERSATION],
        ),
        op_info(
            OP_ADD_REACTION,
            "Add reaction",
            "Adds an emoji reaction to a specific chat message.",
            json!({
                "type": "object",
                "required": ["token", "message_id", "reaction"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "message_id": { "type": "integer" },
                    "reaction": { "type": "string", "minLength": 1 }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "reactions": { "type": "array", "items": { "type": "object" } }
                }
            }),
            CAP_WRITE,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            "Use this to attach a reaction to an existing chat message.",
            &[
                "Passing the rendered emoji name instead of the exact reaction payload expected by the server",
            ],
            &[OP_DELETE_REACTION, OP_GET_MESSAGES],
        ),
        op_info(
            OP_DELETE_REACTION,
            "Delete reaction",
            "Removes an emoji reaction from a specific chat message.",
            json!({
                "type": "object",
                "required": ["token", "message_id", "reaction"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "message_id": { "type": "integer" },
                    "reaction": { "type": "string", "minLength": 1 }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "reactions": { "type": "array", "items": { "type": "object" } }
                }
            }),
            CAP_WRITE,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            "Use this to remove a previously added reaction from a chat message.",
            &["Using a different emoji string than the one originally applied"],
            &[OP_ADD_REACTION, OP_GET_MESSAGES],
        ),
        op_info(
            OP_SHARE_FILE,
            "Share file into conversation",
            "Creates a file share and posts it into a Nextcloud Talk conversation.",
            json!({
                "type": "object",
                "required": ["token", "path"],
                "properties": {
                    "token": { "type": "string", "minLength": 1 },
                    "path": { "type": "string", "minLength": 1 },
                    "reference_id": { "type": "string" },
                    "talk_meta_data": { "type": "object" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "share": { "type": "object" }
                }
            }),
            CAP_WRITE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            "Use this to share a Nextcloud file into a room without manually creating a share link first.",
            &["Passing a filesystem path that does not exist inside the target Nextcloud instance"],
            &[OP_SEND_MESSAGE],
        ),
    ]
}

#[derive(Debug, Deserialize, Default)]
struct ListConversationsInput {
    #[serde(default)]
    include_status: bool,
    #[serde(default)]
    modified_since: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TokenInput {
    token: String,
}

#[derive(Debug, Deserialize)]
struct CreateConversationInput {
    #[serde(flatten)]
    request: CreateConversationRequest,
}

#[derive(Debug, Deserialize)]
struct GetMessagesInput {
    token: String,
    #[serde(flatten)]
    query: ChatMessagesQuery,
}

#[derive(Debug, Deserialize)]
struct SendMessageInput {
    token: String,
    #[serde(flatten)]
    request: SendChatMessageRequest,
}

#[derive(Debug, Deserialize)]
struct DeleteMessageInput {
    token: String,
    message_id: MessageId,
}

#[derive(Debug, Deserialize)]
struct SetReadMarkerInput {
    token: String,
    #[serde(flatten)]
    request: ReadMarkerRequest,
}

#[derive(Debug, Deserialize)]
struct ListParticipantsInput {
    token: String,
    #[serde(flatten)]
    query: ParticipantListQuery,
}

#[derive(Debug, Deserialize)]
struct AddParticipantInput {
    token: String,
    #[serde(flatten)]
    request: AddParticipantRequest,
}

#[derive(Debug, Deserialize)]
struct RemoveParticipantInput {
    token: String,
    attendee_id: AttendeeId,
}

#[derive(Debug, Deserialize)]
struct ReactionInput {
    token: String,
    message_id: MessageId,
    reaction: String,
}

#[derive(Debug, Deserialize)]
struct ShareFileInput {
    token: String,
    #[serde(flatten)]
    request: ShareFileRequest,
}

#[derive(Debug, Deserialize)]
struct HostForwardedWebhookInput {
    headers: BTreeMap<String, String>,
    body: String,
    #[serde(default)]
    body_size_bytes: Option<u64>,
    #[serde(default)]
    body_read_elapsed_ms: Option<u64>,
    #[serde(default)]
    source_id: Option<String>,
    #[serde(default)]
    delivery_id: Option<String>,
    #[serde(default)]
    room_kind: Option<WebhookRoomKind>,
    #[serde(default)]
    mention_text: Option<String>,
    #[serde(default)]
    require_mention: Option<bool>,
    #[serde(default)]
    command_authorized: bool,
    #[serde(default)]
    dispatch_outcome: WebhookDispatchOutcome,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WebhookRoomKind {
    #[default]
    Group,
    Dm,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WebhookDispatchOutcome {
    #[default]
    Commit,
    RetryableError,
    NonretryableError,
}

#[derive(Debug, Deserialize)]
struct ActivityStreamsWebhookPayload {
    #[serde(rename = "type")]
    event_type: String,
    actor: ActivityStreamsActor,
    object: ActivityStreamsObject,
    target: ActivityStreamsTarget,
}

#[derive(Debug, Deserialize)]
struct ActivityStreamsActor {
    #[serde(rename = "type")]
    actor_type: Option<String>,
    id: String,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ActivityStreamsObject {
    #[serde(rename = "type")]
    object_type: Option<String>,
    id: String,
    name: Option<String>,
    content: Option<String>,
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ActivityStreamsTarget {
    #[serde(rename = "type")]
    target_type: Option<String>,
    id: String,
    name: Option<String>,
}

fn parse_input<T>(input: serde_json::Value, operation: &str) -> FcpResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(input).map_err(|error| FcpError::InvalidRequest {
        code: 1005,
        message: format!("Invalid input for {operation}: {error}"),
    })
}

fn parse_conversation_ref(raw_conversation_ref: String) -> FcpResult<ConversationToken> {
    ConversationToken::new(raw_conversation_ref).map_err(|message| FcpError::InvalidRequest {
        code: 1005,
        message,
    })
}

fn resolve_message_query(
    mut query: ChatMessagesQuery,
    config: &NextcloudTalkConfig,
) -> FcpResult<ChatMessagesQuery> {
    if query.look_into_future && query.timeout_secs.is_none() {
        query.timeout_secs =
            Some(
                u16::try_from(config.long_poll_timeout_secs).map_err(|_| FcpError::Internal {
                    message: "validated long_poll_timeout_secs exceeded u16 range".into(),
                })?,
            );
    }
    Ok(query)
}

fn resolve_poll_query(
    mut query: ChatMessagesQuery,
    config: &NextcloudTalkConfig,
) -> FcpResult<ChatMessagesQuery> {
    query = resolve_message_query(query, config)?;
    // Polling is a passive read surface; explicit write operations own read-state mutation.
    query.set_read_marker = false;
    query.mark_notifications_as_read = false;
    query.no_status_update = true;
    Ok(query)
}

const fn webhook_event_caps() -> EventCaps {
    EventCaps {
        streaming: false,
        replay: true,
        min_buffer_events: 0,
        requires_ack: false,
    }
}

fn webhook_event_info() -> EventInfo {
    EventInfo {
        topic: EVENT_WEBHOOK_MESSAGE.to_string(),
        schema: json!({
            "type": "object",
            "required": ["topic", "event_type", "account_id_hash", "room_token_hash", "message_id"],
            "properties": {
                "topic": { "const": EVENT_WEBHOOK_MESSAGE },
                "event_type": { "const": "host_forwarded_webhook_message" },
                "account_id_hash": { "type": "string" },
                "room_token_hash": { "type": "string" },
                "message_id": { "type": "string" },
                "signature": { "type": "object" },
                "replay": { "type": "object" },
                "policy": { "type": "object" }
            }
        }),
        requires_ack: false,
    }
}

#[derive(Debug)]
struct NextcloudTalkWebhookHeaders {
    signature: String,
    random: String,
    backend: String,
}

#[derive(Debug)]
struct NextcloudTalkInboundMessage {
    account_id: String,
    room_token: String,
    room_name: Option<String>,
    message_id: String,
    sender_id: String,
    sender_name: Option<String>,
    text: String,
    sanitized_text: String,
    media_type: String,
    room_kind: WebhookRoomKind,
    actor_type: Option<String>,
    object_type: Option<String>,
    target_type: Option<String>,
}

#[derive(Debug)]
struct WebhookPolicyOutcome {
    status: &'static str,
    emit_event: bool,
    details: Value,
}

impl NextcloudTalkConnector {
    #[allow(clippy::too_many_lines)]
    fn ingest_host_forwarded_webhook(
        &self,
        input: &HostForwardedWebhookInput,
        config: &NextcloudTalkConfig,
    ) -> FcpResult<Value> {
        if !config.webhook.enabled {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "webhook mode is not enabled for Nextcloud Talk".into(),
            });
        }

        let body_size_bytes = input
            .body_size_bytes
            .unwrap_or_else(|| u64::try_from(input.body.len()).unwrap_or(u64::MAX));
        if body_size_bytes > config.webhook.max_body_bytes {
            return Err(FcpError::ResourceExhausted {
                resource: format!(
                    "nextcloud_talk.forwarded_webhook_body:{body_size_bytes}>{}",
                    config.webhook.max_body_bytes
                ),
            });
        }

        let body_read_elapsed_ms = input.body_read_elapsed_ms.unwrap_or(0);
        if body_read_elapsed_ms > config.webhook.body_timeout_ms {
            return Err(FcpError::UpstreamTimeout {
                service: "nextcloud_talk.forwarded_webhook_body_read".into(),
            });
        }

        let headers = extract_nextcloud_talk_headers(&input.headers)?;
        let normalized_backend = verify_nextcloud_talk_backend(config, &headers.backend)?;
        let source_id = input
            .source_id
            .as_deref()
            .map(str::trim)
            .filter(|source| !source.is_empty())
            .unwrap_or(&normalized_backend);
        let webhook_hmac_material = config
            .webhook
            .bot_secret
            .as_ref()
            .and_then(NextcloudTalkSecretRef::inline_secret)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "inline webhook.bot_secret is required for local HMAC verification".into(),
            })?;

        if !verify_nextcloud_talk_hmac(
            webhook_hmac_material,
            &headers.random,
            &input.body,
            &headers.signature,
        ) {
            self.record_webhook_auth_failure(source_id, config)?;
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: "Nextcloud Talk webhook signature verification failed".into(),
            });
        }

        let payload: ActivityStreamsWebhookPayload =
            serde_json::from_str(&input.body).map_err(|error| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid Nextcloud Talk webhook JSON body: {error}"),
            })?;
        let message = payload_to_inbound_message(&payload, config, input.room_kind)?;
        self.record_authenticated_webhook_attempt(&message, config)?;

        let replay_key = WebhookReplayKey::new(
            &message.account_id,
            &message.room_token,
            &message.message_id,
        )?;
        let ttl = Duration::from_secs(config.webhook.replay_ttl_secs);
        let replay_decision =
            self.claim_webhook_replay(replay_key.clone(), ttl, config.webhook.replay_max_entries)?;
        if replay_decision != WebhookReplayDecision::Claimed {
            return Ok(json!({
                "status": replay_decision.as_str(),
                "event": null,
                "signature": signature_decision(&normalized_backend),
                "replay": replay_details(&message, replay_decision),
                "policy": {
                    "decision": "not_evaluated",
                    "reason": replay_decision.as_str(),
                },
            }));
        }

        if payload.event_type != "Create" {
            self.commit_webhook_replay(&replay_key, ttl)?;
            return Ok(json!({
                "status": "ignored",
                "event": null,
                "signature": signature_decision(&normalized_backend),
                "replay": replay_details(&message, WebhookReplayDecision::Claimed),
                "policy": {
                    "decision": "ignored",
                    "reason": "non_create_activitystreams_event",
                    "activity_type": payload.event_type,
                },
            }));
        }

        let policy_outcome = match enforce_nextcloud_talk_inbound_policy(config, input, &message) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.commit_webhook_replay(&replay_key, ttl)?;
                return Err(error);
            }
        };

        if !policy_outcome.emit_event {
            self.commit_webhook_replay(&replay_key, ttl)?;
            return Ok(json!({
                "status": policy_outcome.status,
                "event": null,
                "signature": signature_decision(&normalized_backend),
                "replay": replay_details(&message, WebhookReplayDecision::Claimed),
                "policy": policy_outcome.details,
            }));
        }

        let delivery_id = input
            .delivery_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map_or_else(
                || {
                    format!(
                        "nextcloud-talk:{}:{}:{}",
                        message.account_id, message.room_token, message.message_id
                    )
                },
                ToString::to_string,
            );
        let event = json!({
            "topic": EVENT_WEBHOOK_MESSAGE,
            "event_type": "host_forwarded_webhook_message",
            "delivery_id": delivery_id,
            "account_id_hash": hash_identifier(&message.account_id),
            "room_token_hash": hash_identifier(&message.room_token),
            "message_id": &message.message_id,
            "room": {
                "token": &message.room_token,
                "name": &message.room_name,
                "kind": match message.room_kind {
                    WebhookRoomKind::Group => "group",
                    WebhookRoomKind::Dm => "dm",
                },
                "resource_uri": format!("nextcloud-talk://accounts/{}/rooms/{}", hash_identifier(&message.account_id), hash_identifier(&message.room_token)),
            },
            "sender": {
                "id_hash": hash_identifier(&message.sender_id),
                "display_name": &message.sender_name,
                "actor_type": &message.actor_type,
            },
            "message": {
                "text": &message.text,
                "sanitized_text": &message.sanitized_text,
                "media_type": &message.media_type,
                "object_type": &message.object_type,
                "target_type": &message.target_type,
            },
            "signature": signature_decision(&normalized_backend),
            "replay": replay_details(&message, WebhookReplayDecision::Claimed),
            "policy": policy_outcome.details,
            "ingress": {
                "mode": "host_forwarded",
                "hosted_listener": false,
                "body_size_bytes": body_size_bytes,
                "body_limit_bytes": config.webhook.max_body_bytes,
                "body_read_elapsed_ms": body_read_elapsed_ms,
                "body_timeout_ms": config.webhook.body_timeout_ms,
                "source_hash": hash_identifier(source_id),
                "raw_payload_logged": false,
            },
        });

        match input.dispatch_outcome {
            WebhookDispatchOutcome::Commit => {
                self.commit_webhook_replay(&replay_key, ttl)?;
                Ok(json!({
                    "status": "processed",
                    "event": event,
                    "signature": signature_decision(&normalized_backend),
                    "replay": replay_details(&message, WebhookReplayDecision::Claimed),
                    "policy": policy_outcome.details,
                }))
            }
            WebhookDispatchOutcome::RetryableError => {
                self.release_webhook_replay(&replay_key)?;
                Err(FcpError::External {
                    service: "nextcloud_talk.webhook_dispatch".into(),
                    message: "host-forwarded webhook dispatch failed retryably".into(),
                    status_code: None,
                    retryable: true,
                    retry_after: Some(Duration::from_secs(1)),
                })
            }
            WebhookDispatchOutcome::NonretryableError => {
                self.commit_webhook_replay(&replay_key, ttl)?;
                Err(FcpError::External {
                    service: "nextcloud_talk.webhook_dispatch".into(),
                    message: "host-forwarded webhook dispatch failed nonretryably".into(),
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                })
            }
        }
    }

    fn claim_webhook_replay(
        &self,
        key: WebhookReplayKey,
        ttl: Duration,
        max_entries: usize,
    ) -> FcpResult<WebhookReplayDecision> {
        let mut replay = self.webhook_replay.lock().map_err(|_| FcpError::Internal {
            message: "Nextcloud Talk webhook replay state lock poisoned".into(),
        })?;
        Ok(replay.claim(key, Instant::now(), ttl, max_entries))
    }

    fn commit_webhook_replay(&self, key: &WebhookReplayKey, ttl: Duration) -> FcpResult<()> {
        self.webhook_replay
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Nextcloud Talk webhook replay state lock poisoned".into(),
            })?
            .commit(key, Instant::now(), ttl);
        Ok(())
    }

    fn release_webhook_replay(&self, key: &WebhookReplayKey) -> FcpResult<()> {
        self.webhook_replay
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Nextcloud Talk webhook replay state lock poisoned".into(),
            })?
            .release(key);
        Ok(())
    }

    fn record_webhook_auth_failure(
        &self,
        source_id: &str,
        config: &NextcloudTalkConfig,
    ) -> FcpResult<()> {
        let key = format!("auth_failure:{}", hash_identifier(source_id));
        self.check_webhook_rate(&key, config.webhook.auth_failure_limit_per_minute)
    }

    fn record_authenticated_webhook_attempt(
        &self,
        message: &NextcloudTalkInboundMessage,
        config: &NextcloudTalkConfig,
    ) -> FcpResult<()> {
        let key = format!(
            "sender:{}:{}",
            hash_identifier(&message.account_id),
            hash_identifier(&message.sender_id)
        );
        self.check_webhook_rate(&key, config.webhook.sender_limit_per_minute)
    }

    fn check_webhook_rate(&self, key: &str, limit: u32) -> FcpResult<()> {
        let mut rate = self.webhook_rate.lock().map_err(|_| FcpError::Internal {
            message: "Nextcloud Talk webhook rate state lock poisoned".into(),
        })?;
        if rate.check(key, limit, Instant::now()) {
            Ok(())
        } else {
            Err(FcpError::RateLimited {
                retry_after_ms: 60_000,
                violation: None,
            })
        }
    }
}

fn extract_nextcloud_talk_headers(
    headers: &BTreeMap<String, String>,
) -> FcpResult<NextcloudTalkWebhookHeaders> {
    Ok(NextcloudTalkWebhookHeaders {
        signature: required_header(headers, "x-nextcloud-talk-signature")?,
        random: required_header(headers, "x-nextcloud-talk-random")?,
        backend: required_header(headers, "x-nextcloud-talk-backend")?,
    })
}

fn required_header(headers: &BTreeMap<String, String>, name: &str) -> FcpResult<String> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing required Nextcloud Talk webhook header: {name}"),
        })
}

fn verify_nextcloud_talk_backend(config: &NextcloudTalkConfig, backend: &str) -> FcpResult<String> {
    let normalized_backend = normalize_backend_url("headers.x-nextcloud-talk-backend", backend)?;
    let allowed = effective_backend_allowlist(config)
        .into_iter()
        .filter_map(|allowed| normalize_backend_url("webhook.backend_allowlist", &allowed).ok())
        .any(|allowed| allowed == normalized_backend);
    if allowed {
        return Ok(normalized_backend);
    }
    Err(FcpError::Unauthorized {
        code: 2001,
        message: "Nextcloud Talk webhook backend is not allowed".into(),
    })
}

fn normalize_backend_url(field: &str, value: &str) -> FcpResult<String> {
    let parsed = Url::parse(value.trim()).map_err(|error| FcpError::InvalidRequest {
        code: 1005,
        message: format!("Invalid {field}: {error}"),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must use http or https"),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must not contain a query string or fragment"),
        });
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn verify_nextcloud_talk_hmac(
    signing_material: &str,
    random: &str,
    body: &str,
    presented: &str,
) -> bool {
    let mut mac = HmacSha256::new_from_slice(signing_material.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(random.as_bytes());
    mac.update(body.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    let presented = presented
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or_else(|| presented.trim())
        .to_ascii_lowercase();
    constant_time_eq(expected.as_bytes(), presented.as_bytes())
}

fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    let max_len = expected.len().max(actual.len());
    let mut diff = expected.len() ^ actual.len();
    for index in 0..max_len {
        let expected_byte = expected.get(index).copied().unwrap_or(0);
        let actual_byte = actual.get(index).copied().unwrap_or(0);
        diff |= usize::from(expected_byte ^ actual_byte);
    }
    diff == 0
}

fn payload_to_inbound_message(
    payload: &ActivityStreamsWebhookPayload,
    config: &NextcloudTalkConfig,
    room_kind: Option<WebhookRoomKind>,
) -> FcpResult<NextcloudTalkInboundMessage> {
    let conversation_ref = required_activity_value("target.id", &payload.target.id)?;
    let message_id = required_activity_value("object.id", &payload.object.id)?;
    let sender_id = required_activity_value("actor.id", &payload.actor.id)?;
    let text = payload
        .object
        .content
        .as_deref()
        .or(payload.object.name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "Nextcloud Talk webhook object.content or object.name is required".into(),
        })?
        .to_string();
    let sanitized_text = sanitize_inbound_text(&text);

    Ok(NextcloudTalkInboundMessage {
        account_id: config.account_id().to_string(),
        room_token: conversation_ref,
        room_name: payload
            .target
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
        message_id,
        sender_id,
        sender_name: payload
            .actor
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
        text,
        sanitized_text,
        media_type: payload
            .object
            .media_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("text/plain")
            .to_string(),
        room_kind: room_kind.unwrap_or_default(),
        actor_type: payload.actor.actor_type.clone(),
        object_type: payload.object.object_type.clone(),
        target_type: payload.target.target_type.clone(),
    })
}

fn required_activity_value(field: &str, value: &str) -> FcpResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("Nextcloud Talk webhook {field} must not be empty"),
        });
    }
    Ok(trimmed.to_string())
}

fn enforce_nextcloud_talk_inbound_policy(
    config: &NextcloudTalkConfig,
    input: &HostForwardedWebhookInput,
    message: &NextcloudTalkInboundMessage,
) -> FcpResult<WebhookPolicyOutcome> {
    let policy = &config.inbound_policy;
    if allowlist_matches(&policy.disabled_rooms, &message.room_token) {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Nextcloud Talk webhook room is disabled by inbound policy".into(),
        });
    }

    match message.room_kind {
        WebhookRoomKind::Dm => enforce_nextcloud_talk_dm_policy(policy, message),
        WebhookRoomKind::Group => enforce_nextcloud_talk_group_policy(policy, input, message),
    }
}

fn enforce_nextcloud_talk_dm_policy(
    policy: &crate::config::NextcloudTalkInboundPolicy,
    message: &NextcloudTalkInboundMessage,
) -> FcpResult<WebhookPolicyOutcome> {
    match policy.dm_policy.as_str() {
        "pairing" => Ok(WebhookPolicyOutcome {
            status: "pairing_required",
            emit_event: false,
            details: json!({
                "decision": "pairing_required",
                "reason": "dm_pairing_required",
                "sender_id_hash": hash_identifier(&message.sender_id),
                "room_token_hash": hash_identifier(&message.room_token),
            }),
        }),
        "allowlist" if !allowlist_matches(&policy.allow_from, &message.sender_id) => {
            Err(FcpError::Unauthorized {
                code: 2001,
                message: "Nextcloud Talk webhook DM sender denied by inbound policy".into(),
            })
        }
        "allowlist" => Ok(WebhookPolicyOutcome {
            status: "processed",
            emit_event: true,
            details: json!({
                "decision": "allowed",
                "reason": "dm_sender_allowlist_match",
                "sender_id_hash": hash_identifier(&message.sender_id),
            }),
        }),
        "open" => Ok(WebhookPolicyOutcome {
            status: "processed",
            emit_event: true,
            details: json!({
                "decision": "allowed",
                "reason": "dm_policy_open",
                "sender_id_hash": hash_identifier(&message.sender_id),
            }),
        }),
        _ => Err(FcpError::Unauthorized {
            code: 2001,
            message: "Nextcloud Talk webhook DM policy denied event".into(),
        }),
    }
}

fn enforce_nextcloud_talk_group_policy(
    policy: &crate::config::NextcloudTalkInboundPolicy,
    input: &HostForwardedWebhookInput,
    message: &NextcloudTalkInboundMessage,
) -> FcpResult<WebhookPolicyOutcome> {
    if policy.group_policy == "disabled" {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Nextcloud Talk webhook group events are disabled".into(),
        });
    }
    if !allowlist_matches(&policy.rooms, &message.room_token) {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Nextcloud Talk webhook room denied by allowlist policy".into(),
        });
    }
    if policy.group_policy == "allowlist"
        && !allowlist_matches(&policy.group_allow_from, &message.sender_id)
    {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Nextcloud Talk webhook group sender denied by allowlist policy".into(),
        });
    }
    if message.text.trim_start().starts_with('/') && !input.command_authorized {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Nextcloud Talk webhook command requires explicit authorization".into(),
        });
    }

    let mention_required = input.require_mention.unwrap_or_else(|| {
        policy.mention_required_rooms.is_empty()
            || allowlist_matches(&policy.mention_required_rooms, &message.room_token)
    });
    let mention_text = input
        .mention_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("@flywheel");
    if mention_required && !message.text.contains(mention_text) {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Nextcloud Talk webhook group message missing required mention".into(),
        });
    }

    Ok(WebhookPolicyOutcome {
        status: "processed",
        emit_event: true,
        details: json!({
            "decision": "allowed",
            "reason": if policy.group_policy == "open" {
                "group_policy_open"
            } else {
                "group_sender_allowlist_match"
            },
            "room_token_hash": hash_identifier(&message.room_token),
            "sender_id_hash": hash_identifier(&message.sender_id),
            "mention_required": mention_required,
            "command_authorized": input.command_authorized,
        }),
    })
}

fn allowlist_matches(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim();
        pattern == "*"
            || pattern == value
            || pattern
                .strip_suffix('*')
                .is_some_and(|prefix| value.starts_with(prefix))
    })
}

fn signature_decision(backend: &str) -> Value {
    json!({
        "decision": "verified",
        "algorithm": "hmac_sha256_random_plus_body",
        "backend": backend,
    })
}

fn replay_details(message: &NextcloudTalkInboundMessage, decision: WebhookReplayDecision) -> Value {
    json!({
        "decision": decision.as_str(),
        "mode": "in_memory",
        "key": {
            "account_id_hash": hash_identifier(&message.account_id),
            "room_token_hash": hash_identifier(&message.room_token),
            "message_id": message.message_id,
        },
    })
}

fn sanitize_inbound_text(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
                ' '
            } else {
                ch
            }
        })
        .collect()
}

fn hash_identifier(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("sha256:{}", &digest[..16])
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_HEALTH
        | OP_LIST_CONVERSATIONS
        | OP_GET_CONVERSATION
        | OP_GET_MESSAGES
        | OP_POLL_CONVERSATION_EVENTS
        | OP_LIST_PARTICIPANTS
        | OP_GET_CALL_STATE => CAP_READ,
        OP_INGEST_WEBHOOK => CAP_WEBHOOK,
        OP_SEND_MESSAGE | OP_SET_READ_MARKER | OP_ADD_REACTION | OP_DELETE_REACTION
        | OP_SHARE_FILE => CAP_WRITE,
        OP_CREATE_CONVERSATION | OP_DELETE_MESSAGE | OP_ADD_PARTICIPANT | OP_REMOVE_PARTICIPANT => {
            CAP_MANAGE
        }
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fcp_core::impl_fcp_sealed!(NextcloudTalkConnector);

#[async_trait]
impl FcpConnector for NextcloudTalkConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let chat_coordination_config = parse_nextcloud_talk_chat_coordination_config(
            config.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;
        let config = NextcloudTalkConfig::from_value(config)?;
        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = NextcloudTalkClient::new(&config).map_err(|error| FcpError::Internal {
            message: format!("Failed to create Nextcloud Talk client: {error}"),
        })?;

        self.webhook_replay = Mutex::new(NextcloudTalkWebhookReplayState::default());
        self.webhook_rate = Mutex::new(NextcloudTalkWebhookRateState::default());
        self.client = Some(client);
        self.config = Some(config);
        self.chat_coordination_config = chat_coordination_config;
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
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(webhook_event_caps()),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snapshot = if self.client.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(
            self.config
                .as_ref()
                .map_or_else(|| json!({ "configured": false }), setup_details),
        );
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                self.config.as_ref(),
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(attach_self_check_details(
                SelfCheckReport::failed("runtime_missing", "Connector runtime is not initialized"),
                self.config.as_ref(),
            ));
        };

        match client.health_check(runtime).await {
            Ok(_) => Ok(attach_self_check_details(
                SelfCheckReport::ok(),
                self.config.as_ref(),
            )),
            Err(error) => {
                if error.is_retryable() {
                    Ok(attach_self_check_details(
                        SelfCheckReport::degraded("self_check_retryable", error.to_string()),
                        self.config.as_ref(),
                    ))
                } else {
                    Ok(attach_self_check_details(
                        SelfCheckReport::failed("self_check_failed", error.to_string()),
                        self.config.as_ref(),
                    ))
                }
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let required_cap = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        if self.client.is_none() || self.runtime.is_none() {
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
            verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![required_cap.as_str().to_string()]);
            }
            return Ok(response);
        }
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
            events: vec![webhook_event_info()],
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(webhook_event_caps()),
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

impl NextcloudTalkConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let InvokeRequest {
            id,
            operation,
            input,
            capability_token,
            ..
        } = req;
        let operation_name = operation.as_str();

        if let Some(verifier) = &self.verifier {
            let capability = required_capability(operation_name)?;
            verifier.verify_bound(capability_token, &capability, &operation, &[])?;
        } else {
            return Err(FcpError::NotHandshaken);
        }

        let runtime = self.runtime.as_ref().ok_or(FcpError::NotConfigured)?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;

        let output = match operation_name {
            OP_HEALTH => {
                let capabilities = client
                    .health_check(runtime)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let talk = capabilities.capabilities.spreed;
                json!({
                    "server_url": client.server_url(),
                    "version": capabilities.version.string,
                    "has_talk": talk.is_some(),
                    "features": talk.as_ref().map_or_else(Vec::<String>::new, |talk| talk.features.clone()),
                    "config": talk.map_or_else(|| json!({}), |talk| talk.config),
                })
            }
            OP_LIST_CONVERSATIONS => {
                let input: ListConversationsInput = parse_input(input, operation_name)?;
                let query = ConversationListQuery {
                    include_status: input.include_status,
                    modified_since: input.modified_since,
                };
                let conversations = client
                    .get_conversations(runtime, &query)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "conversations": conversations })
            }
            OP_GET_CONVERSATION => {
                let input: TokenInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let conversation = client
                    .get_conversation(runtime, &room_ref)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "conversation": conversation })
            }
            OP_CREATE_CONVERSATION => {
                let input: CreateConversationInput = parse_input(input, operation_name)?;
                let conversation = client
                    .create_conversation(runtime, &input.request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "conversation": conversation })
            }
            OP_GET_MESSAGES => {
                let input: GetMessagesInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let query = resolve_message_query(input.query, config)?;
                let page = client
                    .get_messages(runtime, &room_ref, &query)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({
                    "messages": page.messages,
                    "last_given": page.last_given.map(MessageId::get),
                    "last_common_read": page.last_common_read.map(MessageId::get),
                    "not_modified": page.not_modified,
                })
            }
            OP_POLL_CONVERSATION_EVENTS => {
                let input: GetMessagesInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let query = resolve_poll_query(input.query, config)?;
                let page = client
                    .get_messages(runtime, &room_ref, &query)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let last_event_message_id = page.messages.last().map(|message| message.id.get());
                let last_known_message_id = page
                    .last_given
                    .map(MessageId::get)
                    .or(last_event_message_id)
                    .or_else(|| query.last_known_message_id.map(MessageId::get));
                let last_common_read_id = page
                    .last_common_read
                    .map(MessageId::get)
                    .or_else(|| query.last_common_read_id.map(MessageId::get));
                let events: Vec<_> = page
                    .messages
                    .into_iter()
                    .map(|message| {
                        json!({
                            "type": "chat_message",
                            "conversation_token": message.token.as_str(),
                            "message_id": message.id.get(),
                            "message": message,
                        })
                    })
                    .collect();
                json!({
                    "events": events,
                    "cursor": {
                        "last_known_message_id": last_known_message_id,
                        "last_common_read_id": last_common_read_id,
                    },
                    "not_modified": page.not_modified,
                })
            }
            OP_INGEST_WEBHOOK => {
                let input: HostForwardedWebhookInput = parse_input(input, operation_name)?;
                self.ingest_host_forwarded_webhook(&input, config)?
            }
            OP_SEND_MESSAGE => self.send_message_output(runtime, client, input).await?,
            OP_DELETE_MESSAGE => {
                let input: DeleteMessageInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let message = client
                    .delete_message(runtime, &room_ref, input.message_id)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "message": message })
            }
            OP_SET_READ_MARKER => {
                let input: SetReadMarkerInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let conversation = client
                    .set_read_marker(runtime, &room_ref, &input.request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "conversation": conversation })
            }
            OP_LIST_PARTICIPANTS => {
                let input: ListParticipantsInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let participants = client
                    .list_participants(runtime, &room_ref, &input.query)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "participants": participants })
            }
            OP_ADD_PARTICIPANT => {
                let input: AddParticipantInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let result = client
                    .add_participant(runtime, &room_ref, &input.request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "result": result })
            }
            OP_REMOVE_PARTICIPANT => {
                let input: RemoveParticipantInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let request = RemoveParticipantRequest {
                    attendee_id: input.attendee_id,
                };
                client
                    .remove_participant(runtime, &room_ref, &request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({
                    "status": "removed",
                    "attendee_id": input.attendee_id.get(),
                })
            }
            OP_GET_CALL_STATE => {
                let input: TokenInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let participants = client
                    .get_call_state(runtime, &room_ref)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "participants": participants })
            }
            OP_ADD_REACTION => {
                let input: ReactionInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let request = ReactionRequest {
                    reaction: input.reaction,
                };
                let reactions = client
                    .add_reaction(runtime, &room_ref, input.message_id, &request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "reactions": reactions })
            }
            OP_DELETE_REACTION => {
                let input: ReactionInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let request = ReactionRequest {
                    reaction: input.reaction,
                };
                let reactions = client
                    .delete_reaction(runtime, &room_ref, input.message_id, &request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "reactions": reactions })
            }
            OP_SHARE_FILE => {
                let input: ShareFileInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let share = client
                    .share_file(runtime, &room_ref, &input.request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "share": share })
            }
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(id, output))
    }

    async fn send_message_output(
        &self,
        runtime: &ConnectorRuntime,
        client: &NextcloudTalkClient,
        input: Value,
    ) -> FcpResult<Value> {
        let input: SendMessageInput = parse_input(input, OP_SEND_MESSAGE)?;
        input
            .request
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid input for {OP_SEND_MESSAGE}: {message}"),
            })?;
        let room_ref = parse_conversation_ref(input.token)?;
        let (zone_id, claimant_agent_id) = self.chat_coordination_context();
        let coordination = self
            .claim_before_nextcloud_talk_send(
                zone_id,
                &room_ref,
                input.request.reply_to,
                claimant_agent_id.clone(),
            )
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                error = %error,
                "Nextcloud Talk send_message denied by chat coordination"
            );
            return Err(error.clone());
        }

        let message = client
            .send_message(runtime, &room_ref, &input.request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "message": message,
            "coordination": nextcloud_talk_coordination_audit_records(
                &coordination,
                self.chat_coordination_config.backend(),
                &claimant_agent_id,
            ),
        }))
    }

    fn chat_coordination_context(&self) -> (ZoneId, AgentId) {
        let zone_id = self
            .verifier
            .as_ref()
            .map_or_else(ZoneId::work, |verifier| verifier.zone_id.clone());
        let claimant_agent_id = AgentId::new(self.base.instance_id.as_str().to_owned());
        (zone_id, claimant_agent_id)
    }

    async fn claim_before_nextcloud_talk_send(
        &self,
        zone_id: ZoneId,
        room_ref: &ConversationToken,
        reply_to: Option<MessageId>,
        claimant_agent_id: AgentId,
    ) -> ChatCoordinationSendDecision {
        let channel_id = ChannelId::new(room_ref.as_str().trim().to_ascii_lowercase());
        let thread_id =
            reply_to.map(|message_id| ThreadId::new(format!("reply_to:{}", message_id.get())));
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
    use std::{process::Command, sync::Arc, time::Instant};

    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::InstanceId;
    use hmac::Mac;
    use toml::Value as TomlValue;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const NEXTCLOUD_SERVER_HOST_PLACEHOLDER: &str = "${nextcloud_server_host}";
    const NEXTCLOUD_SERVER_EGRESS_OPS: &[&str] = &[
        OP_HEALTH,
        OP_LIST_CONVERSATIONS,
        OP_GET_CONVERSATION,
        OP_CREATE_CONVERSATION,
        OP_GET_MESSAGES,
        OP_POLL_CONVERSATION_EVENTS,
        OP_SEND_MESSAGE,
        OP_DELETE_MESSAGE,
        OP_SET_READ_MARKER,
        OP_LIST_PARTICIPANTS,
        OP_ADD_PARTICIPANT,
        OP_REMOVE_PARTICIPANT,
        OP_GET_CALL_STATE,
        OP_ADD_REACTION,
        OP_DELETE_REACTION,
        OP_SHARE_FILE,
    ];

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
                CapabilityId::from_static(CAP_MANAGE),
                CapabilityId::from_static(CAP_WEBHOOK),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(
        connector_id: &ConnectorId,
        operation: &'static str,
        capability_token: CapabilityToken,
        input: serde_json::Value,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_nextcloud_talk"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token,
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

    fn base_simulate(
        connector_id: &ConnectorId,
        operation: &'static str,
        capability_token: CapabilityToken,
    ) -> SimulateRequest {
        SimulateRequest {
            r#type: "simulate".into(),
            id: RequestId::new("sim_nextcloud_talk"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token,
            estimate_cost: false,
            check_availability: false,
            context: None,
            correlation_id: None,
        }
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operations: &[&'static str],
        instance_id: &InstanceId,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .target_instance(instance_id.as_str())
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .expect("capability token should sign");
        CapabilityToken::from_raw(cose)
    }

    fn activity_body(event_type: &str, room: &str, sender: &str, message: &str) -> String {
        activity_body_with_id(event_type, room, sender, "msg-42", message)
    }

    fn activity_body_with_id(
        event_type: &str,
        room: &str,
        sender: &str,
        message_id: &str,
        message: &str,
    ) -> String {
        json!({
            "type": event_type,
            "actor": {
                "type": "Person",
                "id": sender,
                "name": "Alice"
            },
            "object": {
                "type": "Note",
                "id": message_id,
                "name": "fallback text",
                "content": message,
                "mediaType": "text/plain"
            },
            "target": {
                "type": "Collection",
                "id": room,
                "name": "Engineering"
            }
        })
        .to_string()
    }

    fn nextcloud_signature(signing_material: &str, random: &str, body: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(signing_material.as_bytes()).expect("HMAC accepts test key");
        mac.update(random.as_bytes());
        mac.update(body.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn signed_webhook_input(signing_material: &str, body: &str) -> serde_json::Value {
        let random = "random-nonce-123";
        json!({
            "headers": {
                "X-Nextcloud-Talk-Signature": nextcloud_signature(signing_material, random, body),
                "X-Nextcloud-Talk-Random": random,
                "X-Nextcloud-Talk-Backend": "https://cloud.example.com"
            },
            "body": body,
            "body_size_bytes": 512,
            "body_read_elapsed_ms": 10,
            "source_id": "loopback-forwarder",
            "delivery_id": "delivery-1"
        })
    }

    async fn configured_webhook_connector(
        config: serde_json::Value,
    ) -> (NextcloudTalkConnector, Ed25519SigningKey) {
        let mut connector = NextcloudTalkConnector::new();
        connector.configure(config).await.expect("configure");
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.expect("handshake");
        (connector, signing_key)
    }

    fn webhook_config(signing_material: &str) -> serde_json::Value {
        json!({
            "server_url": "https://cloud.example.com",
            "account_id": "work",
            "auth": {
                "mode": "credential_id",
                "credential_id": "ocs_cred"
            },
            "webhook": {
                "enabled": true,
                "bot_secret": {
                    "source": "inline",
                    "secret": signing_material
                },
                "backend_allowlist": ["https://cloud.example.com"],
                "auth_failure_limit_per_minute": 1,
                "sender_limit_per_minute": 10,
                "replay_ttl_secs": 60,
                "replay_max_entries": 16
            },
            "inbound_policy": {
                "dm_policy": "pairing",
                "group_policy": "allowlist",
                "group_allow_from": ["alice"],
                "rooms": ["room123"],
                "mention_required_rooms": ["room123"]
            }
        })
    }

    fn operation<'a>(manifest: &'a TomlValue, id: &str) -> &'a TomlValue {
        manifest
            .get("provides")
            .and_then(|provides| provides.get("operations"))
            .and_then(|operations| operations.get(id))
            .unwrap_or_else(|| panic!("{id} operation should exist"))
    }

    fn network_constraints<'a>(manifest: &'a TomlValue, id: &str) -> &'a TomlValue {
        operation(manifest, id)
            .get("network_constraints")
            .unwrap_or_else(|| panic!("{id} should declare network_constraints"))
    }

    fn string_array<'a>(constraints: &'a TomlValue, field: &str) -> Vec<&'a str> {
        constraints
            .get(field)
            .and_then(TomlValue::as_array)
            .unwrap_or_else(|| panic!("network_constraints.{field} should be an array"))
            .iter()
            .map(|entry| {
                entry.as_str().unwrap_or_else(|| {
                    panic!("network_constraints.{field} entries should be strings")
                })
            })
            .collect()
    }

    fn integer_array(constraints: &TomlValue, field: &str) -> Vec<i64> {
        constraints
            .get(field)
            .and_then(TomlValue::as_array)
            .unwrap_or_else(|| panic!("network_constraints.{field} should be an array"))
            .iter()
            .map(|entry| {
                entry.as_integer().unwrap_or_else(|| {
                    panic!("network_constraints.{field} entries should be integers")
                })
            })
            .collect()
    }

    fn bool_field(constraints: &TomlValue, field: &str) -> bool {
        constraints
            .get(field)
            .and_then(TomlValue::as_bool)
            .unwrap_or_else(|| panic!("network_constraints.{field} should be a bool"))
    }

    fn integer_field(constraints: &TomlValue, field: &str) -> i64 {
        constraints
            .get(field)
            .and_then(TomlValue::as_integer)
            .unwrap_or_else(|| panic!("network_constraints.{field} should be an integer"))
    }

    fn assert_nextcloud_server_network_constraints(id: &str, constraints: &TomlValue) {
        assert_eq!(
            string_array(constraints, "host_allow"),
            vec![NEXTCLOUD_SERVER_HOST_PLACEHOLDER],
            "{id} should only allow the configured Nextcloud server host"
        );
        assert_eq!(
            integer_array(constraints, "port_allow"),
            vec![80, 443],
            "{id}"
        );
        assert!(
            bool_field(constraints, "require_sni"),
            "{id} should require SNI"
        );
        assert!(
            bool_field(constraints, "deny_localhost"),
            "{id} should deny localhost"
        );
        assert!(
            bool_field(constraints, "deny_private_ranges"),
            "{id} should deny private ranges by default"
        );
        assert!(
            bool_field(constraints, "deny_tailnet_ranges"),
            "{id} should deny tailnet ranges by default"
        );
        assert!(
            !bool_field(constraints, "deny_ip_literals"),
            "{id} should preserve operator-configured public IP deployments"
        );
        assert!(
            bool_field(constraints, "require_host_canonicalization"),
            "{id} should canonicalize the configured host"
        );
        assert_eq!(integer_field(constraints, "dns_max_ips"), 16, "{id}");
        assert_eq!(integer_field(constraints, "max_redirects"), 5, "{id}");
        assert_eq!(
            integer_field(constraints, "connect_timeout_ms"),
            10_000,
            "{id}"
        );
        assert_eq!(
            integer_field(constraints, "max_response_bytes"),
            10_485_760,
            "{id}"
        );
    }

    fn assert_no_connector_egress_network_constraints(id: &str, constraints: &TomlValue) {
        assert_eq!(
            string_array(constraints, "host_allow"),
            vec!["none.invalid"],
            "{id}"
        );
        assert_eq!(integer_array(constraints, "port_allow"), vec![0], "{id}");
        assert!(string_array(constraints, "ip_allow").is_empty(), "{id}");
        assert!(string_array(constraints, "cidr_deny").is_empty(), "{id}");
        assert!(!bool_field(constraints, "require_sni"), "{id}");
        assert!(string_array(constraints, "spki_pins").is_empty(), "{id}");
        assert!(bool_field(constraints, "deny_localhost"), "{id}");
        assert!(bool_field(constraints, "deny_private_ranges"), "{id}");
        assert!(bool_field(constraints, "deny_tailnet_ranges"), "{id}");
        assert!(bool_field(constraints, "deny_ip_literals"), "{id}");
        assert!(
            bool_field(constraints, "require_host_canonicalization"),
            "{id}"
        );
        assert_eq!(integer_field(constraints, "dns_max_ips"), 0, "{id}");
        assert_eq!(integer_field(constraints, "max_redirects"), 0, "{id}");
        assert_eq!(
            integer_field(constraints, "connect_timeout_ms"),
            1_000,
            "{id}"
        );
        assert_eq!(
            integer_field(constraints, "total_timeout_ms"),
            1_000,
            "{id}"
        );
        assert_eq!(
            integer_field(constraints, "max_response_bytes"),
            1_048_576,
            "{id}"
        );
    }

    fn git_revision() -> String {
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|stdout| stdout.trim().to_string())
            .filter(|revision| !revision.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn webhook_evidence_record(
        scenario: &str,
        account_id: &str,
        room_token: &str,
        message_id: &str,
        latency_ms: u128,
        result: Result<&Value, &FcpError>,
        skip_reason: Option<&str>,
    ) -> Value {
        let (status, signature_decision, replay_decision, policy_decision, event_id, error) =
            match result {
                Ok(value) => (
                    value["status"].clone(),
                    value["signature"]["decision"].clone(),
                    value["replay"]["decision"].clone(),
                    value["policy"]["decision"].clone(),
                    value["event"]["delivery_id"].clone(),
                    Value::Null,
                ),
                Err(error) => (
                    Value::String("error".to_string()),
                    Value::String("error_before_or_during_verification".to_string()),
                    Value::String("not_committed".to_string()),
                    Value::String("error".to_string()),
                    Value::Null,
                    Value::String(error.to_string()),
                ),
            };
        json!({
            "record_type": "nextcloud_talk_host_forwarded_webhook_e2e",
            "scenario": scenario,
            "command_line": std::env::args().collect::<Vec<_>>().join(" "),
            "git_revision": git_revision(),
            "account_id_hash": hash_identifier(account_id),
            "room_token_hash": hash_identifier(room_token),
            "message_id": message_id,
            "signature_decision": signature_decision,
            "replay_decision": replay_decision,
            "policy_decision": policy_decision,
            "status": status,
            "event_id": event_id,
            "latency_ms": latency_ms,
            "cleanup": {
                "hosted_listener": false,
                "replay_workers": 0,
                "shutdown_required": false
            },
            "skip_reason": skip_reason,
            "error": error,
        })
    }

    fn encode_jsonl(records: &[Value]) -> String {
        records
            .iter()
            .map(|record| serde_json::to_string(record).expect("serialize webhook evidence"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn maybe_write_webhook_jsonl(jsonl: &str) {
        if let Some(path) = std::env::var_os("NEXTCLOUD_TALK_WEBHOOK_E2E_JSONL_OUT") {
            std::fs::write(path, jsonl).expect("write webhook evidence JSONL");
        }
    }

    #[test]
    fn manifest_declares_per_operation_network_constraints() {
        let manifest: TomlValue =
            toml::from_str(MANIFEST_TOML).expect("Nextcloud Talk manifest should parse as TOML");
        let operation_count = manifest
            .get("provides")
            .and_then(|provides| provides.get("operations"))
            .and_then(TomlValue::as_table)
            .expect("provides.operations should be a table")
            .len();
        assert_eq!(operation_count, 17);

        for operation_id in NEXTCLOUD_SERVER_EGRESS_OPS {
            let constraints = network_constraints(&manifest, operation_id);
            assert_nextcloud_server_network_constraints(operation_id, constraints);
            let expected_timeout = match *operation_id {
                OP_GET_MESSAGES | OP_POLL_CONVERSATION_EVENTS => 70_000,
                _ => 30_000,
            };
            assert_eq!(
                integer_field(constraints, "total_timeout_ms"),
                expected_timeout,
                "{operation_id}"
            );
        }

        let ingest = network_constraints(&manifest, OP_INGEST_WEBHOOK);
        assert_no_connector_egress_network_constraints(OP_INGEST_WEBHOOK, ingest);
    }

    #[test]
    fn doctor_before_configure_fails() {
        let connector = NextcloudTalkConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "configuration")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_updates_doctor_state() {
        let mut connector = NextcloudTalkConnector::new();
        connector
            .configure(json!({
                "server_url": "https://cloud.example.com",
                "auth": {
                    "mode": "credential_id",
                    "credential_id": "cred_123"
                }
            }))
            .await
            .expect("configure");

        let report = connector.doctor();
        assert!(report.passed);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "ocs_auth_source")
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "webhook_readiness")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_reports_webhook_setup_without_secret_leak() {
        let mut connector = NextcloudTalkConnector::new();
        connector
            .configure(json!({
                "server_url": "https://cloud.example.com",
                "auth": {
                    "mode": "credential_id",
                    "credential_id": "ocs_cred"
                },
                "account_id": "work",
                "account_name": "Work Talk",
                "webhook": {
                    "enabled": true,
                    "bot_secret": {
                        "source": "inline",
                        "secret": "super-private-webhook-material"
                    },
                    "backend_allowlist": ["https://cloud.example.com"]
                },
                "inbound_policy": {
                    "dm_policy": "allowlist",
                    "allow_from": ["alice"],
                    "rooms": ["engineering"]
                }
            }))
            .await
            .expect("configure");

        let report = connector.doctor();
        let encoded = serde_json::to_string(&report).expect("doctor json");
        assert!(report.passed);
        assert!(encoded.contains("webhook_ready"));
        assert!(encoded.contains("sha256:"));
        assert!(!encoded.contains("super-private-webhook-material"));
        assert!(report.checks.iter().any(|check| {
            check.name == "webhook_readiness"
                && check
                    .message
                    .as_deref()
                    .is_some_and(|m| m.contains("bot secret source: inline"))
        }));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_requires_configuration() {
        let connector = NextcloudTalkConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let grant = generate_valid_token(
            &signing_key,
            CAP_READ,
            &[OP_HEALTH],
            &connector.base.instance_id,
        );
        let response = connector
            .simulate(base_simulate(connector.id(), OP_HEALTH, grant))
            .await
            .expect("simulate");

        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotConfigured.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_checks_bound_capability_token() {
        let server = MockServer::start().await;
        let mut connector = NextcloudTalkConnector::new();
        connector
            .configure(json!({
                "server_url": server.uri(),
                "auth": {
                    "mode": "bearer_token",
                    "access_token": "oauth-test-material"
                },
                "network": { "allow_private_networks": true }
            }))
            .await
            .expect("configure");
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.expect("handshake");

        let grant = generate_valid_token(
            &signing_key,
            CAP_READ,
            &[OP_SEND_MESSAGE],
            &connector.base.instance_id,
        );
        let response = connector
            .simulate(base_simulate(connector.id(), OP_SEND_MESSAGE, grant))
            .await
            .expect("simulate");

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-3003"));
        assert!(response.missing_capabilities.is_empty());
    }

    #[test]
    fn introspect_exposes_health_operation() {
        let connector = NextcloudTalkConnector::new();
        let introspection = connector.introspect();
        let operations = introspection.operations;
        assert_eq!(operations.len(), 17);
        assert!(operations.iter().any(|op| op.id.as_str() == OP_HEALTH));
        assert!(
            operations
                .iter()
                .any(|op| op.id.as_str() == OP_SEND_MESSAGE)
        );
        assert!(
            operations
                .iter()
                .any(|op| op.id.as_str() == OP_POLL_CONVERSATION_EVENTS)
        );
        assert!(
            operations
                .iter()
                .any(|op| op.id.as_str() == OP_INGEST_WEBHOOK)
        );
        assert!(introspection.event_caps.expect("event caps").replay);
        assert_eq!(introspection.events[0].topic, EVENT_WEBHOOK_MESSAGE);
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_ingest_valid_signature_emits_event_and_dedupes() {
        let signing_material = "webhook-shared-material";
        let (connector, signing_key) =
            configured_webhook_connector(webhook_config(signing_material)).await;
        let body = activity_body("Create", "room123", "alice", "hello @flywheel");
        let input = signed_webhook_input(signing_material, &body);

        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                input.clone(),
            ))
            .await
            .expect("webhook ingest");
        let result = response.result.as_ref().expect("webhook result");
        assert_eq!(result["status"], "processed");
        assert_eq!(result["event"]["topic"], EVENT_WEBHOOK_MESSAGE);
        assert_eq!(result["event"]["signature"]["decision"], "verified");
        assert_eq!(result["event"]["replay"]["decision"], "claimed");
        assert_eq!(result["event"]["policy"]["decision"], "allowed");
        assert!(
            !serde_json::to_string(result)
                .expect("result json")
                .contains(signing_material)
        );

        let duplicate_grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let duplicate = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                duplicate_grant,
                input,
            ))
            .await
            .expect("duplicate webhook ingest");
        let duplicate_result = duplicate.result.as_ref().expect("duplicate result");
        assert_eq!(duplicate_result["status"], "duplicate");
        assert!(duplicate_result["event"].is_null());
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_ingest_rejects_missing_headers_bad_backend_and_bad_signature() {
        let signing_material = "webhook-shared-material";
        let (connector, signing_key) =
            configured_webhook_connector(webhook_config(signing_material)).await;
        let body = activity_body("Create", "room123", "alice", "hello @flywheel");
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let missing_headers = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                json!({ "headers": {}, "body": body }),
            ))
            .await
            .expect_err("missing headers reject");
        assert!(matches!(missing_headers, FcpError::InvalidRequest { .. }));

        let body = activity_body("Create", "room123", "alice", "hello @flywheel");
        let mut bad_backend = signed_webhook_input(signing_material, &body);
        bad_backend["headers"]["X-Nextcloud-Talk-Backend"] = json!("https://evil.example.com");
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let backend_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                bad_backend,
            ))
            .await
            .expect_err("backend reject");
        assert!(matches!(backend_error, FcpError::Unauthorized { .. }));

        let mut bad_signature = signed_webhook_input(signing_material, &body);
        bad_signature["headers"]["X-Nextcloud-Talk-Signature"] = json!("00");
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let signature_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                bad_signature.clone(),
            ))
            .await
            .expect_err("bad signature reject");
        assert!(matches!(signature_error, FcpError::Unauthorized { .. }));

        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let rate_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                bad_signature,
            ))
            .await
            .expect_err("bad signature rate limited");
        assert!(matches!(rate_error, FcpError::RateLimited { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_ingest_enforces_body_budgets_and_payload_shape() {
        let signing_material = "webhook-shared-material";
        let (connector, signing_key) =
            configured_webhook_connector(webhook_config(signing_material)).await;
        let body = activity_body("Create", "room123", "alice", "hello @flywheel");
        let mut oversized = signed_webhook_input(signing_material, &body);
        oversized["body_size_bytes"] = json!(2_000_000);
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let size_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                oversized,
            ))
            .await
            .expect_err("oversized body reject");
        assert!(matches!(size_error, FcpError::ResourceExhausted { .. }));

        let mut timed_out = signed_webhook_input(signing_material, &body);
        timed_out["body_read_elapsed_ms"] = json!(10_000);
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let timeout_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                timed_out,
            ))
            .await
            .expect_err("body timeout reject");
        assert!(matches!(timeout_error, FcpError::UpstreamTimeout { .. }));

        let malformed_body = "{not-json";
        let random = "random-nonce-123";
        let malformed = json!({
            "headers": {
                "X-Nextcloud-Talk-Signature": nextcloud_signature(signing_material, random, malformed_body),
                "X-Nextcloud-Talk-Random": random,
                "X-Nextcloud-Talk-Backend": "https://cloud.example.com"
            },
            "body": malformed_body
        });
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let json_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                malformed,
            ))
            .await
            .expect_err("malformed JSON reject");
        assert!(matches!(json_error, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_ingest_handles_non_create_pairing_policy_and_group_denials() {
        let signing_material = "webhook-shared-material";
        let (connector, signing_key) =
            configured_webhook_connector(webhook_config(signing_material)).await;
        let update = signed_webhook_input(
            signing_material,
            &activity_body("Update", "room123", "alice", "hello @flywheel"),
        );
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                update,
            ))
            .await
            .expect("non-create ignored");
        assert_eq!(
            response.result.as_ref().expect("result")["status"],
            "ignored"
        );

        let dm = signed_webhook_input(
            signing_material,
            &activity_body("Create", "room-dm", "alice", "hello privately"),
        );
        let mut dm = dm;
        dm["room_kind"] = json!("dm");
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(connector.id(), OP_INGEST_WEBHOOK, grant, dm))
            .await
            .expect("DM pairing challenge");
        let result = response.result.as_ref().expect("dm result");
        assert_eq!(result["status"], "pairing_required");
        assert!(result["event"].is_null());

        let denied_room = signed_webhook_input(
            signing_material,
            &activity_body("Create", "unlisted", "alice", "hello @flywheel"),
        );
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let room_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                denied_room,
            ))
            .await
            .expect_err("room denied");
        assert!(matches!(room_error, FcpError::Unauthorized { .. }));

        let missing_mention = signed_webhook_input(
            signing_material,
            &activity_body_with_id(
                "Create",
                "room123",
                "alice",
                "msg-44",
                "hello without mention",
            ),
        );
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let mention_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                missing_mention,
            ))
            .await
            .expect_err("mention denied");
        assert!(matches!(mention_error, FcpError::Unauthorized { .. }));

        let command = signed_webhook_input(
            signing_material,
            &activity_body_with_id("Create", "room123", "alice", "msg-45", "/deploy @flywheel"),
        );
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let command_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                command,
            ))
            .await
            .expect_err("command denied");
        assert!(matches!(command_error, FcpError::Unauthorized { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_replay_releases_retryable_and_commits_nonretryable_dispatch_results() {
        let signing_material = "webhook-shared-material";
        let (connector, signing_key) =
            configured_webhook_connector(webhook_config(signing_material)).await;
        let body = activity_body("Create", "room123", "alice", "hello @flywheel");
        let mut retryable = signed_webhook_input(signing_material, &body);
        retryable["dispatch_outcome"] = json!("retryable_error");
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let retryable_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                retryable,
            ))
            .await
            .expect_err("retryable dispatch error");
        assert!(matches!(
            retryable_error,
            FcpError::External {
                retryable: true,
                ..
            }
        ));

        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                signed_webhook_input(signing_material, &body),
            ))
            .await
            .expect("released replay can process");
        assert_eq!(
            response.result.as_ref().expect("result")["status"],
            "processed"
        );

        let nonretry_body =
            activity_body_with_id("Create", "room123", "alice", "msg-43", "again @flywheel");
        let mut nonretryable = signed_webhook_input(signing_material, &nonretry_body);
        nonretryable["dispatch_outcome"] = json!("nonretryable_error");
        nonretryable["delivery_id"] = json!("delivery-2");
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let nonretry_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                nonretryable,
            ))
            .await
            .expect_err("nonretryable dispatch error");
        assert!(matches!(
            nonretry_error,
            FcpError::External {
                retryable: false,
                ..
            }
        ));

        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let duplicate = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                signed_webhook_input(signing_material, &nonretry_body),
            ))
            .await
            .expect("committed nonretryable replay should dedupe");
        assert_eq!(
            duplicate.result.as_ref().expect("duplicate")["status"],
            "duplicate"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_ingest_no_mock_evidence_jsonl_covers_forwarded_ingress() {
        let signing_material = "webhook-shared-material";
        let (connector, signing_key) =
            configured_webhook_connector(webhook_config(signing_material)).await;
        let mut records = Vec::new();

        let scenarios = [
            (
                "success",
                "room123",
                "msg-100",
                signed_webhook_input(
                    signing_material,
                    &activity_body_with_id(
                        "Create",
                        "room123",
                        "alice",
                        "msg-100",
                        "hello @flywheel",
                    ),
                ),
            ),
            (
                "missing_headers",
                "room123",
                "msg-101",
                json!({
                    "headers": {},
                    "body": activity_body_with_id(
                        "Create",
                        "room123",
                        "alice",
                        "msg-101",
                        "hello @flywheel",
                    )
                }),
            ),
            ("malformed_payload", "room123", "msg-102", {
                let body = "{not-json";
                let random = "random-nonce-123";
                json!({
                    "headers": {
                        "X-Nextcloud-Talk-Signature": nextcloud_signature(signing_material, random, body),
                        "X-Nextcloud-Talk-Random": random,
                        "X-Nextcloud-Talk-Backend": "https://cloud.example.com"
                    },
                    "body": body
                })
            }),
            (
                "disallowed_room",
                "blocked-room",
                "msg-103",
                signed_webhook_input(
                    signing_material,
                    &activity_body_with_id(
                        "Create",
                        "blocked-room",
                        "alice",
                        "msg-103",
                        "hello @flywheel",
                    ),
                ),
            ),
            (
                "missing_mention",
                "room123",
                "msg-104",
                signed_webhook_input(
                    signing_material,
                    &activity_body_with_id(
                        "Create",
                        "room123",
                        "alice",
                        "msg-104",
                        "hello without mention",
                    ),
                ),
            ),
            ("pairing_challenge", "room-dm", "msg-105", {
                let mut input = signed_webhook_input(
                    signing_material,
                    &activity_body_with_id(
                        "Create",
                        "room-dm",
                        "alice",
                        "msg-105",
                        "hello privately",
                    ),
                );
                input["room_kind"] = json!("dm");
                input
            }),
            ("timeout", "room123", "msg-106", {
                let mut input = signed_webhook_input(
                    signing_material,
                    &activity_body_with_id(
                        "Create",
                        "room123",
                        "alice",
                        "msg-106",
                        "hello @flywheel",
                    ),
                );
                input["body_read_elapsed_ms"] = json!(10_000);
                input
            }),
        ];

        for (scenario, room_token, message_id, input) in scenarios {
            let grant = generate_valid_token(
                &signing_key,
                CAP_WEBHOOK,
                &[OP_INGEST_WEBHOOK],
                &connector.base.instance_id,
            );
            let start = std::time::Instant::now();
            let response = connector
                .invoke(base_invoke(connector.id(), OP_INGEST_WEBHOOK, grant, input))
                .await;
            let latency_ms = start.elapsed().as_millis();
            let record = match response {
                Ok(response) => {
                    let value = response.result.as_ref().expect("webhook result");
                    webhook_evidence_record(
                        scenario,
                        "work",
                        room_token,
                        message_id,
                        latency_ms,
                        Ok(value),
                        None,
                    )
                }
                Err(error) => webhook_evidence_record(
                    scenario,
                    "work",
                    room_token,
                    message_id,
                    latency_ms,
                    Err(&error),
                    None,
                ),
            };
            records.push(record);
        }

        let duplicate_input = signed_webhook_input(
            signing_material,
            &activity_body_with_id("Create", "room123", "alice", "msg-100", "hello @flywheel"),
        );
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let start = std::time::Instant::now();
        let duplicate = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                duplicate_input,
            ))
            .await
            .expect("duplicate evidence invoke");
        records.push(webhook_evidence_record(
            "duplicate_replay",
            "work",
            "room123",
            "msg-100",
            start.elapsed().as_millis(),
            Ok(duplicate.result.as_ref().expect("duplicate result")),
            None,
        ));

        let mut bad_signature = signed_webhook_input(
            signing_material,
            &activity_body_with_id("Create", "room123", "alice", "msg-107", "hello @flywheel"),
        );
        bad_signature["headers"]["X-Nextcloud-Talk-Signature"] = json!("00");
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let start = std::time::Instant::now();
        let signature_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                bad_signature,
            ))
            .await
            .expect_err("bad signature evidence");
        records.push(webhook_evidence_record(
            "bad_signature",
            "work",
            "room123",
            "msg-107",
            start.elapsed().as_millis(),
            Err(&signature_error),
            None,
        ));

        let mut invalid_backend = signed_webhook_input(
            signing_material,
            &activity_body_with_id("Create", "room123", "alice", "msg-108", "hello @flywheel"),
        );
        invalid_backend["headers"]["X-Nextcloud-Talk-Backend"] = json!("https://evil.example.com");
        let grant = generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_INGEST_WEBHOOK],
            &connector.base.instance_id,
        );
        let start = std::time::Instant::now();
        let backend_error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_INGEST_WEBHOOK,
                grant,
                invalid_backend,
            ))
            .await
            .expect_err("invalid backend evidence");
        records.push(webhook_evidence_record(
            "invalid_backend",
            "work",
            "room123",
            "msg-108",
            start.elapsed().as_millis(),
            Err(&backend_error),
            None,
        ));

        let jsonl = encode_jsonl(&records);
        assert!(!jsonl.trim().is_empty());
        assert!(!jsonl.contains(signing_material));
        assert!(jsonl.contains("nextcloud_talk_host_forwarded_webhook_e2e"));
        assert!(jsonl.contains("duplicate_replay"));
        assert!(jsonl.contains("pairing_challenge"));
        for line in jsonl.lines() {
            let value: Value = serde_json::from_str(line).expect("JSONL line should parse");
            assert_eq!(
                value["record_type"],
                "nextcloud_talk_host_forwarded_webhook_e2e"
            );
            assert!(
                value["command_line"]
                    .as_str()
                    .is_some_and(|line| !line.is_empty())
            );
            assert!(
                value["git_revision"]
                    .as_str()
                    .is_some_and(|revision| !revision.is_empty())
            );
            assert!(
                value["account_id_hash"]
                    .as_str()
                    .is_some_and(|hash| hash.starts_with("sha256:"))
            );
            assert!(
                value["room_token_hash"]
                    .as_str()
                    .is_some_and(|hash| hash.starts_with("sha256:"))
            );
            assert!(value.get("signature_decision").is_some());
            assert!(value.get("replay_decision").is_some());
            assert!(value.get("policy_decision").is_some());
            assert!(value.get("event_id").is_some());
            assert!(value.get("latency_ms").is_some());
            assert!(value.get("cleanup").is_some());
            assert!(value.get("skip_reason").is_some());
        }
        maybe_write_webhook_jsonl(&jsonl);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_uses_capabilities_probe() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ocs/v1.php/cloud/capabilities"))
            .and(query_param("format", "json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ocs": {
                    "meta": {
                        "status": "ok",
                        "statuscode": 100,
                        "message": "OK"
                    },
                    "data": {
                        "version": {
                            "major": 29,
                            "minor": 0,
                            "micro": 0,
                            "string": "29.0.0"
                        },
                        "capabilities": {
                            "spreed": {
                                "features": ["chat-read-marker", "reactions"],
                                "config": {
                                    "chat": {
                                        "max-length": 32000
                                    }
                                }
                            }
                        }
                    }
                }
            })))
            .mount(&server)
            .await;

        let mut connector = NextcloudTalkConnector::new();
        connector
            .configure(json!({
                "server_url": server.uri(),
                "auth": {
                    "mode": "bearer_token",
                    "access_token": "oidc"
                },
                "network": { "allow_private_networks": true }
            }))
            .await
            .expect("configure");
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.expect("handshake");

        let grant = generate_valid_token(
            &signing_key,
            CAP_READ,
            &[OP_HEALTH],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(connector.id(), OP_HEALTH, grant, json!({})))
            .await
            .expect("invoke");

        assert_eq!(response.status, InvokeStatus::Ok);
        let result = response.result.as_ref().expect("invoke result");
        assert_eq!(result["version"], "29.0.0");
        assert_eq!(result["has_talk"], true);
        assert_eq!(result["features"][0], "chat-read-marker");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_list_conversations_returns_conversations() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ocs/v2.php/apps/spreed/api/v4/room"))
            .and(query_param("format", "json"))
            .and(query_param("includeStatus", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ocs": {
                    "meta": {
                        "status": "ok",
                        "statuscode": 100,
                        "message": "OK"
                    },
                    "data": [
                        {
                            "token": "room123",
                            "type": 2,
                            "displayName": "Engineering",
                            "unreadMessages": 3
                        }
                    ]
                }
            })))
            .mount(&server)
            .await;

        let mut connector = NextcloudTalkConnector::new();
        connector
            .configure(json!({
                "server_url": server.uri(),
                "auth": {
                    "mode": "app_password",
                    "username": "alice",
                    "app_password": "app-material"
                },
                "network": { "allow_private_networks": true }
            }))
            .await
            .expect("configure");
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.expect("handshake");

        let grant = generate_valid_token(
            &signing_key,
            CAP_READ,
            &[OP_LIST_CONVERSATIONS],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(
                connector.id(),
                OP_LIST_CONVERSATIONS,
                grant,
                json!({ "include_status": true }),
            ))
            .await
            .expect("invoke");

        assert_eq!(response.status, InvokeStatus::Ok);
        let result = response.result.as_ref().expect("invoke result");
        assert_eq!(result["conversations"][0]["token"], "room123");
        assert_eq!(result["conversations"][0]["displayName"], "Engineering");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_send_message_returns_chat_message() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
            .and(query_param("format", "json"))
            .and(body_string_contains("message=hello+world"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ocs": {
                    "meta": {
                        "status": "ok",
                        "statuscode": 100,
                        "message": "OK"
                    },
                    "data": {
                        "id": 42,
                        "token": "room123",
                        "actorType": "users",
                        "actorId": "alice",
                        "actorDisplayName": "Alice",
                        "timestamp": 1_710_000_000u64,
                        "systemMessage": "",
                        "messageType": "comment",
                        "message": "hello world",
                        "messageParameters": {},
                        "reactions": {},
                        "reactionsSelf": []
                    }
                }
            })))
            .mount(&server)
            .await;

        let mut connector = NextcloudTalkConnector::new();
        connector
            .configure(json!({
                "server_url": server.uri(),
                "auth": {
                    "mode": "app_password",
                    "username": "alice",
                    "app_password": "app-material"
                },
                "network": { "allow_private_networks": true }
            }))
            .await
            .expect("configure");
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.expect("handshake");

        let grant = generate_valid_token(
            &signing_key,
            CAP_WRITE,
            &[OP_SEND_MESSAGE],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(
                connector.id(),
                OP_SEND_MESSAGE,
                grant,
                json!({
                    "token": "room123",
                    "message": "hello world",
                    "silent": true
                }),
            ))
            .await
            .expect("invoke");

        assert_eq!(response.status, InvokeStatus::Ok);
        let result = response.result.as_ref().expect("invoke result");
        assert_eq!(result["message"]["id"], 42);
        assert_eq!(result["message"]["message"], "hello world");
        let coordination = result["coordination"]
            .as_array()
            .expect("coordination audit records");
        assert_eq!(coordination[0]["event"], "claim_attempt");
        assert_eq!(coordination[1]["event"], "claim_outcome");
        assert_eq!(coordination[1]["outcome"], "granted");
        assert_eq!(coordination[2]["event"], "send_executed");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_send_message_denies_duplicate_owner_before_http_post() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
            .and(query_param("format", "json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ocs": {
                    "meta": {
                        "status": "ok",
                        "statuscode": 100,
                        "message": "OK"
                    },
                    "data": {}
                }
            })))
            .expect(0)
            .mount(&server)
            .await;

        let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
        let mut connector =
            NextcloudTalkConnector::new().with_thread_ownership_checker(checker.clone());
        connector
            .configure(json!({
                "server_url": server.uri(),
                "auth": {
                    "mode": "app_password",
                    "username": "alice",
                    "app_password": "app-material"
                },
                "network": { "allow_private_networks": true }
            }))
            .await
            .expect("configure");
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.expect("handshake");

        let claim_key = ClaimKey::new(
            ZoneId::work(),
            connector.base.id.clone(),
            ChannelId::new("room123"),
            ThreadId::new("reply_to:41"),
        );
        checker.claim_now(claim_key, AgentId::new("peer-agent"), Instant::now());

        let grant = generate_valid_token(
            &signing_key,
            CAP_WRITE,
            &[OP_SEND_MESSAGE],
            &connector.base.instance_id,
        );
        let error = connector
            .invoke(base_invoke(
                connector.id(),
                OP_SEND_MESSAGE,
                grant,
                json!({
                    "token": "room123",
                    "message": "duplicate owner should block this send",
                    "reply_to": 41
                }),
            ))
            .await
            .expect_err("duplicate owner should be denied before HTTP POST");

        assert!(matches!(error, FcpError::Unauthorized { code: 4090, .. }));
        if let FcpError::Unauthorized { message, .. } = error {
            assert!(message.contains("thread_owned_by_peer:peer-agent"));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_delete_message_returns_deleted_system_message() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123/42"))
            .and(query_param("format", "json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ocs": {
                    "meta": {
                        "status": "ok",
                        "statuscode": 100,
                        "message": "OK"
                    },
                    "data": {
                        "id": 43,
                        "token": "room123",
                        "actorType": "users",
                        "actorId": "alice",
                        "actorDisplayName": "Alice",
                        "timestamp": 1_710_000_100u64,
                        "systemMessage": "message_deleted",
                        "messageType": "system",
                        "message": "",
                        "messageParameters": {},
                        "parent": {
                            "id": 42,
                            "message": "Message deleted by you"
                        },
                        "reactions": {},
                        "reactionsSelf": []
                    }
                }
            })))
            .mount(&server)
            .await;

        let mut connector = NextcloudTalkConnector::new();
        connector
            .configure(json!({
                "server_url": server.uri(),
                "auth": {
                    "mode": "app_password",
                    "username": "alice",
                    "app_password": "app-material"
                },
                "network": { "allow_private_networks": true }
            }))
            .await
            .expect("configure");
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.expect("handshake");

        let grant = generate_valid_token(
            &signing_key,
            CAP_MANAGE,
            &[OP_DELETE_MESSAGE],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(
                connector.id(),
                OP_DELETE_MESSAGE,
                grant,
                json!({
                    "token": "room123",
                    "message_id": 42
                }),
            ))
            .await
            .expect("invoke");

        assert_eq!(response.status, InvokeStatus::Ok);
        let result = response.result.as_ref().expect("invoke result");
        assert_eq!(result["message"]["id"], 43);
        assert_eq!(result["message"]["systemMessage"], "message_deleted");
        assert_eq!(result["message"]["parent"]["id"], 42);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_get_messages_uses_configured_long_poll_timeout_by_default() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
            .and(query_param("format", "json"))
            .and(query_param("lookIntoFuture", "1"))
            .and(query_param("timeout", "17"))
            .and(query_param("setReadMarker", "1"))
            .and(query_param("includeLastKnown", "0"))
            .and(query_param("noStatusUpdate", "0"))
            .and(query_param("markNotificationsAsRead", "1"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;

        let mut connector = NextcloudTalkConnector::new();
        connector
            .configure(json!({
                "server_url": server.uri(),
                "auth": {
                    "mode": "bearer_token",
                    "access_token": "oidc"
                },
                "long_poll_timeout_secs": 17,
                "network": { "allow_private_networks": true }
            }))
            .await
            .expect("configure");
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.expect("handshake");

        let grant = generate_valid_token(
            &signing_key,
            CAP_READ,
            &[OP_GET_MESSAGES],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(
                connector.id(),
                OP_GET_MESSAGES,
                grant,
                json!({
                    "token": "room123",
                    "look_into_future": true
                }),
            ))
            .await
            .expect("invoke");

        assert_eq!(response.status, InvokeStatus::Ok);
        let result = response.result.as_ref().expect("invoke result");
        assert_eq!(result["messages"], json!([]));
        assert_eq!(result["not_modified"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn poll_conversation_events_returns_event_envelopes_and_cursor() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
            .and(query_param("format", "json"))
            .and(query_param("lookIntoFuture", "1"))
            .and(query_param("timeout", "11"))
            .and(query_param("setReadMarker", "0"))
            .and(query_param("includeLastKnown", "0"))
            .and(query_param("noStatusUpdate", "1"))
            .and(query_param("markNotificationsAsRead", "0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Chat-Last-Given", "42")
                    .insert_header("X-Chat-Last-Common-Read", "41")
                    .set_body_json(json!({
                        "ocs": {
                            "meta": {
                                "status": "ok",
                                "statuscode": 100,
                                "message": "OK"
                            },
                            "data": [
                                {
                                    "id": 42,
                                    "token": "room123",
                                    "actorType": "users",
                                    "actorId": "alice",
                                    "actorDisplayName": "Alice",
                                    "timestamp": 1_710_000_200u64,
                                    "systemMessage": "",
                                    "messageType": "comment",
                                    "message": "hello from poll",
                                    "messageParameters": {},
                                    "reactions": {},
                                    "reactionsSelf": []
                                }
                            ]
                        }
                    })),
            )
            .mount(&server)
            .await;

        let mut connector = NextcloudTalkConnector::new();
        connector
            .configure(json!({
                "server_url": server.uri(),
                "auth": {
                    "mode": "bearer_token",
                    "access_token": "oidc"
                },
                "long_poll_timeout_secs": 11,
                "network": { "allow_private_networks": true }
            }))
            .await
            .expect("configure");
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.expect("handshake");

        let grant = generate_valid_token(
            &signing_key,
            CAP_READ,
            &[OP_POLL_CONVERSATION_EVENTS],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(
                connector.id(),
                OP_POLL_CONVERSATION_EVENTS,
                grant,
                json!({
                    "token": "room123",
                    "look_into_future": true
                }),
            ))
            .await
            .expect("invoke");

        assert_eq!(response.status, InvokeStatus::Ok);
        let result = response.result.as_ref().expect("invoke result");
        assert_eq!(result["events"][0]["type"], "chat_message");
        assert_eq!(result["events"][0]["message_id"], 42);
        assert_eq!(result["events"][0]["message"]["message"], "hello from poll");
        assert_eq!(result["cursor"]["last_known_message_id"], 42);
        assert_eq!(result["cursor"]["last_common_read_id"], 41);
        assert_eq!(result["not_modified"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn poll_conversation_events_preserves_cursor_when_not_modified() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
            .and(query_param("format", "json"))
            .and(query_param("lookIntoFuture", "1"))
            .and(query_param("timeout", "11"))
            .and(query_param("lastKnownMessageId", "42"))
            .and(query_param("lastCommonReadId", "41"))
            .and(query_param("setReadMarker", "0"))
            .and(query_param("includeLastKnown", "0"))
            .and(query_param("noStatusUpdate", "1"))
            .and(query_param("markNotificationsAsRead", "0"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;

        let mut connector = NextcloudTalkConnector::new();
        connector
            .configure(json!({
                "server_url": server.uri(),
                "auth": {
                    "mode": "bearer_token",
                    "access_token": "oidc"
                },
                "long_poll_timeout_secs": 11,
                "network": { "allow_private_networks": true }
            }))
            .await
            .expect("configure");
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.expect("handshake");

        let grant = generate_valid_token(
            &signing_key,
            CAP_READ,
            &[OP_POLL_CONVERSATION_EVENTS],
            &connector.base.instance_id,
        );
        let response = connector
            .invoke(base_invoke(
                connector.id(),
                OP_POLL_CONVERSATION_EVENTS,
                grant,
                json!({
                    "token": "room123",
                    "look_into_future": true,
                    "last_known_message_id": 42,
                    "last_common_read_id": 41
                }),
            ))
            .await
            .expect("invoke");

        assert_eq!(response.status, InvokeStatus::Ok);
        let result = response.result.as_ref().expect("invoke result");
        assert_eq!(result["events"], json!([]));
        assert_eq!(result["cursor"]["last_known_message_id"], 42);
        assert_eq!(result["cursor"]["last_common_read_id"], 41);
        assert_eq!(result["not_modified"], true);
    }
}
