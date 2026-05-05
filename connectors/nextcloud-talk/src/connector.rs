//! Nextcloud Talk connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};

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
#[derive(Debug)]
pub struct NextcloudTalkConnector {
    base: BaseConnector,
    config: Option<NextcloudTalkConfig>,
    client: Option<NextcloudTalkClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
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
        }
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

fn secret_fingerprint(secret: &NextcloudTalkSecretRef) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.fingerprint_material().as_bytes());
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

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_HEALTH
        | OP_LIST_CONVERSATIONS
        | OP_GET_CONVERSATION
        | OP_GET_MESSAGES
        | OP_POLL_CONVERSATION_EVENTS
        | OP_LIST_PARTICIPANTS
        | OP_GET_CALL_STATE => CAP_READ,
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
        let config = NextcloudTalkConfig::from_value(config)?;
        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = NextcloudTalkClient::new(&config).map_err(|error| FcpError::Internal {
            message: format!("Failed to create Nextcloud Talk client: {error}"),
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
            OP_SEND_MESSAGE => {
                let input: SendMessageInput = parse_input(input, operation_name)?;
                let room_ref = parse_conversation_ref(input.token)?;
                let message = client
                    .send_message(runtime, &room_ref, &input.request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "message": message })
            }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::InstanceId;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
                        "secret": "super-secret-webhook-material"
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
        assert!(!encoded.contains("super-secret-webhook-material"));
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
        let operations = connector.introspect().operations;
        assert_eq!(operations.len(), 16);
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
                    "app_password": "secret"
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
                    "app_password": "secret"
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
                    "app_password": "secret"
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
