//! `BlueBubbles` `iMessage` connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, EventInfo, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_sdk::prelude::*;
use fcp_webhook::{
    SignatureAlgorithm, SignatureVerifier, WebhookConfig, WebhookError, WebhookHandler,
    WebhookResult,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::client::BlueBubblesClient;
use crate::types::{
    BlueBubblesConfig, Message, QueryParams, bluebubbles_webhook_dedupe_id, default_webhook_events,
    normalize_bluebubbles_webhook_payload,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_SEND_MESSAGE: &str = "imessage.send_message";
const OP_GET_CHATS: &str = "imessage.get_chats";
const OP_GET_CHAT: &str = "imessage.get_chat";
const OP_GET_MESSAGES: &str = "imessage.get_messages";
const OP_SYNC_EVENTS: &str = "imessage.sync_events";
const OP_DOWNLOAD_ATTACHMENT: &str = "imessage.download_attachment";
const OP_MARK_READ: &str = "imessage.mark_read";
const OP_GET_SERVER_INFO: &str = "imessage.get_server_info";
const OP_REGISTER_WEBHOOK: &str = "imessage.register_webhook";
const OP_LIST_WEBHOOKS: &str = "imessage.list_webhooks";
const OP_UNREGISTER_WEBHOOK: &str = "imessage.unregister_webhook";
const OP_INGEST_WEBHOOK_EVENT: &str = "imessage.ingest_webhook_event";

// Capability IDs
const CAP_SEND: &str = "imessage.send";
const CAP_READ: &str = "imessage.read";
const CAP_ADMIN: &str = "imessage.admin";

const DEFAULT_SYNC_CHAT_LIMIT: u64 = 25;
const DEFAULT_SYNC_MESSAGE_LIMIT: u64 = 50;
const WEBHOOK_DEDUPE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Debug, Clone)]
struct BlueBubblesWebhookPassthroughVerifier;

impl SignatureVerifier for BlueBubblesWebhookPassthroughVerifier {
    fn verify(&self, _payload: &[u8], _signature: &str) -> WebhookResult<()> {
        Ok(())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::HmacSha256
    }
}

// Doctor types
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

/// `BlueBubbles` `iMessage` connector state.
#[derive(Debug)]
struct BlueBubblesState {
    config: BlueBubblesConfig,
    client: BlueBubblesClient,
    runtime: ConnectorRuntime,
    webhook_dedupe: WebhookHandler<BlueBubblesWebhookPassthroughVerifier>,
}

impl BlueBubblesState {
    fn from_config(config: BlueBubblesConfig) -> FcpResult<Self> {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        );
        let client =
            BlueBubblesClient::from_config(&config).map_err(|error| FcpError::Internal {
                message: format!("Failed to create BlueBubbles client: {error}"),
            })?;
        let webhook_dedupe = WebhookHandler::with_config(
            BlueBubblesWebhookPassthroughVerifier,
            "bluebubbles",
            WebhookConfig::default().with_idempotency_ttl(WEBHOOK_DEDUPE_TTL),
        );

        Ok(Self {
            config,
            client,
            runtime,
            webhook_dedupe,
        })
    }
}

#[derive(Debug)]
pub struct BlueBubblesConnector {
    base: BaseConnector,
    state: Option<BlueBubblesState>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    manifest_toml: &'static str,
}

impl BlueBubblesConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self::with_connector_metadata("fcp.imessage", MANIFEST_TOML)
    }

    /// Create a new connector instance with an explicit connector identifier.
    ///
    /// This allows thin wrapper crates to expose the same bridge-backed
    /// implementation under a different connector ID and manifest surface.
    #[must_use]
    pub fn with_connector_id(connector_id: &'static str) -> Self {
        Self::with_connector_metadata(connector_id, MANIFEST_TOML)
    }

    /// Create a connector with explicit connector metadata.
    #[must_use]
    pub fn with_connector_metadata(
        connector_id: &'static str,
        manifest_toml: &'static str,
    ) -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static(connector_id)),
            state: None,
            started_at: Instant::now(),
            verifier: None,
            manifest_toml,
        }
    }

    fn manifest_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.manifest_toml.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
        let capability = match operation {
            OP_SEND_MESSAGE | OP_MARK_READ => CAP_SEND,
            OP_GET_CHATS
            | OP_GET_CHAT
            | OP_GET_MESSAGES
            | OP_SYNC_EVENTS
            | OP_DOWNLOAD_ATTACHMENT
            | OP_INGEST_WEBHOOK_EVENT => CAP_READ,
            OP_GET_SERVER_INFO | OP_REGISTER_WEBHOOK | OP_LIST_WEBHOOKS | OP_UNREGISTER_WEBHOOK => {
                CAP_ADMIN
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

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        let configured = self.state.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let client_ok = self.state.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.state.is_some();
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });

        if let Some(state) = &self.state {
            let config = &state.config;
            let scheme = if config.server_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            checks.push(DoctorCheck {
                name: "server_url".into(),
                passed: true,
                message: Some(format!("Server URL ({scheme}): {}", config.server_url)),
                critical: false,
            });

            let host_part = config.server_host().unwrap_or_default();
            let host_ok = host_part == "localhost" || host_part == "127.0.0.1";
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(if host_ok {
                    "Server URL is local (localhost or 127.0.0.1)".into()
                } else {
                    format!("Server URL host '{host_part}' is not localhost; ensure trust boundary")
                }),
                critical: false,
            });

            let passcode_ok = !config.server_passcode.is_empty();
            checks.push(DoctorCheck {
                name: "password".into(),
                passed: passcode_ok,
                message: Some(if passcode_ok {
                    "Password is set".into()
                } else {
                    "Password is empty".into()
                }),
                critical: true,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for BlueBubblesConnector {
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
            id: OperationId::from_static(OP_SEND_MESSAGE),
            summary: "Send an iMessage".into(),
            description: Some(
                "Sends a text message to a chat via BlueBubbles, choosing an explicit AppleScript or Private API send method from server capabilities".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_guid", "message"],
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Target chat GUID (e.g. iMessage;-;+15551234567)"
                    },
                    "message": {
                        "type": "string",
                        "description": "Message text to send"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "integer" },
                    "message": { "type": "string" },
                    "data": { "type": "object" },
                    "send_method": { "type": "string", "enum": ["apple-script", "private-api"] },
                    "send_method_decision": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send an iMessage to a contact or group chat".into(),
                common_mistakes: vec![
                    "Chat GUID format is 'iMessage;-;+15551234567' for DMs or 'iMessage;+;chatXXX' for groups".into(),
                    "The BlueBubbles server must be running on a Mac with iMessage signed in".into(),
                    "Plain text sends refresh server info and prefer Private API on macOS 26+ when the bridge reports Private API support".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_CHATS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_CHATS),
            summary: "List iMessage chats".into(),
            description: Some(
                "Gets a paginated list of iMessage chats from the BlueBubbles server".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "offset": { "type": "integer", "description": "Pagination offset" },
                    "limit": { "type": "integer", "description": "Max results to return" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "total": { "type": "integer" },
                    "offset": { "type": "integer" },
                    "limit": { "type": "integer" },
                    "data": {
                        "type": "array",
                        "items": { "type": "object" }
                    }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to browse or search iMessage conversations".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_MESSAGES)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_CHAT),
            summary: "Get a single iMessage chat".into(),
            description: Some(
                "Gets detailed metadata for one iMessage chat by chat GUID".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_guid"],
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Chat GUID to fetch"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "guid": { "type": "string" },
                    "display_name": { "type": "string" },
                    "participants": {
                        "type": "array",
                        "items": { "type": "object" }
                    },
                    "is_group": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need detailed metadata for a specific iMessage chat".into(),
                common_mistakes: vec![
                    "Use get_chats first if you do not already know the chat GUID".into(),
                ],
                examples: Vec::new(),
                related: vec![
                    CapabilityId::from_static(OP_GET_CHATS),
                    CapabilityId::from_static(OP_GET_MESSAGES),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_MESSAGES),
            summary: "Get messages from a chat".into(),
            description: Some(
                "Gets a paginated list of messages from a specific iMessage chat".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_guid"],
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Chat GUID to fetch messages from"
                    },
                    "offset": { "type": "integer", "description": "Pagination offset" },
                    "limit": { "type": "integer", "description": "Max results" },
                    "after": { "type": "integer", "description": "Only messages after this timestamp (epoch ms)" },
                    "before": { "type": "integer", "description": "Only messages before this timestamp (epoch ms)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "total": { "type": "integer" },
                    "offset": { "type": "integer" },
                    "limit": { "type": "integer" },
                    "data": {
                        "type": "array",
                        "items": { "type": "object" }
                    }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read message history from an iMessage chat".into(),
                common_mistakes: vec![
                    "You must specify a valid chat_guid; use get_chats first to discover available chats".into(),
                ],
                examples: Vec::new(),
                related: vec![
                    CapabilityId::from_static(OP_GET_CHATS),
                    CapabilityId::from_static(OP_SEND_MESSAGE),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SYNC_EVENTS),
            summary: "Sync iMessage events".into(),
            description: Some(
                "Polls BlueBubbles for recent messages and returns them as normalized iMessage event records".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Optional chat GUID to scope the sync to one conversation"
                    },
                    "after": {
                        "type": "integer",
                        "description": "Only include messages created after this epoch-ms timestamp"
                    },
                    "before": {
                        "type": "integer",
                        "description": "Only include messages created before this epoch-ms timestamp"
                    },
                    "chat_limit": {
                        "type": "integer",
                        "description": "Maximum chats to scan when chat_guid is omitted"
                    },
                    "message_limit": {
                        "type": "integer",
                        "description": "Maximum messages to fetch per scanned chat"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "events": {
                        "type": "array",
                        "items": { "type": "object" }
                    },
                    "next_after": { "type": "integer" },
                    "synced_chats": { "type": "integer" },
                    "chat_guid": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need a polling-friendly view of new iMessage activity without relying on long-lived streaming".into(),
                common_mistakes: vec![
                    "Use the returned next_after value on the next call to avoid re-reading the same messages".into(),
                    "Set chat_guid when you already know the conversation you want to monitor".into(),
                ],
                examples: vec![
                    r#"{"chat_guid": "chat-guid-1", "after": 1700000000000}"#.into(),
                    r#"{"after": 1700000000000, "chat_limit": 10, "message_limit": 25}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static(OP_GET_CHAT),
                    CapabilityId::from_static(OP_GET_MESSAGES),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOWNLOAD_ATTACHMENT),
            summary: "Download an iMessage attachment".into(),
            description: Some(
                "Downloads the binary payload for an attachment referenced by a BlueBubbles message"
                    .into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["attachment_guid"],
                "properties": {
                    "attachment_guid": {
                        "type": "string",
                        "description": "Attachment GUID from a message attachment entry"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "attachment_guid": { "type": "string" },
                    "encoding": { "type": "string" },
                    "data_base64": { "type": "string" },
                    "byte_len": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need the raw contents of an attachment referenced by an iMessage".into(),
                common_mistakes: vec![
                    "Pass the attachment GUID from a message attachment, not the chat GUID".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_MESSAGES)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MARK_READ),
            summary: "Mark a chat as read".into(),
            description: Some(
                "Marks all messages in an iMessage chat as read".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_guid"],
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Chat GUID to mark as read"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When you want to mark an iMessage conversation as read".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_MESSAGES)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_REGISTER_WEBHOOK),
            summary: "Register a BlueBubbles webhook".into(),
            description: Some(
                "Registers a BlueBubbles callback URL for message webhook events, reusing an existing matching registration by default".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Absolute callback URL. Defaults to the connector webhook_host/webhook_port/webhook_path with password query auth."
                    },
                    "events": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "BlueBubbles event names to register",
                        "default": default_webhook_events()
                    },
                    "skip_if_existing": {
                        "type": "boolean",
                        "description": "When true, list existing webhooks and avoid duplicate registration for the same URL",
                        "default": true
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "registration_status": { "type": "string", "enum": ["existing", "registered"] },
                    "webhook": { "type": "object" },
                    "response": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_ADMIN),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When the host has a supervised BlueBubbles webhook receiver URL and needs the Mac bridge to start delivering message events".into(),
                common_mistakes: vec![
                    "Registering duplicate callback URLs after a restart instead of using skip_if_existing".into(),
                    "Assuming this starts the local HTTP listener; it only registers the remote BlueBubbles callback".into(),
                ],
                examples: vec![
                    r#"{"url": "http://localhost:8645/bluebubbles-webhook?password=secret"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static(OP_LIST_WEBHOOKS),
                    CapabilityId::from_static(OP_UNREGISTER_WEBHOOK),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_LIST_WEBHOOKS),
            summary: "List BlueBubbles webhooks".into(),
            description: Some("Lists webhook registrations currently configured on the BlueBubbles server".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "webhooks": { "type": "array", "items": { "type": "object" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_ADMIN),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to inspect current BlueBubbles webhook callback registrations before registering or cleaning up".into(),
                common_mistakes: vec![
                    "Assuming the webhook URL is secret-free; BlueBubbles callback auth may be embedded in the URL".into(),
                ],
                examples: vec![r"{}".into()],
                related: vec![CapabilityId::from_static(OP_REGISTER_WEBHOOK)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_UNREGISTER_WEBHOOK),
            summary: "Unregister BlueBubbles webhooks".into(),
            description: Some(
                "Deletes one BlueBubbles webhook by ID or all registrations matching a callback URL".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "webhook_id": {
                        "type": "string",
                        "description": "Specific BlueBubbles webhook ID to delete"
                    },
                    "url": {
                        "type": "string",
                        "description": "Callback URL; all matching registered webhooks with IDs are deleted"
                    }
                },
                "anyOf": [
                    { "required": ["webhook_id"] },
                    { "required": ["url"] }
                ]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "deleted_count": { "type": "integer" },
                    "deleted": { "type": "array", "items": { "type": "object" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_ADMIN),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When a BlueBubbles callback is no longer valid or duplicate callback registrations need cleanup".into(),
                common_mistakes: vec![
                    "Deleting a webhook before the replacement receiver has been registered and verified".into(),
                ],
                examples: vec![
                    r#"{"webhook_id": "42"}"#.into(),
                    r#"{"url": "http://localhost:8645/bluebubbles-webhook?password=secret"}"#.into(),
                ],
                related: vec![CapabilityId::from_static(OP_LIST_WEBHOOKS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_INGEST_WEBHOOK_EVENT),
            summary: "Normalize a BlueBubbles webhook event".into(),
            description: Some(
                "Normalizes a host-delivered BlueBubbles webhook payload into an FCP event-shaped record and atomically claims its account-scoped dedupe key".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["payload"],
                "properties": {
                    "payload": {
                        "type": "object",
                        "description": "Raw BlueBubbles webhook JSON body"
                    },
                    "event_type": {
                        "type": "string",
                        "description": "Optional event type override when the transport carries it outside the JSON body"
                    },
                    "account_id": {
                        "type": "string",
                        "description": "Optional account namespace for dedupe; defaults to connector webhook_account_id"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string", "enum": ["accepted", "duplicate"] },
                    "dedupe_id": { "type": "string" },
                    "event": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When a trusted FCP webhook receiver has authenticated a BlueBubbles POST and needs connector-local payload normalization and duplicate replay suppression".into(),
                common_mistakes: vec![
                    "Treating this as external sender authorization; pairing and sender policy are separate follow-up gates".into(),
                    "Assuming in-process dedupe survives connector restart; the durable seven-day store is a separate follow-up".into(),
                ],
                examples: vec![
                    r#"{"payload": {"type": "new-message", "data": {"guid": "msg-1", "text": "hello"}}}"#.into(),
                ],
                related: vec![CapabilityId::from_static(OP_SYNC_EVENTS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_SERVER_INFO),
            summary: "Get BlueBubbles server info".into(),
            description: Some(
                "Gets information about the BlueBubbles server (version, OS, private API status)".into(),
            ),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "os_version": { "type": "string" },
                    "server_version": { "type": "string" },
                    "private_api": { "type": "boolean" },
                    "proxy_service": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_ADMIN),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to check the BlueBubbles server status or capabilities".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

const fn message_event_topic(message: &Message) -> &'static str {
    if message.group_action_type.is_some() {
        "imessage.chat.group_action"
    } else if message.associated_message_type.is_some() {
        "imessage.message.associated"
    } else if message.is_from_me {
        "imessage.message.outbound"
    } else {
        "imessage.message.inbound"
    }
}

fn message_to_sync_event(chat_guid: &str, message: &Message) -> serde_json::Value {
    json!({
        "topic": message_event_topic(message),
        "event_id": message.guid,
        "chat_guid": chat_guid,
        "timestamp_ms": message.date_created,
        "is_from_me": message.is_from_me,
        "thread": message.thread_originator_guid.as_ref().map(|guid| {
            json!({
                "kind": "message_thread",
                "thread_originator_guid": guid,
            })
        }),
        "participant_address": message.handle.as_ref().map(|handle| handle.address.clone()),
        "has_attachments": !message.attachments.is_empty(),
        "message": message,
    })
}

fn required_string<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{field}' field"),
        })
}

fn optional_string<'a>(input: &'a Value, field: &str) -> Option<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn webhook_events_from_input(input: &Value) -> FcpResult<Vec<String>> {
    let Some(values) = input.get("events") else {
        return Ok(default_webhook_events());
    };
    let events = values.as_array().ok_or_else(|| FcpError::InvalidRequest {
        code: 1005,
        message: "events must be an array of non-empty strings".into(),
    })?;
    let events = events
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: "events must contain only non-empty strings".into(),
                })
        })
        .collect::<FcpResult<Vec<_>>>()?;
    if events.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "events must not be empty".into(),
        });
    }
    Ok(events)
}

#[must_use]
pub fn events_info() -> Vec<EventInfo> {
    let schema = json!({
        "type": "object",
        "required": ["event_type", "topic", "event_id", "is_from_me", "is_group"],
        "properties": {
            "event_type": { "type": "string" },
            "topic": { "type": "string" },
            "event_id": { "type": "string" },
            "chat_guid": { "type": "string" },
            "chat_identifier": { "type": "string" },
            "sender_id": { "type": "string" },
            "sender_name": { "type": "string" },
            "text": { "type": "string" },
            "is_from_me": { "type": "boolean" },
            "is_group": { "type": "boolean" },
            "attachments": { "type": "array", "items": { "type": "object" } },
            "reply_to_message_guid": { "type": "string" },
            "associated_message_guid": { "type": "string" },
            "associated_message_type": { "type": "integer" },
            "balloon_bundle_id": { "type": "string" },
            "is_tapback": { "type": "boolean" }
        }
    });
    [
        "imessage.message.inbound",
        "imessage.message.outbound",
        "imessage.message.updated",
        "imessage.message.tapback",
    ]
    .into_iter()
    .map(|topic| EventInfo {
        topic: topic.to_string(),
        schema: schema.clone(),
        requires_ack: false,
    })
    .collect()
}

fcp_core::impl_fcp_sealed!(BlueBubblesConnector);

#[async_trait]
impl FcpConnector for BlueBubblesConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = BlueBubblesConfig::from_value(config)?;
        self.state = Some(BlueBubblesState::from_config(config)?);
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
            manifest_hash: self.manifest_hash(),
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
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(state) = &self.state else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        match state.client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(err) => {
                if err.is_retryable() {
                    Ok(SelfCheckReport::degraded(
                        "self_check_retryable",
                        err.to_string(),
                    ))
                } else {
                    Ok(SelfCheckReport::failed(
                        "self_check_failed",
                        err.to_string(),
                    ))
                }
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match Self::required_capability(req.operation.as_str()) {
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

        let Some(verifier) = &self.verifier else {
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

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(state) = &self.state {
            state.runtime.shutdown();
        }
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: events_info(),
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

impl BlueBubblesConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        let required_cap = Self::required_capability(operation)?;

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let runtime = &state.runtime;
        let client = &state.client;

        let output = match operation {
            OP_SEND_MESSAGE => {
                let chat_guid = req
                    .input
                    .get("chat_guid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_guid' field".into(),
                    })?;
                let message = req
                    .input
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message' field".into(),
                    })?;

                let outcome = client
                    .send_message(runtime, chat_guid, message)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                let mut output =
                    serde_json::to_value(&outcome.response).map_err(|e| FcpError::Internal {
                        message: format!("Failed to serialize response: {e}"),
                    })?;
                if let Value::Object(ref mut object) = output {
                    object.insert(
                        "send_method".into(),
                        Value::String(outcome.decision.method.clone()),
                    );
                    object.insert(
                        "send_method_decision".into(),
                        serde_json::to_value(&outcome.decision).map_err(|e| {
                            FcpError::Internal {
                                message: format!("Failed to serialize send decision: {e}"),
                            }
                        })?,
                    );
                }
                output
            }
            OP_GET_CHATS => {
                let offset = req.input.get("offset").and_then(serde_json::Value::as_u64);
                let limit = req.input.get("limit").and_then(serde_json::Value::as_u64);

                let params = QueryParams {
                    offset,
                    limit,
                    ..QueryParams::default()
                };

                let resp = client
                    .get_chats(runtime, &params)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_GET_CHAT => {
                let chat_guid = req
                    .input
                    .get("chat_guid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_guid' field".into(),
                    })?;

                let resp = client
                    .get_chat(runtime, chat_guid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_GET_MESSAGES => {
                let chat_guid = req
                    .input
                    .get("chat_guid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_guid' field".into(),
                    })?;
                let offset = req.input.get("offset").and_then(serde_json::Value::as_u64);
                let limit = req.input.get("limit").and_then(serde_json::Value::as_u64);
                let after = req.input.get("after").and_then(serde_json::Value::as_i64);
                let before = req.input.get("before").and_then(serde_json::Value::as_i64);

                let params = QueryParams {
                    offset,
                    limit,
                    after,
                    before,
                    ..QueryParams::default()
                };

                let resp = client
                    .get_messages(runtime, chat_guid, &params)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_SYNC_EVENTS => {
                let requested_chat_guid = req.input.get("chat_guid").and_then(|v| v.as_str());
                let after = req.input.get("after").and_then(serde_json::Value::as_i64);
                let before = req.input.get("before").and_then(serde_json::Value::as_i64);
                let chat_limit = req
                    .input
                    .get("chat_limit")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(DEFAULT_SYNC_CHAT_LIMIT);
                let message_limit = req
                    .input
                    .get("message_limit")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(DEFAULT_SYNC_MESSAGE_LIMIT);

                let chat_guids = if let Some(chat_guid) = requested_chat_guid {
                    vec![chat_guid.to_string()]
                } else {
                    let chat_params = QueryParams {
                        limit: Some(chat_limit),
                        sort: Some("ASC".into()),
                        ..QueryParams::default()
                    };
                    client
                        .get_chats(runtime, &chat_params)
                        .await
                        .map_err(|e| e.to_fcp_error())?
                        .data
                        .into_iter()
                        .map(|chat| chat.guid)
                        .collect::<Vec<_>>()
                };

                let mut next_after = after;
                let mut ordered_events = Vec::new();

                for chat_guid in &chat_guids {
                    let params = QueryParams {
                        limit: Some(message_limit),
                        after,
                        before,
                        sort: Some("ASC".into()),
                        ..QueryParams::default()
                    };

                    let resp = client
                        .get_messages(runtime, chat_guid, &params)
                        .await
                        .map_err(|e| e.to_fcp_error())?;

                    for message in resp.data {
                        if let Some(ts) = message.date_created {
                            next_after = Some(next_after.map_or(ts, |current| current.max(ts)));
                        }

                        let event = message_to_sync_event(chat_guid, &message);
                        ordered_events.push((
                            message.date_created.unwrap_or_default(),
                            message.guid.clone(),
                            event,
                        ));
                    }
                }

                ordered_events
                    .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

                json!({
                    "events": ordered_events
                        .into_iter()
                        .map(|(_, _, event)| event)
                        .collect::<Vec<_>>(),
                    "next_after": next_after.map(|ts| ts.saturating_add(1)),
                    "synced_chats": chat_guids.len(),
                    "chat_guid": requested_chat_guid,
                })
            }
            OP_DOWNLOAD_ATTACHMENT => {
                let attachment_guid = req
                    .input
                    .get("attachment_guid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'attachment_guid' field".into(),
                    })?;

                let attachment = client
                    .download_attachment(runtime, attachment_guid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                json!({
                    "attachment_guid": attachment_guid,
                    "encoding": "base64",
                    "data_base64": base64::engine::general_purpose::STANDARD.encode(&attachment),
                    "byte_len": attachment.len(),
                })
            }
            OP_MARK_READ => {
                let chat_guid = req
                    .input
                    .get("chat_guid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_guid' field".into(),
                    })?;

                client
                    .mark_read(runtime, chat_guid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                json!({ "status": "marked_read" })
            }
            OP_REGISTER_WEBHOOK => {
                let webhook_url = optional_string(&req.input, "url")
                    .map(str::to_string)
                    .map_or_else(|| state.config.webhook_registration_url(), Ok)?;
                let events = webhook_events_from_input(&req.input)?;
                let skip_if_existing = req
                    .input
                    .get("skip_if_existing")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);

                client
                    .register_webhook(runtime, &webhook_url, events, skip_if_existing)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_LIST_WEBHOOKS => {
                let webhooks = client
                    .list_webhooks(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "webhooks": webhooks })
            }
            OP_UNREGISTER_WEBHOOK => {
                let mut deleted = Vec::new();
                if let Some(webhook_id) = optional_string(&req.input, "webhook_id") {
                    let response = client
                        .delete_webhook(runtime, webhook_id)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    deleted.push(json!({
                        "webhook_id": webhook_id,
                        "response": response,
                    }));
                } else {
                    let webhook_url = required_string(&req.input, "url")?;
                    let webhooks = client
                        .list_webhooks(runtime)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    for webhook in webhooks
                        .into_iter()
                        .filter(|webhook| webhook.url.as_deref() == Some(webhook_url))
                    {
                        if let Some(webhook_id) = webhook.id.as_deref() {
                            let response = client
                                .delete_webhook(runtime, webhook_id)
                                .await
                                .map_err(|e| e.to_fcp_error())?;
                            deleted.push(json!({
                                "webhook_id": webhook_id,
                                "url": webhook.url,
                                "response": response,
                            }));
                        }
                    }
                }
                json!({
                    "deleted_count": deleted.len(),
                    "deleted": deleted,
                })
            }
            OP_INGEST_WEBHOOK_EVENT => {
                let payload = req
                    .input
                    .get("payload")
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'payload' field".into(),
                    })?;
                let account_id = optional_string(&req.input, "account_id")
                    .unwrap_or(state.config.webhook_account_id.as_str());
                let event_type = optional_string(&req.input, "event_type");
                let event = normalize_bluebubbles_webhook_payload(payload, event_type)?;
                let dedupe_id = bluebubbles_webhook_dedupe_id(account_id, &event);
                match state.webhook_dedupe.claim_event(&dedupe_id) {
                    Ok(()) => json!({
                        "status": "accepted",
                        "dedupe_id": dedupe_id,
                        "event": event,
                    }),
                    Err(WebhookError::ReplayDetected { .. }) => json!({
                        "status": "duplicate",
                        "dedupe_id": dedupe_id,
                        "event": event,
                    }),
                    Err(error) => {
                        return Err(FcpError::Internal {
                            message: format!("BlueBubbles webhook dedupe failed: {error}"),
                        });
                    }
                }
            }
            OP_GET_SERVER_INFO => {
                let info = client
                    .server_info(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&info).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize server info: {e}"),
                })?
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
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::CapabilityConstraints;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener as StdTcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_SEND),
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_ADMIN),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(connector_id: &ConnectorId, operation: &'static str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
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

    fn test_config() -> serde_json::Value {
        json!({
            "password": "test-password-123"
        })
    }

    fn test_config_with_url(server_url: &str) -> serde_json::Value {
        json!({
            "server_url": server_url,
            "password": "test-password-123"
        })
    }

    fn generate_valid_token(
        connector: &BlueBubblesConnector,
        signing_key: &Ed25519SigningKey,
        op: &str,
    ) -> CapabilityToken {
        let capability = match op {
            OP_SEND_MESSAGE | OP_MARK_READ => CAP_SEND,
            OP_GET_SERVER_INFO | OP_REGISTER_WEBHOOK | OP_LIST_WEBHOOKS | OP_UNREGISTER_WEBHOOK => {
                CAP_ADMIN
            }
            _ => CAP_READ,
        };
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .target_instance(connector.base.instance_id.as_str())
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn handshake_for_signing_key(signing_key: &Ed25519SigningKey) -> HandshakeRequest {
        let mut handshake = base_handshake();
        handshake.host_public_key = signing_key.verifying_key().to_bytes();
        handshake
    }

    #[derive(Clone, Debug)]
    struct LoopbackRequest {
        target: String,
        body: Vec<u8>,
    }

    impl LoopbackRequest {
        fn json_body(&self) -> Value {
            serde_json::from_slice(&self.body).expect("loopback request body should be valid JSON")
        }
    }

    #[derive(Clone, Debug)]
    struct LoopbackResponse {
        status: u16,
        body: Vec<u8>,
        delay: Duration,
    }

    impl LoopbackResponse {
        fn json(status: u16, body: &Value) -> Self {
            Self {
                status,
                body: body.to_string().into_bytes(),
                delay: Duration::ZERO,
            }
        }

        fn raw_json(status: u16, body: &'static str) -> Self {
            Self {
                status,
                body: body.as_bytes().to_vec(),
                delay: Duration::ZERO,
            }
        }
    }

    struct BlueBubblesLoopback {
        base_url: String,
        requests: Arc<Mutex<Vec<LoopbackRequest>>>,
        logs: Arc<Mutex<Vec<Value>>>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl BlueBubblesLoopback {
        fn spawn(name: &'static str, responses: Vec<LoopbackResponse>) -> Self {
            let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind loopback server");
            let addr = listener.local_addr().expect("loopback server addr");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let logs = Arc::new(Mutex::new(Vec::new()));
            let requests_for_thread = Arc::clone(&requests);
            let logs_for_thread = Arc::clone(&logs);

            let join = thread::spawn(move || {
                for (sequence, response) in responses.into_iter().enumerate() {
                    let (mut stream, _) = listener.accept().expect("accept loopback connection");
                    let request = read_loopback_request(&mut stream);
                    logs_for_thread
                        .lock()
                        .expect("lock loopback logs")
                        .push(json!({
                            "event": "bluebubbles-send-mode-loopback",
                            "server": name,
                            "sequence": sequence,
                            "target": redacted_target(&request.target),
                            "password_redacted": true,
                            "request_body_len": request.body.len(),
                            "response_status": response.status,
                            "response_body_len": response.body.len(),
                        }));
                    requests_for_thread
                        .lock()
                        .expect("lock loopback requests")
                        .push(request);
                    if !response.delay.is_zero() {
                        thread::sleep(response.delay);
                    }
                    let _ = write_loopback_response(&mut stream, &response);
                }
            });

            Self {
                base_url: format!("http://{addr}"),
                requests,
                logs,
                join: Some(join),
            }
        }

        fn uri(&self) -> &str {
            &self.base_url
        }

        fn finish(mut self) -> (Vec<LoopbackRequest>, Vec<Value>) {
            if let Some(join) = self.join.take() {
                join.join().expect("loopback thread should exit");
            }
            let requests = self
                .requests
                .lock()
                .expect("lock loopback requests")
                .clone();
            let logs = self.logs.lock().expect("lock loopback logs").clone();
            (requests, logs)
        }
    }

    fn redacted_target(target: &str) -> String {
        target.replace("test-password-123", "[REDACTED]")
    }

    fn target_has_query_key(target: &str, key: &str) -> bool {
        target.split_once('?').is_some_and(|(_, query)| {
            query
                .split('&')
                .filter_map(|param| param.split_once('='))
                .any(|(name, _)| name == key)
        })
    }

    const fn status_reason(status: u16) -> &'static str {
        match status {
            401 => "Unauthorized",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "OK",
        }
    }

    fn read_loopback_request(stream: &mut TcpStream) -> LoopbackRequest {
        let mut buffer = Vec::new();
        let mut scratch = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut scratch).expect("read loopback request");
            assert!(read > 0, "unexpected EOF before HTTP headers");
            buffer.extend_from_slice(&scratch[..read]);
            if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };

        let header_text =
            std::str::from_utf8(&buffer[..header_end]).expect("HTTP headers are UTF-8");
        let mut lines = header_text.split("\r\n");
        let request_line = lines.next().expect("request line");
        let mut parts = request_line.split_whitespace();
        let _method = parts.next().expect("method");
        let target = parts.next().expect("target").to_string();
        let mut headers = HashMap::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').expect("header separator");
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
        let content_length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = buffer[header_end..].to_vec();
        while body.len() < content_length {
            let read = stream.read(&mut scratch).expect("read loopback body");
            assert!(read > 0, "unexpected EOF before HTTP body");
            body.extend_from_slice(&scratch[..read]);
        }
        body.truncate(content_length);

        LoopbackRequest { target, body }
    }

    fn write_loopback_response(
        stream: &mut TcpStream,
        response: &LoopbackResponse,
    ) -> std::io::Result<()> {
        let head = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            response.status,
            status_reason(response.status),
            response.body.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(&response.body)?;
        stream.flush()
    }

    fn loopback_config(server_url: &str) -> Value {
        json!({
            "server_url": server_url,
            "password": "test-password-123",
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 0,
                "max_delay_ms": 0,
                "jitter_enabled": false
            }
        })
    }

    async fn invoke_send_against_loopback(
        server_url: &str,
        request_timeout_ms: Option<u64>,
    ) -> FcpResult<Value> {
        let mut config = loopback_config(server_url);
        if let Some(timeout) = request_timeout_ms {
            config["request_timeout_ms"] = json!(timeout);
        }

        let mut connector = BlueBubblesConnector::new();
        connector.configure(config).await?;
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await?;
        let req = InvokeRequest {
            input: json!({
                "chat_guid": "iMessage;-;+15551234567",
                "message": "hello from fcp"
            }),
            capability_token: generate_valid_token(&connector, &signing_key, OP_SEND_MESSAGE),
            ..base_invoke(connector.id(), OP_SEND_MESSAGE)
        };
        let response = connector.invoke(req).await?;
        response.result.ok_or_else(|| FcpError::Internal {
            message: "send response should include a result".into(),
        })
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = BlueBubblesConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = BlueBubblesConnector::new();
        let result = connector.configure(test_config()).await;
        assert!(result.is_ok());
        assert!(connector.state.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_password() {
        let mut connector = BlueBubblesConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = BlueBubblesConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = BlueBubblesConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_zero_request_timeout() {
        let mut connector = BlueBubblesConnector::new();
        let result = connector
            .configure(json!({
                "password": "test-password-123",
                "request_timeout_ms": 0
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_reports_remote_server_host() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_url("https://bluebubbles.example.com"))
            .await
            .unwrap();
        let report = connector.doctor();
        let network_check = report
            .checks
            .iter()
            .find(|check| check.name == "network_constraints")
            .unwrap();
        assert!(!network_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = BlueBubblesConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            generate_valid_token(&connector, &signing_key, OP_SEND_MESSAGE),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_before_configure() {
        let connector = BlueBubblesConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code, Some(FcpError::NotConfigured.error_code()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_before_handshake() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code, Some(FcpError::NotHandshaken.error_code()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_wrong_operation_token() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            generate_valid_token(&connector, &signing_key, OP_GET_CHATS),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code.as_deref(), Some("FCP-3003"));
    }

    #[test]
    fn test_introspection_operations() {
        let connector = BlueBubblesConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 12);
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_SEND_MESSAGE)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_GET_CHATS)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_GET_CHAT)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_GET_MESSAGES)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_SYNC_EVENTS)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_DOWNLOAD_ATTACHMENT)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_MARK_READ)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_GET_SERVER_INFO)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_REGISTER_WEBHOOK)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_LIST_WEBHOOKS)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_UNREGISTER_WEBHOOK)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_INGEST_WEBHOOK_EVENT)
        );
        assert!(
            intro
                .events
                .iter()
                .any(|event| event.topic == "imessage.message.tapback")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "imessage.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = BlueBubblesConnector::new();
        let req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_configured_without_handshake_reports_not_handshaken() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        let result = connector.invoke(req).await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_chat_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        req.input = json!({ "message": "hello" }); // missing chat_guid
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_message() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        req.input = json!({ "chat_guid": "iMessage;-;+15551234567" }); // missing message
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_loopback_uses_private_api_for_macos26_when_available() {
        let server = BlueBubblesLoopback::spawn(
            "macos26-private-api",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "26.0.1",
                            "server_version": "1.9.0",
                            "private_api": true
                        }
                    }),
                ),
                LoopbackResponse::json(
                    200,
                    &json!({
                        "status": 200,
                        "message": "Message sent!",
                        "data": {
                            "guid": "msg-private-api",
                            "text": "hello from fcp",
                            "is_from_me": true,
                            "attachments": []
                        }
                    }),
                ),
            ],
        );

        let result = invoke_send_against_loopback(server.uri(), None)
            .await
            .expect("send should succeed");
        assert_eq!(result["send_method"], "private-api");
        assert_eq!(
            result["send_method_decision"]["reason"],
            "macos26_private_api_available"
        );
        assert_eq!(result["data"]["guid"], "msg-private-api");

        let (requests, logs) = server.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].target.starts_with("/api/v1/server/info?"));
        assert!(target_has_query_key(&requests[0].target, "password"));
        assert_eq!(
            requests[1].target.split_once('?').map(|(path, _)| path),
            Some("/api/v1/message/text")
        );
        assert!(target_has_query_key(&requests[1].target, "password"));
        let send_body = requests[1].json_body();
        assert_eq!(send_body["method"], "private-api");
        assert_eq!(send_body["chatGuid"], "iMessage;-;+15551234567");
        assert_eq!(send_body["message"], "hello from fcp");
        assert!(
            send_body["tempGuid"]
                .as_str()
                .is_some_and(|guid| !guid.is_empty())
        );
        assert!(
            logs.iter().all(|entry| entry["target"]
                .as_str()
                .is_some_and(|target| !target.contains("test-password-123"))),
            "loopback transcript must redact the passcode"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_loopback_falls_back_to_apple_script_when_private_api_disabled() {
        let server = BlueBubblesLoopback::spawn(
            "macos26-private-api-disabled",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "26.0",
                            "server_version": "1.9.0",
                            "private_api": false
                        }
                    }),
                ),
                LoopbackResponse::json(
                    200,
                    &json!({
                        "status": 200,
                        "message": "Message sent!",
                        "data": {
                            "guid": "msg-apple-script",
                            "text": "hello from fcp",
                            "is_from_me": true,
                            "attachments": []
                        }
                    }),
                ),
            ],
        );

        let result = invoke_send_against_loopback(server.uri(), None)
            .await
            .expect("send should succeed");
        assert_eq!(result["send_method"], "apple-script");
        assert_eq!(
            result["send_method_decision"]["reason"],
            "macos26_private_api_disabled_apple_script_fallback"
        );

        let (requests, logs) = server.finish();
        assert_eq!(requests[1].json_body()["method"], "apple-script");
        assert!(
            logs.iter()
                .any(|entry| entry["event"] == "bluebubbles-send-mode-loopback")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_loopback_error_modes_are_deterministic() {
        let auth_failure = BlueBubblesLoopback::spawn(
            "auth-failure",
            vec![
                LoopbackResponse::json(401, &json!({"error": "bad password"})),
                LoopbackResponse::json(401, &json!({"error": "bad password"})),
            ],
        );
        let auth_error = invoke_send_against_loopback(auth_failure.uri(), None)
            .await
            .expect_err("auth failure should be denied");
        assert!(matches!(auth_error, FcpError::Unauthorized { .. }));
        let (_, auth_logs) = auth_failure.finish();
        assert_eq!(auth_logs[0]["response_status"], 401);

        let rate_limit = BlueBubblesLoopback::spawn(
            "rate-limit",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "26.0",
                            "server_version": "1.9.0",
                            "private_api": true
                        }
                    }),
                ),
                LoopbackResponse::json(429, &json!({"error": "slow down"})),
            ],
        );
        let rate_error = invoke_send_against_loopback(rate_limit.uri(), None)
            .await
            .expect_err("rate limit should fail after bounded retry budget");
        assert!(matches!(rate_error, FcpError::RateLimited { .. }));
        let (_, rate_logs) = rate_limit.finish();
        assert_eq!(rate_logs[1]["response_status"], 429);

        let malformed = BlueBubblesLoopback::spawn(
            "malformed-send-response",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "26.0",
                            "server_version": "1.9.0",
                            "private_api": true
                        }
                    }),
                ),
                LoopbackResponse::raw_json(200, "{not-json"),
            ],
        );
        let malformed_error = invoke_send_against_loopback(malformed.uri(), None)
            .await
            .expect_err("malformed send response should fail closed");
        assert!(malformed_error.to_string().contains("error"));
        let (_, malformed_logs) = malformed.finish();
        assert_eq!(malformed_logs[1]["response_status"], 200);

        let server_info_unavailable = BlueBubblesLoopback::spawn(
            "server-info-unavailable",
            vec![
                LoopbackResponse::json(503, &json!({"error": "server info temporarily down"})),
                LoopbackResponse::json(
                    200,
                    &json!({
                        "status": 200,
                        "message": "Message sent!",
                        "data": {
                            "guid": "msg-timeout-fallback",
                            "text": "hello from fcp",
                            "is_from_me": true,
                            "attachments": []
                        }
                    }),
                ),
            ],
        );
        let unavailable_result = invoke_send_against_loopback(server_info_unavailable.uri(), None)
            .await
            .expect("send should preserve apple-script fallback when server info is unavailable");
        assert_eq!(unavailable_result["send_method"], "apple-script");
        assert_eq!(
            unavailable_result["send_method_decision"]["reason"],
            "server_info_unavailable_apple_script_fallback"
        );
        let (_, unavailable_logs) = server_info_unavailable.finish();
        assert_eq!(unavailable_logs.len(), 2);
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 12);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_send_message_is_risky() {
        let ops = operations_info();
        let send = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_get_chats_is_safe() {
        let ops = operations_info();
        let chats = ops
            .iter()
            .find(|op| op.id.as_str() == OP_GET_CHATS)
            .unwrap();
        assert_eq!(chats.safety_tier, SafetyTier::Safe);
        assert_eq!(chats.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_download_attachment_is_safe() {
        let ops = operations_info();
        let download = ops
            .iter()
            .find(|op| op.id.as_str() == OP_DOWNLOAD_ATTACHMENT)
            .unwrap();
        assert_eq!(download.safety_tier, SafetyTier::Safe);
        assert_eq!(download.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_sync_events_is_safe() {
        let ops = operations_info();
        let sync = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SYNC_EVENTS)
            .unwrap();
        assert_eq!(sync.safety_tier, SafetyTier::Safe);
        assert_eq!(sync.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_mark_read_is_best_effort() {
        let ops = operations_info();
        let mark = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MARK_READ)
            .unwrap();
        assert_eq!(mark.safety_tier, SafetyTier::Safe);
        assert_eq!(mark.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn test_webhook_register_is_risky_best_effort() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_REGISTER_WEBHOOK)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let connector = BlueBubblesConnector::new();
        let hash1 = connector.manifest_hash();
        let hash2 = connector.manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = BlueBubblesConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let req = ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1000,
            drain: false,
            reason: Some("test".into()),
        };
        let result = connector.shutdown(req).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_impl() {
        let connector = BlueBubblesConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.imessage");
    }

    #[test]
    fn test_custom_connector_id() {
        let connector = BlueBubblesConnector::with_connector_id("fcp.bluebubbles");
        assert_eq!(connector.id().as_str(), "fcp.bluebubbles");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_get_messages_missing_chat_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_GET_MESSAGES);
        req.input = json!({ "limit": 10 }); // missing chat_guid
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_mark_read_missing_chat_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_MARK_READ);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_get_chat_missing_chat_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_GET_CHAT);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_download_attachment_missing_attachment_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_DOWNLOAD_ATTACHMENT);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_sync_events_single_chat() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/chat/chat-guid-1/message"))
            .and(query_param("password", "test-password-123"))
            .and(query_param("after", "1700000000000"))
            .and(query_param("limit", "10"))
            .and(query_param("sort", "ASC"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 10,
                "data": [
                    {
                        "guid": "msg-001",
                        "text": "hello from bridge",
                        "date_created": 1_700_000_000_100_i64,
                        "is_from_me": false,
                        "handle": {
                            "address": "+15551234567",
                            "display_name": "Alice"
                        },
                        "thread_originator_guid": "root-1",
                        "attachments": []
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_url(&mock_server.uri()))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.unwrap();

        let req = InvokeRequest {
            input: json!({
                "chat_guid": "chat-guid-1",
                "after": 1_700_000_000_000_i64,
                "message_limit": 10
            }),
            capability_token: generate_valid_token(&connector, &signing_key, OP_SYNC_EVENTS),
            ..base_invoke(connector.id(), OP_SYNC_EVENTS)
        };

        let response = connector.invoke(req).await.unwrap();
        let result = response.result.as_ref().unwrap();
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["topic"], "imessage.message.inbound");
        assert_eq!(events[0]["chat_guid"], "chat-guid-1");
        assert_eq!(events[0]["thread"]["thread_originator_guid"], "root-1");
        assert_eq!(result["next_after"], 1_700_000_000_101_i64);
        assert_eq!(result["synced_chats"], 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_dedupes_replay() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let input = json!({
            "account_id": "acct-a",
            "payload": {
                "type": "new-message",
                "data": {
                    "guid": "msg-1",
                    "text": "hello",
                    "handle": { "address": "+15551234567" },
                    "chats": [{ "guid": "iMessage;-;+15551234567" }],
                    "isFromMe": false
                }
            }
        });
        let req = InvokeRequest {
            input: input.clone(),
            capability_token: generate_valid_token(
                &connector,
                &signing_key,
                OP_INGEST_WEBHOOK_EVENT,
            ),
            ..base_invoke(connector.id(), OP_INGEST_WEBHOOK_EVENT)
        };
        let first = connector.invoke(req).await.unwrap();
        let first_result = first.result.as_ref().unwrap();
        assert_eq!(first_result["status"], "accepted");
        assert_eq!(first_result["dedupe_id"], "acct-a:msg-1");
        assert_eq!(first_result["event"]["topic"], "imessage.message.inbound");

        let req = InvokeRequest {
            input,
            capability_token: generate_valid_token(
                &connector,
                &signing_key,
                OP_INGEST_WEBHOOK_EVENT,
            ),
            ..base_invoke(connector.id(), OP_INGEST_WEBHOOK_EVENT)
        };
        let second = connector.invoke(req).await.unwrap();
        assert_eq!(second.result.as_ref().unwrap()["status"], "duplicate");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_register_webhook_posts_when_no_existing_match() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/webhook"))
            .and(query_param("password", "test-password-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": []
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/webhook"))
            .and(query_param("password", "test-password-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": 200,
                "message": "registered",
                "data": {
                    "id": "wh-1",
                    "url": "http://localhost:8645/bluebubbles-webhook?password=secret",
                    "events": ["new-message", "updated-message"]
                }
            })))
            .mount(&mock_server)
            .await;

        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_url(&mock_server.uri()))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();
        let req = InvokeRequest {
            input: json!({
                "url": "http://localhost:8645/bluebubbles-webhook?password=secret"
            }),
            capability_token: generate_valid_token(&connector, &signing_key, OP_REGISTER_WEBHOOK),
            ..base_invoke(connector.id(), OP_REGISTER_WEBHOOK)
        };

        let response = connector.invoke(req).await.unwrap();
        let result = response.result.as_ref().unwrap();
        assert_eq!(result["registration_status"], "registered");
        assert_eq!(result["response"]["data"]["id"], "wh-1");
    }
}
