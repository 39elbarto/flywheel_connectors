//! FCP Slack Connector implementation.

use std::collections::HashSet;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use fcp_async_core::channel::{broadcast, watch};
use fcp_async_core::sync::RwLock;
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, EventData, EventEnvelope, EventInfo, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, IdempotencyClass, Introspection, ObjectId, OperationId,
    OperationInfo, Principal, RiskLevel, SafetyTier, SelfCheckReport, SessionId, SimulateRequest,
    SimulateResponse, ThreadInfo, TrustLevel, ZoneId,
};
use fcp_streaming::{WsClient, WsConnection, WsMessage};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{info, instrument, warn};
use url::Url;

use crate::{
    client::SlackClient,
    error::SlackError,
    types::{DoctorCheck, DoctorReport, OperationReceipt},
};

const SLACK_API_HOST: &str = "slack.com";
const SOCKET_EVENT_BUFFER_CAPACITY: usize = 200;
const SOCKET_TOPIC_COMPONENT_MAX_CHARS: usize = 64;
const SOCKET_SUBSCRIBE_TOPIC_MAX_CHARS: usize = 128;
const SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT: usize = 64;

fn is_local_test_host(host: &str) -> bool {
    (cfg!(test) || cfg!(debug_assertions)) && matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Validate a Slack `base_url` override.
///
/// Direct-token mode pins the host to `slack.com`.
/// Empty/whitespace overrides fall through to the client default upstream.
/// Custom vault-proxy hosts are not supported here -
/// Slack's connector does not yet have a credential_id auth mode.
fn validate_slack_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not be empty".into(),
        });
    }
    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }
    let local = is_local_test_host(host);
    let host_ok = host.eq_ignore_ascii_case(SLACK_API_HOST) || local;
    let scheme_ok = parsed.scheme() == "https" || local;
    if !host_ok || !scheme_ok {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must use https and {SLACK_API_HOST} (localhost/127.0.0.1/::1 allowed only in test/debug builds): {trimmed}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}
const SOCKET_RECONNECT_MIN_MS: u64 = 1_000;
const SOCKET_RECONNECT_MAX_MS: u64 = 30_000;
const SOCKET_DEFAULT_TOPICS: &[&str] = &[
    "slack.message.new",
    "slack.message.edited",
    "slack.message.deleted",
    "slack.reaction.added",
    "slack.reaction.removed",
];

async fn connect_socket_mode_websocket(
    url: &str,
) -> Result<WsConnection, fcp_streaming::StreamError> {
    WsClient::new(url).connect().await
}

/// FCP Slack Connector.
pub struct SlackConnector {
    base: Arc<BaseConnector>,
    client: Option<SlackClient>,
    socket_mode_token: Option<String>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    socket_mode_running: Arc<RwLock<bool>>,
    socket_mode_task: Option<fcp_async_core::task::JoinHandle<()>>,
    socket_mode_shutdown_tx: Option<watch::Sender<bool>>,
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    next_event_seq: Arc<AtomicU64>,
    subscribed_topics: Arc<RwLock<Vec<String>>>,
}

impl SlackConnector {
    /// Create a new Slack connector.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(SOCKET_EVENT_BUFFER_CAPACITY);
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("slack"))),
            client: None,
            socket_mode_token: None,
            verifier: None,
            session_id: None,
            socket_mode_running: Arc::new(RwLock::new(false)),
            socket_mode_task: None,
            socket_mode_shutdown_tx: None,
            event_tx,
            next_event_seq: Arc::new(AtomicU64::new(1)),
            subscribed_topics: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Subscribe to emitted connector events.
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<FcpResult<EventEnvelope>> {
        self.event_tx.subscribe()
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.stop_socket_mode().await;

        let token = params
            .get("token")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing token in configuration".into(),
            })?;

        let base_url = match params.get("base_url").and_then(|v| v.as_str()) {
            Some(raw) => Some(validate_slack_base_url(raw)?),
            None => None,
        };
        let app_token = params
            .get("app_token")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty());
        let socket_mode_token = app_token.unwrap_or(token).to_string();

        let mut client = SlackClient::new(token).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.socket_mode_token = Some(socket_mode_token);
        *self.subscribed_topics.write().await = Vec::new();
        self.base.set_configured(true);
        info!("Slack connector configured");

        Ok(json!({
            "status": "configured",
            "socket_mode_auth": if app_token.is_some() { "app_token" } else { "bot_token_fallback" }
        }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:slack-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: SOCKET_EVENT_BUFFER_CAPACITY as u32,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let socket_mode_running = *self.socket_mode_running.read().await;
        let subscribed_topics = self.subscribed_topics.read().await.clone();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
                "events_emitted": metrics.events_emitted,
            },
            "streaming": {
                "socket_mode_running": socket_mode_running,
                "buffer_capacity": SOCKET_EVENT_BUFFER_CAPACITY,
                "subscribed_topics": subscribed_topics,
            },
        }))
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "slack.post_message",
                    "Post a message to a Slack channel",
                    json!({
                        "type": "object",
                        "required": ["channel", "text"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "text": { "type": "string", "description": "Message text" },
                            "thread_ts": { "type": "string", "description": "Thread timestamp for replies" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a message to a Slack channel.".into(),
                        common_mistakes: vec!["Using channel name instead of channel ID".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "text": "Hello from FCP!"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slack.get_channel_history"),
                            CapabilityId::from_static("slack.reply_thread"),
                        ],
                    },
                ),
                op_info(
                    "slack.reply_thread",
                    "Reply to a thread in a Slack channel",
                    json!({
                        "type": "object",
                        "required": ["channel", "text", "thread_ts"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "text": { "type": "string", "description": "Reply text" },
                            "thread_ts": { "type": "string", "description": "Thread timestamp" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Reply to an existing thread in a Slack channel.".into(),
                        common_mistakes: vec!["Using message ts instead of thread_ts".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "text": "Replying!", "thread_ts": "1234567890.123456"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slack.post_message"),
                            CapabilityId::from_static("slack.get_channel_history"),
                        ],
                    },
                ),
                op_info(
                    "slack.get_channel_history",
                    "Get conversation history for a channel",
                    json!({
                        "type": "object",
                        "required": ["channel"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "limit": { "type": "integer", "description": "Max messages to return" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "messages": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve recent messages from a Slack channel.".into(),
                        common_mistakes: vec!["Not specifying a limit, which defaults to Slack's default".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "limit": 10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slack.post_message"),
                            CapabilityId::from_static("slack.search_messages"),
                        ],
                    },
                ),
                op_info(
                    "slack.search_messages",
                    "Search messages across the workspace",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": { "query": { "type": "string", "description": "Search query" } }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "object" },
                            "total": { "type": "integer" }
                        }
                    }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for messages matching a query across Slack.".into(),
                        common_mistakes: vec!["Using non-Slack search syntax".into()],
                        examples: vec![
                            r#"{"query": "deployment in:#general"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.get_channel_history")],
                    },
                ),
                op_info(
                    "slack.list_channels",
                    "List channels in the workspace",
                    json!({
                        "type": "object",
                        "properties": {
                            "types": { "type": "string", "description": "Comma-separated channel types (public_channel, private_channel, mpim, im)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "channels": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List available channels in a Slack workspace.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"types": "public_channel"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.get_channel_history")],
                    },
                ),
                op_info(
                    "slack.get_user_info",
                    "Get information about a Slack user",
                    json!({
                        "type": "object",
                        "required": ["user"],
                        "properties": {
                            "user": { "type": "string", "description": "User ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "user": { "type": "object" } } }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Look up details about a Slack user by ID.".into(),
                        common_mistakes: vec!["Using display name instead of user ID".into()],
                        examples: vec![
                            r#"{"user": "U01234567"}"#.into(),
                        ],
                        related: vec![],
                    },
                ),
                op_info(
                    "slack.upload_file",
                    "Upload host-resolved object content to Slack channels",
                    json!({
                        "type": "object",
                        "required": ["channels", "content_object_id", "resolved_content"],
                        "properties": {
                            "channels": { "type": "string", "description": "Comma-separated channel IDs" },
                            "content_object_id": { "type": "string", "description": "Source mesh object reference (hex ObjectId)" },
                            "resolved_content": { "type": "string", "description": "Host-materialized content bytes for content_object_id" },
                            "filename": { "type": "string", "description": "Filename to display" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["file", "file_object_id", "source_object_id"],
                        "properties": {
                            "file": { "type": "object" },
                            "file_object_id": { "type": "string" },
                            "source_object_id": { "type": "string" }
                        }
                    }),
                    "slack.files.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Upload content referenced by a mesh object to one or more Slack channels.".into(),
                        common_mistakes: vec![
                            "Forgetting to pass content_object_id".into(),
                            "Not providing host-resolved content for the object reference".into(),
                        ],
                        examples: vec![
                            r#"{"channels":"C01234567","content_object_id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","resolved_content":"log data here","filename":"output.log"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.download_file")],
                    },
                ),
                op_info(
                    "slack.download_file",
                    "Fetch Slack file metadata and emit a content object reference",
                    json!({
                        "type": "object",
                        "required": ["file_id"],
                        "properties": {
                            "file_id": { "type": "string", "description": "Slack file ID" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["file", "content_object_id"],
                        "properties": {
                            "file": { "type": "object" },
                            "content_object_id": { "type": "string" }
                        }
                    }),
                    "slack.files.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get sanitized Slack file metadata plus a deterministic content object reference.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"file_id": "F01234567"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.upload_file")],
                    },
                ),
                op_info(
                    "slack.add_reaction",
                    "Add an emoji reaction to a message",
                    json!({
                        "type": "object",
                        "required": ["channel", "timestamp", "name"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "timestamp": { "type": "string", "description": "Message timestamp" },
                            "name": { "type": "string", "description": "Emoji name without colons" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "ok": { "type": "boolean" } } }),
                    "slack.write",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "React to a Slack message with an emoji.".into(),
                        common_mistakes: vec!["Including colons around the emoji name".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "timestamp": "1234567890.123456", "name": "thumbsup"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.post_message")],
                    },
                ),
                op_info(
                    "slack.set_channel_topic",
                    "Set the topic for a Slack channel",
                    json!({
                        "type": "object",
                        "required": ["channel", "topic"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "topic": { "type": "string", "description": "New channel topic" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "topic": { "type": "string" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Update the topic of a Slack channel.".into(),
                        common_mistakes: vec!["Using channel name instead of ID".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "topic": "Sprint 42 - Deployment day"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.list_channels")],
                    },
                ),
            ],
            events: SOCKET_DEFAULT_TOPICS
                .iter()
                .map(|topic| EventInfo {
                    topic: (*topic).to_string(),
                    schema: json!({ "type": "object" }),
                    requires_ack: false,
                })
                .collect(),
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: SOCKET_EVENT_BUFFER_CAPACITY as u32,
                requires_ack: false,
            }),
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let operation = req.operation.as_str();
        if !is_supported_operation(operation) {
            let error = FcpError::OperationNotGranted {
                operation: operation.into(),
            };
            return Self::serialize_simulate_response(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        let cap_id: CapabilityId = required_capability_for_operation(operation)
            .parse()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid capability ID format".into(),
            })?;

        if let Err(error) = validate_simulate_input(operation, &req.input) {
            return Self::serialize_simulate_response(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        let resource_uris = match resource_uris_for_operation(operation, &req.input) {
            Ok(resource_uris) => resource_uris,
            Err(error) => {
                return Self::serialize_simulate_response(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };

        if self.client.is_none() {
            let error = FcpError::NotConfigured;
            return Self::serialize_simulate_response(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        let Some(verifier) = &self.verifier else {
            let error = FcpError::NotHandshaken;
            return Self::serialize_simulate_response(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        };

        let response = match verifier.verify_bound(
            req.capability_token,
            &cap_id,
            &req.operation,
            &resource_uris,
        ) {
            Ok(_) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let is_grant_mismatch = matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                );
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if is_grant_mismatch {
                    response =
                        response.with_missing_capabilities(vec![cap_id.as_str().to_string()]);
                }
                response
            }
        };

        Self::serialize_simulate_response(response)
    }

    fn serialize_simulate_response(response: SimulateResponse) -> FcpResult<serde_json::Value> {
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle subscribe method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the connector is not configured or socket mode cannot start.
    pub async fn handle_subscribe(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }
        if self.verifier.is_none() {
            return Err(FcpError::NotHandshaken);
        }

        let topics = parse_subscribe_topics(&params);
        {
            let mut subscribed = self.subscribed_topics.write().await;
            (*subscribed).clone_from(&topics);
        }

        let started = self.ensure_socket_mode_running().await?;
        Ok(json!({
            "confirmed_topics": topics,
            "replay_supported": false,
            "buffer": {
                "min_events": SOCKET_EVENT_BUFFER_CAPACITY,
                "overflow": "stream.reset"
            },
            "connection_status": if started { "started" } else { "already_running" }
        }))
    }

    async fn ensure_socket_mode_running(&mut self) -> FcpResult<bool> {
        if let Some(task) = &self.socket_mode_task
            && !task.is_finished()
            && *self.socket_mode_running.read().await
        {
            return Ok(false);
        }

        self.stop_socket_mode().await;

        let http_client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let socket_mode_token =
            self.socket_mode_token
                .clone()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Socket Mode token not configured".into(),
                })?;

        let mut socket_client =
            SlackClient::new(socket_mode_token).map_err(|e| FcpError::Internal {
                message: format!("Failed to create Socket Mode HTTP client: {e}"),
            })?;
        socket_client = socket_client.with_base_url(http_client.base_url().to_string());

        let event_tx = self.event_tx.clone();
        let connector_id = self.base.id.clone();
        let instance_id = self.base.instance_id.clone();
        let base = self.base.clone();
        let socket_mode_running = self.socket_mode_running.clone();
        let next_event_seq = self.next_event_seq.clone();
        let subscribed_topics = self.subscribed_topics.clone();

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        self.socket_mode_shutdown_tx = Some(shutdown_tx.clone());
        *self.socket_mode_running.write().await = true;

        let task = fcp_async_core::task::spawn(async move {
            info!("Starting Slack Socket Mode event loop");
            let mut reconnect_delay_ms = SOCKET_RECONNECT_MIN_MS;

            loop {
                if *shutdown_rx.borrow() {
                    break;
                }

                let ws_url = match socket_client.open_socket_mode_connection().await {
                    Ok(url) => url,
                    Err(err) => {
                        warn!("Socket Mode URL open failed: {err}");
                        if fcp_async_core::shutdown::sleep_or_shutdown(
                            Duration::from_millis(reconnect_delay_ms),
                            &mut shutdown_rx,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                        reconnect_delay_ms = (reconnect_delay_ms * 2).min(SOCKET_RECONNECT_MAX_MS);
                        continue;
                    }
                };

                match connect_socket_mode_websocket(&ws_url).await {
                    Ok(mut ws_stream) => {
                        reconnect_delay_ms = SOCKET_RECONNECT_MIN_MS;

                        loop {
                            fcp_async_core::select! {
                                changed = shutdown_rx.changed() => {
                                    if changed.is_ok() && *shutdown_rx.borrow() {
                                        let _ = ws_stream.close().await;
                                        break;
                                    }
                                    if changed.is_err() {
                                        break;
                                    }
                                },
                                inbound = ws_stream.recv() => {
                                    let frame = match inbound {
                                        Ok(Some(frame)) => frame,
                                        Ok(None) => break,
                                        Err(err) => {
                                            warn!("Socket Mode websocket receive error: {err}");
                                            break;
                                        }
                                    };

                                    match frame {
                                        WsMessage::Text(text) => {
                                            let parsed_frame: SocketModeFrame = match serde_json::from_str(&text) {
                                                Ok(frame) => frame,
                                                Err(err) => {
                                                    warn!("Socket Mode frame parse failed: {err}");
                                                    continue;
                                                }
                                            };

                                            if parsed_frame.frame_type == "hello" {
                                                continue;
                                            }

                                            if let Some(envelope_id) = parsed_frame.envelope_id.as_deref() {
                                                let ack = json!({ "envelope_id": envelope_id }).to_string();
                                                if let Err(err) = ws_stream.send_text(ack).await {
                                                    warn!("Socket Mode ack send failed: {err}");
                                                    break;
                                                }
                                            }

                                            let payload = parsed_frame.payload.unwrap_or_else(|| json!({}));
                                            let topic = socket_frame_topic(&parsed_frame.frame_type, &payload);
                                            let allowed = {
                                                let subscribed = subscribed_topics.read().await;
                                                topic_allowed(&topic, subscribed.as_slice())
                                            };
                                            if !allowed {
                                                continue;
                                            }

                                            let seq = next_event_seq.fetch_add(1, Ordering::Relaxed);
                                            let event = socket_frame_to_event(
                                                &parsed_frame.frame_type,
                                                parsed_frame.envelope_id.as_deref(),
                                                &payload,
                                                &connector_id,
                                                &instance_id,
                                                seq,
                                            );
                                            base.record_event();
                                            if event_tx.send(Ok(event)).is_err() {
                                                warn!("Socket Mode event dropped: no active subscribers");
                                            }
                                        }
                                        WsMessage::Ping(data) => {
                                            if let Err(err) = ws_stream.send(WsMessage::Pong(data)).await {
                                                warn!("Socket Mode pong send failed: {err}");
                                                break;
                                            }
                                        }
                                        WsMessage::Close(_frame) => {
                                            break;
                                        }
                                        WsMessage::Binary(_) | WsMessage::Pong(_) => {
                                            // ignore non-text control/data frames for socket-mode events
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        warn!("Socket Mode websocket connect failed: {err}");
                    }
                }

                if fcp_async_core::shutdown::sleep_or_shutdown(
                    Duration::from_millis(reconnect_delay_ms),
                    &mut shutdown_rx,
                )
                .await
                .is_err()
                {
                    break;
                }
                reconnect_delay_ms = (reconnect_delay_ms * 2).min(SOCKET_RECONNECT_MAX_MS);
            }

            *socket_mode_running.write().await = false;
            info!("Slack Socket Mode event loop stopped");
        });

        self.socket_mode_task = Some(task);
        Ok(true)
    }

    async fn stop_socket_mode(&mut self) {
        if let Some(shutdown_tx) = self.socket_mode_shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }

        if let Some(task) = self.socket_mode_task.take() {
            if let Err(err) = task.await {
                warn!("Socket Mode task join failed: {err}");
            }
        }

        *self.socket_mode_running.write().await = false;
    }

    /// Handle invoke method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = required_capability_for_operation(operation)
            .parse()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid capability ID format".into(),
            })?;

        let resource_uris = resource_uris_for_operation(operation, &input)?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(token, &cap_id, &op_id, &resource_uris)?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "slack.post_message" => self.invoke_post_message(input).await,
            "slack.reply_thread" => self.invoke_reply_thread(input).await,
            "slack.get_channel_history" => self.invoke_get_channel_history(input).await,
            "slack.search_messages" => self.invoke_search_messages(input).await,
            "slack.list_channels" => self.invoke_list_channels(input).await,
            "slack.get_user_info" => self.invoke_get_user_info(input).await,
            "slack.upload_file" => self.invoke_upload_file(input).await,
            "slack.download_file" => self.invoke_download_file(input).await,
            "slack.add_reaction" => self.invoke_add_reaction(input).await,
            "slack.set_channel_topic" => self.invoke_set_channel_topic(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_post_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let text = require_str(&input, "text")?;
        let thread_ts = input.get("thread_ts").and_then(|v| v.as_str());

        let message = client
            .post_message(channel, text, thread_ts)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.post_message".into(),
            effect: "message_created".into(),
            resource: format!("channel:{channel}"),
            timestamp: message.ts.clone(),
        };

        Ok(json!({ "message": message, "receipt": receipt }))
    }

    async fn invoke_reply_thread(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let text = require_str(&input, "text")?;
        let thread_ts = require_str(&input, "thread_ts")?;

        let message = client
            .post_message(channel, text, Some(thread_ts))
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.reply_thread".into(),
            effect: "thread_reply_created".into(),
            resource: format!("channel:{channel}:thread:{thread_ts}"),
            timestamp: message.ts.clone(),
        };

        Ok(json!({ "message": message, "receipt": receipt }))
    }

    async fn invoke_get_channel_history(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let messages = client
            .get_channel_history(channel, limit)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "messages": messages }))
    }

    async fn invoke_search_messages(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;

        let results = client
            .search_messages(query)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let total = results.messages.total;
        Ok(json!({
            "messages": results.messages,
            "total": total
        }))
    }

    async fn invoke_list_channels(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let types = input.get("types").and_then(|v| v.as_str());

        let channels = client
            .list_channels(types)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "channels": channels }))
    }

    async fn invoke_get_user_info(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user = require_str(&input, "user")?;

        let user_info = client
            .get_user_info(user)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "user": user_info }))
    }

    async fn invoke_upload_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channels = require_str(&input, "channels")?;
        let source_object_id = require_object_id_str(&input, "content_object_id")?;
        let content = require_str(&input, "resolved_content")?;
        let filename = input.get("filename").and_then(|v| v.as_str());

        let file = client
            .upload_file(channels, content, filename)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;
        let file_object_id = derive_slack_file_object_id("upload", &file.id, source_object_id);
        let redacted_file = redact_file_urls(file);

        let receipt = OperationReceipt {
            operation: "slack.upload_file".into(),
            effect: "file_uploaded".into(),
            resource: format!("file_object:{file_object_id}"),
            timestamp: String::new(),
        };

        Ok(json!({
            "file": redacted_file,
            "file_object_id": file_object_id.to_string(),
            "source_object_id": source_object_id,
            "receipt": receipt
        }))
    }

    async fn invoke_download_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;

        let file = client
            .get_file_info(file_id)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;
        let content_object_id = derive_slack_file_object_id("download", &file.id, "slack");
        let redacted_file = redact_file_urls(file);

        Ok(json!({
            "file": redacted_file,
            "content_object_id": content_object_id.to_string()
        }))
    }

    async fn invoke_add_reaction(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let timestamp = require_str(&input, "timestamp")?;
        let name = require_str(&input, "name")?;

        client
            .add_reaction(channel, timestamp, name)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.add_reaction".into(),
            effect: "reaction_added".into(),
            resource: format!("channel:{channel}:message:{timestamp}"),
            timestamp: timestamp.to_string(),
        };

        Ok(json!({ "ok": true, "receipt": receipt }))
    }

    async fn invoke_set_channel_topic(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let topic = require_str(&input, "topic")?;

        let result = client
            .set_channel_topic(channel, topic)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.set_channel_topic".into(),
            effect: "topic_updated".into(),
            resource: format!("channel:{channel}"),
            timestamp: String::new(),
        };

        Ok(json!({ "topic": result, "receipt": receipt }))
    }

    /// Required OAuth scopes for core connector functionality.
    ///
    /// Read scopes allow channel/user/message listing.
    /// Write scopes allow posting messages and reactions.
    const REQUIRED_SCOPES: &'static [&'static str] = &[
        "channels:read",
        "channels:history",
        "chat:write",
        "users:read",
    ];

    /// Handle doctor readiness check.
    ///
    /// Validates:
    /// 1. Token is present (client configured)
    /// 2. Token is valid (auth.test succeeds)
    /// 3. Required OAuth scopes are granted
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the doctor report fails.
    #[instrument(skip(self))]
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // Check 1: Client configured (token present)
        let client_present = self.client.is_some();
        checks.push(DoctorCheck {
            name: "token_present".into(),
            passed: client_present,
            message: if client_present {
                "Bot token is configured".into()
            } else {
                "No token configured — call configure with a valid bot token".into()
            },
        });

        // If no client, remaining checks cannot proceed.
        if !client_present {
            let report = DoctorReport {
                ready: false,
                checks,
            };
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize doctor report: {e}"),
            });
        }

        let client = self.client.as_ref().expect("checked above");

        // Check 2: Token validity via auth.test (also proves network reachability)
        match client.auth_test().await {
            Ok((auth_info, scopes)) => {
                checks.push(DoctorCheck {
                    name: "token_valid".into(),
                    passed: true,
                    message: format!(
                        "Token valid — team: {} ({}), user: {} ({})",
                        auth_info.team, auth_info.team_id, auth_info.user, auth_info.user_id
                    ),
                });

                // Check 3: Required scopes
                let missing = SlackClient::validate_scopes(&scopes, Self::REQUIRED_SCOPES);
                if missing.is_empty() {
                    checks.push(DoctorCheck {
                        name: "scopes_valid".into(),
                        passed: true,
                        message: format!("All required scopes granted ({})", scopes.join(", ")),
                    });
                } else {
                    checks.push(DoctorCheck {
                        name: "scopes_valid".into(),
                        passed: false,
                        message: format!(
                            "Missing required scopes: {}. Granted: {}",
                            missing.join(", "),
                            scopes.join(", ")
                        ),
                    });
                }
            }
            Err(e) => {
                let is_auth = matches!(
                    &e,
                    SlackError::Api { error, .. }
                        if error == "not_authed" || error == "invalid_auth" || error == "token_revoked"
                );
                checks.push(DoctorCheck {
                    name: "token_valid".into(),
                    passed: false,
                    message: if is_auth {
                        format!("Token invalid or revoked: {e}")
                    } else {
                        format!("auth.test failed (network or server issue): {e}")
                    },
                });
                // Skip scope check since auth failed
                checks.push(DoctorCheck {
                    name: "scopes_valid".into(),
                    passed: false,
                    message: "Cannot validate scopes — auth.test failed".into(),
                });
            }
        }

        let all_passed = checks.iter().all(|c| c.passed);
        let report = DoctorReport {
            ready: all_passed,
            checks,
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor report: {e}"),
        })
    }

    /// Handle connector self-check.
    ///
    /// Validates token and API reachability via auth.test.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the self-check report fails.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let report = match client.auth_test().await {
            Ok((auth_info, scopes)) => {
                let missing = SlackClient::validate_scopes(&scopes, Self::REQUIRED_SCOPES);
                if missing.is_empty() {
                    let mut report = SelfCheckReport::ok();
                    report.details = Some(json!({
                        "token_ok": true,
                        "team": auth_info.team,
                        "team_id": auth_info.team_id,
                        "user": auth_info.user,
                        "scopes_ok": true,
                    }));
                    report
                } else {
                    let mut report = SelfCheckReport::failed(
                        "provisioning_scopes_missing",
                        format!("Missing required scopes: {}", missing.join(", ")),
                    );
                    report.details = Some(json!({
                        "token_ok": true,
                        "team": auth_info.team,
                        "scopes_ok": false,
                        "missing_scopes": missing,
                        "granted_scopes": scopes,
                    }));
                    report
                }
            }
            Err(e) => {
                if e.is_retryable() {
                    SelfCheckReport::degraded("api_transient_error", e.to_string())
                } else {
                    SelfCheckReport::failed("provisioning_token_invalid", e.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.stop_socket_mode().await;
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Slack connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for SlackConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct SocketModeFrame {
    #[serde(rename = "type", default)]
    frame_type: String,
    #[serde(default)]
    envelope_id: Option<String>,
    #[serde(default)]
    payload: Option<Value>,
}

fn parse_subscribe_topics(params: &serde_json::Value) -> Vec<String> {
    let mut topics = params
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|topic| !topic.is_empty())
                .filter(|topic| is_valid_subscribe_topic_pattern(topic))
                .take(SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if topics.is_empty() {
        topics = SOCKET_DEFAULT_TOPICS
            .iter()
            .map(|topic| (*topic).to_string())
            .collect();
    }

    let mut dedup = HashSet::new();
    topics
        .into_iter()
        .filter(|topic| dedup.insert(topic.clone()))
        .collect()
}

fn is_valid_subscribe_topic_pattern(topic: &str) -> bool {
    if topic.len() > SOCKET_SUBSCRIBE_TOPIC_MAX_CHARS {
        return false;
    }
    if topic == "*" {
        return true;
    }

    let component = topic.strip_suffix('*').unwrap_or(topic);
    !component.is_empty()
        && component
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn topic_allowed(topic: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }

    patterns.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return topic.starts_with(prefix);
        }
        pattern == topic
    })
}

fn socket_frame_topic(frame_type: &str, payload: &Value) -> String {
    if frame_type != "events_api" {
        return match frame_type {
            "interactive" => "slack.interactive".to_string(),
            "slash_commands" => "slack.command".to_string(),
            "disconnect" => "slack.disconnect".to_string(),
            "hello" => "slack.hello".to_string(),
            _ => format!(
                "slack.socket.{}",
                safe_socket_topic_component(frame_type).unwrap_or("unknown")
            ),
        };
    }

    let event_type = payload
        .get("event")
        .and_then(|event| event.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    match event_type {
        "message" => {
            let subtype = payload
                .get("event")
                .and_then(|event| event.get("subtype"))
                .and_then(Value::as_str);
            match subtype {
                Some("message_changed") => "slack.message.edited".to_string(),
                Some("message_deleted") => "slack.message.deleted".to_string(),
                _ => "slack.message.new".to_string(),
            }
        }
        "reaction_added" => "slack.reaction.added".to_string(),
        "reaction_removed" => "slack.reaction.removed".to_string(),
        _ => format!(
            "slack.event.{}",
            safe_socket_topic_component(event_type).unwrap_or("unknown")
        ),
    }
}

fn safe_socket_topic_component(raw: &str) -> Option<&str> {
    if raw.is_empty() || raw.len() > SOCKET_TOPIC_COMPONENT_MAX_CHARS {
        return None;
    }
    raw.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .then_some(raw)
}

fn socket_frame_to_event(
    frame_type: &str,
    envelope_id: Option<&str>,
    payload: &Value,
    connector_id: &ConnectorId,
    instance_id: &fcp_core::InstanceId,
    seq: u64,
) -> EventEnvelope {
    let topic = socket_frame_topic(frame_type, payload);
    let principal = socket_payload_principal(payload);
    let cursor = payload
        .get("event_id")
        .and_then(Value::as_str)
        .or(envelope_id)
        .map_or_else(|| seq.to_string(), str::to_owned);

    let mut resource_uris = Vec::new();
    if let Some(channel) = payload
        .get("event")
        .and_then(|event| event.get("channel"))
        .and_then(Value::as_str)
        .or_else(|| payload.get("channel").and_then(Value::as_str))
    {
        resource_uris.push(format!("slack:channel:{channel}"));
    }
    if let Some(team_id) = payload.get("team_id").and_then(Value::as_str) {
        resource_uris.push(format!("slack:team:{team_id}"));
    }

    let event_data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        ZoneId::community(),
        principal,
        payload.clone(),
    )
    .with_resource_uris(resource_uris);
    let event_data = if let Some(thread_info) = socket_payload_thread_info(payload) {
        event_data.with_thread_info(thread_info)
    } else {
        event_data
    };

    EventEnvelope::new(topic, event_data)
        .with_seq(seq)
        .with_cursor(cursor)
}

fn socket_payload_thread_info(payload: &Value) -> Option<ThreadInfo> {
    let event = payload.get("event")?;
    let thread_ts = event
        .get("thread_ts")
        .and_then(Value::as_str)
        .or_else(|| {
            event
                .get("message")
                .and_then(|message| message.get("thread_ts"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            event
                .get("previous_message")
                .and_then(|message| message.get("thread_ts"))
                .and_then(Value::as_str)
        })?;

    Some(ThreadInfo::from_slack_thread(thread_ts, None))
}

fn socket_payload_principal(payload: &Value) -> Principal {
    if let Some(user_id) = payload
        .get("event")
        .and_then(|event| event.get("user"))
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("user")
                .and_then(|user| user.get("id"))
                .and_then(Value::as_str)
        })
        .or_else(|| payload.get("user_id").and_then(Value::as_str))
    {
        return Principal {
            kind: "slack_user".into(),
            id: user_id.to_string(),
            trust: TrustLevel::Untrusted,
            display: payload
                .get("user")
                .and_then(|user| user.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
    }

    if let Some(bot_id) = payload
        .get("event")
        .and_then(|event| event.get("bot_id"))
        .and_then(Value::as_str)
        .or_else(|| payload.get("bot_id").and_then(Value::as_str))
    {
        return Principal {
            kind: "slack_bot".into(),
            id: bot_id.to_string(),
            trust: TrustLevel::Untrusted,
            display: None,
        };
    }

    Principal {
        kind: "slack_actor".into(),
        id: "unknown".into(),
        trust: TrustLevel::Untrusted,
        display: None,
    }
}

fn required_capability_for_operation(operation: &str) -> &str {
    match operation {
        "slack.upload_file" => "slack.files.write",
        "slack.download_file" => "slack.files.read",
        _ => operation,
    }
}

fn is_supported_operation(operation: &str) -> bool {
    matches!(
        operation,
        "slack.post_message"
            | "slack.reply_thread"
            | "slack.get_channel_history"
            | "slack.search_messages"
            | "slack.list_channels"
            | "slack.get_user_info"
            | "slack.upload_file"
            | "slack.download_file"
            | "slack.add_reaction"
            | "slack.set_channel_topic"
    )
}

fn validate_simulate_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    match operation {
        "slack.post_message" => {
            require_str(input, "channel")?;
            require_str(input, "text")?;
        }
        "slack.reply_thread" => {
            require_str(input, "channel")?;
            require_str(input, "text")?;
            require_str(input, "thread_ts")?;
        }
        "slack.get_channel_history" | "slack.set_channel_topic" => {
            require_str(input, "channel")?;
            if operation == "slack.set_channel_topic" {
                require_str(input, "topic")?;
            }
        }
        "slack.search_messages" => {
            require_str(input, "query")?;
        }
        "slack.get_user_info" => {
            require_str(input, "user")?;
        }
        "slack.upload_file" => {
            require_str(input, "channels")?;
            require_object_id_str(input, "content_object_id")?;
            require_str(input, "resolved_content")?;
        }
        "slack.download_file" => {
            require_str(input, "file_id")?;
        }
        "slack.add_reaction" => {
            require_str(input, "channel")?;
            require_str(input, "timestamp")?;
            require_str(input, "name")?;
        }
        "slack.list_channels" => {}
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    }
    Ok(())
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    let mut resource_uris = Vec::new();

    let mut push_unique = |uri: String| {
        if !resource_uris.contains(&uri) {
            resource_uris.push(uri);
        }
    };

    match operation {
        "slack.post_message" => {
            let channel = require_str(input, "channel")?;
            push_unique(format!("slack:channel:{channel}"));
            if let Some(thread_ts) = input.get("thread_ts").and_then(|v| v.as_str()) {
                push_unique(format!("slack:thread:{channel}:{thread_ts}"));
            }
        }
        "slack.reply_thread" => {
            let channel = require_str(input, "channel")?;
            let thread_ts = require_str(input, "thread_ts")?;
            push_unique(format!("slack:channel:{channel}"));
            push_unique(format!("slack:thread:{channel}:{thread_ts}"));
        }
        "slack.get_channel_history" | "slack.set_channel_topic" => {
            let channel = require_str(input, "channel")?;
            push_unique(format!("slack:channel:{channel}"));
        }
        "slack.get_user_info" => {
            let user = require_str(input, "user")?;
            push_unique(format!("slack:user:{user}"));
        }
        "slack.upload_file" => {
            let channels = require_str(input, "channels")?;
            for channel in channels
                .split(',')
                .map(str::trim)
                .filter(|channel| !channel.is_empty())
            {
                push_unique(format!("slack:channel:{channel}"));
            }
        }
        "slack.download_file" => {
            let file_id = require_str(input, "file_id")?;
            push_unique(format!("slack:file:{file_id}"));
        }
        "slack.add_reaction" => {
            let channel = require_str(input, "channel")?;
            let timestamp = require_str(input, "timestamp")?;
            push_unique(format!("slack:channel:{channel}"));
            push_unique(format!("slack:message:{channel}:{timestamp}"));
        }
        "slack.search_messages" | "slack.list_channels" => {}
        _ => {}
    }

    Ok(resource_uris)
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn require_object_id_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    let object_id = require_str(input, field)?;
    if object_id.len() != 64 || !object_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Field `{field}` must be a 64-char hex ObjectId"),
        });
    }
    Ok(object_id)
}

fn derive_slack_file_object_id(namespace: &str, file_id: &str, seed: &str) -> ObjectId {
    let material = format!("slack:{namespace}:{file_id}:{seed}");
    ObjectId::from_unscoped_bytes(material.as_bytes())
}

fn redact_file_urls(mut file: crate::types::SlackFile) -> crate::types::SlackFile {
    file.url_private = None;
    file.url_private_download = None;
    file
}

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_prelude::CapabilityConstraints;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn validate_slack_base_url_accepts_slack_com() {
        let normalized =
            validate_slack_base_url("https://slack.com/api/").expect("slack.com/api is allowed");
        assert_eq!(normalized, "https://slack.com/api");
    }

    #[test]
    fn validate_slack_base_url_allows_localhost_http_for_tests() {
        validate_slack_base_url("http://localhost:8080").expect("localhost permitted for tests");
        validate_slack_base_url("http://127.0.0.1/api").expect("127.0.0.1 permitted for tests");
    }

    #[test]
    fn validate_slack_base_url_rejects_other_hosts() {
        let err = validate_slack_base_url("https://evil.example.com/api").unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("slack.com"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_slack_base_url_rejects_plain_http_on_public_host() {
        let err = validate_slack_base_url("http://slack.com/api").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_slack_base_url_rejects_substring_smuggle() {
        // "api.slack.com" subdomain-like smuggling via evil host containing the string
        let err = validate_slack_base_url("https://evil.com/slack.com").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_slack_base_url_rejects_userinfo_query_and_fragment() {
        let userinfo = validate_slack_base_url("https://bot:secret@slack.com/api").unwrap_err();
        assert!(matches!(
            userinfo,
            FcpError::InvalidRequest { ref message, .. } if message.contains("userinfo")
        ));

        let query = validate_slack_base_url("https://slack.com/api?trace=1").unwrap_err();
        assert!(matches!(
            query,
            FcpError::InvalidRequest { ref message, .. } if message.contains("query")
        ));

        let fragment = validate_slack_base_url("https://slack.com/api#token").unwrap_err();
        assert!(matches!(
            fragment,
            FcpError::InvalidRequest { ref message, .. } if message.contains("fragment")
        ));
    }

    #[test]
    fn validate_slack_base_url_rejects_empty() {
        let err = validate_slack_base_url("   ").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    fn run_with_test_runtime<F, T>(future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("build sync test runtime")
    }

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        generate_token_with_resources(signing_key, cap, &["*"])
    }

    fn generate_token_with_resources(
        signing_key: &Ed25519SigningKey,
        cap: &str,
        resource_allow: &[&str],
    ) -> CapabilityToken {
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: resource_allow
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .constraints_cbor(&cbor)
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn simulate_request(
        signing_key: &Ed25519SigningKey,
        cap: &str,
        operation: &'static str,
        input: serde_json::Value,
        resource_allow: &[&str],
    ) -> serde_json::Value {
        let req = SimulateRequest::new(
            ConnectorId::from_static("slack"),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            generate_token_with_resources(signing_key, cap, resource_allow),
        );
        serde_json::to_value(req).expect("serialize simulate request")
    }

    #[test]
    fn test_resource_uris_for_operation_bind_slack_targets() {
        let uris = resource_uris_for_operation(
            "slack.reply_thread",
            &json!({
                "channel": "C123",
                "thread_ts": "171234.5678"
            }),
        )
        .unwrap();
        assert_eq!(
            uris,
            vec![
                "slack:channel:C123".to_string(),
                "slack:thread:C123:171234.5678".to_string()
            ]
        );

        let uris = resource_uris_for_operation(
            "slack.upload_file",
            &json!({
                "channels": "C111, C222,C111",
                "content_object_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "resolved_content": "hello"
            }),
        )
        .unwrap();
        assert_eq!(
            uris,
            vec![
                "slack:channel:C111".to_string(),
                "slack:channel:C222".to_string()
            ]
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = SlackConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_without_config_denied() {
        let connector = SlackConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "slack.post_message",
                    "slack.post_message",
                    json!({"channel": "C123", "text": "hello"}),
                    &["*"],
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-5002"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_before_handshake_denied() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "slack.post_message",
                    "slack.post_message",
                    json!({"channel": "C123", "text": "hello"}),
                    &["*"],
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-5003"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_subscribe_before_handshake_denied() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );
        connector.socket_mode_token = Some("xapp-test-token".to_string());
        connector.base.set_configured(true);

        let err = connector
            .handle_subscribe(json!({ "topics": ["slack.message.new"] }))
            .await
            .unwrap_err();

        assert!(matches!(err, FcpError::NotHandshaken));
        assert!(!*connector.socket_mode_running.read().await);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_missing_required_input_denied() {
        let connector = SlackConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "slack.post_message",
                    "slack.post_message",
                    json!({"channel": "C123"}),
                    &["*"],
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-1003"));
        assert!(
            response
                .failure_reason
                .as_deref()
                .unwrap_or_default()
                .contains("text")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_unknown_operation_denied() {
        let connector = SlackConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "slack.noop",
                    "slack.noop",
                    json!({}),
                    &["*"],
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-3003"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_known_operation_allowed() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.post_message"]
            }))
            .await
            .unwrap();

        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "slack.post_message",
                    "slack.post_message",
                    json!({"channel": "C123", "text": "hello"}),
                    &["*"],
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(response.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_channel_outside_resource_allow() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.post_message"]
            }))
            .await
            .unwrap();

        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "slack.post_message",
                    "slack.post_message",
                    json!({"channel": "C-denied", "text": "hello"}),
                    &["slack:channel:C-allowed"],
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-3004"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = SlackConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = SlackConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.list_channels"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "slack.list_channels");

        let result = connector
            .handle_invoke(json!({
                "operation": "slack.list_channels",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.post_message"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "slack.post_message");

        let result = connector
            .handle_invoke(json!({
                "operation": "slack.post_message",
                "input": { "channel": "C01234567" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("text"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rejects_channel_outside_resource_allow() {
        let mut connector = SlackConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.post_message"]
            }))
            .await
            .unwrap();

        let token = generate_token_with_resources(
            &signing_key,
            "slack.post_message",
            &["slack:channel:C-allowed"],
        );

        let err = connector
            .handle_invoke(json!({
                "operation": "slack.post_message",
                "input": {
                    "channel": "C-denied",
                    "text": "hello"
                },
                "capability_token": token
            }))
            .await
            .unwrap_err();

        match err {
            FcpError::ResourceNotAllowed { resource } => {
                assert_eq!(resource, "slack:channel:C-denied");
            }
            other => panic!("expected ResourceNotAllowed, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"slack.post_message"));
        assert!(op_ids.contains(&"slack.reply_thread"));
        assert!(op_ids.contains(&"slack.get_channel_history"));
        assert!(op_ids.contains(&"slack.search_messages"));
        assert!(op_ids.contains(&"slack.list_channels"));
        assert!(op_ids.contains(&"slack.get_user_info"));
        assert!(op_ids.contains(&"slack.upload_file"));
        assert!(op_ids.contains(&"slack.download_file"));
        assert!(op_ids.contains(&"slack.add_reaction"));
        assert!(op_ids.contains(&"slack.set_channel_topic"));
        assert_eq!(ops.len(), 10);
    }

    // ── Doctor / Provisioning tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = SlackConnector::new();
        let result = connector.handle_doctor().await.unwrap();

        assert!(!result["ready"].as_bool().unwrap());
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0]["name"], "token_present");
        assert!(!checks[0]["passed"].as_bool().unwrap());
    }

    #[test]
    fn test_doctor_valid_token_all_scopes() {
        run_with_test_runtime(async {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/auth.test"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header(
                            "x-oauth-scopes",
                            "channels:read,channels:history,chat:write,users:read,reactions:write",
                        )
                        .set_body_json(json!({
                            "ok": true,
                            "url": "https://test-workspace.slack.com/",
                            "team": "Test Workspace",
                            "user": "testbot",
                            "team_id": "T00000001",
                            "user_id": "U00000001",
                            "bot_id": "B00000001",
                            "is_enterprise_install": false
                        })),
                )
                .mount(&mock_server)
                .await;

            let mut connector = SlackConnector::new();
            connector.client = Some(
                SlackClient::new("xoxb-test-token")
                    .unwrap()
                    .with_base_url(mock_server.uri()),
            );

            let result = connector.handle_doctor().await.unwrap();

            assert!(result["ready"].as_bool().unwrap());
            let checks = result["checks"].as_array().unwrap();
            assert_eq!(checks.len(), 3);

            for check in checks {
                assert!(
                    check["passed"].as_bool().unwrap(),
                    "Check {} failed: {}",
                    check["name"],
                    check["message"]
                );
            }
        });
    }

    #[test]
    fn test_doctor_missing_scopes() {
        run_with_test_runtime(async {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/auth.test"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("x-oauth-scopes", "channels:read")
                        .set_body_json(json!({
                            "ok": true,
                            "url": "https://test.slack.com/",
                            "team": "Test",
                            "user": "bot",
                            "team_id": "T1",
                            "user_id": "U1"
                        })),
                )
                .mount(&mock_server)
                .await;

            let mut connector = SlackConnector::new();
            connector.client = Some(
                SlackClient::new("xoxb-test")
                    .unwrap()
                    .with_base_url(mock_server.uri()),
            );

            let result = connector.handle_doctor().await.unwrap();

            assert!(!result["ready"].as_bool().unwrap());
            let checks = result["checks"].as_array().unwrap();

            let scope_check = checks.iter().find(|c| c["name"] == "scopes_valid").unwrap();
            assert!(!scope_check["passed"].as_bool().unwrap());
            let msg = scope_check["message"].as_str().unwrap();
            assert!(msg.contains("channels:history"));
            assert!(msg.contains("chat:write"));
            assert!(msg.contains("users:read"));
        });
    }

    #[test]
    fn test_doctor_invalid_token() {
        run_with_test_runtime(async {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/auth.test"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "ok": false,
                    "error": "invalid_auth"
                })))
                .mount(&mock_server)
                .await;

            let mut connector = SlackConnector::new();
            connector.client = Some(
                SlackClient::new("xoxb-bad-token")
                    .unwrap()
                    .with_base_url(mock_server.uri()),
            );

            let result = connector.handle_doctor().await.unwrap();

            assert!(!result["ready"].as_bool().unwrap());
            let checks = result["checks"].as_array().unwrap();

            let token_check = checks.iter().find(|c| c["name"] == "token_valid").unwrap();
            assert!(!token_check["passed"].as_bool().unwrap());
            assert!(token_check["message"].as_str().unwrap().contains("invalid"));
        });
    }

    #[test]
    fn test_validate_scopes_all_present() {
        let granted: Vec<String> = vec![
            "channels:read".into(),
            "channels:history".into(),
            "chat:write".into(),
            "users:read".into(),
        ];
        let missing = SlackClient::validate_scopes(&granted, &["channels:read", "chat:write"]);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_validate_scopes_some_missing() {
        let granted: Vec<String> = vec!["channels:read".into()];
        let missing =
            SlackClient::validate_scopes(&granted, &["channels:read", "chat:write", "users:read"]);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"chat:write".to_string()));
        assert!(missing.contains(&"users:read".to_string()));
    }

    // ── Schema completeness tests ────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_ops_have_input_and_output_schemas() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                op.get("input_schema").is_some(),
                "{id} missing input_schema"
            );
            assert!(
                op.get("output_schema").is_some(),
                "{id} missing output_schema"
            );
            assert_eq!(
                op["input_schema"]["type"].as_str().unwrap(),
                "object",
                "{id} input_schema should be object type"
            );
            assert_eq!(
                op["output_schema"]["type"].as_str().unwrap(),
                "object",
                "{id} output_schema should be object type"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_is_deterministic() {
        let connector = SlackConnector::new();
        let r1 = connector.handle_introspect().await.unwrap();
        let r2 = connector.handle_introspect().await.unwrap();
        assert_eq!(r1, r2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_no_duplicate_operation_ids() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            assert!(seen.insert(*id), "Duplicate operation ID: {id}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_unknown_operation_returns_none() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert!(
            !ops.iter()
                .map(|o| o["id"].as_str().unwrap())
                .any(|x| x == "slack.nonexistent")
        );
    }

    // ── Introspection metadata tests ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_ops_have_required_metadata() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(op.get("summary").is_some(), "{id} missing summary");
            assert!(
                !op["summary"].as_str().unwrap().is_empty(),
                "{id} empty summary"
            );
            assert!(op.get("capability").is_some(), "{id} missing capability");
            assert!(op.get("risk_level").is_some(), "{id} missing risk_level");
            assert!(op.get("safety_tier").is_some(), "{id} missing safety_tier");
            assert!(op.get("idempotency").is_some(), "{id} missing idempotency");
            assert!(op.get("ai_hints").is_some(), "{id} missing ai_hints");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_valid_risk_levels() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let valid = ["low", "medium", "high", "critical"];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&risk), "{id} has invalid risk_level: {risk}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_valid_safety_tiers() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let valid = ["safe", "risky", "dangerous"];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                valid.contains(&tier),
                "{id} has invalid safety_tier: {tier}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_ai_hints_have_when_to_use() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let hints = &op["ai_hints"];
            assert!(
                hints.get("when_to_use").is_some(),
                "{id} ai_hints missing when_to_use"
            );
            assert!(
                !hints["when_to_use"].as_str().unwrap().is_empty(),
                "{id} ai_hints has empty when_to_use"
            );
        }
    }

    // ── Capability mapping tests ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_capabilities_start_with_slack() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("slack."),
                "{id} capability '{cap}' should start with 'slack.'"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_use_read_capability() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let read_ops = [
            "slack.get_channel_history",
            "slack.search_messages",
            "slack.list_channels",
            "slack.get_user_info",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["capability"].as_str().unwrap(),
                    "slack.read",
                    "{id} should use slack.read capability"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_write_ops_use_write_capability() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let write_ops = [
            "slack.post_message",
            "slack.reply_thread",
            "slack.add_reaction",
            "slack.set_channel_topic",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if write_ops.contains(&id) {
                assert_eq!(
                    op["capability"].as_str().unwrap(),
                    "slack.write",
                    "{id} should use slack.write capability"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_file_ops_use_file_capabilities() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let upload = ops.iter().find(|o| o["id"] == "slack.upload_file").unwrap();
        assert_eq!(
            upload["capability"].as_str().unwrap(),
            "slack.files.write",
            "slack.upload_file should use slack.files.write capability"
        );

        let download = ops
            .iter()
            .find(|o| o["id"] == "slack.download_file")
            .unwrap();
        assert_eq!(
            download["capability"].as_str().unwrap(),
            "slack.files.read",
            "slack.download_file should use slack.files.read capability"
        );
    }

    // ── Safety tier tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_are_safe() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let read_ops = [
            "slack.get_channel_history",
            "slack.search_messages",
            "slack.list_channels",
            "slack.get_user_info",
            "slack.download_file",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "{id} should be safe"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_write_ops_are_risky_except_reaction() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let risky_ops = [
            "slack.post_message",
            "slack.reply_thread",
            "slack.upload_file",
            "slack.set_channel_topic",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if risky_ops.contains(&id) {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "risky",
                    "{id} should be risky"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_add_reaction_is_safe() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let reaction = ops
            .iter()
            .find(|o| o["id"] == "slack.add_reaction")
            .unwrap();
        assert_eq!(reaction["safety_tier"].as_str().unwrap(), "safe");
    }

    // ── Risk level tests ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_are_low_risk() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let read_ops = [
            "slack.get_channel_history",
            "slack.search_messages",
            "slack.list_channels",
            "slack.get_user_info",
            "slack.download_file",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "{id} should be low risk"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_write_ops_are_medium_risk() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let medium_ops = [
            "slack.post_message",
            "slack.reply_thread",
            "slack.upload_file",
            "slack.set_channel_topic",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if medium_ops.contains(&id) {
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "medium",
                    "{id} should be medium risk"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_add_reaction_is_low_risk() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let reaction = ops
            .iter()
            .find(|o| o["id"] == "slack.add_reaction")
            .unwrap();
        assert_eq!(reaction["risk_level"].as_str().unwrap(), "low");
    }

    // ── Idempotency tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_have_strict_idempotency() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let read_ops = [
            "slack.get_channel_history",
            "slack.search_messages",
            "slack.list_channels",
            "slack.get_user_info",
            "slack.download_file",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "strict",
                    "{id} should have strict idempotency"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_post_and_reply_have_none_idempotency() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if id == "slack.post_message" || id == "slack.reply_thread" || id == "slack.upload_file"
            {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "none",
                    "{id} should have none idempotency"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_reaction_and_topic_have_best_effort_idempotency() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if id == "slack.add_reaction" || id == "slack.set_channel_topic" {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "best_effort",
                    "{id} should have best_effort idempotency"
                );
            }
        }
    }

    // ── Required fields in schemas ───────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_required_fields_in_schemas() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let checks: &[(&str, &[&str])] = &[
            ("slack.post_message", &["channel", "text"]),
            ("slack.reply_thread", &["channel", "text", "thread_ts"]),
            ("slack.get_channel_history", &["channel"]),
            ("slack.search_messages", &["query"]),
            ("slack.get_user_info", &["user"]),
            (
                "slack.upload_file",
                &["channels", "content_object_id", "resolved_content"],
            ),
            ("slack.download_file", &["file_id"]),
            ("slack.add_reaction", &["channel", "timestamp", "name"]),
            ("slack.set_channel_topic", &["channel", "topic"]),
        ];

        for (op_id, expected) in checks {
            let op = ops.iter().find(|o| o["id"] == *op_id).unwrap();
            let required = op["input_schema"]["required"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();

            for field in *expected {
                assert!(required.contains(field), "{op_id} should require '{field}'");
            }
        }
    }

    // ── Event/streaming tests ────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_events() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let events = result["events"].as_array().unwrap();

        assert_eq!(events.len(), 5);
        let topics: Vec<&str> = events
            .iter()
            .map(|e| e["topic"].as_str().unwrap())
            .collect();
        assert!(topics.contains(&"slack.message.new"));
        assert!(topics.contains(&"slack.message.edited"));
        assert!(topics.contains(&"slack.message.deleted"));
        assert!(topics.contains(&"slack.reaction.added"));
        assert!(topics.contains(&"slack.reaction.removed"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_event_caps() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let event_caps = &result["event_caps"];
        assert!(event_caps["streaming"].as_bool().unwrap());
        assert!(!event_caps["replay"].as_bool().unwrap());
        assert_eq!(
            event_caps["min_buffer_events"].as_u64().unwrap(),
            SOCKET_EVENT_BUFFER_CAPACITY as u64
        );
    }

    // ── Helper function tests ────────────────────────────────────

    #[test]
    fn test_topic_allowed_empty_patterns_allows_all() {
        assert!(topic_allowed("anything", &[]));
    }

    #[test]
    fn test_topic_allowed_exact_match() {
        let patterns = vec!["slack.message.new".to_string()];
        assert!(topic_allowed("slack.message.new", &patterns));
        assert!(!topic_allowed("slack.message.edited", &patterns));
    }

    #[test]
    fn test_topic_allowed_wildcard() {
        let patterns = vec!["*".to_string()];
        assert!(topic_allowed("anything", &patterns));
    }

    #[test]
    fn test_topic_allowed_prefix_wildcard() {
        let patterns = vec!["slack.message.*".to_string()];
        assert!(topic_allowed("slack.message.new", &patterns));
        assert!(topic_allowed("slack.message.edited", &patterns));
        assert!(!topic_allowed("slack.reaction.added", &patterns));
    }

    #[test]
    fn test_parse_subscribe_topics_defaults() {
        let params = json!({});
        let topics = parse_subscribe_topics(&params);
        assert_eq!(topics.len(), 5);
        assert!(topics.contains(&"slack.message.new".to_string()));
    }

    #[test]
    fn test_parse_subscribe_topics_custom() {
        let params = json!({ "topics": ["slack.message.new", "slack.reaction.added"] });
        let topics = parse_subscribe_topics(&params);
        assert_eq!(topics.len(), 2);
        assert!(topics.contains(&"slack.message.new".to_string()));
        assert!(topics.contains(&"slack.reaction.added".to_string()));
    }

    #[test]
    fn test_parse_subscribe_topics_deduplicates() {
        let params =
            json!({ "topics": ["slack.message.new", "slack.message.new", "slack.message.new"] });
        let topics = parse_subscribe_topics(&params);
        assert_eq!(topics.len(), 1);
    }

    #[test]
    fn test_parse_subscribe_topics_skips_empty() {
        let params = json!({ "topics": ["slack.message.new", "", "  "] });
        let topics = parse_subscribe_topics(&params);
        assert_eq!(topics.len(), 1);
    }

    #[test]
    fn test_parse_subscribe_topics_rejects_oversized_and_malformed_patterns() {
        let oversized = format!("slack.{}", "a".repeat(SOCKET_SUBSCRIBE_TOPIC_MAX_CHARS));
        let params = json!({
            "topics": [
                oversized,
                "slack.message.new",
                "slack.message.*",
                "slack.message.*.extra",
                "slack.message.* ",
                "slack.message./etc/passwd",
                "*"
            ]
        });
        let topics = parse_subscribe_topics(&params);

        assert_eq!(
            topics,
            vec![
                "slack.message.new".to_string(),
                "slack.message.*".to_string(),
                "*".to_string()
            ]
        );
    }

    #[test]
    fn test_parse_subscribe_topics_caps_count() {
        let input_topics: Vec<String> = (0..(SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT + 8))
            .map(|idx| format!("slack.event.{idx}"))
            .collect();
        let params = json!({ "topics": input_topics });
        let topics = parse_subscribe_topics(&params);

        assert_eq!(topics.len(), SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT);
        assert_eq!(topics[0], "slack.event.0");
        assert_eq!(
            topics[SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT - 1],
            format!("slack.event.{}", SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT - 1)
        );
    }

    // ── Socket frame topic mapping tests ─────────────────────────

    #[test]
    fn test_socket_frame_topic_events_api_message_new() {
        let payload = json!({ "event": { "type": "message" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.message.new"
        );
    }

    #[test]
    fn test_socket_frame_topic_events_api_message_edited() {
        let payload = json!({ "event": { "type": "message", "subtype": "message_changed" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.message.edited"
        );
    }

    #[test]
    fn test_socket_frame_topic_events_api_message_deleted() {
        let payload = json!({ "event": { "type": "message", "subtype": "message_deleted" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.message.deleted"
        );
    }

    #[test]
    fn test_socket_frame_topic_reaction_added() {
        let payload = json!({ "event": { "type": "reaction_added" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.reaction.added"
        );
    }

    #[test]
    fn test_socket_frame_topic_reaction_removed() {
        let payload = json!({ "event": { "type": "reaction_removed" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.reaction.removed"
        );
    }

    #[test]
    fn test_socket_frame_topic_unknown_event() {
        let payload = json!({ "event": { "type": "app_mention" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.event.app_mention"
        );
    }

    #[test]
    fn test_socket_frame_topic_sanitizes_unknown_event_type() {
        let oversized = "a".repeat(SOCKET_TOPIC_COMPONENT_MAX_CHARS + 1);
        let payload = json!({ "event": { "type": oversized } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.event.unknown"
        );

        let payload = json!({ "event": { "type": "bad/event" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.event.unknown"
        );
    }

    #[test]
    fn test_socket_frame_topic_non_events_api() {
        assert_eq!(
            socket_frame_topic("interactive", &json!({})),
            "slack.interactive"
        );
        assert_eq!(
            socket_frame_topic("slash_commands", &json!({})),
            "slack.command"
        );
        assert_eq!(
            socket_frame_topic("disconnect", &json!({})),
            "slack.disconnect"
        );
        assert_eq!(socket_frame_topic("hello", &json!({})), "slack.hello");
        assert_eq!(
            socket_frame_topic("custom_type", &json!({})),
            "slack.socket.custom_type"
        );
        assert_eq!(
            socket_frame_topic("bad/type", &json!({})),
            "slack.socket.unknown"
        );
        assert_eq!(
            socket_frame_topic(
                &"a".repeat(SOCKET_TOPIC_COMPONENT_MAX_CHARS + 1),
                &json!({})
            ),
            "slack.socket.unknown"
        );
    }

    // ── Principal extraction tests ───────────────────────────────

    #[test]
    fn test_socket_payload_principal_user_in_event() {
        let payload = json!({ "event": { "user": "U12345" } });
        let principal = socket_payload_principal(&payload);
        assert_eq!(principal.kind, "slack_user");
        assert_eq!(principal.id, "U12345");
    }

    #[test]
    fn test_socket_payload_principal_user_id_field() {
        let payload = json!({ "user_id": "U99999" });
        let principal = socket_payload_principal(&payload);
        assert_eq!(principal.kind, "slack_user");
        assert_eq!(principal.id, "U99999");
    }

    #[test]
    fn test_socket_payload_principal_bot_in_event() {
        let payload = json!({ "event": { "bot_id": "B12345" } });
        let principal = socket_payload_principal(&payload);
        assert_eq!(principal.kind, "slack_bot");
        assert_eq!(principal.id, "B12345");
    }

    #[test]
    fn test_socket_payload_principal_unknown() {
        let payload = json!({ "some_field": "value" });
        let principal = socket_payload_principal(&payload);
        assert_eq!(principal.kind, "slack_actor");
        assert_eq!(principal.id, "unknown");
    }

    #[test]
    fn test_socket_frame_to_event_sets_thread_info_from_thread_ts() {
        let connector_id = ConnectorId::from_static("slack");
        let instance_id = fcp_core::InstanceId::new();
        let payload = json!({
            "event": {
                "type": "message",
                "user": "U12345",
                "channel": "C12345",
                "thread_ts": "1700000000.000100",
                "text": "reply"
            },
            "team_id": "T12345"
        });

        let event = socket_frame_to_event(
            "events_api",
            Some("env-1"),
            &payload,
            &connector_id,
            &instance_id,
            9,
        );

        assert_eq!(
            event.data.thread_info,
            Some(ThreadInfo::from_slack_thread("1700000000.000100", None))
        );
    }

    // ── Shutdown test ────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let mut connector = SlackConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    // ── Configure test ───────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_token() {
        let mut connector = SlackConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    // ── Require_str helper ───────────────────────────────────────

    #[test]
    fn test_require_str_present() {
        let input = json!({ "channel": "C123" });
        assert_eq!(require_str(&input, "channel").unwrap(), "C123");
    }

    #[test]
    fn test_require_str_missing() {
        let input = json!({});
        let result = require_str(&input, "channel");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn test_require_str_not_string() {
        let input = json!({ "channel": 42 });
        let result = require_str(&input, "channel");
        assert!(result.is_err());
    }

    // ── Default trait ────────────────────────────────────────────

    #[test]
    fn test_default_creates_new_connector() {
        let _connector: SlackConnector = SlackConnector::default();
    }

    // ── Self-check tests ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_self_check_unconfigured() {
        let connector = SlackConnector::new();
        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "degraded");
        assert_eq!(value["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_with_valid_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth.test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "url": "https://test.slack.com/",
                "team": "Test Team",
                "user": "testbot",
                "team_id": "T123",
                "user_id": "U123",
                "bot_id": "B123"
            })).insert_header("x-oauth-scopes", "chat:write,channels:read,channels:history,users:read,reactions:write,team:read"))
            .mount(&mock_server)
            .await;

        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("xoxb-test")
                .unwrap()
                .with_base_url(mock_server.uri()),
        );
        connector.base.set_configured(true);

        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["details"]["token_ok"], true);
        assert_eq!(value["details"]["scopes_ok"], true);
    }
}
