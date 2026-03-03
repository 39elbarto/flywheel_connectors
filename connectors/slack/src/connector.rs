//! FCP Slack Connector implementation.

use std::collections::HashSet;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use fcp_async_core::channel::{broadcast, watch};
use fcp_async_core::sync::RwLock;
use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, EventData, EventEnvelope, EventInfo, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, IdempotencyClass, Introspection, OperationId,
    OperationInfo, Principal, RiskLevel, SafetyTier, SessionId, SimulateRequest, SimulateResponse,
    TrustLevel, ZoneId,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use tracing::{info, instrument, warn};

use crate::{
    client::SlackClient,
    error::SlackError,
    types::{DoctorCheck, DoctorReport, OperationReceipt},
};

const SOCKET_EVENT_BUFFER_CAPACITY: usize = 200;
const SOCKET_RECONNECT_MIN_MS: u64 = 1_000;
const SOCKET_RECONNECT_MAX_MS: u64 = 30_000;
const SOCKET_DEFAULT_TOPICS: &[&str] = &[
    "slack.message.new",
    "slack.message.edited",
    "slack.message.deleted",
    "slack.reaction.added",
    "slack.reaction.removed",
];

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

        let token =
            params
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing token in configuration".into(),
                })?;

        let base_url = params.get("base_url").and_then(|v| v.as_str());
        let app_token = params.get("app_token").and_then(|v| v.as_str());
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
                    "Upload a file to Slack channels",
                    json!({
                        "type": "object",
                        "required": ["channels", "content"],
                        "properties": {
                            "channels": { "type": "string", "description": "Comma-separated channel IDs" },
                            "content": { "type": "string", "description": "File content" },
                            "filename": { "type": "string", "description": "Filename to display" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "file": { "type": "object" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Upload file content to one or more Slack channels.".into(),
                        common_mistakes: vec!["Forgetting to specify channels".into()],
                        examples: vec![
                            r#"{"channels": "C01234567", "content": "log data here", "filename": "output.log"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.download_file")],
                    },
                ),
                op_info(
                    "slack.download_file",
                    "Get file info and download URL",
                    json!({
                        "type": "object",
                        "required": ["file_id"],
                        "properties": {
                            "file_id": { "type": "string", "description": "Slack file ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "file": { "type": "object" } } }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve info about a file including its download URL.".into(),
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

        let response = SimulateResponse::allowed(req.id);
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

                match connect_async(&ws_url).await {
                    Ok((stream, _response)) => {
                        reconnect_delay_ms = SOCKET_RECONNECT_MIN_MS;
                        let (mut ws_write, mut ws_read) = stream.split();

                        loop {
                            fcp_async_core::select! {
                                changed = shutdown_rx.changed() => {
                                    if changed.is_ok() && *shutdown_rx.borrow() {
                                        let _ = ws_write.send(WsMessage::Close(None)).await;
                                        break;
                                    }
                                    if changed.is_err() {
                                        break;
                                    }
                                }
                                inbound = ws_read.next() => {
                                    let Some(frame_result) = inbound else {
                                        break;
                                    };

                                    let frame = match frame_result {
                                        Ok(frame) => frame,
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
                                                if let Err(err) = ws_write.send(WsMessage::Text(ack.into())).await {
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
                                            if let Err(err) = ws_write.send(WsMessage::Pong(data)).await {
                                                warn!("Socket Mode pong send failed: {err}");
                                                break;
                                            }
                                        }
                                        WsMessage::Close(_frame) => {
                                            break;
                                        }
                                        WsMessage::Binary(_)
                                        | WsMessage::Pong(_)
                                        | WsMessage::Frame(_) => {
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
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
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
            .map(|v| v as u32);

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
        let content = require_str(&input, "content")?;
        let filename = input.get("filename").and_then(|v| v.as_str());

        let file = client
            .upload_file(channels, content, filename)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.upload_file".into(),
            effect: "file_uploaded".into(),
            resource: format!("file:{id}", id = file.id),
            timestamp: String::new(),
        };

        Ok(json!({ "file": file, "receipt": receipt }))
    }

    async fn invoke_download_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;

        let file = client
            .get_file_info(file_id)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "file": file }))
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

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.stop_socket_mode().await;
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
            _ => format!("slack.socket.{frame_type}"),
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
        _ => format!("slack.event.{event_type}"),
    }
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

    EventEnvelope::new(topic, event_data)
        .with_seq(seq)
        .with_cursor(cursor)
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

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
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
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
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

    #[fcp_async_core::runtime::test]
    async fn test_doctor_valid_token_all_scopes() {
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

        // All checks should pass
        for check in checks {
            assert!(
                check["passed"].as_bool().unwrap(),
                "Check {} failed: {}",
                check["name"],
                check["message"]
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_missing_scopes() {
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
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_invalid_token() {
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
            "slack.download_file",
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
            "slack.upload_file",
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
            ("slack.upload_file", &["channels", "content"]),
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
}
