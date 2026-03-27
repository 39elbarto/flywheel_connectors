//! Mattermost connector implementation.

use std::collections::HashSet;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use fcp_async_core::channel::{broadcast, watch};
use fcp_async_core::sync::RwLock;
use fcp_core::{
    AgentHint, ApprovalMode, AuthCaps, BaseConnector, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, EventData, EventEnvelope, EventInfo, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, OrderingPolicy,
    Principal, ResourceTypeInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    SimulateRequest, SimulateResponse, SubscribeRequest, ThreadInfo, ThreadKind, TrustLevel, ZoneId,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_streaming::{WsClient, WsConnection, WsMessage};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::client::MattermostClient;
use crate::error::MattermostError;
use crate::types::{
    Channel, CreateDirectChannelRequest, CreateGroupChannelRequest, CreatePostRequest,
    CreateReactionRequest, DeleteReactionRequest, GetThreadRequest, MattermostAuth,
    MattermostConfig, MattermostWebSocketMessage, Post, Reaction, SearchPostsRequest,
    ThreadResponse, UpdatePostRequest, UploadFileRequest,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const SOCKET_EVENT_BUFFER_CAPACITY: usize = 256;
const SOCKET_EVENT_BUFFER_CAPACITY_U32: u32 = 256;
const SOCKET_RECONNECT_MIN_MS: u64 = 1_000;
const SOCKET_RECONNECT_MAX_MS: u64 = 30_000;
const SOCKET_PING_INTERVAL: Duration = Duration::from_secs(25);
const SOCKET_DEFAULT_TOPICS: &[&str] = &[
    "mattermost.posted",
    "mattermost.post_edited",
    "mattermost.post_deleted",
    "mattermost.reaction_added",
    "mattermost.reaction_removed",
    "mattermost.thread_updated",
    "mattermost.channel_created",
    "mattermost.channel_updated",
    "mattermost.channel_deleted",
    "mattermost.typing",
];

async fn connect_mattermost_websocket(
    url: &str,
    config: fcp_streaming::WsConfig,
) -> Result<WsConnection, fcp_streaming::StreamError> {
    WsClient::with_config(url, config).connect().await
}

/// Mattermost connector state.
#[derive(Debug)]
pub struct MattermostConnector {
    base: Arc<BaseConnector>,
    config: Option<MattermostConfig>,
    client: Option<MattermostClient>,
    runtime: Option<ConnectorRuntime>,
    /// Retained for future retry policy enforcement.
    #[allow(dead_code)]
    retry_config: HttpRetryConfig,
    verifier: Option<CapabilityVerifier>,
    socket_running: Arc<RwLock<bool>>,
    socket_connected: Arc<RwLock<bool>>,
    socket_task: Option<fcp_async_core::task::JoinHandle<()>>,
    socket_shutdown_tx: Option<watch::Sender<bool>>,
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    next_event_seq: Arc<AtomicU64>,
    subscribed_topics: Arc<RwLock<Vec<String>>>,
    started_at: Instant,
}

impl MattermostConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(SOCKET_EVENT_BUFFER_CAPACITY);
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "fcp.mattermost",
            ))),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            verifier: None,
            socket_running: Arc::new(RwLock::new(false)),
            socket_connected: Arc::new(RwLock::new(false)),
            socket_task: None,
            socket_shutdown_tx: None,
            event_tx,
            next_event_seq: Arc::new(AtomicU64::new(1)),
            subscribed_topics: Arc::new(RwLock::new(Vec::new())),
            started_at: Instant::now(),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Connector ID.
    #[must_use]
    pub fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    /// Subscribe to emitted connector events.
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<FcpResult<EventEnvelope>> {
        self.event_tx.subscribe()
    }

    /// Configure the connector.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration JSON is invalid or the client cannot be built.
    pub fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let mut config: MattermostConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 5001,
                message: format!("invalid configuration: {e}"),
            })?;

        let base_url = config.base_url.trim().to_owned();
        if base_url.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 5001,
                message: "base_url is required for Mattermost's self-hosted deployment model"
                    .to_string(),
            });
        }
        base_url.clone_into(&mut config.base_url);

        let token = config
            .token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let credential_id = config
            .credential_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let auth = match (token, credential_id) {
            (Some(token), None) => {
                config.token = Some(token.clone());
                config.credential_id = None;
                MattermostAuth::Token(token)
            }
            (None, Some(credential_id)) => {
                config.token = None;
                config.credential_id = Some(credential_id.clone());
                MattermostAuth::CredentialId(credential_id)
            }
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 5001,
                    message:
                        "configure exactly one auth mode: token (personal or bot access token) or credential_id"
                            .to_string(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 5001,
                    message:
                        "either token (personal or bot access token) or credential_id must be provided"
                            .to_string(),
                });
            }
        };

        if config.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 5001,
                message: "request_timeout_ms must be greater than zero".to_string(),
            });
        }

        let timeout = Duration::from_millis(config.request_timeout_ms);
        let client = MattermostClient::new(&config.base_url, auth, timeout).map_err(|e| {
            FcpError::Internal {
                message: format!("client initialization failed: {e}"),
            }
        })?;

        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(timeout),
        ));
        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    /// Perform the handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake parameters are invalid.
    pub fn handshake(&mut self, req: &HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .iter()
            .map(|cap| fcp_core::CapabilityGrant {
                capability: cap.clone(),
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
                streaming: true,
                replay: false,
                min_buffer_events: SOCKET_EVENT_BUFFER_CAPACITY_U32,
                requires_ack: false,
            }),
            auth_caps: Some(mattermost_auth_caps()),
            op_catalog_hash: None,
        })
    }

    /// Health check.
    #[must_use]
    pub fn health(&self) -> HealthSnapshot {
        let status = if self.client.is_some() {
            HealthState::Ready
        } else {
            HealthState::Starting
        };
        let uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        HealthSnapshot {
            status,
            uptime_ms,
            load: None,
            details: None,
            rate_limit: None,
        }
    }

    /// Introspect operations and events.
    #[must_use]
    pub fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: event_info(),
            resource_types: mattermost_resource_types(),
            auth_caps: Some(mattermost_auth_caps()),
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: SOCKET_EVENT_BUFFER_CAPACITY_U32,
                requires_ack: false,
            }),
        }
    }

    /// Invoke an operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector is not configured, the operation is unknown,
    /// required fields are missing, or the upstream API call fails.
    pub async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;

        let operation = req.operation.as_str();
        let required_capability = required_capability_for_operation(operation)?;
        let verifier = self.verifier.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing capability verifier".into(),
        })?;
        verifier.verify(
            &req.capability_token,
            &required_capability,
            &req.operation,
            &[],
        )?;

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Mattermost client".into(),
        })?;

        debug!(operation = %operation, "invoking mattermost operation");

        let output = match operation {
            "mattermost.get_me" => invoke_get_me(client).await?,
            "mattermost.get_user" => invoke_get_user(client, &req.input).await?,
            "mattermost.get_my_teams" => invoke_get_my_teams(client).await?,
            "mattermost.get_team" => invoke_get_team(client, &req.input).await?,
            "mattermost.get_channels_for_team" => {
                invoke_get_channels_for_team(client, &req.input).await?
            }
            "mattermost.get_channel" => invoke_get_channel(client, &req.input).await?,
            "mattermost.get_thread" => invoke_get_thread(client, &req.input).await?,
            "mattermost.create_direct_channel" => {
                invoke_create_direct_channel(client, &req.input).await?
            }
            "mattermost.create_post" => invoke_create_post(client, &req.input).await?,
            "mattermost.get_post" => invoke_get_post(client, &req.input).await?,
            "mattermost.get_posts_for_channel" => {
                invoke_get_posts_for_channel(client, &req.input).await?
            }
            "mattermost.search_posts" => invoke_search_posts(client, &req.input).await?,
            "mattermost.create_reaction" => invoke_create_reaction(client, &req.input).await?,
            "mattermost.delete_reaction" => invoke_delete_reaction(client, &req.input).await?,
            "mattermost.get_file_info" => invoke_get_file_info(client, &req.input).await?,
            "mattermost.get_file_link" => invoke_get_file_link(client, &req.input).await?,
            "mattermost.download_file" => invoke_download_file(client, &req.input).await?,
            "mattermost.get_file_infos_for_post" => {
                invoke_get_file_infos_for_post(client, &req.input).await?
            }
            "mattermost.upload_file" => invoke_upload_file(client, &req.input).await?,
            "mattermost.delete_post" => invoke_delete_post(client, &req.input).await?,
            "mattermost.update_post" => invoke_update_post(client, &req.input).await?,
            "mattermost.pin_post" => invoke_pin_post(client, &req.input).await?,
            "mattermost.unpin_post" => invoke_unpin_post(client, &req.input).await?,
            "mattermost.get_reactions_for_post" => {
                invoke_get_reactions_for_post(client, &req.input).await?
            }
            "mattermost.create_group_channel" => {
                invoke_create_group_channel(client, &req.input).await?
            }
            _ => {
                warn!(operation = %operation, "unknown operation");
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }

    /// Shutdown the connector.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown cleanup fails.
    pub fn shutdown(&mut self) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.client = None;
        Ok(())
    }

    /// Handle configure method.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector cannot be reconfigured or the response cannot be encoded.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.stop_socket_mode().await;
        self.configure(params)?;
        *self.subscribed_topics.write().await = Vec::new();
        Ok(json!({"status": "configured"}))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake request is invalid or the response cannot be encoded.
    pub fn handle_handshake(&mut self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid handshake request: {e}"),
            })?;
        let response = self.handshake(&req)?;
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize handshake response: {e}"),
        })
    }

    /// Handle health method.
    ///
    /// # Errors
    ///
    /// Returns an error if the health payload cannot be encoded.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let socket_running = *self.socket_running.read().await;
        let socket_connected = *self.socket_connected.read().await;
        let subscribed_topics = self.subscribed_topics.read().await.clone();
        let mut snapshot = if !subscribed_topics.is_empty() && !socket_connected {
            HealthSnapshot::degraded("stream subscription active but websocket is not connected")
        } else {
            self.health()
        };
        snapshot.details = Some(json!({
            "streaming": {
                "socket_running": socket_running,
                "socket_connected": socket_connected,
                "buffer_capacity": SOCKET_EVENT_BUFFER_CAPACITY,
                "subscribed_topics": subscribed_topics,
            }
        }));
        serde_json::to_value(snapshot).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize health snapshot: {e}"),
        })
    }

    /// Handle doctor diagnostics.
    ///
    /// # Errors
    ///
    /// Returns `FcpError` if the doctor report cannot be serialized.
    ///
    /// # Panics
    ///
    /// Panics if `client` is `None` after the configured guard (unreachable).
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks: Vec<serde_json::Value> = Vec::new();

        let configured = self.client.is_some();
        checks.push(json!({
            "name": "client_configured",
            "passed": configured,
            "message": if configured { "Mattermost client is configured" } else { "Not configured — call configure with server URL and token" },
        }));

        if !configured {
            return Ok(json!({ "ready": false, "checks": checks }));
        }

        let client = self.client.as_ref().expect("checked above");

        match client.get_me().await {
            Ok(user) => {
                checks.push(json!({
                    "name": "api_reachable",
                    "passed": true,
                    "message": format!("API reachable — user: {} ({})", user.username, user.id),
                }));
            }
            Err(e) => {
                checks.push(json!({
                    "name": "api_reachable",
                    "passed": false,
                    "message": format!("API unreachable: {e}"),
                }));
            }
        }

        let socket_connected = *self.socket_connected.read().await;
        checks.push(json!({
            "name": "websocket_connected",
            "passed": socket_connected,
            "message": if socket_connected { "WebSocket connection is active" } else { "WebSocket not connected (streaming events unavailable)" },
        }));

        let ready = checks.iter().all(|c| c["passed"].as_bool().unwrap_or(false));
        Ok(json!({ "ready": ready, "checks": checks }))
    }

    /// Handle self-check.
    ///
    /// # Errors
    ///
    /// Returns `FcpError` if the self-check report cannot be serialized.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        };

        let report = match client.get_me().await {
            Ok(user) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "api_reachable": true,
                    "user_id": user.id,
                    "username": user.username,
                }));
                report
            }
            Err(e) => {
                if e.is_retryable() {
                    SelfCheckReport::degraded("api_transient_error", e.to_string())
                } else {
                    SelfCheckReport::failed("api_unreachable", e.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check: {e}"),
        })
    }

    /// Handle simulate.
    ///
    /// # Errors
    ///
    /// Returns `FcpError` if the request is invalid or the response cannot be serialized.
    pub fn handle_simulate(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize simulate response: {e}"),
        })
    }

    /// Handle introspect method.
    ///
    /// # Errors
    ///
    /// Returns an error if introspection data cannot be encoded.
    pub fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        serde_json::to_value(self.introspect()).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize introspection: {e}"),
        })
    }

    /// Handle invoke method.
    ///
    /// # Errors
    ///
    /// Returns an error if the invoke request is invalid, the operation fails, or the response cannot be encoded.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: InvokeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid invoke request: {e}"),
            })?;
        let response = self.invoke(req).await?;
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize invoke response: {e}"),
        })
    }

    /// Handle subscribe method.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector is not configured, socket mode cannot start, or the response cannot be encoded.
    pub async fn handle_subscribe(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let _: SubscribeRequest =
            serde_json::from_value(params.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid subscribe request: {e}"),
            })?;

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

    /// Handle shutdown method.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.stop_socket_mode().await;
        *self.subscribed_topics.write().await = Vec::new();
        self.shutdown()?;
        Ok(json!({"status": "shutdown_accepted"}))
    }

    #[allow(clippy::too_many_lines)]
    async fn ensure_socket_mode_running(&mut self) -> FcpResult<bool> {
        if let Some(task) = &self.socket_task
            && !task.is_finished()
            && *self.socket_running.read().await
        {
            return Ok(false);
        }

        self.stop_socket_mode().await;

        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FcpError::Internal {
                message: "connector ready state missing Mattermost client".into(),
            })?
            .clone();
        let auth_token = client.auth_token().map(str::to_owned);
        let ws_config = client.websocket_config().map_err(map_mm_err)?;

        let event_tx = self.event_tx.clone();
        let connector_id = self.base.id.clone();
        let instance_id = self.base.instance_id.clone();
        let base = self.base.clone();
        let socket_running = self.socket_running.clone();
        let socket_connected = self.socket_connected.clone();
        let next_event_seq = self.next_event_seq.clone();
        let subscribed_topics = self.subscribed_topics.clone();

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        self.socket_shutdown_tx = Some(shutdown_tx);
        *self.socket_running.write().await = true;
        *self.socket_connected.write().await = false;

        let task = fcp_async_core::task::spawn(async move {
            info!("Starting Mattermost websocket event loop");

            let mut reconnect_delay_ms = SOCKET_RECONNECT_MIN_MS;
            let mut connection_id = String::new();
            let mut expected_server_seq = 0_u64;

            loop {
                if *shutdown_rx.borrow() {
                    break;
                }

                let ws_url = match client
                    .websocket_url(Some(connection_id.as_str()), Some(expected_server_seq))
                {
                    Ok(url) => url,
                    Err(err) => {
                        warn!("Failed to build Mattermost websocket URL: {err}");
                        break;
                    }
                };

                match connect_mattermost_websocket(&ws_url, ws_config.clone()).await {
                    Ok(mut ws_stream) => {
                        *socket_connected.write().await = true;
                        reconnect_delay_ms = SOCKET_RECONNECT_MIN_MS;
                        let mut request_seq = 1_u64;

                        if let Some(token) = auth_token.as_deref() {
                            if let Err(err) = send_socket_action(
                                &mut ws_stream,
                                "authentication_challenge",
                                request_seq,
                                json!({"token": token}),
                            )
                            .await
                            {
                                warn!("Mattermost websocket auth challenge failed: {err}");
                            } else {
                                request_seq = request_seq.saturating_add(1);
                            }
                        }

                        let mut ping_interval =
                            fcp_async_core::time::interval(SOCKET_PING_INTERVAL);
                        ping_interval.tick().await;

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
                                _ = ping_interval.tick() => {
                                    if let Err(err) = send_socket_action(&mut ws_stream, "ping", request_seq, json!({})).await {
                                        warn!("Mattermost websocket ping failed: {err}");
                                        break;
                                    }
                                    request_seq = request_seq.saturating_add(1);
                                },
                                inbound = ws_stream.recv() => {
                                    let frame = match inbound {
                                        Ok(Some(frame)) => frame,
                                        Ok(None) => break,
                                        Err(err) => {
                                            warn!("Mattermost websocket receive error: {err}");
                                            break;
                                        }
                                    };

                                    match frame {
                                        WsMessage::Text(text) => {
                                            let message: MattermostWebSocketMessage = match serde_json::from_str(&text) {
                                                Ok(message) => message,
                                                Err(err) => {
                                                    warn!("Failed to parse Mattermost websocket frame: {err}");
                                                    continue;
                                                }
                                            };

                                            if message.seq_reply.is_some() {
                                                if message.status.as_deref() != Some("OK")
                                                    || message.error.is_some()
                                                {
                                                    warn!(
                                                        seq_reply = ?message.seq_reply,
                                                        error = ?message.error,
                                                        "Mattermost websocket request returned an error"
                                                    );
                                                }
                                                continue;
                                            }

                                            let Some(event_name) = message.event.as_deref() else {
                                                continue;
                                            };

                                            if !apply_socket_resume_state(
                                                &message,
                                                &mut connection_id,
                                                &mut expected_server_seq,
                                            ) {
                                                warn!(
                                                    expected_server_seq,
                                                    received_seq = ?message.seq,
                                                    "Mattermost websocket sequence mismatch; reconnecting"
                                                );
                                                break;
                                            }

                                            if event_name == "hello" {
                                                continue;
                                            }

                                            let topic = mattermost_event_topic(event_name);
                                            let allowed = {
                                                let subscribed = subscribed_topics.read().await;
                                                topic_allowed(&topic, subscribed.as_slice())
                                            };
                                            if !allowed {
                                                continue;
                                            }

                                            if let Some(event) = websocket_message_to_event(
                                                &message,
                                                &connector_id,
                                                &instance_id,
                                                next_event_seq.as_ref(),
                                            ) {
                                                base.record_event();
                                                if event_tx.send(Ok(event)).is_err() {
                                                    warn!("Mattermost event dropped: no active subscribers");
                                                }
                                            }
                                        }
                                        WsMessage::Ping(data) => {
                                            if let Err(err) = ws_stream.send(WsMessage::Pong(data)).await {
                                                warn!("Mattermost websocket pong failed: {err}");
                                                break;
                                            }
                                        }
                                        WsMessage::Close(_) => break,
                                        WsMessage::Binary(_) | WsMessage::Pong(_) => {}
                                    }
                                }
                            }
                        }
                        *socket_connected.write().await = false;
                    }
                    Err(err) => {
                        *socket_connected.write().await = false;
                        warn!("Mattermost websocket connect failed: {err}");
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

            *socket_running.write().await = false;
            *socket_connected.write().await = false;
            info!("Mattermost websocket event loop stopped");
        });

        self.socket_task = Some(task);
        Ok(true)
    }

    async fn stop_socket_mode(&mut self) {
        if let Some(shutdown_tx) = self.socket_shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }

        if let Some(task) = self.socket_task.take()
            && let Err(err) = task.await
        {
            warn!("Mattermost websocket task join failed: {err}");
        }

        *self.socket_running.write().await = false;
        *self.socket_connected.write().await = false;
    }
}

impl Default for MattermostConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Per-operation invoke handlers ───────────────────────────────────────

fn to_json<T: serde::Serialize>(value: T) -> FcpResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| FcpError::Internal {
        message: e.to_string(),
    })
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("missing required field '{field}'"),
        })
}

/// Convert a Mattermost error to an FCP error.
#[allow(clippy::needless_pass_by_value)]
fn map_mm_err(error: MattermostError) -> FcpError {
    error.to_fcp_error()
}

async fn invoke_get_me(client: &MattermostClient) -> FcpResult<serde_json::Value> {
    let user = client.get_me().await.map_err(map_mm_err)?;
    to_json(user)
}

async fn invoke_get_user(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let user_id = require_str(input, "user_id")?;
    let user = client.get_user(user_id).await.map_err(map_mm_err)?;
    to_json(user)
}

async fn invoke_get_my_teams(client: &MattermostClient) -> FcpResult<serde_json::Value> {
    let teams = client.get_my_teams().await.map_err(map_mm_err)?;
    to_json(teams)
}

async fn invoke_get_team(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let team_id = require_str(input, "team_id")?;
    let team = client.get_team(team_id).await.map_err(map_mm_err)?;
    to_json(team)
}

async fn invoke_get_channels_for_team(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let team_id = require_str(input, "team_id")?;
    let user_id = match input.get("user_id").and_then(Value::as_str) {
        Some(user_id) if !user_id.is_empty() && user_id != "me" => user_id.to_string(),
        _ => client.get_me().await.map_err(map_mm_err)?.id,
    };
    let include_deleted = input
        .get("include_deleted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let channels = client
        .get_channels_for_team(team_id, &user_id, include_deleted)
        .await
        .map_err(map_mm_err)?;
    to_json(channels)
}

async fn invoke_get_channel(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let channel_id = require_str(input, "channel_id")?;
    let channel = client.get_channel(channel_id).await.map_err(map_mm_err)?;
    to_json(channel)
}

async fn invoke_create_direct_channel(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let request: CreateDirectChannelRequest =
        serde_json::from_value(input.clone()).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid create_direct_channel input: {error}"),
        })?;

    if request.user_ids.len() != 2 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "user_ids must contain exactly two Mattermost user IDs".into(),
        });
    }
    if request
        .user_ids
        .iter()
        .any(|user_id| user_id.trim().is_empty())
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "user_ids must not contain empty values".into(),
        });
    }
    let unique_user_ids = request.user_ids.iter().collect::<HashSet<_>>();
    if unique_user_ids.len() != 2 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "user_ids must contain two distinct users".into(),
        });
    }

    let channel = client
        .create_direct_channel(&request)
        .await
        .map_err(map_mm_err)?;
    to_json(channel)
}

async fn invoke_create_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let create_req: CreatePostRequest =
        serde_json::from_value(input.clone()).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid create_post input: {e}"),
        })?;
    validate_create_post_request(&create_req)?;
    let post = client.create_post(&create_req).await.map_err(map_mm_err)?;
    to_json(post)
}

fn validate_create_post_request(request: &CreatePostRequest) -> FcpResult<()> {
    if request.channel_id.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "channel_id is required".into(),
        });
    }
    if let Some(file_ids) = &request.file_ids
        && file_ids.iter().any(|file_id| file_id.trim().is_empty())
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "file_ids must not contain empty values".into(),
        });
    }
    Ok(())
}

async fn invoke_get_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let post_id = require_str(input, "post_id")?;
    let post = client.get_post(post_id).await.map_err(map_mm_err)?;
    to_json(post)
}

async fn invoke_get_thread(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let request: GetThreadRequest =
        serde_json::from_value(input.clone()).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid get_thread input: {e}"),
        })?;
    if request.post_id.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "missing required field 'post_id'".into(),
        });
    }
    let thread = client.get_thread(&request).await.map_err(map_mm_err)?;
    to_json(thread)
}

async fn invoke_get_posts_for_channel(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let channel_id = require_str(input, "channel_id")?;
    let page = input.get("page").and_then(Value::as_u64).unwrap_or(0);
    let page = u32::try_from(page).unwrap_or(u32::MAX);
    let per_page = input.get("per_page").and_then(Value::as_u64).unwrap_or(60);
    let per_page = u32::try_from(per_page).unwrap_or(u32::MAX);
    let posts = client
        .get_posts_for_channel(channel_id, page, per_page)
        .await
        .map_err(map_mm_err)?;
    to_json(posts)
}

async fn invoke_search_posts(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let team_id = require_str(input, "team_id")?;
    let search_req: SearchPostsRequest =
        serde_json::from_value(input.clone()).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid search input: {e}"),
        })?;
    let results = client
        .search_posts(team_id, &search_req)
        .await
        .map_err(map_mm_err)?;
    to_json(results)
}

async fn invoke_create_reaction(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let request: CreateReactionRequest =
        serde_json::from_value(input.clone()).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid create_reaction input: {error}"),
        })?;
    if request.user_id.trim().is_empty()
        || request.post_id.trim().is_empty()
        || request.emoji_name.trim().is_empty()
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "user_id, post_id, and emoji_name are required".into(),
        });
    }

    let reaction = client.create_reaction(&request).await.map_err(map_mm_err)?;
    to_json(reaction)
}

async fn invoke_delete_reaction(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let request: DeleteReactionRequest =
        serde_json::from_value(input.clone()).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid delete_reaction input: {error}"),
        })?;
    if request.user_id.trim().is_empty()
        || request.post_id.trim().is_empty()
        || request.emoji_name.trim().is_empty()
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "user_id, post_id, and emoji_name are required".into(),
        });
    }

    client.delete_reaction(&request).await.map_err(map_mm_err)?;
    Ok(json!({
        "status": "deleted",
        "user_id": request.user_id,
        "post_id": request.post_id,
        "emoji_name": request.emoji_name,
    }))
}

async fn invoke_get_file_info(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let file_id = require_str(input, "file_id")?;
    let file = client.get_file_info(file_id).await.map_err(map_mm_err)?;
    Ok(json!({
        "file": file,
        "paths": client.file_access_paths(file_id),
    }))
}

async fn invoke_get_file_link(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let file_id = require_str(input, "file_id")?;
    let response = client.get_file_link(file_id).await.map_err(map_mm_err)?;
    Ok(json!({
        "file_id": file_id,
        "link": response.get("link").cloned().unwrap_or(Value::Null),
        "paths": client.file_access_paths(file_id),
    }))
}

async fn invoke_download_file(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let file_id = require_str(input, "file_id")?;
    let payload = client.download_file(file_id).await.map_err(map_mm_err)?;
    to_json(payload)
}

async fn invoke_get_file_infos_for_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let post_id = require_str(input, "post_id")?;
    let files = client
        .get_file_infos_for_post(post_id)
        .await
        .map_err(map_mm_err)?;
    let files = files
        .into_iter()
        .map(|file| {
            json!({
                "file": file,
                "paths": client.file_access_paths(&file.id),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({ "files": files }))
}

async fn invoke_upload_file(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let request: UploadFileRequest =
        serde_json::from_value(input.clone()).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid upload_file input: {error}"),
        })?;
    if request.channel_id.trim().is_empty()
        || request.filename.trim().is_empty()
        || request.content_base64.trim().is_empty()
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "channel_id, filename, and content_base64 are required".into(),
        });
    }

    let contents = request
        .decode_bytes()
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("content_base64 is not valid base64: {error}"),
        })?;
    let response = client
        .upload_file(&request, contents)
        .await
        .map_err(map_mm_err)?;
    let files = response
        .file_infos
        .into_iter()
        .map(|file| {
            json!({
                "file": file,
                "paths": client.file_access_paths(&file.id),
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "files": files,
        "client_ids": response.client_ids,
    }))
}

async fn invoke_delete_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let post_id = require_str(input, "post_id")?;
    client.delete_post(post_id).await.map_err(map_mm_err)?;
    Ok(json!({"status": "deleted", "post_id": post_id}))
}

async fn invoke_update_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let request: UpdatePostRequest =
        serde_json::from_value(input.clone()).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid update_post input: {e}"),
        })?;
    if request.id.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "post id is required".into(),
        });
    }
    let post = client.update_post(&request).await.map_err(map_mm_err)?;
    to_json(post)
}

async fn invoke_pin_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let post_id = require_str(input, "post_id")?;
    client.pin_post(post_id).await.map_err(map_mm_err)?;
    Ok(json!({"status": "pinned", "post_id": post_id}))
}

async fn invoke_unpin_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let post_id = require_str(input, "post_id")?;
    client.unpin_post(post_id).await.map_err(map_mm_err)?;
    Ok(json!({"status": "unpinned", "post_id": post_id}))
}

async fn invoke_get_reactions_for_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let post_id = require_str(input, "post_id")?;
    let reactions = client
        .get_reactions_for_post(post_id)
        .await
        .map_err(map_mm_err)?;
    to_json(reactions)
}

async fn invoke_create_group_channel(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let request: CreateGroupChannelRequest =
        serde_json::from_value(input.clone()).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid create_group_channel input: {e}"),
        })?;
    if request.user_ids.len() < 3 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "user_ids must contain at least three users for a group channel".into(),
        });
    }
    let mut seen = HashSet::new();
    if request.user_ids.iter().any(|id| !seen.insert(id.as_str())) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "user_ids must not contain duplicates".into(),
        });
    }
    let channel = client
        .create_group_channel(&request)
        .await
        .map_err(map_mm_err)?;
    to_json(channel)
}

// ── Operation descriptors ───────────────────────────────────────────────

/// Typed operation descriptors for introspection.
#[must_use]
pub fn operations_info() -> Vec<OperationInfo> {
    let mut ops = user_and_team_operations();
    ops.extend(channel_and_post_read_operations());
    ops.extend(file_read_operations());
    ops.extend(read_reaction_operations());
    ops.extend(search_operations());
    ops.extend(write_operations());
    ops
}

fn mattermost_auth_caps() -> AuthCaps {
    AuthCaps {
        methods: vec![
            "personal_access_token".to_string(),
            "bot_access_token".to_string(),
            "credential_id".to_string(),
        ],
        oauth: None,
    }
}

fn mattermost_resource_types() -> Vec<ResourceTypeInfo> {
    vec![
        ResourceTypeInfo {
            name: "mattermost.user".into(),
            uri_pattern: "mattermost://users/{user_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": {"type": "string"},
                    "username": {"type": "string"},
                    "email": {"type": "string"},
                    "roles": {"type": "string"}
                }
            }),
        },
        ResourceTypeInfo {
            name: "mattermost.team".into(),
            uri_pattern: "mattermost://teams/{team_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "display_name": {"type": "string"},
                    "type": {"type": "string"}
                }
            }),
        },
        ResourceTypeInfo {
            name: "mattermost.channel".into(),
            uri_pattern: "mattermost://channels/{channel_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": {"type": "string"},
                    "team_id": {"type": "string"},
                    "type": {"type": "string"},
                    "display_name": {"type": "string"},
                    "name": {"type": "string"}
                }
            }),
        },
        ResourceTypeInfo {
            name: "mattermost.post".into(),
            uri_pattern: "mattermost://posts/{post_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": {"type": "string"},
                    "channel_id": {"type": "string"},
                    "user_id": {"type": "string"},
                    "root_id": {"type": "string"},
                    "message": {"type": "string"},
                    "file_ids": {"type": "array", "items": {"type": "string"}}
                }
            }),
        },
        ResourceTypeInfo {
            name: "mattermost.file".into(),
            uri_pattern: "mattermost://files/{file_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": {"type": "string"},
                    "post_id": {"type": "string"},
                    "channel_id": {"type": "string"},
                    "name": {"type": "string"},
                    "mime_type": {"type": "string"},
                    "size": {"type": "integer"}
                }
            }),
        },
    ]
}

fn required_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        "mattermost.get_me"
        | "mattermost.get_user"
        | "mattermost.get_my_teams"
        | "mattermost.get_team"
        | "mattermost.get_channels_for_team"
        | "mattermost.get_channel"
        | "mattermost.get_post"
        | "mattermost.get_thread"
        | "mattermost.get_posts_for_channel"
        | "mattermost.search_posts"
        | "mattermost.get_file_info"
        | "mattermost.get_file_link"
        | "mattermost.download_file"
        | "mattermost.get_file_infos_for_post"
        | "mattermost.get_reactions_for_post" => "mattermost.read",
        "mattermost.create_direct_channel"
        | "mattermost.create_group_channel"
        | "mattermost.create_post"
        | "mattermost.update_post"
        | "mattermost.pin_post"
        | "mattermost.unpin_post"
        | "mattermost.create_reaction"
        | "mattermost.delete_reaction"
        | "mattermost.upload_file"
        | "mattermost.delete_post" => "mattermost.write",
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("unknown operation: {operation}"),
            });
        }
    };

    Ok(CapabilityId::from_static(capability))
}

fn user_and_team_operations() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("mattermost.get_me"),
            summary: "Get the authenticated user's profile.".into(),
            description: Some("Returns the user profile associated with the current token.".into()),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "username": {"type": "string"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to verify authentication and get the bot or user identity."
                    .into(),
                common_mistakes: vec!["Using an expired token.".into()],
                examples: vec![r"{}".into()],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_user"),
            summary: "Get a user by ID.".into(),
            description: Some(
                "Retrieve a specific user's profile by their Mattermost user ID.".into(),
            ),
            input_schema: json!({"type": "object", "properties": {"user_id": {"type": "string"}}, "required": ["user_id"]}),
            output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "username": {"type": "string"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to look up another user's profile by their ID.".into(),
                common_mistakes: vec!["Passing a username instead of a Mattermost user ID.".into()],
                examples: vec![r#"{"user_id": "abc123def456"}"#.into()],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_my_teams"),
            summary: "List teams the user belongs to.".into(),
            description: Some(
                "Returns all teams that the authenticated user is a member of.".into(),
            ),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "array", "items": {"type": "object"}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to discover available teams before listing channels.".into(),
                common_mistakes: vec![
                    "Assuming a bot or personal token can see teams it has not been added to."
                        .into(),
                ],
                examples: vec![r"{}".into()],
                related: vec![
                    CapabilityId::from_static("mattermost.get_team"),
                    CapabilityId::from_static("mattermost.get_channels_for_team"),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_team"),
            summary: "Get a team by ID.".into(),
            description: Some("Fetch metadata for a single Mattermost team.".into()),
            input_schema: json!({"type": "object", "properties": {"team_id": {"type": "string"}}, "required": ["team_id"]}),
            output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "display_name": {"type": "string"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use:
                    "Use to resolve a team name, slug, or description from a known team ID.".into(),
                common_mistakes: vec!["Passing a team name instead of a team ID.".into()],
                examples: vec![r#"{"team_id": "team123"}"#.into()],
                related: vec![CapabilityId::from_static("mattermost.get_my_teams")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

#[allow(clippy::too_many_lines)]
fn channel_and_post_read_operations() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("mattermost.get_channels_for_team"),
            summary: "List channels the user can access in a team.".into(),
            description: Some(
                "Returns the channels visible to a user inside a team, including direct and private channels when permitted.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "team_id": {"type": "string"},
                    "user_id": {"type": "string", "description": "Defaults to 'me'"},
                    "include_deleted": {"type": "boolean", "default": false}
                },
                "required": ["team_id"]
            }),
            output_schema: json!({"type": "array", "items": {"type": "object"}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to enumerate the channels available in a team before reading or posting.".into(),
                common_mistakes: vec![
                    "Forgetting that user_id defaults to 'me'.".into(),
                    "Expecting private or DM channels to appear when the acting identity is not a member.".into(),
                ],
                examples: vec![r#"{"team_id": "team123"}"#.into()],
                related: vec![CapabilityId::from_static("mattermost.get_channel")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_channel"),
            summary: "Get a channel by ID.".into(),
            description: Some(
                "Retrieve channel details including header, purpose, and type.".into(),
            ),
            input_schema: json!({"type": "object", "properties": {"channel_id": {"type": "string"}}, "required": ["channel_id"]}),
            output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "display_name": {"type": "string"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to get details about a specific channel.".into(),
                common_mistakes: vec!["Using a channel name instead of a channel ID.".into()],
                examples: vec![r#"{"channel_id": "abc123"}"#.into()],
                related: vec![CapabilityId::from_static("mattermost.get_channels_for_team")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_post"),
            summary: "Get a post by ID.".into(),
            description: Some("Retrieve a specific Mattermost post or thread root by ID.".into()),
            input_schema: json!({"type": "object", "properties": {"post_id": {"type": "string"}}, "required": ["post_id"]}),
            output_schema: json!({"type": "object"}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to retrieve a specific post or message by its ID.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"post_id": "abc123"}"#.into()],
                related: vec![CapabilityId::from_static("mattermost.get_posts_for_channel")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_thread"),
            summary: "Get a post thread by root or child post ID.".into(),
            description: Some(
                "Returns a thread as a Mattermost post list, including pagination and collapsed-thread controls.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "post_id": {"type": "string"},
                    "per_page": {"type": "integer"},
                    "from_post": {"type": "string"},
                    "from_create_at": {"type": "integer"},
                    "from_update_at": {"type": "integer"},
                    "direction": {"type": "string"},
                    "skip_fetch_threads": {"type": "boolean"},
                    "collapsed_threads": {"type": "boolean"},
                    "collapsed_threads_extended": {"type": "boolean"},
                    "updates_only": {"type": "boolean"}
                },
                "required": ["post_id"]
            }),
            output_schema: json!({"type": "object", "properties": {"order": {"type": "array"}, "posts": {"type": "object"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to reconstruct a thread rooted at a post, including replies and pagination cursors.".into(),
                common_mistakes: vec!["Passing the wrong post_id when you meant a thread root.".into()],
                examples: vec![r#"{"post_id": "post123", "per_page": 50}"#.into()],
                related: vec![
                    CapabilityId::from_static("mattermost.get_post"),
                    CapabilityId::from_static("mattermost.get_posts_for_channel"),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_posts_for_channel"),
            summary: "List posts in a channel (paginated).".into(),
            description: Some(
                "Returns posts in reverse chronological order with pagination support.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string"},
                    "page": {"type": "integer", "default": 0},
                    "per_page": {"type": "integer", "default": 60}
                },
                "required": ["channel_id"]
            }),
            output_schema: json!({"type": "object", "properties": {"order": {"type": "array"}, "posts": {"type": "object"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to read message history in a channel or thread root.".into(),
                common_mistakes: vec!["Setting per_page too high for the upstream server's configured limits.".into()],
                examples: vec![
                    r#"{"channel_id": "abc123", "page": 0, "per_page": 30}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("mattermost.get_channel"),
                    CapabilityId::from_static("mattermost.search_posts"),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fn file_read_operations() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("mattermost.get_file_info"),
            summary: "Get file metadata and access paths by file ID.".into(),
            description: Some(
                "Returns Mattermost file metadata plus deterministic download, preview, and thumbnail paths.".into(),
            ),
            input_schema: json!({"type": "object", "properties": {"file_id": {"type": "string"}}, "required": ["file_id"]}),
            output_schema: json!({"type": "object", "properties": {"file": {"type": "object"}, "paths": {"type": "object"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to inspect file attachments before deciding whether to download or preview them.".into(),
                common_mistakes: vec!["Passing a post ID instead of a file ID.".into()],
                examples: vec![r#"{"file_id": "file123"}"#.into()],
                related: vec![CapabilityId::from_static("mattermost.get_file_infos_for_post")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_file_link"),
            summary: "Get the public link for a file.".into(),
            description: Some(
                "Returns the externally shareable file link together with the deterministic file access paths.".into(),
            ),
            input_schema: json!({"type": "object", "properties": {"file_id": {"type": "string"}}, "required": ["file_id"]}),
            output_schema: json!({"type": "object", "properties": {"file_id": {"type": "string"}, "link": {"type": ["string", "null"]}, "paths": {"type": "object"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to retrieve the public sharing URL for a file when a direct link is needed.".into(),
                common_mistakes: vec!["Passing a post ID instead of a file ID.".into()],
                examples: vec![r#"{"file_id": "file123"}"#.into()],
                related: vec![CapabilityId::from_static("mattermost.get_file_info")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.download_file"),
            summary: "Download a file as base64 content.".into(),
            description: Some(
                "Downloads the file body and returns a base64-encoded payload plus content metadata.".into(),
            ),
            input_schema: json!({"type": "object", "properties": {"file_id": {"type": "string"}}, "required": ["file_id"]}),
            output_schema: json!({"type": "object", "properties": {"file_id": {"type": "string"}, "content_base64": {"type": "string"}, "content_type": {"type": ["string", "null"]}, "size_bytes": {"type": "integer"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use when the connector needs the file body itself, not just metadata or a share link.".into(),
                common_mistakes: vec!["Downloading large files when metadata inspection would have been enough.".into()],
                examples: vec![r#"{"file_id": "file123"}"#.into()],
                related: vec![CapabilityId::from_static("mattermost.get_file_info")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_file_infos_for_post"),
            summary: "List file metadata for all files attached to a post.".into(),
            description: Some(
                "Returns all file attachments on a post together with stable download, preview, and thumbnail paths.".into(),
            ),
            input_schema: json!({"type": "object", "properties": {"post_id": {"type": "string"}}, "required": ["post_id"]}),
            output_schema: json!({"type": "object", "properties": {"files": {"type": "array"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to enumerate all files attached to a post before fetching individual file metadata.".into(),
                common_mistakes: vec!["Passing a root thread ID when you meant a specific post ID.".into()],
                examples: vec![r#"{"post_id": "post123"}"#.into()],
                related: vec![CapabilityId::from_static("mattermost.get_file_info")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fn search_operations() -> Vec<OperationInfo> {
    vec![OperationInfo {
        id: OperationId::from_static("mattermost.search_posts"),
        summary: "Search posts in a team.".into(),
        description: Some(
            "Full-text search across all channels the user can access in a team.".into(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "team_id": {"type": "string"},
                "terms": {"type": "string"},
                "is_or_search": {"type": "boolean", "default": false}
            },
            "required": ["team_id", "terms"]
        }),
        output_schema: json!({"type": "object", "properties": {"order": {"type": "array"}, "posts": {"type": "object"}}}),
        capability: CapabilityId::from_static("mattermost.read"),
        risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Safe,
        idempotency: IdempotencyClass::Strict,
        ai_hints: AgentHint {
            when_to_use: "Use to search messages across a team's channels.".into(),
            common_mistakes: vec![
                "Not specifying team_id.".into(),
                "Expecting server-wide search; the first slice is team-scoped only.".into(),
            ],
            examples: vec![r#"{"team_id": "t1", "terms": "deployment issue"}"#.into()],
            related: vec![
                CapabilityId::from_static("mattermost.get_posts_for_channel"),
                CapabilityId::from_static("mattermost.get_my_teams"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }]
}

fn read_reaction_operations() -> Vec<OperationInfo> {
    vec![get_reactions_for_post_operation()]
}

fn write_operations() -> Vec<OperationInfo> {
    vec![
        create_direct_channel_operation(),
        create_group_channel_operation(),
        create_post_operation(),
        update_post_operation(),
        pin_post_operation(),
        unpin_post_operation(),
        create_reaction_operation(),
        delete_reaction_operation(),
        upload_file_operation(),
        delete_post_operation(),
    ]
}

fn create_direct_channel_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.create_direct_channel"),
        summary: "Create or fetch a direct message channel.".into(),
        description: Some(
            "Creates the 1:1 direct channel for exactly two Mattermost user IDs or returns the existing direct channel.".into(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "user_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 2,
                    "maxItems": 2,
                    "uniqueItems": true
                }
            },
            "required": ["user_ids"]
        }),
        output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "display_name": {"type": "string"}, "type": {"type": "string"}}}),
        capability: CapabilityId::from_static("mattermost.write"),
        risk_level: RiskLevel::Medium,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::BestEffort,
        ai_hints: AgentHint {
            when_to_use: "Use when a workflow needs to open or ensure a direct-message channel before posting.".into(),
            common_mistakes: vec![
                "Passing fewer or more than two user IDs.".into(),
                "Passing duplicate user IDs instead of the two participants.".into(),
                "Assuming UI-level direct-message restrictions are the same as backend API authorization.".into(),
            ],
            examples: vec![r#"{"user_ids": ["user_a", "user_b"]}"#.into()],
            related: vec![
                CapabilityId::from_static("mattermost.get_channel"),
                CapabilityId::from_static("mattermost.create_post"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn create_post_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.create_post"),
        summary: "Send a message to a channel.".into(),
        description: Some(
            "Create a new post (message) in a Mattermost channel. Can also reply to threads."
                .into(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "channel_id": {"type": "string"},
                "message": {"type": "string"},
                "root_id": {"type": "string", "description": "Thread root post ID for replies"},
                "file_ids": {"type": "array", "items": {"type": "string"}, "description": "Previously uploaded Mattermost file IDs to attach"},
                "props": {"type": "object", "description": "Optional Mattermost post props"}
            },
            "required": ["channel_id", "message"]
        }),
        output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "message": {"type": "string"}}}),
        capability: CapabilityId::from_static("mattermost.write"),
        risk_level: RiskLevel::Medium,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::None,
        ai_hints: AgentHint {
            when_to_use: "Use to send a message to a channel or reply to an existing thread."
                .into(),
            common_mistakes: vec![
                "Forgetting to set channel_id.".into(),
                "Not using root_id when replying to a thread.".into(),
                "Using a bot token that has not been added to the target team or channel.".into(),
            ],
            examples: vec![
                r#"{"channel_id": "abc123", "message": "Hello team!"}"#.into(),
                r#"{"channel_id": "abc123", "message": "Reply here", "root_id": "post_id"}"#.into(),
            ],
            related: vec![
                CapabilityId::from_static("mattermost.upload_file"),
                CapabilityId::from_static("mattermost.get_channel"),
                CapabilityId::from_static("mattermost.get_post"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn create_reaction_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.create_reaction"),
        summary: "Add an emoji reaction to a post.".into(),
        description: Some("Adds a reaction for a specific user on a Mattermost post.".into()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "post_id": {"type": "string"},
                "emoji_name": {"type": "string"}
            },
            "required": ["user_id", "post_id", "emoji_name"]
        }),
        output_schema: json!({"type": "object", "properties": {"user_id": {"type": "string"}, "post_id": {"type": "string"}, "emoji_name": {"type": "string"}}}),
        capability: CapabilityId::from_static("mattermost.write"),
        risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::BestEffort,
        ai_hints: AgentHint {
            when_to_use: "Use to acknowledge or classify a post with an emoji reaction without editing the post body.".into(),
            common_mistakes: vec![
                "Passing an empty emoji_name.".into(),
                "Using a post ID that the acting user cannot access.".into(),
            ],
            examples: vec![
                r#"{"user_id": "user_a", "post_id": "post123", "emoji_name": "thumbsup"}"#
                    .into(),
            ],
            related: vec![
                CapabilityId::from_static("mattermost.get_post"),
                CapabilityId::from_static("mattermost.delete_reaction"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn delete_reaction_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.delete_reaction"),
        summary: "Remove an emoji reaction from a post.".into(),
        description: Some("Deletes a specific user's reaction from a Mattermost post.".into()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "post_id": {"type": "string"},
                "emoji_name": {"type": "string"}
            },
            "required": ["user_id", "post_id", "emoji_name"]
        }),
        output_schema: json!({"type": "object", "properties": {"status": {"type": "string"}, "user_id": {"type": "string"}, "post_id": {"type": "string"}, "emoji_name": {"type": "string"}}}),
        capability: CapabilityId::from_static("mattermost.write"),
        risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::BestEffort,
        ai_hints: AgentHint {
            when_to_use:
                "Use to clean up or revert a reaction without deleting the underlying post.".into(),
            common_mistakes: vec![
                "Trying to remove a reaction without the acting user ID.".into(),
                "Forgetting that server-side permissions still apply when removing someone else's reaction.".into(),
            ],
            examples: vec![
                r#"{"user_id": "user_a", "post_id": "post123", "emoji_name": "thumbsup"}"#
                    .into(),
            ],
            related: vec![
                CapabilityId::from_static("mattermost.create_reaction"),
                CapabilityId::from_static("mattermost.get_post"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn upload_file_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.upload_file"),
        summary: "Upload a file to a channel.".into(),
        description: Some(
            "Uploads one file to Mattermost and returns the resulting file IDs and deterministic access paths so the file can be attached to a later post.".into(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "channel_id": {"type": "string"},
                "filename": {"type": "string"},
                "content_base64": {"type": "string"},
                "client_id": {"type": "string"},
                "content_type": {"type": "string"}
            },
            "required": ["channel_id", "filename", "content_base64"]
        }),
        output_schema: json!({"type": "object", "properties": {"files": {"type": "array"}, "client_ids": {"type": "array"}}}),
        capability: CapabilityId::from_static("mattermost.write"),
        risk_level: RiskLevel::Medium,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::None,
        ai_hints: AgentHint {
            when_to_use: "Use before create_post when a workflow needs to attach a file to a Mattermost message.".into(),
            common_mistakes: vec![
                "Passing raw bytes instead of base64-encoded content.".into(),
                "Forgetting to carry the returned file IDs into create_post.".into(),
                "Trying to upload as a bot that is not a member of the target channel.".into(),
            ],
            examples: vec![r#"{"channel_id": "abc123", "filename": "report.txt", "content_base64": "aGVsbG8="}"#.into()],
            related: vec![
                CapabilityId::from_static("mattermost.create_post"),
                CapabilityId::from_static("mattermost.get_file_info"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn delete_post_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.delete_post"),
        summary: "Delete a post.".into(),
        description: Some("Permanently delete a post. Requires appropriate permissions.".into()),
        input_schema: json!({"type": "object", "properties": {"post_id": {"type": "string"}}, "required": ["post_id"]}),
        output_schema: json!({"type": "object", "properties": {"status": {"type": "string"}}}),
        capability: CapabilityId::from_static("mattermost.write"),
        risk_level: RiskLevel::High,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::BestEffort,
        ai_hints: AgentHint {
            when_to_use: "Use to delete a message after verifying the post ID carefully.".into(),
            common_mistakes: vec![
                "Deleting the wrong post by not verifying post_id first.".into(),
                "Treating this connector like a workspace-admin surface; delete permissions still depend on the acting account and server policy.".into(),
            ],
            examples: vec![r#"{"post_id": "abc123"}"#.into()],
            related: vec![CapabilityId::from_static("mattermost.get_post")],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::Interactive),
    }
}

fn get_reactions_for_post_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.get_reactions_for_post"),
        summary: "Get all reactions for a post.".into(),
        description: Some(
            "Returns the full list of emoji reactions on a post, including user IDs and timestamps."
                .into(),
        ),
        input_schema: json!({"type": "object", "properties": {"post_id": {"type": "string"}}, "required": ["post_id"]}),
        output_schema: json!({"type": "array", "items": {"type": "object", "properties": {"user_id": {"type": "string"}, "post_id": {"type": "string"}, "emoji_name": {"type": "string"}, "create_at": {"type": "integer"}}}}),
        capability: CapabilityId::from_static("mattermost.read"),
        risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Safe,
        idempotency: IdempotencyClass::Strict,
        ai_hints: AgentHint {
            when_to_use: "Use to retrieve all reactions on a message, such as counting votes or checking acknowledgments.".into(),
            common_mistakes: vec![
                "Assuming reaction names include colons; Mattermost uses bare emoji names like 'thumbsup'.".into(),
            ],
            examples: vec![r#"{"post_id": "abc123"}"#.into()],
            related: vec![
                CapabilityId::from_static("mattermost.create_reaction"),
                CapabilityId::from_static("mattermost.delete_reaction"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn create_group_channel_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.create_group_channel"),
        summary: "Create or fetch a group message channel.".into(),
        description: Some(
            "Creates a group direct-message channel for three or more Mattermost user IDs, or returns the existing channel if one already exists for that exact set of participants."
                .into(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "user_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 3,
                    "uniqueItems": true
                }
            },
            "required": ["user_ids"]
        }),
        output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "display_name": {"type": "string"}, "type": {"type": "string"}}}),
        capability: CapabilityId::from_static("mattermost.write"),
        risk_level: RiskLevel::Medium,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::BestEffort,
        ai_hints: AgentHint {
            when_to_use: "Use when a workflow needs a group DM channel with three or more participants.".into(),
            common_mistakes: vec![
                "Passing fewer than three user IDs; use create_direct_channel for 1:1 conversations.".into(),
                "Passing duplicate user IDs.".into(),
            ],
            examples: vec![r#"{"user_ids": ["user_a", "user_b", "user_c"]}"#.into()],
            related: vec![
                CapabilityId::from_static("mattermost.create_direct_channel"),
                CapabilityId::from_static("mattermost.create_post"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn update_post_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.update_post"),
        summary: "Edit an existing post.".into(),
        description: Some(
            "Update the message text, props, or file attachments of an existing post. Only the fields provided in the request body are patched."
                .into(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Post ID to update"},
                "message": {"type": "string", "description": "New message text"},
                "props": {"type": "object", "description": "Updated post props"},
                "file_ids": {"type": "array", "items": {"type": "string"}, "description": "Updated file attachment IDs"},
                "has_reactions": {"type": "boolean"}
            },
            "required": ["id"]
        }),
        output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "message": {"type": "string"}}}),
        capability: CapabilityId::from_static("mattermost.write"),
        risk_level: RiskLevel::Medium,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::BestEffort,
        ai_hints: AgentHint {
            when_to_use: "Use to edit a message after it has been posted, such as correcting a typo or updating status information.".into(),
            common_mistakes: vec![
                "Forgetting to include the post id field.".into(),
                "Assuming you can change the channel_id or user_id of an existing post.".into(),
                "Not having edit permissions for the target post.".into(),
            ],
            examples: vec![
                r#"{"id": "abc123", "message": "Updated message text"}"#.into(),
            ],
            related: vec![
                CapabilityId::from_static("mattermost.create_post"),
                CapabilityId::from_static("mattermost.get_post"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn pin_post_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.pin_post"),
        summary: "Pin a post to its channel.".into(),
        description: Some(
            "Pins a post so it appears in the channel's pinned messages list. Pinning is idempotent."
                .into(),
        ),
        input_schema: json!({"type": "object", "properties": {"post_id": {"type": "string"}}, "required": ["post_id"]}),
        output_schema: json!({"type": "object", "properties": {"status": {"type": "string"}, "post_id": {"type": "string"}}}),
        capability: CapabilityId::from_static("mattermost.write"),
        risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::BestEffort,
        ai_hints: AgentHint {
            when_to_use: "Use to highlight an important message so channel members can find it easily.".into(),
            common_mistakes: vec![
                "Pinning without verifying the post_id first.".into(),
            ],
            examples: vec![r#"{"post_id": "abc123"}"#.into()],
            related: vec![
                CapabilityId::from_static("mattermost.unpin_post"),
                CapabilityId::from_static("mattermost.get_post"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn unpin_post_operation() -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static("mattermost.unpin_post"),
        summary: "Unpin a post from its channel.".into(),
        description: Some(
            "Removes a post from the channel's pinned messages list. Unpinning is idempotent."
                .into(),
        ),
        input_schema: json!({"type": "object", "properties": {"post_id": {"type": "string"}}, "required": ["post_id"]}),
        output_schema: json!({"type": "object", "properties": {"status": {"type": "string"}, "post_id": {"type": "string"}}}),
        capability: CapabilityId::from_static("mattermost.write"),
        risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::BestEffort,
        ai_hints: AgentHint {
            when_to_use: "Use to remove a post from the pinned messages list.".into(),
            common_mistakes: vec![
                "Unpinning a post that was not pinned; this is a no-op on most Mattermost versions.".into(),
            ],
            examples: vec![r#"{"post_id": "abc123"}"#.into()],
            related: vec![
                CapabilityId::from_static("mattermost.pin_post"),
                CapabilityId::from_static("mattermost.get_post"),
            ],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn event_info() -> Vec<EventInfo> {
    fn schema(extra: &serde_json::Value) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "event": {"type": "string"},
                "data": extra,
                "broadcast": {"type": "object"},
                "seq": {"type": "integer"}
            }
        })
    }

    vec![
        EventInfo {
            topic: "mattermost.posted".into(),
            schema: schema(&json!({"type": "object"})),
            requires_ack: false,
        },
        EventInfo {
            topic: "mattermost.post_edited".into(),
            schema: schema(&json!({"type": "object"})),
            requires_ack: false,
        },
        EventInfo {
            topic: "mattermost.post_deleted".into(),
            schema: schema(&json!({"type": "object"})),
            requires_ack: false,
        },
        EventInfo {
            topic: "mattermost.reaction_added".into(),
            schema: schema(&json!({"type": "object"})),
            requires_ack: false,
        },
        EventInfo {
            topic: "mattermost.reaction_removed".into(),
            schema: schema(&json!({"type": "object"})),
            requires_ack: false,
        },
        EventInfo {
            topic: "mattermost.thread_updated".into(),
            schema: schema(&json!({"type": "object"})),
            requires_ack: false,
        },
        EventInfo {
            topic: "mattermost.channel_created".into(),
            schema: schema(&json!({"type": "object"})),
            requires_ack: false,
        },
        EventInfo {
            topic: "mattermost.channel_updated".into(),
            schema: schema(&json!({"type": "object"})),
            requires_ack: false,
        },
        EventInfo {
            topic: "mattermost.channel_deleted".into(),
            schema: schema(&json!({"type": "object"})),
            requires_ack: false,
        },
        EventInfo {
            topic: "mattermost.typing".into(),
            schema: schema(&json!({"type": "object"})),
            requires_ack: false,
        },
    ]
}

// ── Websocket helpers ───────────────────────────────────────────────────

fn parse_subscribe_topics(params: &serde_json::Value) -> Vec<String> {
    let mut topics = params
        .get("topics")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
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

async fn send_socket_action(
    ws_stream: &mut WsConnection,
    action: &str,
    seq: u64,
    data: Value,
) -> Result<(), fcp_streaming::StreamError> {
    ws_stream
        .send_text(
            json!({
                "action": action,
                "seq": seq,
                "data": data,
            })
            .to_string(),
        )
        .await
}

fn mattermost_event_topic(event_name: &str) -> String {
    match event_name {
        "posted" => "mattermost.posted".to_string(),
        "post_edited" => "mattermost.post_edited".to_string(),
        "post_deleted" => "mattermost.post_deleted".to_string(),
        "reaction_added" => "mattermost.reaction_added".to_string(),
        "reaction_removed" => "mattermost.reaction_removed".to_string(),
        "thread_updated" => "mattermost.thread_updated".to_string(),
        "channel_created" => "mattermost.channel_created".to_string(),
        "channel_updated" => "mattermost.channel_updated".to_string(),
        "channel_deleted" => "mattermost.channel_deleted".to_string(),
        "typing" => "mattermost.typing".to_string(),
        "direct_added" => "mattermost.direct_added".to_string(),
        other => format!("mattermost.event.{other}"),
    }
}

fn apply_socket_resume_state(
    message: &MattermostWebSocketMessage,
    connection_id: &mut String,
    expected_server_seq: &mut u64,
) -> bool {
    if message.event.as_deref() == Some("hello")
        && let Some(new_connection_id) = message
            .data
            .get("connection_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
    {
        // Mattermost resets the resume stream when the server no longer recognizes the
        // prior connection/sequence state. The hello packet advertises the new connection_id.
        if !connection_id.is_empty() && connection_id != new_connection_id {
            *expected_server_seq = 0;
        }
        connection_id.clone_from(&new_connection_id.to_string());
    }

    if let Some(seq) = message.seq {
        if seq != *expected_server_seq {
            return false;
        }
        *expected_server_seq = seq.saturating_add(1);
    }

    true
}

fn websocket_message_to_event(
    message: &MattermostWebSocketMessage,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
    fallback_seq: &AtomicU64,
) -> Option<EventEnvelope> {
    let event_name = message.event.as_deref()?;
    let topic = mattermost_event_topic(event_name);
    let post = post_from_socket_message(message);
    let reaction = reaction_from_socket_message(message);
    let channel = channel_from_socket_message(message);
    let thread = thread_from_socket_message(message);

    let payload = normalized_socket_payload(
        message,
        post.as_ref(),
        reaction.as_ref(),
        channel.as_ref(),
        thread.as_ref(),
    );
    let principal = principal_from_socket_message(message, post.as_ref(), reaction.as_ref());
    let mut data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        ZoneId::work(),
        principal,
        payload,
    );
    if let Some(thread_info) =
        thread_info_from_socket_message(message, post.as_ref(), thread.as_ref())
    {
        data = data.with_thread_info(thread_info);
    }

    let seq = message
        .seq
        .unwrap_or_else(|| fallback_seq.fetch_add(1, Ordering::Relaxed));
    let mut envelope = EventEnvelope::new(topic, data)
        .with_seq(seq)
        .with_cursor_seq(seq)
        .with_ordering(OrderingPolicy::Gateway);

    if let Some(stream_key) =
        stream_key_from_socket_message(message, post.as_ref(), channel.as_ref(), thread.as_ref())
    {
        envelope = envelope.with_stream_key(stream_key);
    }

    Some(envelope)
}

fn normalized_socket_payload(
    message: &MattermostWebSocketMessage,
    post: Option<&Post>,
    reaction: Option<&Reaction>,
    channel: Option<&Channel>,
    thread: Option<&ThreadResponse>,
) -> Value {
    let data = match &message.data {
        Value::Object(map) => {
            let mut map = map.clone();
            if let Some(post) = post
                && let Ok(value) = serde_json::to_value(post)
            {
                map.insert("post".into(), value);
            }
            if let Some(reaction) = reaction
                && let Ok(value) = serde_json::to_value(reaction)
            {
                map.insert("reaction".into(), value);
            }
            if let Some(channel) = channel
                && let Ok(value) = serde_json::to_value(channel)
            {
                map.insert("channel".into(), value);
            }
            if let Some(thread) = thread
                && let Ok(value) = serde_json::to_value(thread)
            {
                map.insert("thread".into(), value);
            }
            Value::Object(map)
        }
        other => other.clone(),
    };

    json!({
        "event": message.event,
        "data": data,
        "broadcast": message.broadcast,
        "seq": message.seq,
    })
}

fn principal_from_socket_message(
    message: &MattermostWebSocketMessage,
    post: Option<&Post>,
    reaction: Option<&Reaction>,
) -> Principal {
    if let Some(post) = post {
        let user_id = if post.user_id.is_empty() {
            fallback_principal_id(message)
        } else {
            post.user_id.clone()
        };
        return Principal {
            kind: "mattermost_user".into(),
            id: user_id,
            trust: TrustLevel::Untrusted,
            display: message
                .data
                .get("sender_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
    }

    if let Some(reaction) = reaction {
        return Principal {
            kind: "mattermost_user".into(),
            id: if reaction.user_id.is_empty() {
                fallback_principal_id(message)
            } else {
                reaction.user_id.clone()
            },
            trust: TrustLevel::Untrusted,
            display: None,
        };
    }

    Principal {
        kind: if message.broadcast.user_id.is_empty() {
            "mattermost_system".into()
        } else {
            "mattermost_user".into()
        },
        id: fallback_principal_id(message),
        trust: TrustLevel::Untrusted,
        display: None,
    }
}

fn fallback_principal_id(message: &MattermostWebSocketMessage) -> String {
    message
        .data
        .get("user_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            (!message.broadcast.user_id.is_empty()).then(|| message.broadcast.user_id.clone())
        })
        .unwrap_or_else(|| "unknown".into())
}

fn thread_info_from_socket_message(
    message: &MattermostWebSocketMessage,
    post: Option<&Post>,
    thread: Option<&ThreadResponse>,
) -> Option<ThreadInfo> {
    if let Some(post) = post
        && !post.root_id.is_empty()
    {
        return Some(
            ThreadInfo::new(post.root_id.clone(), ThreadKind::Reply)
                .with_parent_id(post.root_id.clone()),
        );
    }

    if let Some(parent_id) = message.data.get("parent_id").and_then(Value::as_str)
        && !parent_id.is_empty()
    {
        return Some(
            ThreadInfo::new(parent_id.to_string(), ThreadKind::Reply)
                .with_parent_id(parent_id.to_string()),
        );
    }

    thread.map(|thread| {
        ThreadInfo::new(thread.id.clone(), ThreadKind::Thread).with_parent_id(thread.id.clone())
    })
}

fn stream_key_from_socket_message(
    message: &MattermostWebSocketMessage,
    post: Option<&Post>,
    channel: Option<&Channel>,
    thread: Option<&ThreadResponse>,
) -> Option<String> {
    if let Some(post) = post
        && !post.channel_id.is_empty()
    {
        return Some(post.channel_id.clone());
    }

    if let Some(channel_id) = message.data.get("channel_id").and_then(Value::as_str)
        && !channel_id.is_empty()
    {
        return Some(channel_id.to_string());
    }

    if let Some(channel) = channel
        && !channel.id.is_empty()
    {
        return Some(channel.id.clone());
    }

    if let Some(thread) = thread
        && let Some(post) = &thread.post
        && !post.channel_id.is_empty()
    {
        return Some(post.channel_id.clone());
    }

    if !message.broadcast.channel_id.is_empty() {
        return Some(message.broadcast.channel_id.clone());
    }

    (!message.broadcast.team_id.is_empty()).then(|| format!("team:{}", message.broadcast.team_id))
}

fn post_from_socket_message(message: &MattermostWebSocketMessage) -> Option<Post> {
    match message.event.as_deref() {
        Some("posted" | "post_edited" | "post_deleted") => {
            decode_embedded_json(message.data.get("post"))
        }
        _ => None,
    }
}

fn reaction_from_socket_message(message: &MattermostWebSocketMessage) -> Option<Reaction> {
    match message.event.as_deref() {
        Some("reaction_added" | "reaction_removed") => {
            decode_embedded_json(message.data.get("reaction"))
        }
        _ => None,
    }
}

fn channel_from_socket_message(message: &MattermostWebSocketMessage) -> Option<Channel> {
    match message.event.as_deref() {
        Some("channel_created" | "channel_updated" | "channel_deleted") => {
            decode_embedded_json(message.data.get("channel"))
        }
        _ => None,
    }
}

fn thread_from_socket_message(message: &MattermostWebSocketMessage) -> Option<ThreadResponse> {
    match message.event.as_deref() {
        Some("thread_updated") => decode_embedded_json(message.data.get("thread")),
        _ => None,
    }
}

fn decode_embedded_json<T: DeserializeOwned>(value: Option<&Value>) -> Option<T> {
    let value = value?;
    match value {
        Value::String(text) => serde_json::from_str(text).ok(),
        other => serde_json::from_value(other.clone()).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{CapabilityToken, RequestId};
    use fcp_crypto::ed25519::Ed25519SigningKey;

    fn invoke_request(
        connector: &MattermostConnector,
        operation: &str,
        input: Value,
        capability_token: CapabilityToken,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector.id().clone(),
            operation: OperationId::new(operation).expect("valid Mattermost operation id"),
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

    #[test]
    fn connector_new() {
        let connector = MattermostConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.mattermost");
    }

    #[test]
    fn connector_default() {
        let connector = MattermostConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.mattermost");
    }

    #[test]
    fn operations_info_has_entries() {
        let ops = operations_info();
        assert!(!ops.is_empty());
        assert!(ops.len() >= 22);
    }

    #[test]
    fn operations_info_ids_unique() {
        let ops = operations_info();
        let mut ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate operation IDs found");
    }

    #[test]
    fn operations_info_all_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.ai_hints.when_to_use.is_empty(),
                "operation {} missing when_to_use hint",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn write_operations_are_risky() {
        let ops = operations_info();
        for op in &ops {
            if op.capability.as_str().rsplit('.').next() == Some("write") {
                assert!(
                    matches!(op.safety_tier, SafetyTier::Risky),
                    "write operation {} should be Risky, got {:?}",
                    op.id.as_str(),
                    op.safety_tier
                );
            }
        }
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            if op.capability.as_str().rsplit('.').next() == Some("read") {
                assert!(
                    matches!(op.safety_tier, SafetyTier::Safe),
                    "read operation {} should be Safe, got {:?}",
                    op.id.as_str(),
                    op.safety_tier
                );
            }
        }
    }

    #[test]
    fn read_operations_are_strictly_idempotent() {
        let ops = operations_info();
        for op in &ops {
            if op.capability.as_str().rsplit('.').next() == Some("read") {
                assert!(
                    matches!(op.idempotency, IdempotencyClass::Strict),
                    "read operation {} should be Strict, got {:?}",
                    op.id.as_str(),
                    op.idempotency
                );
            }
        }
    }

    #[test]
    fn introspect_returns_operations_and_events() {
        let connector = MattermostConnector::new();
        let introspection = connector.introspect();
        assert!(introspection.operations.len() >= 22);
        assert!(introspection.events.len() >= 10);
        assert!(introspection.event_caps.as_ref().unwrap().streaming);
        assert_eq!(
            introspection.auth_caps.as_ref().unwrap().methods,
            vec![
                "personal_access_token".to_string(),
                "bot_access_token".to_string(),
                "credential_id".to_string()
            ]
        );
        assert!(introspection.resource_types.len() >= 5);
    }

    #[test]
    fn introspection_exposes_self_hosted_scope_resources() {
        let introspection = MattermostConnector::new().introspect();
        let resource_names = introspection
            .resource_types
            .iter()
            .map(|resource| resource.name.as_str())
            .collect::<HashSet<_>>();

        assert!(resource_names.contains("mattermost.user"));
        assert!(resource_names.contains("mattermost.team"));
        assert!(resource_names.contains("mattermost.channel"));
        assert!(resource_names.contains("mattermost.post"));
        assert!(resource_names.contains("mattermost.file"));
    }

    #[test]
    fn health_not_configured() {
        let connector = MattermostConnector::new();
        let health = connector.health();
        assert!(matches!(health.status, HealthState::Starting));
        assert!(health.uptime_ms < 1_000);
    }

    #[test]
    fn health_reports_elapsed_uptime() {
        let mut connector = MattermostConnector::new();
        connector.started_at = Instant::now()
            .checked_sub(Duration::from_millis(25))
            .expect("subtracting 25ms from now should be valid");

        let health = connector.health();
        assert!(health.uptime_ms >= 25);
    }

    #[test]
    fn handshake_reports_manifest_hash() {
        let mut connector = MattermostConnector::new();
        let response = connector
            .handshake(&HandshakeRequest {
                protocol_version: "1.0".into(),
                host_public_key: [7; 32],
                zone: ZoneId::work(),
                zone_dir: None,
                capabilities_requested: vec![CapabilityId::from_static("mattermost.read")],
                nonce: [9; 32],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            })
            .expect("handshake should succeed");

        assert_eq!(response.manifest_hash, MattermostConnector::manifest_hash());
        assert!(response.manifest_hash.starts_with("sha256:"));
    }

    #[fcp_async_core::runtime::test]
    async fn handle_health_marks_unconnected_stream_as_degraded() {
        let mut connector = MattermostConnector::new();
        connector
            .configure(json!({
                "base_url": "https://mattermost.example.com",
                "token": "tok_123"
            }))
            .unwrap();
        *connector.subscribed_topics.write().await = vec!["mattermost.posted".to_string()];
        *connector.socket_running.write().await = true;

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"]["state"], "degraded");
        assert_eq!(
            health["status"]["reason"],
            "stream subscription active but websocket is not connected"
        );
        assert_eq!(health["details"]["streaming"]["socket_running"], true);
        assert_eq!(health["details"]["streaming"]["socket_connected"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn handle_health_reports_connected_stream_as_ready() {
        let mut connector = MattermostConnector::new();
        connector
            .configure(json!({
                "base_url": "https://mattermost.example.com",
                "token": "tok_123"
            }))
            .unwrap();
        *connector.subscribed_topics.write().await = vec!["mattermost.posted".to_string()];
        *connector.socket_running.write().await = true;
        *connector.socket_connected.write().await = true;

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"]["state"], "ready");
        assert_eq!(health["details"]["streaming"]["socket_running"], true);
        assert_eq!(health["details"]["streaming"]["socket_connected"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn handle_shutdown_clears_stream_subscription_state() {
        let mut connector = MattermostConnector::new();
        connector
            .configure(json!({
                "base_url": "https://mattermost.example.com",
                "token": "tok_123"
            }))
            .unwrap();
        *connector.subscribed_topics.write().await = vec!["mattermost.posted".to_string()];
        *connector.socket_running.write().await = true;
        *connector.socket_connected.write().await = true;

        let response = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(response["status"], "shutdown_accepted");
        assert!(connector.subscribed_topics.read().await.is_empty());

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"]["state"], "starting");
        assert_eq!(health["details"]["streaming"]["socket_running"], false);
        assert_eq!(health["details"]["streaming"]["socket_connected"], false);
        assert_eq!(
            health["details"]["streaming"]["subscribed_topics"],
            json!([])
        );
    }

    #[test]
    fn delete_requires_approval() {
        let ops = operations_info();
        let delete_op = ops
            .iter()
            .find(|o| o.id.as_str() == "mattermost.delete_post")
            .expect("delete operation should exist");
        assert!(
            matches!(delete_op.requires_approval, Some(ApprovalMode::Interactive)),
            "delete should require interactive approval"
        );
    }

    #[test]
    fn mutation_expansion_operations_exist() {
        let ops = operations_info();
        let ids = ops.iter().map(|op| op.id.as_str()).collect::<HashSet<_>>();
        assert!(ids.contains("mattermost.create_direct_channel"));
        assert!(ids.contains("mattermost.create_reaction"));
        assert!(ids.contains("mattermost.delete_reaction"));
        assert!(ids.contains("mattermost.upload_file"));
    }

    #[test]
    fn direct_channel_operation_is_best_effort() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|operation| operation.id.as_str() == "mattermost.create_direct_channel")
            .expect("direct channel operation should exist");
        assert!(matches!(op.idempotency, IdempotencyClass::BestEffort));
        assert!(matches!(op.requires_approval, Some(ApprovalMode::None)));
    }

    #[test]
    fn operations_do_not_expose_workspace_admin_capability() {
        let ops = operations_info();
        assert!(
            ops.iter()
                .all(|operation| operation.capability.as_str() != "mattermost.admin"),
            "first-slice Mattermost connector should not expose workspace-admin operations"
        );
    }

    #[test]
    fn configure_rejects_ambiguous_auth_modes() {
        let err = MattermostConnector::new()
            .configure(json!({
                "base_url": "https://mattermost.example.com",
                "token": "tok_123",
                "credential_id": "cred_123"
            }))
            .unwrap_err();

        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        assert!(err.to_string().contains("configure exactly one auth mode"));
    }

    #[test]
    fn configure_rejects_blank_base_url() {
        let err = MattermostConnector::new()
            .configure(json!({
                "base_url": "   ",
                "token": "tok_123"
            }))
            .unwrap_err();

        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        assert!(err.to_string().contains("base_url is required"));
    }

    #[test]
    fn configure_normalizes_trimmed_auth_config() {
        let mut connector = MattermostConnector::new();
        connector
            .configure(json!({
                "base_url": " https://mattermost.example.com ",
                "token": "  tok_123  ",
                "credential_id": "   ",
                "request_timeout_ms": 5_000
            }))
            .expect("configuration should succeed");

        let config = connector
            .config
            .as_ref()
            .expect("configuration should be stored");
        assert_eq!(config.base_url, "https://mattermost.example.com");
        assert_eq!(config.token.as_deref(), Some("tok_123"));
        assert!(config.credential_id.is_none());
    }

    #[test]
    fn create_post_schema_supports_file_ids() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|operation| operation.id.as_str() == "mattermost.create_post")
            .expect("create_post operation should exist");
        assert_eq!(op.input_schema["properties"]["file_ids"]["type"], "array");
    }

    #[test]
    fn create_post_validation_rejects_blank_channel_id() {
        let err = validate_create_post_request(&CreatePostRequest {
            channel_id: "   ".into(),
            message: "hello".into(),
            root_id: None,
            file_ids: None,
            props: None,
        })
        .unwrap_err();

        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        assert_eq!(err.to_string(), "Invalid request: channel_id is required");
    }

    #[test]
    fn create_post_validation_rejects_blank_file_ids() {
        let err = validate_create_post_request(&CreatePostRequest {
            channel_id: "channel-1".into(),
            message: String::new(),
            root_id: None,
            file_ids: Some(vec!["file-1".into(), "   ".into()]),
            props: None,
        })
        .unwrap_err();

        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        assert_eq!(
            err.to_string(),
            "Invalid request: file_ids must not contain empty values"
        );
    }

    #[test]
    fn create_post_validation_allows_attachment_only_posts() {
        let result = validate_create_post_request(&CreatePostRequest {
            channel_id: "channel-1".into(),
            message: String::new(),
            root_id: None,
            file_ids: Some(vec!["file-1".into()]),
            props: None,
        });

        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_handshake_after_configuration() {
        let mut connector = MattermostConnector::new();
        connector
            .configure(json!({
                "base_url": "https://mattermost.example.com",
                "token": "tok",
            }))
            .unwrap();

        let err = connector
            .invoke(invoke_request(
                &connector,
                "mattermost.get_me",
                json!({}),
                CapabilityToken::test_token(),
            ))
            .await
            .unwrap_err();

        assert!(matches!(err, FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_rejects_invalid_capability_token_before_dispatch() {
        let mut connector = MattermostConnector::new();
        connector
            .configure(json!({
                "base_url": "https://mattermost.example.com",
                "token": "tok",
            }))
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(&HandshakeRequest {
                protocol_version: "1.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [0u8; 32],
                capabilities_requested: vec![CapabilityId::from_static("mattermost.read")],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            })
            .unwrap();

        let err = connector
            .invoke(invoke_request(
                &connector,
                "mattermost.get_user",
                json!({}),
                CapabilityToken::test_token(),
            ))
            .await
            .unwrap_err();

        assert!(matches!(err, FcpError::InvalidSignature));
    }

    #[fcp_async_core::runtime::test]
    async fn subscribe_requires_handshake_after_configuration() {
        let mut connector = MattermostConnector::new();
        connector
            .configure(json!({
                "base_url": "https://mattermost.example.com",
                "token": "tok",
            }))
            .unwrap();

        let err = connector
            .handle_subscribe(json!({
                "type": "subscribe",
                "id": "sub_1",
                "topics": ["mattermost.posted"],
            }))
            .await
            .unwrap_err();

        assert!(matches!(err, FcpError::NotHandshaken));
    }

    #[test]
    fn parse_subscribe_topics_defaults() {
        let topics = parse_subscribe_topics(&json!({}));
        assert_eq!(topics[0], "mattermost.posted");
        assert!(topics.contains(&"mattermost.thread_updated".to_string()));
    }

    #[test]
    fn parse_subscribe_topics_deduplicates_and_filters_empty() {
        let topics = parse_subscribe_topics(&json!({
            "topics": ["mattermost.posted", "", "mattermost.posted", "mattermost.channel_*"]
        }));
        assert_eq!(
            topics,
            vec![
                "mattermost.posted".to_string(),
                "mattermost.channel_*".to_string()
            ]
        );
    }

    #[test]
    fn topic_allowed_supports_exact_and_prefix_patterns() {
        assert!(topic_allowed(
            "mattermost.posted",
            &["mattermost.posted".into()]
        ));
        assert!(topic_allowed(
            "mattermost.channel_updated",
            &["mattermost.channel_*".into()]
        ));
        assert!(topic_allowed("mattermost.typing", &["*".into()]));
        assert!(!topic_allowed(
            "mattermost.thread_updated",
            &["mattermost.posted".into()]
        ));
    }

    #[test]
    fn websocket_message_to_event_normalizes_posted_payload() {
        let message: MattermostWebSocketMessage = serde_json::from_value(json!({
            "event": "posted",
            "data": {
                "post": "{\"id\":\"p1\",\"channel_id\":\"c1\",\"user_id\":\"u1\",\"message\":\"hello\",\"root_id\":\"root1\",\"file_ids\":[\"f1\"]}",
                "sender_name": "alice"
            },
            "broadcast": {
                "channel_id": "c1",
                "team_id": "t1",
                "user_id": "u1"
            },
            "seq": 41
        }))
        .unwrap();

        let connector_id = ConnectorId::from_static("fcp.mattermost");
        let instance_id = InstanceId::new();
        let fallback = AtomicU64::new(1);
        let event =
            websocket_message_to_event(&message, &connector_id, &instance_id, &fallback).unwrap();

        assert_eq!(event.topic, "mattermost.posted");
        assert_eq!(event.seq, 41);
        assert_eq!(event.stream_key.as_deref(), Some("c1"));
        assert_eq!(event.data.principal.id, "u1");
        assert_eq!(
            event
                .data
                .thread_info
                .as_ref()
                .map(|info| info.thread_id.as_str()),
            Some("root1")
        );
        assert_eq!(event.data.payload["data"]["post"]["file_ids"][0], "f1");
    }

    #[test]
    fn websocket_message_to_event_normalizes_thread_update() {
        let message: MattermostWebSocketMessage = serde_json::from_value(json!({
            "event": "thread_updated",
            "data": {
                "thread": "{\"id\":\"root1\",\"reply_count\":2,\"post\":{\"id\":\"root1\",\"channel_id\":\"chan1\",\"message\":\"root\"}}"
            },
            "broadcast": {
                "channel_id": "chan1",
                "team_id": "team1",
                "user_id": "u1"
            }
        }))
        .unwrap();

        let connector_id = ConnectorId::from_static("fcp.mattermost");
        let instance_id = InstanceId::new();
        let fallback = AtomicU64::new(88);
        let event =
            websocket_message_to_event(&message, &connector_id, &instance_id, &fallback).unwrap();

        assert_eq!(event.topic, "mattermost.thread_updated");
        assert_eq!(event.seq, 88);
        assert_eq!(event.stream_key.as_deref(), Some("chan1"));
        assert_eq!(event.data.payload["data"]["thread"]["reply_count"], 2);
    }

    #[test]
    fn hello_with_new_connection_id_resets_resume_sequence() {
        let message: MattermostWebSocketMessage = serde_json::from_value(json!({
            "event": "hello",
            "data": {
                "connection_id": "conn-new"
            },
            "seq": 0
        }))
        .unwrap();

        let mut connection_id = String::from("conn-old");
        let mut expected_server_seq = 44;

        assert!(apply_socket_resume_state(
            &message,
            &mut connection_id,
            &mut expected_server_seq
        ));
        assert_eq!(connection_id, "conn-new");
        assert_eq!(expected_server_seq, 1);
    }

    #[test]
    fn non_hello_sequence_mismatch_still_requests_reconnect() {
        let message: MattermostWebSocketMessage = serde_json::from_value(json!({
            "event": "posted",
            "seq": 9
        }))
        .unwrap();

        let mut connection_id = String::from("conn-a");
        let mut expected_server_seq = 3;

        assert!(!apply_socket_resume_state(
            &message,
            &mut connection_id,
            &mut expected_server_seq
        ));
        assert_eq!(connection_id, "conn-a");
        assert_eq!(expected_server_seq, 3);
    }

    #[test]
    fn new_mutation_operations_present() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        assert!(
            ids.contains(&"mattermost.update_post"),
            "missing update_post"
        );
        assert!(ids.contains(&"mattermost.pin_post"), "missing pin_post");
        assert!(ids.contains(&"mattermost.unpin_post"), "missing unpin_post");
        assert!(
            ids.contains(&"mattermost.get_reactions_for_post"),
            "missing get_reactions_for_post"
        );
        assert!(
            ids.contains(&"mattermost.create_group_channel"),
            "missing create_group_channel"
        );
    }

    #[test]
    fn update_post_operation_has_correct_classification() {
        let op = update_post_operation();
        assert_eq!(op.capability.as_str(), "mattermost.write");
        assert!(matches!(op.safety_tier, SafetyTier::Risky));
        assert!(matches!(op.risk_level, RiskLevel::Medium));
        assert!(matches!(op.idempotency, IdempotencyClass::BestEffort));
    }

    #[test]
    fn pin_unpin_operations_have_correct_classification() {
        let pin = pin_post_operation();
        assert_eq!(pin.capability.as_str(), "mattermost.write");
        assert!(matches!(pin.risk_level, RiskLevel::Low));
        assert!(matches!(pin.safety_tier, SafetyTier::Risky));

        let unpin = unpin_post_operation();
        assert_eq!(unpin.capability.as_str(), "mattermost.write");
        assert!(matches!(unpin.risk_level, RiskLevel::Low));
        assert!(matches!(unpin.safety_tier, SafetyTier::Risky));
    }

    #[test]
    fn get_reactions_for_post_is_safe_read() {
        let op = get_reactions_for_post_operation();
        assert_eq!(op.capability.as_str(), "mattermost.read");
        assert!(matches!(op.safety_tier, SafetyTier::Safe));
        assert!(matches!(op.risk_level, RiskLevel::Low));
    }

    #[test]
    fn create_group_channel_operation_classification() {
        let op = create_group_channel_operation();
        assert_eq!(op.capability.as_str(), "mattermost.write");
        assert!(matches!(op.safety_tier, SafetyTier::Risky));
        assert!(matches!(op.risk_level, RiskLevel::Medium));
    }

    #[test]
    fn update_post_requires_id() {
        let input = json!({"id": "  ", "message": "new text"});
        let req: crate::types::UpdatePostRequest = serde_json::from_value(input).unwrap();
        assert!(req.id.trim().is_empty());
    }

    #[test]
    fn create_group_channel_rejects_too_few_users() {
        let input = json!({"user_ids": ["u1", "u2"]});
        let req: crate::types::CreateGroupChannelRequest = serde_json::from_value(input).unwrap();
        assert!(req.user_ids.len() < 3);
    }

    #[test]
    fn create_group_channel_rejects_duplicates() {
        let input = json!({"user_ids": ["u1", "u2", "u1"]});
        let req: crate::types::CreateGroupChannelRequest = serde_json::from_value(input).unwrap();
        let mut seen = HashSet::new();
        let has_dup = req.user_ids.iter().any(|id| !seen.insert(id.as_str()));
        assert!(has_dup);
    }

    #[test]
    fn required_capability_for_new_operations() {
        assert_eq!(
            required_capability_for_operation("mattermost.update_post")
                .unwrap()
                .as_str(),
            "mattermost.write"
        );
        assert_eq!(
            required_capability_for_operation("mattermost.pin_post")
                .unwrap()
                .as_str(),
            "mattermost.write"
        );
        assert_eq!(
            required_capability_for_operation("mattermost.unpin_post")
                .unwrap()
                .as_str(),
            "mattermost.write"
        );
        assert_eq!(
            required_capability_for_operation("mattermost.get_reactions_for_post")
                .unwrap()
                .as_str(),
            "mattermost.read"
        );
        assert_eq!(
            required_capability_for_operation("mattermost.create_group_channel")
                .unwrap()
                .as_str(),
            "mattermost.write"
        );
    }

    #[test]
    fn manifest_lists_extended_post_and_group_operations() {
        let manifest_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        let manifest = std::fs::read_to_string(&manifest_path)
            .expect("mattermost manifest.toml should be readable");

        for operation in [
            "mattermost.get_reactions_for_post",
            "mattermost.create_group_channel",
            "mattermost.update_post",
            "mattermost.pin_post",
            "mattermost.unpin_post",
        ] {
            assert!(
                manifest.contains(operation),
                "manifest should advertise {operation}"
            );
        }
    }

    // ── Doctor / Self-check / Simulate tests ───────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_unconfigured() {
        let connector = MattermostConnector::new();
        let value = connector.handle_doctor().await.unwrap();
        assert_eq!(value["ready"], false);
        let checks = value["checks"].as_array().unwrap();
        assert_eq!(checks[0]["name"], "client_configured");
        assert_eq!(checks[0]["passed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_unconfigured() {
        let connector = MattermostConnector::new();
        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "degraded");
        assert_eq!(value["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_invalid_input() {
        let connector = MattermostConnector::new();
        let result = connector.handle_simulate(json!({}));
        assert!(result.is_err());
    }
}
