//! Twitter FCP Connector implementation.
//!
//! Implements the Flywheel Connector Protocol for Twitter/X API.
//! Supports Operational, Streaming, and Bidirectional archetypes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, HandshakeRequest, HandshakeResponse, SessionId, SimulateRequest,
    SimulateResponse,
};
use fcp_sdk::runtime::{
    InMemoryStreamingSession, StreamingConnection, StreamingError, StreamingSupervisor,
    SupervisorConfig,
};
use serde_json::{Value, json};
use tokio::sync::{RwLock, broadcast, watch};
use tracing::{debug, info, instrument};

use crate::{
    client::TwitterApiClient,
    config::TwitterConfig,
    stream::{FilteredStream, StreamEvent},
    types::{CreateTweetRequest, SearchTweetsParams, StreamRule, TweetReply, User},
};

/// Twitter FCP Connector.
pub struct TwitterConnector {
    /// Base connector with metrics
    base: BaseConnector,

    /// Configuration (set via configure)
    config: Option<TwitterConfig>,

    /// API client (created after configure)
    client: Option<Arc<TwitterApiClient>>,

    /// Authenticated user info
    authenticated_user: Option<User>,

    /// Capability verifier
    verifier: Option<CapabilityVerifier>,

    /// Session ID
    session_id: Option<SessionId>,

    /// Event broadcast sender for subscriptions
    event_tx: broadcast::Sender<Value>,

    /// Active stream handle
    stream_active: Arc<RwLock<bool>>,

    /// Stream subscriber count
    stream_subscribers: Arc<AtomicU64>,

    /// Stream shutdown signal
    stream_shutdown_tx: Option<watch::Sender<bool>>,

    /// Stream supervisor task
    stream_task: Option<tokio::task::JoinHandle<()>>,
}

impl TwitterConnector {
    /// Create a new Twitter connector.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(256);

        Self {
            base: BaseConnector::new(ConnectorId::from_static("twitter:social:v1")),
            config: None,
            client: None,
            authenticated_user: None,
            verifier: None,
            session_id: None,
            event_tx,
            stream_active: Arc::new(RwLock::new(false)),
            stream_subscribers: Arc::new(AtomicU64::new(0)),
            stream_shutdown_tx: None,
            stream_task: None,
        }
    }

    /// Handle the configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(&mut self, params: Value) -> Result<Value, FcpError> {
        info!("Configuring Twitter connector");

        let config: TwitterConfig =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {e}"),
            })?;

        // Validate required fields
        if config.consumer_key.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: "consumer_key is required".into(),
            });
        }
        if config.consumer_secret.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: "consumer_secret is required".into(),
            });
        }
        if config.access_token.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: "access_token is required".into(),
            });
        }
        if config.access_token_secret.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: "access_token_secret is required".into(),
            });
        }

        // Create API client
        let client = TwitterApiClient::new(&config).map_err(|e| FcpError::External {
            service: "twitter".into(),
            message: format!("Failed to create API client: {e}"),
            status_code: None,
            retryable: false,
            retry_after: None,
        })?;

        self.config = Some(config);
        self.client = Some(Arc::new(client));
        self.base.set_configured(true);

        Ok(json!({
            "status": "configured"
        }))
    }

    /// Handle the handshake method.
    #[instrument(skip(self, params))]
    pub async fn handle_handshake(&mut self, params: Value) -> Result<Value, FcpError> {
        info!("Performing Twitter connector handshake");

        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        let client = self.require_client()?;

        // Get authenticated user to verify credentials
        let response = client.get_me().await.map_err(|e| e.to_fcp_error())?;

        let user = response.data.ok_or_else(|| FcpError::Unauthorized {
            code: 2001,
            message: "Failed to get authenticated user".into(),
        })?;

        info!(username = %user.username, user_id = %user.id, "Authenticated as user");
        self.authenticated_user = Some(user);

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        // Convert capability IDs to grants
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
            manifest_hash: "sha256:twitter-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle the health method.
    #[instrument(skip(self))]
    pub async fn handle_health(&self) -> Result<Value, FcpError> {
        let metrics = self.base.metrics();
        let is_ready = self.base.check_ready().is_ok();

        Ok(json!({
            "status": if is_ready { "healthy" } else { "not_ready" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_success": metrics.requests_success,
                "requests_error": metrics.requests_error
            },
            "stream_active": *self.stream_active.read().await,
            "stream_subscribers": self.stream_subscribers.load(Ordering::Relaxed)
        }))
    }

    /// Handle the introspect method.
    #[instrument(skip(self))]
    pub async fn handle_introspect(&self) -> Result<Value, FcpError> {
        // Return introspection data as JSON - the proper Introspection struct
        // requires many fields that we can't easily populate here
        Ok(json!({
            "connector": {
                "id": "twitter:social:v1",
                "name": "fcp-twitter",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "X/Twitter API connector for the Flywheel Connector Protocol"
            },
            "archetypes": ["operational", "streaming", "bidirectional"],
            "operations": [
                {"id": "twitter.user.me", "summary": "Get the authenticated user", "risk": "low"},
                {"id": "twitter.user.get", "summary": "Get a user by ID", "risk": "low"},
                {"id": "twitter.user.by_username", "summary": "Get a user by username", "risk": "low"},
                {"id": "twitter.tweet.get", "summary": "Get a tweet by ID", "risk": "low"},
                {"id": "twitter.tweet.search", "summary": "Search recent tweets", "risk": "low"},
                {"id": "twitter.user.timeline", "summary": "Get a user's tweets", "risk": "low"},
                {"id": "twitter.user.mentions", "summary": "Get mentions", "risk": "low"},
                {"id": "twitter.tweet.create", "summary": "Create a new tweet", "risk": "high"},
                {"id": "twitter.tweet.reply", "summary": "Reply to a tweet", "risk": "high"},
                {"id": "twitter.tweet.delete", "summary": "Delete a tweet", "risk": "high"},
                {"id": "twitter.stream.rules.list", "summary": "List stream filter rules", "risk": "low"},
                {"id": "twitter.stream.rules.add", "summary": "Add stream filter rules", "risk": "high"},
                {"id": "twitter.stream.rules.delete", "summary": "Delete stream filter rules", "risk": "high"}
            ],
            "network_constraints": {
                "host_allow": ["api.twitter.com", "upload.twitter.com", "stream.twitter.com"],
                "port_allow": [443],
                "deny_localhost": true,
                "deny_private_ranges": true
            }
        }))
    }

    /// Handle the simulate method.
    #[instrument(skip(self, params))]
    pub async fn handle_simulate(&self, params: Value) -> Result<Value, FcpError> {
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

    /// Handle the invoke method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: Value) -> Result<Value, FcpError> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing 'operation' field".into(),
            })?;

        let args = params.get("args").cloned().unwrap_or_else(|| json!({}));

        debug!(operation = %operation, "Invoking Twitter operation");

        // Extract and verify capability token
        let token_value =
            params
                .get("capability_token")
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: fcp_core::OperationId =
            operation.parse().map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid operation ID format".into(),
            })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        // Extract resource URIs
        let mut resource_uris = Vec::new();
        if let Some(user_id) = args.get("user_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("twitter:user:{user_id}"));
        }
        if let Some(tweet_id) = args.get("tweet_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("twitter:tweet:{tweet_id}"));
        }

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &resource_uris)?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        let result = self.dispatch_operation(operation, args).await;

        // Record request success/failure
        self.base.record_request(result.is_ok());

        result
    }

    /// Handle the subscribe method.
    #[instrument(skip(self, params))]
    pub async fn handle_subscribe(&mut self, params: Value) -> Result<Value, FcpError> {
        let event_type = params
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("stream");

        if event_type != "stream" {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown event type: {event_type}"),
            });
        }

        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;

        // Start stream if not already active
        let should_start = {
            let mut active = self.stream_active.write().await;
            if *active {
                false
            } else {
                *active = true;
                true
            }
        };

        if should_start {
            let stream = match FilteredStream::new(config.clone()) {
                Ok(stream) => stream,
                Err(err) => {
                    *self.stream_active.write().await = false;
                    return Err(err.to_fcp_error());
                }
            };
            let stream = Arc::new(stream);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            self.stream_shutdown_tx = Some(shutdown_tx.clone());

            let event_tx = self.event_tx.clone();
            let stream_active_flag = self.stream_active.clone();

            let mut supervisor = StreamingSupervisor::new(
                SupervisorConfig {
                    heartbeat_interval_ms: 0, // SSE heartbeats are connector-managed
                    ..SupervisorConfig::default()
                },
                InMemoryStreamingSession::new(),
            );

            let task = tokio::spawn(async move {
                let outcome = supervisor
                    .run(
                        shutdown_rx,
                        |_session| {
                            let stream = Arc::clone(&stream);
                            async move {
                                let handle = stream
                                    .connect_once()
                                    .await
                                    .map_err(|e| -> StreamingError { Box::new(e) })?;
                                let join_handle = tokio::spawn(async move {
                                    match handle.join_handle.await {
                                        Ok(Ok(())) => Ok(()),
                                        Ok(Err(e)) => Err(Box::new(e) as StreamingError),
                                        Err(e) => Err(Box::new(e) as StreamingError),
                                    }
                                });
                                Ok(StreamingConnection {
                                    events: handle.events,
                                    join_handle,
                                })
                            }
                        },
                        |event, _session| {
                            let event_tx = event_tx.clone();
                            let shutdown_tx = shutdown_tx.clone();
                            async move {
                                let value = match &event {
                                    StreamEvent::Tweet(tweet) => {
                                        json!({
                                            "type": "tweet",
                                            "data": tweet
                                        })
                                    }
                                    StreamEvent::Connected => {
                                        json!({
                                            "type": "connected"
                                        })
                                    }
                                    StreamEvent::Disconnected { reason } => {
                                        json!({
                                            "type": "disconnected",
                                            "reason": reason
                                        })
                                    }
                                    StreamEvent::Heartbeat => {
                                        json!({
                                            "type": "heartbeat"
                                        })
                                    }
                                    StreamEvent::Error(msg) => {
                                        json!({
                                            "type": "error",
                                            "message": msg
                                        })
                                    }
                                };

                                if event_tx.send(value).is_err() {
                                    let _ = shutdown_tx.send(true);
                                }

                                Ok(())
                            }
                        },
                    )
                    .await;

                info!(?outcome, "Twitter stream supervisor stopped");
                let mut active = stream_active_flag.write().await;
                *active = false;
            });

            self.stream_task = Some(task);
        }

        self.stream_subscribers.fetch_add(1, Ordering::Relaxed);

        Ok(json!({
            "status": "subscribed",
            "event_type": "stream"
        }))
    }

    /// Handle the shutdown method.
    #[instrument(skip(self, _params))]
    pub async fn handle_shutdown(&mut self, _params: Value) -> Result<Value, FcpError> {
        info!("Shutting down Twitter connector");

        if let Some(shutdown_tx) = self.stream_shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }

        if let Some(task) = self.stream_task.take() {
            task.abort();
        }

        // Mark stream as inactive
        {
            let mut stream_active = self.stream_active.write().await;
            *stream_active = false;
        }

        self.base.set_handshaken(false);

        Ok(json!({
            "status": "shutdown"
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn require_client(&self) -> Result<Arc<TwitterApiClient>, FcpError> {
        self.client.clone().ok_or(FcpError::NotConfigured)
    }

    async fn dispatch_operation(&self, operation: &str, args: Value) -> Result<Value, FcpError> {
        match operation {
            // User operations
            "twitter.user.me" => self.op_user_me().await,
            "twitter.user.get" => self.op_user_get(args).await,
            "twitter.user.by_username" => self.op_user_by_username(args).await,

            // Tweet operations
            "twitter.tweet.get" => self.op_tweet_get(args).await,
            "twitter.tweet.search" => self.op_tweet_search(args).await,
            "twitter.tweet.create" => self.op_tweet_create(args).await,
            "twitter.tweet.reply" => self.op_tweet_reply(args).await,
            "twitter.tweet.delete" => self.op_tweet_delete(args).await,

            // Timeline operations
            "twitter.user.timeline" => self.op_user_timeline(args).await,
            "twitter.user.mentions" => self.op_user_mentions(args).await,

            // Stream rule operations
            "twitter.stream.rules.list" => self.op_stream_rules_list().await,
            "twitter.stream.rules.add" => self.op_stream_rules_add(args).await,
            "twitter.stream.rules.delete" => self.op_stream_rules_delete(args).await,

            _ => Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_user_me(&self) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let response = client.get_me().await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "user": response.data,
            "includes": response.includes
        }))
    }

    async fn op_user_get(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let user_id = args
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'user_id' argument".into(),
            })?;

        let response = client
            .get_user(user_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "user": response.data,
            "includes": response.includes
        }))
    }

    async fn op_user_by_username(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let username = args
            .get("username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'username' argument".into(),
            })?;

        // Strip @ if present
        let username = username.trim_start_matches('@');

        let response = client
            .get_user_by_username(username)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "user": response.data,
            "includes": response.includes
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tweet operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_tweet_get(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let tweet_id = args
            .get("tweet_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_id' argument".into(),
            })?;

        let response = client
            .get_tweet(tweet_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweet": response.data,
            "includes": response.includes
        }))
    }

    async fn op_tweet_search(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let query =
            args.get("query")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1006,
                    message: "Missing 'query' argument".into(),
                })?;

        let params = SearchTweetsParams {
            query: query.to_string(),
            max_results: args
                .get("max_results")
                .and_then(serde_json::Value::as_u64)
                .map(|v| v as u32),
            next_token: args
                .get("next_token")
                .and_then(|v| v.as_str())
                .map(String::from),
            since_id: args
                .get("since_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            sort_order: args
                .get("sort_order")
                .and_then(|v| v.as_str())
                .map(String::from),
            ..Default::default()
        };

        let response = client
            .search_recent(&params)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweets": response.data,
            "includes": response.includes,
            "meta": response.meta
        }))
    }

    async fn op_tweet_create(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let text =
            args.get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1006,
                    message: "Missing 'text' argument".into(),
                })?;

        // Validate tweet length (280 characters max)
        if text.chars().count() > 280 {
            return Err(FcpError::InvalidRequest {
                code: 1007,
                message: "Tweet exceeds 280 character limit".into(),
            });
        }

        let request = CreateTweetRequest {
            text: Some(text.to_string()),
            ..Default::default()
        };

        let response = client
            .create_tweet(&request)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweet": {
                "id": response.data.id,
                "text": response.data.text
            }
        }))
    }

    async fn op_tweet_reply(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let text =
            args.get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1006,
                    message: "Missing 'text' argument".into(),
                })?;

        let reply_to = args
            .get("reply_to")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'reply_to' argument".into(),
            })?;

        // Validate tweet length
        if text.chars().count() > 280 {
            return Err(FcpError::InvalidRequest {
                code: 1007,
                message: "Tweet exceeds 280 character limit".into(),
            });
        }

        let request = CreateTweetRequest {
            text: Some(text.to_string()),
            reply: Some(TweetReply {
                in_reply_to_tweet_id: reply_to.to_string(),
                exclude_reply_user_ids: None,
            }),
            ..Default::default()
        };

        let response = client
            .create_tweet(&request)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweet": {
                "id": response.data.id,
                "text": response.data.text
            }
        }))
    }

    async fn op_tweet_delete(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let tweet_id = args
            .get("tweet_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_id' argument".into(),
            })?;

        let response = client
            .delete_tweet(tweet_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "deleted": response.data.deleted
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Timeline operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_user_timeline(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let user_id = args
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'user_id' argument".into(),
            })?;

        let max_results = args
            .get("max_results")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as u32);
        let pagination_token = args.get("pagination_token").and_then(|v| v.as_str());

        let response = client
            .get_user_tweets(user_id, max_results, pagination_token)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweets": response.data,
            "includes": response.includes,
            "meta": response.meta
        }))
    }

    async fn op_user_mentions(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        // Use authenticated user ID if not provided
        let user_id = if let Some(id) = args.get("user_id").and_then(|v| v.as_str()) {
            id.to_string()
        } else if let Some(user) = &self.authenticated_user {
            user.id.clone()
        } else {
            return Err(FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'user_id' argument and no authenticated user".into(),
            });
        };

        let max_results = args
            .get("max_results")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as u32);
        let pagination_token = args.get("pagination_token").and_then(|v| v.as_str());

        let response = client
            .get_user_mentions(&user_id, max_results, pagination_token)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweets": response.data,
            "includes": response.includes,
            "meta": response.meta
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Stream rule operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_stream_rules_list(&self) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let response = client
            .get_stream_rules()
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "rules": response.data,
            "meta": response.meta
        }))
    }

    async fn op_stream_rules_add(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let rules_value = args.get("rules").ok_or_else(|| FcpError::InvalidRequest {
            code: 1006,
            message: "Missing 'rules' argument".into(),
        })?;

        let rules: Vec<StreamRule> =
            serde_json::from_value(rules_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1007,
                message: format!("Invalid rules format: {e}"),
            })?;

        let response = client
            .add_stream_rules(&rules)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "rules": response.data,
            "meta": response.meta,
            "errors": response.errors
        }))
    }

    async fn op_stream_rules_delete(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let ids_value = args.get("ids").ok_or_else(|| FcpError::InvalidRequest {
            code: 1006,
            message: "Missing 'ids' argument".into(),
        })?;

        let ids: Vec<String> =
            serde_json::from_value(ids_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1007,
                message: format!("Invalid ids format: {e}"),
            })?;

        let ids_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let response = client
            .delete_stream_rules(&ids_refs)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "meta": response.meta,
            "errors": response.errors
        }))
    }
}

impl Default for TwitterConnector {
    fn default() -> Self {
        Self::new()
    }
}
