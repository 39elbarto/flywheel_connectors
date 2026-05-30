//! `QQ` HTTP client with token caching and `ConnectorRuntime` integration.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fcp_async_core::sync::Mutex;
use fcp_sdk::runtime::{InMemoryStreamingSession, StreamingSession};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Url, header::HeaderMap};
use serde_json::{Value, json};

use crate::error::{QqError, QqResult};
use crate::types::{
    AccessTokenResponse, EVENT_QQ_EVENT_DROPPED, EVENT_QQ_MESSAGE_AUTHORIZED, NormalizedQqEvent,
    QqAccessPolicyMode, QqApprovalAction, QqConfig, QqGatewayDrainResult, QqGatewayEvent,
    QqGatewayEventProjection, QqGatewayLifecycleDirective, QqGatewayQueuedEvent,
    QqGatewayRuntimeConfig, QqGatewayRuntimeSnapshot, QqInboundPolicyConfig,
    QqInboundPolicyDecision, QqInteractionKind, QqMessageEvent, QqRouting,
    TOKEN_REFRESH_SAFETY_MARGIN_SECS,
};

const QQ_GATEWAY_ACTION_NONE: &str = "none";
const QQ_GATEWAY_ACTION_DRAIN_EVENTS: &str = "drain_events";
const QQ_GATEWAY_ACTION_SEND_HEARTBEAT: &str = "send_heartbeat";
const QQ_GATEWAY_ACTION_IDENTIFY: &str = "identify";
const QQ_GATEWAY_ACTION_RESUME: &str = "resume";
const QQ_GATEWAY_ACTION_RECONNECT_IDENTIFY: &str = "reconnect_identify";
const QQ_GATEWAY_ACTION_RECONNECT_RESUME: &str = "reconnect_resume";
const QQ_GATEWAY_ACTION_STOP_RECONNECT: &str = "stop_reconnect";

const QQ_GATEWAY_EVENT_READY: &str = "READY";
const QQ_GATEWAY_EVENT_RESUMED: &str = "RESUMED";

const QQ_GATEWAY_EVENT_TYPE_MAX_CHARS: usize = 64;
const QQ_GATEWAY_ID_MAX_CHARS: usize = 256;
const QQ_GATEWAY_TEXT_MAX_CHARS: usize = 8_192;
const QQ_GATEWAY_ATTACHMENT_FIELD_MAX_CHARS: usize = 1_024;
const QQ_GATEWAY_ATTACHMENTS_MAX_COUNT: usize = 32;
const QQ_GATEWAY_COMMAND_NAME_MAX_CHARS: usize = 64;
const QQ_GATEWAY_HELLO_HEARTBEAT_INTERVAL_MAX_MS: u64 = 5 * 60 * 1000;

#[derive(Clone)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

impl std::fmt::Debug for CachedAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedAccessToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

pub struct QqClient {
    config: QqConfig,
    client: reqwest::Client,
    token_cache: Arc<Mutex<Option<CachedAccessToken>>>,
    gateway_runtime: Arc<Mutex<QqGatewayRuntime>>,
    runtime: ConnectorRuntime,
}

impl std::fmt::Debug for QqClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QqClient")
            .field("config", &self.config)
            .field("client", &"reqwest::Client")
            .field("token_cache", &"token cache")
            .field("gateway_runtime", &"gateway runtime")
            .field("runtime", &"ConnectorRuntime")
            .finish_non_exhaustive()
    }
}

impl QqClient {
    /// Build a configured `QQ` HTTP client.
    ///
    /// # Errors
    ///
    /// Returns an error if the config is invalid or the underlying HTTP client
    /// cannot be initialized.
    pub fn new(config: QqConfig) -> QqResult<Self> {
        let config = config.normalized();
        validate_host(
            &config.base_url,
            &["api.sgroup.qq.com", "localhost", "127.0.0.1"],
        )?;
        validate_host(
            &config.token_base_url,
            &["bots.qq.com", "localhost", "127.0.0.1"],
        )?;
        if config.app_id.trim().is_empty() {
            return Err(QqError::Config("app_id must not be empty".into()));
        }
        if config.client_secret.trim().is_empty() {
            return Err(QqError::Config("client_secret must not be empty".into()));
        }
        if config.request_timeout_ms == 0 {
            return Err(QqError::Config(
                "request_timeout_ms must be greater than zero".into(),
            ));
        }
        validate_gateway_config(&config.gateway)?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(QqError::Http)?;

        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        );

        Ok(Self {
            gateway_runtime: Arc::new(Mutex::new(QqGatewayRuntime::new(config.gateway.clone()))),
            config,
            client,
            token_cache: Arc::new(Mutex::new(None)),
            runtime,
        })
    }

    #[must_use]
    pub const fn runtime(&self) -> &ConnectorRuntime {
        &self.runtime
    }

    #[must_use]
    pub const fn config(&self) -> &QqConfig {
        &self.config
    }

    /// Snapshot the in-memory QQ gateway runtime state.
    pub async fn gateway_runtime_snapshot(&self) -> QqGatewayRuntimeSnapshot {
        self.gateway_runtime.lock().await.snapshot()
    }

    /// Project a raw QQ gateway frame through session state, replay checks, and inbound policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the client runtime has shut down, or when a dispatch payload is
    /// malformed. Non-message dispatches, duplicates, stale sequences, and policy denials are
    /// represented as dropped projections.
    pub async fn project_gateway_event(
        &self,
        event: QqGatewayEvent,
    ) -> QqResult<QqGatewayEventProjection> {
        let mut gateway_runtime = self.gateway_runtime.lock().await;
        self.ensure_gateway_runtime_active()?;
        gateway_runtime.project_event(event)
    }

    /// Drain accepted gateway events for host fan-out.
    ///
    /// # Errors
    ///
    /// Returns an error when the client runtime has shut down.
    pub async fn drain_gateway_events(&self, limit: usize) -> QqResult<QqGatewayDrainResult> {
        let mut gateway_runtime = self.gateway_runtime.lock().await;
        self.ensure_gateway_runtime_active()?;
        Ok(gateway_runtime.drain_accepted_events(limit))
    }

    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn ensure_gateway_runtime_active(&self) -> QqResult<()> {
        if self.runtime.is_shutting_down() {
            return Err(QqError::Async(
                "QQ gateway runtime is shut down; refusing event fan-out".into(),
            ));
        }
        Ok(())
    }

    fn api_url(&self, path: &str) -> QqResult<Url> {
        Url::parse(self.config.base_url.trim())
            .map(|mut url| {
                url.set_path(path);
                url
            })
            .map_err(|e| QqError::Config(format!("invalid base_url: {e}")))
    }

    fn token_url(&self, path: &str) -> QqResult<Url> {
        Url::parse(self.config.token_base_url.trim())
            .map(|mut url| {
                url.set_path(path);
                url
            })
            .map_err(|e| QqError::Config(format!("invalid token_base_url: {e}")))
    }

    /// Fetch or reuse a cached `QQ` bot access token.
    ///
    /// # Errors
    ///
    /// Returns an error if the token endpoint rejects the credentials or the
    /// response payload is malformed.
    pub async fn access_token(&self) -> QqResult<String> {
        {
            let cache = self.token_cache.lock().await;
            if let Some(cached) = cache.as_ref() {
                if Instant::now() < cached.expires_at {
                    return Ok(cached.token.clone());
                }
            }
        }

        let url = self.token_url("/app/getAppAccessToken")?;
        let response = self
            .client
            .post(url)
            .json(&json!({
                "appId": self.config.app_id,
                "clientSecret": self.config.client_secret
            }))
            .send()
            .await
            .map_err(QqError::Http)?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response.text().await.unwrap_or_default();
            return Err(http_status_error(status, &headers, &body));
        }

        let body: Value = response
            .json()
            .await
            .map_err(|e| QqError::Token(format!("failed to decode access token response: {e}")))?;

        let token: AccessTokenResponse = serde_json::from_value(body.clone())
            .map_err(|e| QqError::Token(format!("failed to parse access token payload: {e}")))?;

        if token.access_token.trim().is_empty() {
            return Err(QqError::Token(
                "access token response missing or empty access_token field".to_string(),
            ));
        }

        let ttl = token
            .expires_in
            .saturating_sub(TOKEN_REFRESH_SAFETY_MARGIN_SECS)
            .max(1);
        *self.token_cache.lock().await = Some(CachedAccessToken {
            token: token.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
        });

        Ok(token.access_token)
    }

    async fn invalidate_access_token(&self) {
        *self.token_cache.lock().await = None;
    }

    async fn send_api_request_with_token(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        access_material: &str,
    ) -> QqResult<reqwest::Response> {
        let url = self.api_url(path)?;
        let request = self
            .client
            .request(method, url)
            .header("Authorization", format!("QQBot {access_material}"));
        let request = if let Some(body) = body {
            request.json(body)
        } else {
            request
        };
        request.send().await.map_err(QqError::Http)
    }

    /// Send an authenticated API request to `QQ`.
    ///
    /// # Errors
    ///
    /// Returns an error if token acquisition fails, the HTTP request cannot be
    /// sent, or the API returns a non-success response.
    pub async fn api_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> QqResult<Value> {
        let mut access_material = self.access_token().await?;
        let mut response = self
            .send_api_request_with_token(method.clone(), path, body.as_ref(), &access_material)
            .await?;

        if should_refresh_token_after_api_status(response.status().as_u16()) {
            self.invalidate_access_token().await;
            access_material = self.access_token().await?;
            response = self
                .send_api_request_with_token(method, path, body.as_ref(), &access_material)
                .await?;
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response.text().await.unwrap_or_default();
            let message = format!("QQ API request failed [{status}]: {body}");
            return Err(http_status_error(status, &headers, &message));
        }

        response.json().await.map_err(QqError::Http)
    }
}

const fn should_refresh_token_after_api_status(status: u16) -> bool {
    matches!(status, 401 | 403)
}

#[derive(Debug)]
pub struct QqGatewayRuntime {
    config: QqGatewayRuntimeConfig,
    session: InMemoryStreamingSession,
    seen_event_ids: VecDeque<String>,
    reply_references: VecDeque<String>,
    pending_events: VecDeque<QqGatewayQueuedEvent>,
    heartbeat_interval_ms: u64,
    heartbeat_sent_count: u64,
    heartbeat_ack_count: u64,
    reconnect_attempts: u32,
    terminal_reconnect_failures: u64,
    known_reply_references: u64,
    unknown_reply_references: u64,
    accepted_events: u64,
    dropped_events: u64,
    duplicate_events: u64,
    stale_sequence_events: u64,
}

impl QqGatewayRuntime {
    #[must_use]
    pub fn new(config: QqGatewayRuntimeConfig) -> Self {
        let mut session = InMemoryStreamingSession::new();
        if let Some(session_id) = config.restore_session_id.clone() {
            session.set_resume_token(session_id);
        }
        if let Some(sequence) = config.restore_sequence {
            session.set_sequence(sequence);
        }
        let heartbeat_interval_ms = config.heartbeat_interval_ms;
        Self {
            config,
            session,
            seen_event_ids: VecDeque::new(),
            reply_references: VecDeque::new(),
            pending_events: VecDeque::new(),
            heartbeat_interval_ms,
            heartbeat_sent_count: 0,
            heartbeat_ack_count: 0,
            reconnect_attempts: 0,
            terminal_reconnect_failures: 0,
            known_reply_references: 0,
            unknown_reply_references: 0,
            accepted_events: 0,
            dropped_events: 0,
            duplicate_events: 0,
            stale_sequence_events: 0,
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> QqGatewayRuntimeSnapshot {
        let (peer_queue_count, largest_peer_queue_depth) = self.peer_queue_stats();
        QqGatewayRuntimeSnapshot {
            enabled: self.config.enabled,
            session_id: self.session.resume_token(),
            last_sequence: self.session.sequence(),
            heartbeat_interval_ms: self.heartbeat_interval_ms,
            heartbeat_sent_count: self.heartbeat_sent_count,
            heartbeat_ack_count: self.heartbeat_ack_count,
            reconnect_attempts: self.reconnect_attempts,
            max_reconnect_attempts: self.config.max_reconnect_attempts,
            terminal_reconnect_failures: self.terminal_reconnect_failures,
            reconnect_backoff_ms: self.config.reconnect_backoff_ms,
            max_reconnect_backoff_ms: self.config.max_reconnect_backoff_ms,
            queue_depth: self.pending_events.len(),
            max_queue_depth: self.config.max_queue_depth,
            peer_queue_count,
            largest_peer_queue_depth,
            max_peer_queue_depth: self.config.max_peer_queue_depth,
            dedupe_size: self.seen_event_ids.len(),
            dedupe_window_size: self.config.dedupe_window_size,
            reply_reference_count: self.reply_references.len(),
            max_reply_references: self.max_reply_references(),
            known_reply_references: self.known_reply_references,
            unknown_reply_references: self.unknown_reply_references,
            accepted_events: self.accepted_events,
            dropped_events: self.dropped_events,
            duplicate_events: self.duplicate_events,
            stale_sequence_events: self.stale_sequence_events,
        }
    }

    /// Project a raw QQ gateway frame through the runtime state machine.
    ///
    /// # Errors
    ///
    /// Returns an error when the gateway envelope is malformed or when a dispatch event
    /// looks like a QQ message event but the message payload is malformed or exceeds
    /// parser bounds.
    pub fn project_event(&mut self, event: QqGatewayEvent) -> QqResult<QqGatewayEventProjection> {
        validate_gateway_event_envelope(&event)?;
        if !self.config.enabled {
            return Ok(self.dropped_projection(event.s, event.id, "gateway_disabled"));
        }

        match event.op {
            0 => self.project_dispatch(&event),
            1 => {
                self.session.record_heartbeat_sent(Instant::now());
                self.heartbeat_sent_count = self.heartbeat_sent_count.saturating_add(1);
                Ok(self.dropped_projection_with_lifecycle(
                    event.s,
                    event.id,
                    "heartbeat_request",
                    QQ_GATEWAY_ACTION_SEND_HEARTBEAT,
                ))
            }
            10 => {
                if let Some(heartbeat_interval_ms) = gateway_hello_heartbeat_interval_ms(&event)? {
                    self.heartbeat_interval_ms = heartbeat_interval_ms;
                }
                if let Some(session_id) = event
                    .d
                    .as_ref()
                    .and_then(|data| data.get("session_id"))
                    .and_then(Value::as_str)
                    .filter(|session_id| !session_id.trim().is_empty())
                {
                    self.session.set_resume_token(session_id.trim().to_string());
                }
                self.reconnect_attempts = 0;
                let action = if self.session.resume_token().is_some() {
                    QQ_GATEWAY_ACTION_RESUME
                } else {
                    QQ_GATEWAY_ACTION_IDENTIFY
                };
                Ok(self.dropped_projection_with_lifecycle(event.s, event.id, "hello", action))
            }
            7 => Ok(self.reconnect_projection(event.s, event.id, "reconnect_requested", true)),
            9 => {
                let resumable = event.d.as_ref().and_then(Value::as_bool).unwrap_or(false);
                let reason_code = if resumable {
                    "invalid_session_resumable"
                } else {
                    "invalid_session_identify_required"
                };
                Ok(self.reconnect_projection(event.s, event.id, reason_code, resumable))
            }
            11 => {
                if self.session.heartbeat_seq() <= self.session.ack_seq() {
                    return Ok(self.dropped_projection(
                        event.s,
                        event.id,
                        "heartbeat_ack_unmatched",
                    ));
                }
                self.session.record_heartbeat_ack(Instant::now());
                self.heartbeat_ack_count = self.heartbeat_ack_count.saturating_add(1);
                Ok(self.dropped_projection(event.s, event.id, "heartbeat_ack"))
            }
            _ => Ok(self.dropped_projection(event.s, event.id, "unsupported_opcode")),
        }
    }

    #[must_use]
    pub fn drain_accepted_events(&mut self, limit: usize) -> QqGatewayDrainResult {
        let drain_count = limit.min(self.pending_events.len());
        let mut events = Vec::with_capacity(drain_count);
        for _ in 0..drain_count {
            if let Some(event) = self.pending_events.pop_front() {
                events.push(event);
            }
        }
        QqGatewayDrainResult {
            drained_count: events.len(),
            remaining_count: self.pending_events.len(),
            events,
            runtime: self.snapshot(),
        }
    }

    fn reconnect_projection(
        &mut self,
        sequence: Option<u64>,
        event_id: Option<String>,
        reason_code: &'static str,
        resumable: bool,
    ) -> QqGatewayEventProjection {
        self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
        let (reason_code, action) = if self.reconnect_attempts > self.config.max_reconnect_attempts
        {
            self.terminal_reconnect_failures = self.terminal_reconnect_failures.saturating_add(1);
            (
                "reconnect_attempts_exhausted",
                QQ_GATEWAY_ACTION_STOP_RECONNECT,
            )
        } else if resumable && self.session.resume_token().is_some() {
            (reason_code, QQ_GATEWAY_ACTION_RECONNECT_RESUME)
        } else {
            (reason_code, QQ_GATEWAY_ACTION_RECONNECT_IDENTIFY)
        };
        self.dropped_projection_with_lifecycle(sequence, event_id, reason_code, action)
    }

    fn project_dispatch(&mut self, event: &QqGatewayEvent) -> QqResult<QqGatewayEventProjection> {
        let event_id = gateway_event_id(event);
        if let Some(id) = event_id.as_deref()
            && self.seen_event_ids.iter().any(|seen| seen == id)
        {
            self.duplicate_events = self.duplicate_events.saturating_add(1);
            return Ok(self.dropped_projection(event.s, event_id, "duplicate_event"));
        }

        if let Some(control_projection) = self.project_session_dispatch(event, event_id.clone())? {
            return Ok(control_projection);
        }

        if let Some(stale_projection) = self.record_dispatch_sequence(event.s, event_id.clone()) {
            return Ok(stale_projection);
        }

        let normalized = match normalize_message_event(event) {
            Ok(normalized) => normalized,
            Err(QqError::InvalidInput(message)) if message.contains("not a normalizable") => {
                return Ok(self.dropped_projection(event.s, event_id, "not_normalizable"));
            }
            Err(error) => return Err(error),
        };
        self.remember_event_id(event_id.as_deref());

        let policy = evaluate_inbound_policy(&normalized, &self.config.policy);
        if !policy.allowed {
            self.dropped_events = self.dropped_events.saturating_add(1);
            let reason_code = policy.reason_code;
            return Ok(QqGatewayEventProjection {
                accepted: false,
                topic: EVENT_QQ_EVENT_DROPPED,
                reason_code,
                sequence: event.s,
                event_id,
                normalized: Some(normalized),
                policy: Some(policy),
                runtime: self.snapshot(),
                lifecycle: self.lifecycle_directive(QQ_GATEWAY_ACTION_NONE, reason_code),
            });
        }

        if self.pending_events.len() >= self.config.max_queue_depth {
            return Ok(self.dropped_projection(event.s, event_id, "queue_full"));
        }
        if self.peer_queue_depth_for_policy(&policy) >= self.config.max_peer_queue_depth {
            return Ok(self.dropped_projection(event.s, event_id, "peer_queue_full"));
        }

        self.record_reply_reference_status(&normalized);
        self.remember_reply_reference(normalized.message_id.as_deref());
        self.pending_events.push_back(QqGatewayQueuedEvent {
            topic: EVENT_QQ_MESSAGE_AUTHORIZED,
            sequence: event.s,
            event_id: event_id.clone(),
            normalized: normalized.clone(),
            policy: policy.clone(),
        });
        self.accepted_events = self.accepted_events.saturating_add(1);
        Ok(QqGatewayEventProjection {
            accepted: true,
            topic: EVENT_QQ_MESSAGE_AUTHORIZED,
            reason_code: "accepted",
            sequence: event.s,
            event_id,
            normalized: Some(normalized),
            policy: Some(policy),
            runtime: self.snapshot(),
            lifecycle: self.lifecycle_directive(QQ_GATEWAY_ACTION_DRAIN_EVENTS, "accepted"),
        })
    }

    fn project_session_dispatch(
        &mut self,
        event: &QqGatewayEvent,
        event_id: Option<String>,
    ) -> QqResult<Option<QqGatewayEventProjection>> {
        let Some(event_type) = event.t.as_deref().map(str::trim) else {
            return Ok(None);
        };

        let (reason_code, session_id) = match event_type {
            QQ_GATEWAY_EVENT_READY => ("gateway_ready", Some(required_ready_session_id(event)?)),
            QQ_GATEWAY_EVENT_RESUMED => ("gateway_resumed", optional_dispatch_session_id(event)?),
            _ => return Ok(None),
        };

        if let Some(stale_projection) = self.record_dispatch_sequence(event.s, event_id.clone()) {
            return Ok(Some(stale_projection));
        }
        if let Some(session_id) = session_id {
            self.session.set_resume_token(session_id);
        }
        self.reconnect_attempts = 0;
        self.remember_event_id(event_id.as_deref());
        Ok(Some(self.dropped_projection_with_lifecycle(
            event.s,
            event_id,
            reason_code,
            QQ_GATEWAY_ACTION_NONE,
        )))
    }

    fn record_dispatch_sequence(
        &mut self,
        sequence: Option<u64>,
        event_id: Option<String>,
    ) -> Option<QqGatewayEventProjection> {
        let sequence = sequence?;
        let current = self.session.sequence();
        if current != 0 && sequence <= current {
            self.stale_sequence_events = self.stale_sequence_events.saturating_add(1);
            return Some(self.dropped_projection(Some(sequence), event_id, "stale_sequence"));
        }
        self.session.set_sequence(sequence);
        None
    }

    fn remember_event_id(&mut self, id: Option<&str>) {
        let Some(id) = id.filter(|id| !id.trim().is_empty()) else {
            return;
        };
        self.seen_event_ids.push_back(id.to_string());
        while self.seen_event_ids.len() > self.config.dedupe_window_size {
            self.seen_event_ids.pop_front();
        }
    }

    fn record_reply_reference_status(&mut self, event: &NormalizedQqEvent) {
        let Some(reply_to) = event.reply_to.as_deref().and_then(nonblank_trimmed) else {
            return;
        };
        if self.reply_references.iter().any(|known| known == reply_to) {
            self.known_reply_references = self.known_reply_references.saturating_add(1);
        } else {
            self.unknown_reply_references = self.unknown_reply_references.saturating_add(1);
        }
    }

    fn remember_reply_reference(&mut self, message_id: Option<&str>) {
        let Some(message_id) = message_id.and_then(nonblank_trimmed) else {
            return;
        };
        if let Some(index) = self
            .reply_references
            .iter()
            .position(|known| known == message_id)
        {
            self.reply_references.remove(index);
        }
        self.reply_references.push_back(message_id.to_string());
        while self.reply_references.len() > self.max_reply_references() {
            self.reply_references.pop_front();
        }
    }

    const fn max_reply_references(&self) -> usize {
        self.config.max_queue_depth
    }

    fn peer_queue_depth_for_policy(&self, policy: &QqInboundPolicyDecision) -> usize {
        let Some(target_id) = policy.target_id.as_deref() else {
            return 0;
        };
        self.pending_events
            .iter()
            .filter(|event| {
                event.policy.routing == policy.routing
                    && event.policy.target_id.as_deref() == Some(target_id)
            })
            .count()
    }

    fn peer_queue_stats(&self) -> (usize, usize) {
        let mut keys: Vec<(QqRouting, &str)> = Vec::new();
        let mut largest_depth = 0;
        for event in &self.pending_events {
            let Some(target_id) = event.policy.target_id.as_deref() else {
                continue;
            };
            let key = (event.policy.routing, target_id);
            if keys.contains(&key) {
                continue;
            }
            let depth = self
                .pending_events
                .iter()
                .filter(|queued| {
                    queued.policy.routing == key.0
                        && queued.policy.target_id.as_deref() == Some(key.1)
                })
                .count();
            largest_depth = largest_depth.max(depth);
            keys.push(key);
        }
        (keys.len(), largest_depth)
    }

    fn dropped_projection(
        &mut self,
        sequence: Option<u64>,
        event_id: Option<String>,
        reason_code: &'static str,
    ) -> QqGatewayEventProjection {
        self.dropped_projection_with_lifecycle(
            sequence,
            event_id,
            reason_code,
            QQ_GATEWAY_ACTION_NONE,
        )
    }

    fn dropped_projection_with_lifecycle(
        &mut self,
        sequence: Option<u64>,
        event_id: Option<String>,
        reason_code: &'static str,
        action: &'static str,
    ) -> QqGatewayEventProjection {
        self.dropped_events = self.dropped_events.saturating_add(1);
        QqGatewayEventProjection {
            accepted: false,
            topic: EVENT_QQ_EVENT_DROPPED,
            reason_code,
            sequence,
            event_id,
            normalized: None,
            policy: None,
            runtime: self.snapshot(),
            lifecycle: self.lifecycle_directive(action, reason_code),
        }
    }

    fn lifecycle_directive(
        &self,
        action: &'static str,
        reason_code: &'static str,
    ) -> QqGatewayLifecycleDirective {
        let resume_session_id = matches!(
            action,
            QQ_GATEWAY_ACTION_RESUME | QQ_GATEWAY_ACTION_RECONNECT_RESUME
        )
        .then(|| self.session.resume_token())
        .flatten();
        let reconnect_after_ms = matches!(
            action,
            QQ_GATEWAY_ACTION_RECONNECT_IDENTIFY | QQ_GATEWAY_ACTION_RECONNECT_RESUME
        )
        .then(|| self.reconnect_backoff_delay_ms());
        QqGatewayLifecycleDirective {
            action,
            reason_code,
            resume_session_id,
            resume_sequence: self.session.sequence(),
            heartbeat_interval_ms: self.heartbeat_interval_ms,
            reconnect_after_ms,
        }
    }

    const fn reconnect_backoff_delay_ms(&self) -> u64 {
        let attempt = if self.reconnect_attempts == 0 {
            1
        } else {
            self.reconnect_attempts
        };
        let delay = self
            .config
            .reconnect_backoff_ms
            .saturating_mul(attempt as u64);
        if delay > self.config.max_reconnect_backoff_ms {
            self.config.max_reconnect_backoff_ms
        } else {
            delay
        }
    }
}

fn validate_gateway_config(config: &QqGatewayRuntimeConfig) -> QqResult<()> {
    if config.heartbeat_interval_ms == 0 {
        return Err(QqError::Config(
            "gateway.heartbeat_interval_ms must be greater than zero".into(),
        ));
    }
    if config.reconnect_backoff_ms == 0 {
        return Err(QqError::Config(
            "gateway.reconnect_backoff_ms must be greater than zero".into(),
        ));
    }
    if config.max_reconnect_backoff_ms == 0 {
        return Err(QqError::Config(
            "gateway.max_reconnect_backoff_ms must be greater than zero".into(),
        ));
    }
    if config.max_reconnect_backoff_ms < config.reconnect_backoff_ms {
        return Err(QqError::Config(
            "gateway.max_reconnect_backoff_ms must be >= gateway.reconnect_backoff_ms".into(),
        ));
    }
    if config.dedupe_window_size == 0 {
        return Err(QqError::Config(
            "gateway.dedupe_window_size must be greater than zero".into(),
        ));
    }
    if config.max_queue_depth == 0 {
        return Err(QqError::Config(
            "gateway.max_queue_depth must be greater than zero".into(),
        ));
    }
    if config.max_peer_queue_depth == 0 {
        return Err(QqError::Config(
            "gateway.max_peer_queue_depth must be greater than zero".into(),
        ));
    }
    if config.dedupe_window_size > 10_000 {
        return Err(QqError::Config(
            "gateway.dedupe_window_size must be <= 10000".into(),
        ));
    }
    if config.max_queue_depth > 10_000 {
        return Err(QqError::Config(
            "gateway.max_queue_depth must be <= 10000".into(),
        ));
    }
    if config.max_peer_queue_depth > 10_000 {
        return Err(QqError::Config(
            "gateway.max_peer_queue_depth must be <= 10000".into(),
        ));
    }
    for content_type in &config.policy.allowed_attachment_content_types {
        if canonical_attachment_content_type(content_type).as_deref() != Some(content_type.as_str())
        {
            return Err(QqError::Config(
                "gateway.policy.allowed_attachment_content_types must contain canonical MIME types"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn gateway_event_id(event: &QqGatewayEvent) -> Option<String> {
    event
        .id
        .clone()
        .or_else(|| {
            event
                .d
                .as_ref()
                .and_then(|data| data.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|id| !id.trim().is_empty())
}

fn gateway_hello_heartbeat_interval_ms(event: &QqGatewayEvent) -> QqResult<Option<u64>> {
    let Some(raw_interval) = event
        .d
        .as_ref()
        .and_then(|data| data.get("heartbeat_interval"))
    else {
        return Ok(None);
    };
    let Some(interval_ms) = raw_interval.as_u64() else {
        return Err(QqError::InvalidInput(
            "gateway hello heartbeat_interval must be a positive integer".into(),
        ));
    };
    if interval_ms == 0 {
        return Err(QqError::InvalidInput(
            "gateway hello heartbeat_interval must be greater than zero".into(),
        ));
    }
    if interval_ms > QQ_GATEWAY_HELLO_HEARTBEAT_INTERVAL_MAX_MS {
        return Err(QqError::InvalidInput(format!(
            "gateway hello heartbeat_interval {interval_ms}ms exceeds the {QQ_GATEWAY_HELLO_HEARTBEAT_INTERVAL_MAX_MS}ms limit"
        )));
    }
    Ok(Some(interval_ms))
}

/// Validate top-level gateway frame fields before they can affect runtime state.
///
/// # Errors
///
/// Returns an error when bounded envelope fields exceed parser limits or contain
/// invalid event-type characters.
pub fn validate_gateway_event_envelope(event: &QqGatewayEvent) -> QqResult<()> {
    validate_optional_chars(
        "gateway event id",
        event.id.as_deref(),
        QQ_GATEWAY_ID_MAX_CHARS,
    )?;
    if let Some(data_event_id) = event
        .d
        .as_ref()
        .and_then(|data| data.get("id"))
        .and_then(Value::as_str)
    {
        validate_optional_chars(
            "gateway event id",
            Some(data_event_id),
            QQ_GATEWAY_ID_MAX_CHARS,
        )?;
    }
    if let Some(event_type) = event.t.as_deref() {
        validate_event_type_component(event_type)?;
    }
    if event.op == 10
        && let Some(session_id) = event
            .d
            .as_ref()
            .and_then(|data| data.get("session_id"))
            .and_then(Value::as_str)
    {
        validate_optional_chars(
            "gateway session id",
            Some(session_id),
            QQ_GATEWAY_ID_MAX_CHARS,
        )?;
    }
    if event.op == 0
        && matches!(
            event.t.as_deref().map(str::trim),
            Some(QQ_GATEWAY_EVENT_READY | QQ_GATEWAY_EVENT_RESUMED)
        )
        && let Some(session_id) = event
            .d
            .as_ref()
            .and_then(|data| data.get("session_id"))
            .and_then(Value::as_str)
    {
        validate_optional_chars(
            "gateway session id",
            Some(session_id),
            QQ_GATEWAY_ID_MAX_CHARS,
        )?;
    }
    Ok(())
}

fn required_ready_session_id(event: &QqGatewayEvent) -> QqResult<String> {
    optional_dispatch_session_id(event)?
        .ok_or_else(|| QqError::InvalidInput("READY dispatch missing gateway session_id".into()))
}

fn optional_dispatch_session_id(event: &QqGatewayEvent) -> QqResult<Option<String>> {
    let session_id = event
        .d
        .as_ref()
        .and_then(|data| data.get("session_id"))
        .and_then(Value::as_str)
        .and_then(nonblank_trimmed)
        .map(str::to_owned);
    if let Some(session_id) = session_id.as_deref() {
        validate_optional_chars(
            "gateway session id",
            Some(session_id),
            QQ_GATEWAY_ID_MAX_CHARS,
        )?;
    }
    Ok(session_id)
}

#[must_use]
pub fn evaluate_inbound_policy(
    event: &NormalizedQqEvent,
    policy: &QqInboundPolicyConfig,
) -> QqInboundPolicyDecision {
    if let Some(reason_code) = missing_route_binding_reason(event) {
        return QqInboundPolicyDecision {
            allowed: false,
            reason_code,
            routing: event.routing,
            sender_id: event.sender_id.clone(),
            target_id: route_target_id(event),
            mentioned_bot: false,
        };
    }

    let mut decision = match event.routing {
        QqRouting::C2c => evaluate_c2c_policy(event, policy),
        QqRouting::Group => evaluate_group_policy(event, policy),
        QqRouting::Channel => evaluate_channel_policy(event, policy),
    };
    if decision.allowed
        && let Some(reason_code) = attachment_policy_denial(event, policy)
    {
        decision.allowed = false;
        decision.reason_code = reason_code;
    }
    decision
}

fn missing_route_binding_reason(event: &NormalizedQqEvent) -> Option<&'static str> {
    if is_blank(event.message_id.as_deref()) {
        return Some("message_id_missing");
    }
    if event
        .raw
        .get("message_reference")
        .is_some_and(|reference| !reference.is_null())
        && is_blank(event.reply_to.as_deref())
    {
        return Some("reply_target_missing");
    }

    match event.routing {
        QqRouting::Channel => {
            if is_blank(event.channel_id.as_deref()) {
                Some("channel_target_missing")
            } else if is_blank(event.sender_id.as_deref()) {
                Some("channel_sender_missing")
            } else {
                None
            }
        }
        QqRouting::Group => {
            if is_blank(event.group_id.as_deref()) {
                Some("group_target_missing")
            } else if is_blank(event.sender_id.as_deref()) {
                Some("group_sender_missing")
            } else {
                None
            }
        }
        QqRouting::C2c => {
            if is_blank(event.sender_id.as_deref()) {
                Some("c2c_sender_missing")
            } else {
                None
            }
        }
    }
}

fn route_target_id(event: &NormalizedQqEvent) -> Option<String> {
    match event.routing {
        QqRouting::Channel => event.channel_id.clone(),
        QqRouting::Group => event.group_id.clone(),
        QqRouting::C2c => event.sender_id.clone(),
    }
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

fn nonblank_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn evaluate_c2c_policy(
    event: &NormalizedQqEvent,
    policy: &QqInboundPolicyConfig,
) -> QqInboundPolicyDecision {
    let sender_id = event.sender_id.clone();
    let allowed = mode_allows(
        policy.dm_policy,
        sender_id.as_deref(),
        &policy.dm_allow_from,
    );
    QqInboundPolicyDecision {
        allowed,
        reason_code: if allowed {
            "c2c_allowed"
        } else {
            denied_reason(policy.dm_policy, "c2c")
        },
        routing: event.routing,
        sender_id,
        target_id: event.sender_id.clone(),
        mentioned_bot: true,
    }
}

fn evaluate_group_policy(
    event: &NormalizedQqEvent,
    policy: &QqInboundPolicyConfig,
) -> QqInboundPolicyDecision {
    let sender_id = event.sender_id.clone();
    let group_id = event.group_id.clone();
    let group_or_sender_allowed = group_id
        .as_deref()
        .is_some_and(|id| mode_allows(policy.group_policy, Some(id), &policy.group_allow_from))
        || sender_id
            .as_deref()
            .is_some_and(|id| mode_allows(policy.group_policy, Some(id), &policy.group_allow_from));
    let mode_allowed = match policy.group_policy {
        QqAccessPolicyMode::Open => true,
        QqAccessPolicyMode::Allowlist => group_or_sender_allowed,
        QqAccessPolicyMode::Disabled => false,
    };
    let mentioned_bot = mentions_bot(event, policy);
    let allowed = mode_allowed && (!policy.group_require_mention || mentioned_bot);
    let reason_code = if allowed {
        "group_allowed"
    } else if !mode_allowed {
        denied_reason(policy.group_policy, "group")
    } else {
        "missing_group_mention"
    };
    QqInboundPolicyDecision {
        allowed,
        reason_code,
        routing: event.routing,
        sender_id,
        target_id: group_id,
        mentioned_bot,
    }
}

fn evaluate_channel_policy(
    event: &NormalizedQqEvent,
    policy: &QqInboundPolicyConfig,
) -> QqInboundPolicyDecision {
    let sender_id = event.sender_id.clone();
    let channel_id = event.channel_id.clone();
    let guild_id = event.guild_id.clone();
    let channel_or_sender_allowed =
        channel_id.as_deref().is_some_and(|id| {
            mode_allows(policy.channel_policy, Some(id), &policy.channel_allow_from)
        }) || guild_id.as_deref().is_some_and(|id| {
            mode_allows(policy.channel_policy, Some(id), &policy.channel_allow_from)
        }) || sender_id.as_deref().is_some_and(|id| {
            mode_allows(policy.channel_policy, Some(id), &policy.channel_allow_from)
        });
    let allowed = match policy.channel_policy {
        QqAccessPolicyMode::Open => true,
        QqAccessPolicyMode::Allowlist => channel_or_sender_allowed,
        QqAccessPolicyMode::Disabled => false,
    };
    QqInboundPolicyDecision {
        allowed,
        reason_code: if allowed {
            "channel_allowed"
        } else {
            denied_reason(policy.channel_policy, "channel")
        },
        routing: event.routing,
        sender_id,
        target_id: channel_id,
        mentioned_bot: event.event_type == "AT_MESSAGE_CREATE",
    }
}

fn mode_allows(mode: QqAccessPolicyMode, candidate: Option<&str>, allowlist: &[String]) -> bool {
    match mode {
        QqAccessPolicyMode::Open => true,
        QqAccessPolicyMode::Disabled => false,
        QqAccessPolicyMode::Allowlist => {
            candidate.is_some_and(|candidate| allowlist.iter().any(|allowed| allowed == candidate))
        }
    }
}

fn denied_reason(mode: QqAccessPolicyMode, prefix: &'static str) -> &'static str {
    match (mode, prefix) {
        (QqAccessPolicyMode::Disabled, "channel") => "channel_disabled",
        (QqAccessPolicyMode::Disabled, "c2c") => "c2c_disabled",
        (QqAccessPolicyMode::Disabled, "group") => "group_disabled",
        (QqAccessPolicyMode::Allowlist, "channel") => "channel_not_allowed",
        (QqAccessPolicyMode::Allowlist, "c2c") => "c2c_sender_not_allowed",
        (QqAccessPolicyMode::Allowlist, "group") => "group_not_allowed",
        _ => "policy_denied",
    }
}

fn mentions_bot(event: &NormalizedQqEvent, policy: &QqInboundPolicyConfig) -> bool {
    if event.event_type == "GROUP_AT_MESSAGE_CREATE" {
        return true;
    }
    let Some(bot_user_id) = policy
        .bot_user_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    else {
        return false;
    };
    event
        .text
        .as_deref()
        .is_some_and(|text| text_mentions_bot(text, bot_user_id))
        || structured_mentions_bot(&event.raw, bot_user_id)
}

fn text_mentions_bot(text: &str, bot_user_id: &str) -> bool {
    text.match_indices(bot_user_id)
        .any(|(start, _)| text_mention_has_boundaries(text, start, bot_user_id.len()))
}

fn text_mention_has_boundaries(text: &str, start: usize, len: usize) -> bool {
    let before = text
        .get(..start)
        .and_then(|prefix| prefix.chars().next_back());
    let after = text
        .get(start + len..)
        .and_then(|suffix| suffix.chars().next());
    !before.is_some_and(is_mention_identifier_char)
        && !after.is_some_and(is_mention_identifier_char)
}

const fn is_mention_identifier_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_' || character == '-'
}

fn structured_mentions_bot(raw: &Value, bot_user_id: &str) -> bool {
    raw.get("mentions")
        .is_some_and(|mentions| mention_value_targets_bot(mentions, bot_user_id, false))
        || [
            "message",
            "message_segments",
            "segments",
            "content_segments",
        ]
        .iter()
        .filter_map(|field| raw.get(*field))
        .any(|value| mention_value_targets_bot(value, bot_user_id, true))
}

fn mention_value_targets_bot(
    value: &Value,
    bot_user_id: &str,
    require_explicit_type: bool,
) -> bool {
    match value {
        Value::Array(items) => items
            .iter()
            .any(|item| mention_value_targets_bot(item, bot_user_id, require_explicit_type)),
        Value::String(raw) => !require_explicit_type && raw.trim() == bot_user_id,
        Value::Object(object) => {
            let mention_type = object
                .get("type")
                .and_then(Value::as_str)
                .map(str::trim)
                .map(str::to_ascii_lowercase);
            let looks_like_mention = mention_type
                .as_deref()
                .is_none_or(|kind| matches!(kind, "at" | "mention" | "user_mention"));
            if !looks_like_mention {
                return false;
            }
            if require_explicit_type && mention_type.is_none() {
                return false;
            }

            mention_candidate_fields_match(value, bot_user_id)
                || object
                    .get("data")
                    .is_some_and(|data| mention_candidate_fields_match(data, bot_user_id))
                || object
                    .get("user")
                    .is_some_and(|user| mention_candidate_fields_match(user, bot_user_id))
        }
        _ => false,
    }
}

fn mention_candidate_fields_match(value: &Value, bot_user_id: &str) -> bool {
    [
        "id",
        "user_id",
        "user_openid",
        "openid",
        "member_openid",
        "target",
    ]
    .iter()
    .filter_map(|field| value.get(*field))
    .any(|candidate| mention_candidate_matches(candidate, bot_user_id))
}

fn mention_candidate_matches(candidate: &Value, bot_user_id: &str) -> bool {
    candidate
        .as_str()
        .is_some_and(|candidate| candidate.trim() == bot_user_id)
}

fn attachment_policy_denial(
    event: &NormalizedQqEvent,
    policy: &QqInboundPolicyConfig,
) -> Option<&'static str> {
    let attachments = event.raw.get("attachments").and_then(Value::as_array)?;
    if attachments.is_empty() {
        return None;
    }

    for attachment in attachments {
        if let Some(raw_url) = attachment.get("url").and_then(Value::as_str) {
            let Some(raw_url) = nonblank_trimmed(raw_url) else {
                return Some("attachment_url_not_allowed");
            };
            if !attachment_url_is_fanout_safe(raw_url) {
                return Some("attachment_url_not_allowed");
            }
        }
    }

    if let Some(max_attachment_bytes) = policy.max_attachment_bytes {
        let mut total_bytes = 0_u64;
        for attachment in attachments {
            let Some(size) = attachment.get("size").and_then(Value::as_u64) else {
                return Some("attachment_size_unknown");
            };
            if size > max_attachment_bytes {
                return Some("attachment_bytes_exceeded");
            }
            let Some(next_total) = total_bytes.checked_add(size) else {
                return Some("attachment_bytes_exceeded");
            };
            if next_total > max_attachment_bytes {
                return Some("attachment_bytes_exceeded");
            }
            total_bytes = next_total;
        }
    }

    if !policy.allowed_attachment_content_types.is_empty() {
        for attachment in attachments {
            let Some(content_type) = attachment
                .get("content_type")
                .and_then(Value::as_str)
                .and_then(canonical_attachment_content_type)
            else {
                return Some("attachment_content_type_missing");
            };
            if !policy
                .allowed_attachment_content_types
                .iter()
                .any(|allowed| allowed == &content_type)
            {
                return Some("attachment_content_type_not_allowed");
            }
        }
    }

    None
}

fn attachment_url_is_fanout_safe(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw.trim()) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn canonical_attachment_content_type(raw: &str) -> Option<String> {
    if raw.chars().any(|ch| ch.is_ascii_control()) {
        return None;
    }
    let media_type = raw.split(';').next()?.trim();
    let (kind, subtype) = media_type.split_once('/')?;
    if kind.is_empty()
        || subtype.is_empty()
        || subtype.contains('/')
        || !kind.chars().all(is_mime_token_char)
        || !subtype.chars().all(is_mime_token_char)
    {
        return None;
    }
    Some(format!(
        "{}/{}",
        kind.to_ascii_lowercase(),
        subtype.to_ascii_lowercase()
    ))
}

const fn is_mime_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

fn validate_host(raw: &str, allowed_hosts: &[&str]) -> QqResult<()> {
    let url =
        Url::parse(raw.trim()).map_err(|e| QqError::Config(format!("invalid URL `{raw}`: {e}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(QqError::Config(format!(
            "URL `{raw}` must not include userinfo"
        )));
    }
    if url.query().is_some() {
        return Err(QqError::Config(format!(
            "URL `{raw}` must not include a query string"
        )));
    }
    if url.fragment().is_some() {
        return Err(QqError::Config(format!(
            "URL `{raw}` must not include a fragment"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| QqError::Config(format!("URL `{raw}` must include a host")))?;
    let is_local = matches!(host, "localhost" | "127.0.0.1");
    if !is_local && url.scheme() != "https" {
        return Err(QqError::Config(format!(
            "URL `{raw}` must use https for non-local hosts"
        )));
    }
    if !allowed_hosts.contains(&host) {
        return Err(QqError::Config(format!("URL host `{host}` is not allowed")));
    }
    Ok(())
}

/// Build a channel message body (content + optional `msg_id`).
#[must_use]
pub fn channel_message_body(content: &str, msg_id: Option<&str>) -> Value {
    let mut body = json!({
        "content": content,
    });
    if let Some(msg_id) = msg_id {
        body["msg_id"] = json!(msg_id);
    }
    body
}

/// Build a direct/group message body (content + `msg_type` + `msg_seq` +
/// optional `msg_id`).
#[must_use]
pub fn direct_message_body(content: &str, msg_id: Option<&str>) -> Value {
    let mut body = json!({
        "content": content,
        "msg_type": 0,
        "msg_seq": 1,
    });
    if let Some(msg_id) = msg_id {
        body["msg_id"] = json!(msg_id);
    }
    body
}

/// Validate and sanitize a path segment to prevent URL path injection.
///
/// # Errors
///
/// Returns an error if `value` is empty or contains path traversal characters.
pub fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> QqResult<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(QqError::InvalidInput(format!("{field} must not be empty")));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
    {
        return Err(QqError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Normalize a raw gateway event into a structured `NormalizedQqEvent`.
///
/// Detects routing from the event type, extracts quote context from
/// `message_reference`, and detects whether attachments are present.
///
/// # Errors
///
/// Returns an error if the event type is missing or is not a recognized
/// message event, or if the event data cannot be parsed.
pub fn normalize_message_event(event: &QqGatewayEvent) -> QqResult<NormalizedQqEvent> {
    let event_type = event
        .t
        .as_deref()
        .ok_or_else(|| QqError::InvalidInput("gateway event missing event type (t)".into()))?;
    validate_event_type_component(event_type)?;

    let routing = QqRouting::from_event_type(event_type).ok_or_else(|| {
        QqError::InvalidInput(format!(
            "event type `{event_type}` is not a normalizable message event"
        ))
    })?;

    let raw_data = event.d.clone().unwrap_or_else(|| serde_json::json!({}));

    // Treat null data as empty object for deserialization
    let effective_data = if raw_data.is_null() {
        serde_json::json!({})
    } else {
        raw_data.clone()
    };

    let msg: QqMessageEvent = serde_json::from_value(effective_data)
        .map_err(|e| QqError::InvalidInput(format!("failed to parse message event data: {e}")))?;
    validate_message_event_bounds(&msg)?;

    let reply_to = msg
        .message_reference
        .as_ref()
        .and_then(|r| r.message_id.clone());
    let is_reply = reply_to.is_some();

    let has_attachments = msg.attachments.as_ref().is_some_and(|a| !a.is_empty());

    // Sender ID: for group messages use group_member_openid, for channel/c2c use author.id
    let sender_id = match routing {
        QqRouting::Group => msg
            .group_member_openid
            .clone()
            .or_else(|| msg.author.as_ref().and_then(|a| a.id.clone())),
        _ => msg.author.as_ref().and_then(|a| a.id.clone()),
    };

    let sender_name = msg.author.as_ref().and_then(|a| a.username.clone());

    // Group ID: for group messages use group_openid
    let group_id = match routing {
        QqRouting::Group => msg.group_openid.clone(),
        _ => None,
    };
    let text = effective_message_text(&msg);
    let (interaction_kind, command_name, approval_action) = classify_interaction(text.as_deref());

    Ok(NormalizedQqEvent {
        event_type: event_type.to_string(),
        message_id: msg.id,
        channel_id: msg.channel_id,
        guild_id: msg.guild_id,
        group_id,
        sender_id,
        sender_name,
        text,
        timestamp: msg.timestamp,
        is_reply,
        reply_to,
        has_attachments,
        routing,
        interaction_kind,
        command_name,
        approval_action,
        raw: raw_data,
    })
}

fn validate_event_type_component(event_type: &str) -> QqResult<()> {
    if event_type.is_empty()
        || event_type.chars().count() > QQ_GATEWAY_EVENT_TYPE_MAX_CHARS
        || !event_type
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(QqError::InvalidInput(
            "gateway event type exceeds parser bounds".into(),
        ));
    }
    Ok(())
}

fn validate_message_event_bounds(msg: &QqMessageEvent) -> QqResult<()> {
    validate_optional_chars("message id", msg.id.as_deref(), QQ_GATEWAY_ID_MAX_CHARS)?;
    validate_optional_chars(
        "channel id",
        msg.channel_id.as_deref(),
        QQ_GATEWAY_ID_MAX_CHARS,
    )?;
    validate_optional_chars("guild id", msg.guild_id.as_deref(), QQ_GATEWAY_ID_MAX_CHARS)?;
    validate_optional_chars("content", msg.content.as_deref(), QQ_GATEWAY_TEXT_MAX_CHARS)?;
    validate_optional_chars(
        "timestamp",
        msg.timestamp.as_deref(),
        QQ_GATEWAY_ID_MAX_CHARS,
    )?;
    validate_optional_chars(
        "group openid",
        msg.group_openid.as_deref(),
        QQ_GATEWAY_ID_MAX_CHARS,
    )?;
    validate_optional_chars(
        "group member openid",
        msg.group_member_openid.as_deref(),
        QQ_GATEWAY_ID_MAX_CHARS,
    )?;

    if let Some(author) = &msg.author {
        validate_optional_chars("author id", author.id.as_deref(), QQ_GATEWAY_ID_MAX_CHARS)?;
        validate_optional_chars(
            "author username",
            author.username.as_deref(),
            QQ_GATEWAY_ID_MAX_CHARS,
        )?;
    }

    if let Some(reference) = &msg.message_reference {
        validate_optional_chars(
            "reply message id",
            reference.message_id.as_deref(),
            QQ_GATEWAY_ID_MAX_CHARS,
        )?;
    }

    if let Some(attachments) = &msg.attachments {
        if attachments.len() > QQ_GATEWAY_ATTACHMENTS_MAX_COUNT {
            return Err(QqError::InvalidInput(
                "attachment count exceeds parser bounds".into(),
            ));
        }
        for attachment in attachments {
            validate_optional_chars(
                "attachment url",
                attachment.url.as_deref(),
                QQ_GATEWAY_ATTACHMENT_FIELD_MAX_CHARS,
            )?;
            validate_optional_chars(
                "attachment filename",
                attachment.filename.as_deref(),
                QQ_GATEWAY_ATTACHMENT_FIELD_MAX_CHARS,
            )?;
            validate_optional_chars(
                "attachment content_type",
                attachment.content_type.as_deref(),
                QQ_GATEWAY_ATTACHMENT_FIELD_MAX_CHARS,
            )?;
            validate_optional_chars(
                "attachment asr_refer_text",
                attachment.asr_refer_text.as_deref(),
                QQ_GATEWAY_TEXT_MAX_CHARS,
            )?;
        }
    }

    Ok(())
}

fn effective_message_text(msg: &QqMessageEvent) -> Option<String> {
    if msg
        .content
        .as_deref()
        .is_some_and(|content| !content.trim().is_empty())
    {
        return msg.content.clone();
    }

    if let Some(transcript) = msg.attachments.as_ref().and_then(|attachments| {
        attachments.iter().find_map(|attachment| {
            attachment
                .asr_refer_text
                .as_deref()
                .and_then(nonblank_trimmed)
                .map(str::to_owned)
        })
    }) {
        return Some(transcript);
    }

    msg.content.clone()
}

fn classify_interaction(
    text: Option<&str>,
) -> (QqInteractionKind, Option<String>, Option<QqApprovalAction>) {
    let command_name = text.and_then(extract_slash_command_name);
    let approval_action = command_name
        .as_deref()
        .and_then(approval_action_for_token)
        .or_else(|| {
            text.and_then(first_text_token)
                .and_then(approval_action_for_token)
        });
    let interaction_kind = if approval_action.is_some() {
        QqInteractionKind::Approval
    } else if command_name.is_some() {
        QqInteractionKind::SlashCommand
    } else {
        QqInteractionKind::Plain
    };

    (interaction_kind, command_name, approval_action)
}

fn extract_slash_command_name(text: &str) -> Option<String> {
    let command_text = text.trim_start().strip_prefix('/')?;
    let command_word = command_text.split_whitespace().next()?;
    let mut command_name = String::new();
    for character in command_word.chars() {
        if !is_command_name_char(character)
            || command_name.len() >= QQ_GATEWAY_COMMAND_NAME_MAX_CHARS
        {
            break;
        }
        command_name.push(character.to_ascii_lowercase());
    }
    (!command_name.is_empty()).then_some(command_name)
}

fn first_text_token(text: &str) -> Option<&str> {
    text.split_whitespace()
        .next()
        .map(|token| token.strip_prefix('/').unwrap_or(token))
        .filter(|token| !token.is_empty())
}

const fn is_command_name_char(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || character == '_'
        || character == '-'
        || character == '.'
        || character == ':'
}

fn approval_action_for_token(token: &str) -> Option<QqApprovalAction> {
    let lower = token
        .trim_matches(|character: char| !is_command_name_char(character))
        .to_ascii_lowercase();
    match lower.as_str() {
        "approve" | "approved" | "allow" | "accept" => Some(QqApprovalAction::Approve),
        "reject" | "rejected" => Some(QqApprovalAction::Reject),
        "deny" | "denied" => Some(QqApprovalAction::Deny),
        _ => None,
    }
}

fn validate_optional_chars(label: &str, value: Option<&str>, limit: usize) -> QqResult<()> {
    if value.is_some_and(|value| value.chars().count() > limit) {
        return Err(QqError::InvalidInput(format!(
            "{label} exceeds parser bounds"
        )));
    }
    Ok(())
}

fn http_status_error(status: u16, headers: &HeaderMap, body: &str) -> QqError {
    let message = http_status_message(status, body);
    match status {
        401 | 403 => QqError::Unauthorized(message),
        429 => QqError::RateLimited {
            retry_after_ms: retry_after_ms(headers).unwrap_or(1_000),
        },
        _ => QqError::Api {
            code: u32::from(status),
            message,
        },
    }
}

fn http_status_message(status: u16, body: &str) -> String {
    let prefix = format!("QQ HTTP request failed with status {status}");
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return prefix;
    }

    if contains_sensitive_error_marker(trimmed) {
        return format!("{prefix}; response body redacted");
    }

    if let Ok(value) = serde_json::from_str::<Value>(trimmed)
        && let Some(message) = provider_error_message(&value)
    {
        return format!("{prefix}: {}", truncate_error_message(message));
    }

    format!("{prefix}: {}", truncate_error_message(trimmed))
}

fn provider_error_message(value: &Value) -> Option<&str> {
    let object = value.as_object()?;
    ["message", "msg", "error_description", "error"]
        .into_iter()
        .filter_map(|field| object.get(field).and_then(Value::as_str))
        .map(str::trim)
        .find(|message| !message.is_empty())
}

fn truncate_error_message(message: &str) -> String {
    const MAX_ERROR_MESSAGE_CHARS: usize = 256;
    let mut chars = message.chars();
    let truncated = chars
        .by_ref()
        .take(MAX_ERROR_MESSAGE_CHARS)
        .collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn contains_sensitive_error_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "access material",
        "access_token",
        "authorization",
        "bearer",
        "client_secret",
        "clientsecret",
        "password",
        "qqbot",
        "refresh_token",
        "secret",
        "token",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn retry_after_ms(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1_000))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DEFAULT_TIMEOUT_MS;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    fn localhost_config() -> QqConfig {
        QqConfig {
            base_url: "http://localhost:9999".into(),
            token_base_url: "http://localhost:9999".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
            gateway: QqGatewayRuntimeConfig::default(),
        }
    }

    fn test_config(api_url: &str, token_url: &str) -> QqConfig {
        QqConfig {
            base_url: api_url.to_string(),
            token_base_url: token_url.to_string(),
            app_id: "app-1".into(),
            client_secret: "secret".into(),
            request_timeout_ms: 30_000,
            gateway: QqGatewayRuntimeConfig::default(),
        }
    }

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: Option<Value>,
        body_text: Option<&'static str>,
        headers: Vec<(&'static str, &'static str)>,
        required_header: Option<(&'static str, &'static str)>,
        required_body: Option<Value>,
    }

    struct TestHttpServer {
        url: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestHttpResponse {
        #[must_use]
        fn json(method: &'static str, path: &'static str, status: u16, body: Value) -> Self {
            Self {
                method,
                path,
                status,
                body: Some(body),
                body_text: None,
                headers: Vec::new(),
                required_header: None,
                required_body: None,
            }
        }

        #[must_use]
        fn text(
            method: &'static str,
            path: &'static str,
            status: u16,
            body_text: &'static str,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body: None,
                body_text: Some(body_text),
                headers: Vec::new(),
                required_header: None,
                required_body: None,
            }
        }

        #[must_use]
        fn with_required_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.required_header = Some((name, value));
            self
        }

        #[must_use]
        fn with_required_body(mut self, body: Value) -> Self {
            self.required_body = Some(body);
            self
        }

        #[must_use]
        fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.headers.push((name, value));
            self
        }
    }

    impl TestHttpServer {
        #[must_use]
        fn respond(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handle = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                for response in responses {
                    let stream =
                        accept_test_connection(&listener).expect("test listener accepts request");
                    handle_test_request(stream, response);
                }
            });
            Self {
                url,
                handle: Some(handle),
            }
        }

        #[must_use]
        fn uri(&self) -> &str {
            &self.url
        }
    }

    impl Drop for TestHttpServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                if std::thread::panicking() {
                    let _ = handle.join();
                } else {
                    handle.join().unwrap();
                }
            }
        }
    }

    fn accept_test_connection(listener: &TcpListener) -> std::io::Result<TcpStream> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false)?;
                    return Ok(stream);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "test server did not receive expected request"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn handle_test_request(stream: TcpStream, response: TestHttpResponse) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut request_parts = request_line.split_whitespace();
        assert_eq!(request_parts.next(), Some(response.method));
        let actual_path = request_parts
            .next()
            .and_then(|path| path.split('?').next())
            .unwrap_or_default();
        assert_eq!(actual_path, response.path);

        let mut content_length = 0usize;
        let mut saw_required_header = response.required_header.is_none();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap();
                }
                if let Some((required_name, required_value)) = response.required_header
                    && name.eq_ignore_ascii_case(required_name)
                    && value.trim() == required_value
                {
                    saw_required_header = true;
                }
            }
        }
        assert!(saw_required_header, "required header was not sent");

        let mut request_body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut request_body).unwrap();
        }
        if let Some(required_body) = response.required_body {
            let actual: Value = serde_json::from_slice(&request_body).unwrap();
            assert_json_contains(&actual, &required_body);
        }

        let mut stream = reader.into_inner();
        let is_json_body = response.body.is_some();
        let body = response
            .body
            .map(|body| body.to_string())
            .or_else(|| response.body_text.map(str::to_string))
            .unwrap_or_default();
        let reason = match response.status {
            401 => "Unauthorized",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: close\r\n",
            response.status,
            reason,
            body.len()
        )
        .unwrap();
        if is_json_body {
            write!(stream, "content-type: application/json\r\n").unwrap();
        }
        for (name, value) in response.headers {
            write!(stream, "{name}: {value}\r\n").unwrap();
        }
        write!(stream, "\r\n{body}").unwrap();
        stream.flush().unwrap();
    }

    fn assert_json_contains(actual: &Value, expected: &Value) {
        match (actual, expected) {
            (Value::Object(actual), Value::Object(expected)) => {
                for (key, expected_value) in expected {
                    assert_json_contains(actual.get(key).unwrap_or(&Value::Null), expected_value);
                }
            }
            _ => assert_eq!(actual, expected),
        }
    }

    #[test]
    fn rejects_empty_app_id() {
        let mut config = localhost_config();
        config.app_id = String::new();
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_empty_client_secret() {
        let mut config = localhost_config();
        config.client_secret.clear();
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_zero_timeout() {
        let mut config = localhost_config();
        config.request_timeout_ms = 0;
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_invalid_reconnect_backoff_cap() {
        let mut config = localhost_config();
        config.gateway.reconnect_backoff_ms = 1_000;
        config.gateway.max_reconnect_backoff_ms = 500;
        let error = QqClient::new(config).expect_err("invalid backoff cap should fail");
        assert!(error.to_string().contains("max_reconnect_backoff_ms"));
    }

    #[test]
    fn trims_config_fields() {
        let config = QqConfig {
            base_url: " http://localhost:9999 ".into(),
            token_base_url: " http://localhost:9999 ".into(),
            app_id: " test-app ".into(),
            client_secret: " test-secret ".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
            gateway: QqGatewayRuntimeConfig::default(),
        };
        let client = QqClient::new(config).unwrap();
        assert_eq!(client.config().base_url, "http://localhost:9999");
        assert_eq!(client.config().token_base_url, "http://localhost:9999");
        assert_eq!(client.config().app_id, "test-app");
        assert_eq!(client.config().client_secret, "test-secret");
    }

    #[test]
    fn normalizes_attachment_content_type_allowlist() {
        let mut config = localhost_config();
        config.gateway.policy.allowed_attachment_content_types =
            vec![" Image/PNG ".into(), "image/png".into(), "audio/amr".into()];
        let client = QqClient::new(config).unwrap();
        assert_eq!(
            client
                .config()
                .gateway
                .policy
                .allowed_attachment_content_types,
            vec!["audio/amr", "image/png"]
        );
    }

    #[test]
    fn rejects_noncanonical_attachment_content_type_allowlist() {
        for content_type in [
            "image/png; charset=utf-8",
            "image/png/extra",
            "image/pn@g",
            "image/(png)",
            "text/plain,application/json",
        ] {
            let mut config = localhost_config();
            config.gateway.policy.allowed_attachment_content_types = vec![content_type.into()];
            let error = QqClient::new(config).expect_err("invalid content type should fail config");
            assert!(
                error
                    .to_string()
                    .contains("allowed_attachment_content_types"),
                "{content_type}"
            );
        }
    }

    #[test]
    fn canonical_attachment_content_type_enforces_token_syntax() {
        assert_eq!(
            canonical_attachment_content_type("IMAGE/PNG; charset=binary").as_deref(),
            Some("image/png")
        );
        assert_eq!(
            canonical_attachment_content_type("application/vnd.qq+json").as_deref(),
            Some("application/vnd.qq+json")
        );

        for content_type in [
            "image/png/extra",
            "image/pn@g",
            "image/(png)",
            "image/png\n",
            "text/plain,application/json",
        ] {
            assert!(
                canonical_attachment_content_type(content_type).is_none(),
                "{content_type}"
            );
        }
    }

    #[test]
    fn rejects_disallowed_host() {
        let config = QqConfig {
            base_url: "https://evil.example.com".into(),
            token_base_url: "http://localhost:9999".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
            gateway: QqGatewayRuntimeConfig::default(),
        };
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_disallowed_token_host() {
        let config = QqConfig {
            base_url: "http://localhost:9999".into(),
            token_base_url: "https://evil.example.com".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
            gateway: QqGatewayRuntimeConfig::default(),
        };
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_insecure_public_hosts() {
        let config = QqConfig {
            base_url: "http://api.sgroup.qq.com".into(),
            token_base_url: "https://bots.qq.com".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
            gateway: QqGatewayRuntimeConfig::default(),
        };
        assert!(QqClient::new(config).is_err());

        let config = QqConfig {
            base_url: "https://api.sgroup.qq.com".into(),
            token_base_url: "http://bots.qq.com".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
            gateway: QqGatewayRuntimeConfig::default(),
        };
        assert!(QqClient::new(config).is_err());
    }

    #[test]
    fn rejects_base_url_with_query_fragment_or_userinfo() {
        let query = test_config(
            "https://api.sgroup.qq.com/api?trace=1",
            "https://bots.qq.com/app",
        );
        let err = QqClient::new(query).unwrap_err().to_string();
        assert!(err.contains("must not include a query string"));

        let fragment = test_config(
            "https://api.sgroup.qq.com/api#fragment",
            "https://bots.qq.com/app",
        );
        let err = QqClient::new(fragment).unwrap_err().to_string();
        assert!(err.contains("must not include a fragment"));

        let userinfo = test_config(
            "https://bot:secret@api.sgroup.qq.com/api",
            "https://bots.qq.com/app",
        );
        let err = QqClient::new(userinfo).unwrap_err().to_string();
        assert!(err.contains("must not include userinfo"));
    }

    #[test]
    fn rejects_token_base_url_with_query_fragment_or_userinfo() {
        let query = test_config(
            "https://api.sgroup.qq.com/api",
            "https://bots.qq.com/oauth2/token?trace=1",
        );
        let err = QqClient::new(query).unwrap_err().to_string();
        assert!(err.contains("must not include a query string"));

        let fragment = test_config(
            "https://api.sgroup.qq.com/api",
            "https://bots.qq.com/oauth2/token#fragment",
        );
        let err = QqClient::new(fragment).unwrap_err().to_string();
        assert!(err.contains("must not include a fragment"));

        let userinfo = test_config(
            "https://api.sgroup.qq.com/api",
            "https://bot:secret@bots.qq.com/oauth2/token",
        );
        let err = QqClient::new(userinfo).unwrap_err().to_string();
        assert!(err.contains("must not include userinfo"));
    }

    #[test]
    fn debug_redacts_secret() {
        let config = localhost_config();
        let client = QqClient::new(config).unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("test-secret"));
    }

    #[test]
    fn channel_message_body_without_msg_id() {
        let body = channel_message_body("hello", None);
        assert_eq!(body["content"], "hello");
        assert!(body.get("msg_id").is_none());
    }

    #[test]
    fn channel_message_body_with_msg_id() {
        let body = channel_message_body("hello", Some("msg-1"));
        assert_eq!(body["content"], "hello");
        assert_eq!(body["msg_id"], "msg-1");
    }

    #[test]
    fn direct_message_body_without_msg_id() {
        let body = direct_message_body("hello", None);
        assert_eq!(body["content"], "hello");
        assert_eq!(body["msg_type"], 0);
        assert_eq!(body["msg_seq"], 1);
        assert!(body.get("msg_id").is_none());
    }

    #[test]
    fn direct_message_body_with_msg_id() {
        let body = direct_message_body("hello", Some("msg-2"));
        assert_eq!(body["msg_id"], "msg-2");
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "id").is_err());
        assert!(sanitize_path_segment("foo/bar", "id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "id").is_err());
        assert!(sanitize_path_segment("%2E%2E", "id").is_err());
        assert!(sanitize_path_segment("", "id").is_err());
        assert!(sanitize_path_segment("  ", "id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(sanitize_path_segment("abc123", "id").unwrap(), "abc123");
        assert_eq!(
            sanitize_path_segment("channel-id-42", "id").unwrap(),
            "channel-id-42"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_channel_posts_expected_payload() {
        let api_server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/channels/channel-1/messages",
                200,
                json!({
                    "id": "msg-1",
                    "timestamp": "123456"
                }),
            )
            .with_required_header("authorization", "QQBot token-123")
            .with_required_body(json!({
                "content": "hello qq"
            })),
        ]);
        let token_server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/app/getAppAccessToken",
            200,
            json!({
                "access_token": "token-123",
                "expires_in": 7200
            }),
        )]);

        let client = QqClient::new(test_config(api_server.uri(), token_server.uri())).unwrap();
        let output = client
            .api_request(
                reqwest::Method::POST,
                "/channels/channel-1/messages",
                Some(channel_message_body("hello qq", None)),
            )
            .await
            .unwrap();

        assert_eq!(output["id"], "msg-1");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_request_uses_bearer_token() {
        let api_server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/gateway",
                200,
                json!({
                    "url": "wss://gateway.qq.example/ws"
                }),
            )
            .with_required_header("authorization", "QQBot token-123"),
        ]);
        let token_server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/app/getAppAccessToken",
            200,
            json!({
                "access_token": "token-123",
                "expires_in": 7200
            }),
        )]);

        let client = QqClient::new(test_config(api_server.uri(), token_server.uri())).unwrap();
        let output = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap();

        assert_eq!(output["url"], "wss://gateway.qq.example/ws");
    }

    #[fcp_async_core::runtime::test]
    async fn api_request_returns_error_on_failure() {
        let api_server = TestHttpServer::respond(vec![TestHttpResponse::text(
            "GET",
            "/gateway",
            500,
            "internal error",
        )]);
        let token_server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/app/getAppAccessToken",
            200,
            json!({
                "access_token": "token-123",
                "expires_in": 7200
            }),
        )]);

        let client = QqClient::new(test_config(api_server.uri(), token_server.uri())).unwrap();
        let err = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap_err();

        assert!(matches!(err, QqError::Api { code: 500, .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn access_token_maps_unauthorized_status() {
        let token_server = TestHttpServer::respond(vec![TestHttpResponse::text(
            "POST",
            "/app/getAppAccessToken",
            401,
            "invalid bot secret",
        )]);

        let client =
            QqClient::new(test_config("http://localhost:9999", token_server.uri())).unwrap();
        let err = client.access_token().await.unwrap_err();
        match err {
            QqError::Unauthorized(message) => {
                assert!(message.contains("401"));
                assert!(message.contains("response body redacted"));
                assert!(!message.contains("invalid bot secret"));
            }
            other => assert!(
                matches!(other, QqError::Unauthorized(_)),
                "expected Unauthorized"
            ),
        }
    }

    #[test]
    fn http_status_message_preserves_safe_provider_message() {
        let message = http_status_message(500, r#"{"message":"quota exceeded"}"#);
        assert!(message.contains("500"));
        assert!(message.contains("quota exceeded"));
        assert!(!message.contains("response body redacted"));
    }

    #[test]
    fn http_status_message_redacts_sensitive_provider_body() {
        let message = http_status_message(
            403,
            r#"{"message":"denied","access_token":"qq-secret-token"}"#,
        );
        assert!(message.contains("403"));
        assert!(message.contains("response body redacted"));
        assert!(!message.contains("qq-secret-token"));
        assert!(!message.contains("access_token"));
    }

    #[fcp_async_core::runtime::test]
    async fn api_request_refreshes_token_once_after_unauthorized_api_response() {
        let api_server = TestHttpServer::respond(vec![
            TestHttpResponse::text("GET", "/gateway", 401, "expired access token")
                .with_required_header("authorization", "QQBot expired-token"),
            TestHttpResponse::json(
                "GET",
                "/gateway",
                200,
                json!({
                    "url": "wss://gateway.qq.example/ws"
                }),
            )
            .with_required_header("authorization", "QQBot fresh-token"),
        ]);
        let token_server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/app/getAppAccessToken",
                200,
                json!({
                    "access_token": "expired-token",
                    "expires_in": 7200
                }),
            ),
            TestHttpResponse::json(
                "POST",
                "/app/getAppAccessToken",
                200,
                json!({
                    "access_token": "fresh-token",
                    "expires_in": 7200
                }),
            ),
        ]);

        let client = QqClient::new(test_config(api_server.uri(), token_server.uri())).unwrap();
        let output = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap();

        assert_eq!(output["url"], "wss://gateway.qq.example/ws");
    }

    #[fcp_async_core::runtime::test]
    async fn api_request_maps_retry_after_header_to_rate_limit() {
        let api_server = TestHttpServer::respond(vec![
            TestHttpResponse::text("GET", "/gateway", 429, "rate limited")
                .with_header("Retry-After", "3"),
        ]);
        let token_server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/app/getAppAccessToken",
            200,
            json!({
                "access_token": "token-123",
                "expires_in": 7200
            }),
        )]);

        let client = QqClient::new(test_config(api_server.uri(), token_server.uri())).unwrap();
        let err = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            QqError::RateLimited {
                retry_after_ms: 3_000
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn token_caching_reuses_valid_token() {
        let api_server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/gateway",
                200,
                json!({
                    "url": "wss://gateway.qq.example/ws"
                }),
            ),
            TestHttpResponse::json(
                "GET",
                "/gateway",
                200,
                json!({
                    "url": "wss://gateway.qq.example/ws"
                }),
            ),
        ]);
        let token_server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/app/getAppAccessToken",
            200,
            json!({
                "access_token": "cached-token",
                "expires_in": 7200
            }),
        )]);

        let client = QqClient::new(test_config(api_server.uri(), token_server.uri())).unwrap();

        // First call fetches token
        let _ = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap();

        // Second call should reuse cached token
        let _ = client
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_projection_and_drain_fail_after_client_shutdown() {
        let mut config = localhost_config();
        config.gateway.enabled = true;
        config.gateway.policy.bot_user_id = Some("bot-openid".into());
        let client = QqClient::new(config).unwrap();

        let accepted = client
            .project_gateway_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-before-shutdown",
                    "content": "bot-openid keep this bounded",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1"
                })),
                id: Some("evt-before-shutdown".into()),
            })
            .await
            .unwrap();
        assert!(accepted.accepted);

        let drained = client.drain_gateway_events(usize::MAX).await.unwrap();
        assert_eq!(drained.drained_count, 1);
        assert_eq!(drained.remaining_count, 0);

        client.shutdown();
        assert!(client.runtime().is_shutting_down());

        let projection_error = client
            .project_gateway_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-after-shutdown",
                    "content": "bot-openid must not fan out",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1"
                })),
                id: Some("evt-after-shutdown".into()),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(projection_error, QqError::Async(ref message) if message.contains("shut down")),
            "unexpected projection error: {projection_error:?}"
        );

        let drain_error = client.drain_gateway_events(usize::MAX).await.unwrap_err();
        assert!(
            matches!(drain_error, QqError::Async(ref message) if message.contains("shut down")),
            "unexpected drain error: {drain_error:?}"
        );
    }

    #[test]
    fn gateway_runtime_rejects_malformed_control_frame_envelope() {
        let mut runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: true,
            ..Default::default()
        });
        let oversized_event_id = "x".repeat(QQ_GATEWAY_ID_MAX_CHARS + 1);

        let event_id_error = runtime
            .project_event(QqGatewayEvent {
                op: 7,
                s: None,
                t: None,
                d: None,
                id: Some(oversized_event_id),
            })
            .unwrap_err();
        assert!(
            matches!(event_id_error, QqError::InvalidInput(ref message) if message.contains("gateway event id exceeds parser bounds")),
            "unexpected control event-id error: {event_id_error:?}"
        );
        assert_eq!(runtime.snapshot().reconnect_attempts, 0);

        let oversized_data_event_id = "d".repeat(QQ_GATEWAY_ID_MAX_CHARS + 1);
        let data_event_id_error = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("THREAD_CREATE".into()),
                d: Some(json!({ "id": oversized_data_event_id })),
                id: None,
            })
            .unwrap_err();
        assert!(
            matches!(data_event_id_error, QqError::InvalidInput(ref message) if message.contains("gateway event id exceeds parser bounds")),
            "unexpected data event-id error: {data_event_id_error:?}"
        );
        assert_eq!(runtime.snapshot().last_sequence, 0);

        let oversized_session_id = "s".repeat(QQ_GATEWAY_ID_MAX_CHARS + 1);
        let session_error = runtime
            .project_event(QqGatewayEvent {
                op: 10,
                s: None,
                t: None,
                d: Some(json!({ "session_id": oversized_session_id })),
                id: Some("evt-hello".into()),
            })
            .unwrap_err();
        assert!(
            matches!(session_error, QqError::InvalidInput(ref message) if message.contains("gateway session id exceeds parser bounds")),
            "unexpected control session-id error: {session_error:?}"
        );
        assert_eq!(runtime.snapshot().session_id, None);
        assert_eq!(runtime.snapshot().last_sequence, 0);

        let oversized_ready_session_id = "r".repeat(QQ_GATEWAY_ID_MAX_CHARS + 1);
        let ready_session_error = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some(QQ_GATEWAY_EVENT_READY.into()),
                d: Some(json!({ "session_id": oversized_ready_session_id })),
                id: Some("evt-ready-oversized-session".into()),
            })
            .unwrap_err();
        assert!(
            matches!(ready_session_error, QqError::InvalidInput(ref message) if message.contains("gateway session id exceeds parser bounds")),
            "unexpected READY session-id error: {ready_session_error:?}"
        );
        assert_eq!(runtime.snapshot().session_id, None);
        assert_eq!(runtime.snapshot().last_sequence, 0);

        let ready_missing_session_error = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some(QQ_GATEWAY_EVENT_READY.into()),
                d: Some(json!({})),
                id: Some("evt-ready-missing-session".into()),
            })
            .unwrap_err();
        assert!(
            matches!(ready_missing_session_error, QqError::InvalidInput(ref message) if message.contains("READY dispatch missing gateway session_id")),
            "unexpected READY missing-session error: {ready_missing_session_error:?}"
        );
        assert_eq!(runtime.snapshot().session_id, None);
        assert_eq!(runtime.snapshot().last_sequence, 0);
    }

    #[test]
    fn gateway_runtime_negotiates_hello_heartbeat_interval() {
        let mut runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: true,
            heartbeat_interval_ms: 45_000,
            ..Default::default()
        });

        let hello = runtime
            .project_event(QqGatewayEvent {
                op: 10,
                s: None,
                t: None,
                d: Some(json!({
                    "session_id": "session-from-hello",
                    "heartbeat_interval": 41_250
                })),
                id: Some("evt-hello-heartbeat".into()),
            })
            .unwrap();

        assert_eq!(hello.reason_code, "hello");
        assert_eq!(hello.runtime.heartbeat_interval_ms, 41_250);
        assert_eq!(hello.lifecycle.heartbeat_interval_ms, 41_250);
        assert_eq!(
            runtime.snapshot().session_id.as_deref(),
            Some("session-from-hello")
        );
    }

    #[test]
    fn gateway_runtime_rejects_bad_hello_heartbeat_interval_without_state_mutation() {
        let mut runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: true,
            heartbeat_interval_ms: 45_000,
            ..Default::default()
        });

        let zero_error = runtime
            .project_event(QqGatewayEvent {
                op: 10,
                s: None,
                t: None,
                d: Some(json!({
                    "session_id": "session-zero-interval",
                    "heartbeat_interval": 0
                })),
                id: Some("evt-hello-zero-interval".into()),
            })
            .unwrap_err();
        assert!(
            matches!(zero_error, QqError::InvalidInput(ref message) if message.contains("heartbeat_interval must be greater than zero")),
            "unexpected zero heartbeat error: {zero_error:?}"
        );
        assert_eq!(runtime.snapshot().heartbeat_interval_ms, 45_000);
        assert_eq!(runtime.snapshot().session_id, None);

        let too_large_error = runtime
            .project_event(QqGatewayEvent {
                op: 10,
                s: None,
                t: None,
                d: Some(json!({
                    "session_id": "session-large-interval",
                    "heartbeat_interval": QQ_GATEWAY_HELLO_HEARTBEAT_INTERVAL_MAX_MS + 1
                })),
                id: Some("evt-hello-large-interval".into()),
            })
            .unwrap_err();
        assert!(
            matches!(too_large_error, QqError::InvalidInput(ref message) if message.contains("heartbeat_interval") && message.contains("exceeds")),
            "unexpected large heartbeat error: {too_large_error:?}"
        );
        assert_eq!(runtime.snapshot().heartbeat_interval_ms, 45_000);
        assert_eq!(runtime.snapshot().session_id, None);

        let string_error = runtime
            .project_event(QqGatewayEvent {
                op: 10,
                s: None,
                t: None,
                d: Some(json!({
                    "session_id": "session-string-interval",
                    "heartbeat_interval": "41250"
                })),
                id: Some("evt-hello-string-interval".into()),
            })
            .unwrap_err();
        assert!(
            matches!(string_error, QqError::InvalidInput(ref message) if message.contains("positive integer")),
            "unexpected string heartbeat error: {string_error:?}"
        );
        assert_eq!(runtime.snapshot().heartbeat_interval_ms, 45_000);
        assert_eq!(runtime.snapshot().session_id, None);
    }

    #[test]
    fn gateway_runtime_persists_ready_and_resumed_dispatch_sessions() {
        let mut runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: true,
            reconnect_backoff_ms: 50,
            max_reconnect_backoff_ms: 100,
            ..Default::default()
        });

        let reconnect = runtime
            .project_event(QqGatewayEvent {
                op: 7,
                s: None,
                t: None,
                d: None,
                id: Some("evt-before-ready-reconnect".into()),
            })
            .unwrap();
        assert_eq!(reconnect.reason_code, "reconnect_requested");
        assert_eq!(reconnect.runtime.reconnect_attempts, 1);

        let ready = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some(QQ_GATEWAY_EVENT_READY.into()),
                d: Some(json!({ "session_id": "session-ready-dispatch" })),
                id: Some("evt-ready-dispatch".into()),
            })
            .unwrap();
        assert!(!ready.accepted);
        assert_eq!(ready.reason_code, "gateway_ready");
        assert_eq!(
            ready.runtime.session_id.as_deref(),
            Some("session-ready-dispatch")
        );
        assert_eq!(ready.runtime.last_sequence, 1);
        assert_eq!(ready.runtime.reconnect_attempts, 0);
        assert_eq!(ready.runtime.dedupe_size, 1);
        assert_eq!(ready.lifecycle.action, QQ_GATEWAY_ACTION_NONE);
        assert!(ready.lifecycle.resume_session_id.is_none());
        assert_eq!(ready.lifecycle.resume_sequence, 1);

        let duplicate_ready = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some(QQ_GATEWAY_EVENT_READY.into()),
                d: Some(json!({ "session_id": "session-ignored-duplicate-ready" })),
                id: Some("evt-ready-dispatch".into()),
            })
            .unwrap();
        assert_eq!(duplicate_ready.reason_code, "duplicate_event");
        assert_eq!(
            duplicate_ready.runtime.session_id.as_deref(),
            Some("session-ready-dispatch")
        );
        assert_eq!(duplicate_ready.runtime.last_sequence, 1);
        assert_eq!(duplicate_ready.runtime.duplicate_events, 1);

        let resumed = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some(QQ_GATEWAY_EVENT_RESUMED.into()),
                d: Some(json!({})),
                id: Some("evt-resumed-dispatch".into()),
            })
            .unwrap();
        assert!(!resumed.accepted);
        assert_eq!(resumed.reason_code, "gateway_resumed");
        assert_eq!(
            resumed.runtime.session_id.as_deref(),
            Some("session-ready-dispatch")
        );
        assert_eq!(resumed.runtime.last_sequence, 2);
        assert_eq!(resumed.runtime.reconnect_attempts, 0);
        assert_eq!(resumed.runtime.dedupe_size, 2);
        assert_eq!(resumed.lifecycle.action, QQ_GATEWAY_ACTION_NONE);
        assert_eq!(resumed.lifecycle.resume_sequence, 2);
    }

    // ─── Event normalization tests ──────────────────────────────

    #[test]
    fn normalize_channel_message() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(1),
            t: Some("AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-1",
                "channel_id": "ch-1",
                "guild_id": "guild-1",
                "content": "hello world",
                "timestamp": "2026-03-23T12:00:00Z",
                "author": {"id": "user-1", "username": "Alice", "bot": false}
            })),
            id: Some("evt-1".into()),
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.event_type, "AT_MESSAGE_CREATE");
        assert_eq!(normalized.routing, QqRouting::Channel);
        assert_eq!(normalized.message_id.as_deref(), Some("msg-1"));
        assert_eq!(normalized.channel_id.as_deref(), Some("ch-1"));
        assert_eq!(normalized.guild_id.as_deref(), Some("guild-1"));
        assert!(normalized.group_id.is_none());
        assert_eq!(normalized.sender_id.as_deref(), Some("user-1"));
        assert_eq!(normalized.sender_name.as_deref(), Some("Alice"));
        assert_eq!(normalized.text.as_deref(), Some("hello world"));
        assert!(!normalized.is_reply);
        assert!(normalized.reply_to.is_none());
        assert!(!normalized.has_attachments);
    }

    #[test]
    fn normalize_group_message() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(2),
            t: Some("GROUP_AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-2",
                "content": "group hello",
                "group_openid": "group-1",
                "group_member_openid": "member-1",
                "author": {"id": "user-2", "username": "Bob"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.routing, QqRouting::Group);
        assert_eq!(normalized.group_id.as_deref(), Some("group-1"));
        assert_eq!(normalized.sender_id.as_deref(), Some("member-1"));
        assert_eq!(normalized.sender_name.as_deref(), Some("Bob"));
        assert!(normalized.channel_id.is_none());
        assert!(normalized.guild_id.is_none());
    }

    #[test]
    fn normalize_c2c_message() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(3),
            t: Some("C2C_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-3",
                "content": "private hello",
                "author": {"id": "user-3", "username": "Carol"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.routing, QqRouting::C2c);
        assert_eq!(normalized.sender_id.as_deref(), Some("user-3"));
        assert!(normalized.group_id.is_none());
        assert!(normalized.channel_id.is_none());
    }

    #[test]
    fn normalize_message_with_reply() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(4),
            t: Some("MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-4",
                "channel_id": "ch-1",
                "content": "replying",
                "message_reference": {"message_id": "msg-original"},
                "author": {"id": "user-4"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert!(normalized.is_reply);
        assert_eq!(normalized.reply_to.as_deref(), Some("msg-original"));
    }

    #[test]
    fn normalize_message_with_attachments() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(5),
            t: Some("AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-5",
                "channel_id": "ch-1",
                "content": "see attached",
                "attachments": [
                    {"url": "https://example.com/a.png", "filename": "a.png", "content_type": "image/png", "size": 4096},
                    {"url": "https://example.com/b.pdf", "filename": "b.pdf", "content_type": "application/pdf", "size": 8192}
                ],
                "author": {"id": "user-5"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert!(normalized.has_attachments);
        assert!(!normalized.is_reply);
    }

    #[test]
    fn normalize_voice_attachment_prefers_asr_refer_text_when_content_blank() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(6),
            t: Some("GROUP_AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-voice",
                "content": "   ",
                "group_openid": "group-1",
                "group_member_openid": "member-1",
                "attachments": [
                    {
                        "url": "https://example.com/voice.amr",
                        "filename": "voice.amr",
                        "content_type": "audio/amr",
                        "size": 2048,
                        "asr_refer_text": "transcribed voice command"
                    }
                ]
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(
            normalized.text.as_deref(),
            Some("transcribed voice command")
        );
        assert!(normalized.has_attachments);
    }

    #[test]
    fn normalize_slash_command_routes_command_name() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(6),
            t: Some("GROUP_AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-slash",
                "content": " /Deploy status",
                "group_openid": "group-1",
                "group_member_openid": "member-1"
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.interaction_kind, QqInteractionKind::SlashCommand);
        assert_eq!(normalized.command_name.as_deref(), Some("deploy"));
        assert_eq!(normalized.approval_action, None);
    }

    #[test]
    fn normalize_approval_slash_command_routes_action() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(6),
            t: Some("GROUP_AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-approval",
                "content": "/approve rollout-42",
                "group_openid": "group-1",
                "group_member_openid": "member-1"
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.interaction_kind, QqInteractionKind::Approval);
        assert_eq!(normalized.command_name.as_deref(), Some("approve"));
        assert_eq!(normalized.approval_action, Some(QqApprovalAction::Approve));
    }

    #[test]
    fn normalize_plain_approval_word_routes_action() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(6),
            t: Some("GROUP_AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-plain-approval",
                "content": "reject rollout-42",
                "group_openid": "group-1",
                "group_member_openid": "member-1"
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.interaction_kind, QqInteractionKind::Approval);
        assert_eq!(normalized.command_name, None);
        assert_eq!(normalized.approval_action, Some(QqApprovalAction::Reject));
    }

    #[test]
    fn normalize_message_empty_attachments_not_flagged() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(6),
            t: Some("MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-6",
                "channel_id": "ch-1",
                "content": "no attachments",
                "attachments": [],
                "author": {"id": "user-6"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert!(!normalized.has_attachments);
    }

    #[test]
    fn normalize_rejects_oversized_event_type_without_echoing_it() {
        let oversized_type = "A".repeat(QQ_GATEWAY_EVENT_TYPE_MAX_CHARS + 1);
        let event = QqGatewayEvent {
            op: 0,
            s: Some(7),
            t: Some(oversized_type.clone()),
            d: Some(json!({"content": "hello"})),
            id: None,
        };
        let result = normalize_message_event(&event);

        match result {
            Err(QqError::InvalidInput(message)) => {
                assert!(message.contains("gateway event type exceeds parser bounds"));
                assert!(!message.contains(&oversized_type));
            }
            other => assert!(
                matches!(other, Err(QqError::InvalidInput(_))),
                "expected InvalidInput, got {other:?}"
            ),
        }
    }

    #[test]
    fn normalize_rejects_oversized_content() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(8),
            t: Some("MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-8",
                "content": "x".repeat(QQ_GATEWAY_TEXT_MAX_CHARS + 1)
            })),
            id: None,
        };
        let result = normalize_message_event(&event);

        assert!(
            matches!(result, Err(QqError::InvalidInput(ref message)) if message.contains("content exceeds parser bounds")),
            "expected content bounds rejection, got {result:?}"
        );
    }

    #[test]
    fn normalize_rejects_too_many_attachments() {
        let attachments = (0..=QQ_GATEWAY_ATTACHMENTS_MAX_COUNT)
            .map(|idx| json!({"filename": format!("file-{idx}.txt")}))
            .collect::<Vec<_>>();
        let event = QqGatewayEvent {
            op: 0,
            s: Some(9),
            t: Some("AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-9",
                "attachments": attachments
            })),
            id: None,
        };
        let result = normalize_message_event(&event);

        assert!(
            matches!(result, Err(QqError::InvalidInput(ref message)) if message.contains("attachment count exceeds parser bounds")),
            "expected attachment bounds rejection, got {result:?}"
        );
    }

    #[test]
    fn normalize_rejects_missing_event_type() {
        let event = QqGatewayEvent {
            op: 1,
            s: None,
            t: None,
            d: None,
            id: None,
        };
        let err = normalize_message_event(&event).unwrap_err();
        assert!(matches!(err, QqError::InvalidInput(_)));
    }

    #[test]
    fn normalize_rejects_non_message_event_type() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(1),
            t: Some("GUILD_CREATE".into()),
            d: Some(json!({})),
            id: None,
        };
        let err = normalize_message_event(&event).unwrap_err();
        match &err {
            QqError::InvalidInput(msg) => {
                assert!(msg.contains("GUILD_CREATE"));
                assert!(msg.contains("not a normalizable"));
            }
            other => assert!(
                matches!(other, QqError::InvalidInput(_)),
                "expected InvalidInput"
            ),
        }
    }

    #[test]
    fn normalize_handles_null_data() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(1),
            t: Some("AT_MESSAGE_CREATE".into()),
            d: None,
            id: None,
        };
        // null data deserializes to QqMessageEvent with all None fields
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.routing, QqRouting::Channel);
        assert!(normalized.message_id.is_none());
        assert!(normalized.text.is_none());
        assert!(normalized.sender_id.is_none());
    }

    #[test]
    fn normalize_group_message_create_variant() {
        let event = QqGatewayEvent {
            op: 0,
            s: Some(10),
            t: Some("GROUP_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-10",
                "content": "group variant",
                "group_openid": "group-2",
                "group_member_openid": "member-2"
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.routing, QqRouting::Group);
        assert_eq!(normalized.group_id.as_deref(), Some("group-2"));
        assert_eq!(normalized.sender_id.as_deref(), Some("member-2"));
    }

    #[test]
    fn normalize_group_falls_back_to_author_id() {
        // When group_member_openid is missing, fall back to author.id
        let event = QqGatewayEvent {
            op: 0,
            s: Some(11),
            t: Some("GROUP_AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-11",
                "content": "fallback sender",
                "group_openid": "group-3",
                "author": {"id": "user-fallback", "username": "Fallback"}
            })),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.routing, QqRouting::Group);
        assert_eq!(normalized.sender_id.as_deref(), Some("user-fallback"));
    }

    #[test]
    fn normalize_raw_preserves_original_data() {
        let data = json!({
            "id": "msg-raw",
            "content": "raw test",
            "extra_field": "preserved"
        });
        let event = QqGatewayEvent {
            op: 0,
            s: Some(12),
            t: Some("MESSAGE_CREATE".into()),
            d: Some(data),
            id: None,
        };
        let normalized = normalize_message_event(&event).unwrap();
        assert_eq!(normalized.raw["extra_field"], "preserved");
        assert_eq!(normalized.raw["id"], "msg-raw");
    }

    #[test]
    fn gateway_runtime_projects_group_mentions_and_drops_duplicates() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            dedupe_window_size: 2,
            max_queue_depth: 2,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.bot_user_id = Some("bot-openid".into());
        let mut runtime = QqGatewayRuntime::new(config);

        let hello = runtime
            .project_event(QqGatewayEvent {
                op: 10,
                s: None,
                t: None,
                d: Some(json!({"session_id": "session-1"})),
                id: Some("hello-1".into()),
            })
            .unwrap();
        assert_eq!(hello.reason_code, "hello");
        assert_eq!(
            hello.runtime.session_id.as_deref(),
            Some("session-1"),
            "hello should restore session token"
        );
        assert_eq!(hello.lifecycle.action, QQ_GATEWAY_ACTION_RESUME);
        assert_eq!(
            hello.lifecycle.resume_session_id.as_deref(),
            Some("session-1")
        );

        let event = QqGatewayEvent {
            op: 0,
            s: Some(1),
            t: Some("GROUP_AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": "msg-1",
                "content": "bot-openid please check",
                "group_openid": "group-1",
                "group_member_openid": "member-1",
                "author": {"id": "author-1", "username": "Alice"}
            })),
            id: Some("evt-1".into()),
        };
        let projected = runtime.project_event(event.clone()).unwrap();
        assert!(projected.accepted);
        assert_eq!(projected.topic, EVENT_QQ_MESSAGE_AUTHORIZED);
        assert_eq!(projected.reason_code, "accepted");
        assert_eq!(projected.lifecycle.action, QQ_GATEWAY_ACTION_DRAIN_EVENTS);
        assert_eq!(projected.runtime.last_sequence, 1);
        assert_eq!(projected.runtime.accepted_events, 1);
        assert_eq!(
            projected.policy.as_ref().map(|policy| policy.reason_code),
            Some("group_allowed")
        );

        let duplicate = runtime.project_event(event).unwrap();
        assert!(!duplicate.accepted);
        assert_eq!(duplicate.reason_code, "duplicate_event");
        assert_eq!(duplicate.lifecycle.action, QQ_GATEWAY_ACTION_NONE);
        assert_eq!(duplicate.runtime.duplicate_events, 1);
    }

    #[test]
    fn gateway_runtime_enforces_group_policy_and_queue_bounds() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 1,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.bot_user_id = Some("bot-openid".into());
        config.policy.group_policy = QqAccessPolicyMode::Allowlist;
        config.policy.group_allow_from = vec!["group-allowed".into()];
        let mut runtime = QqGatewayRuntime::new(config);

        let denied = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-denied",
                    "content": "bot-openid denied",
                    "group_openid": "group-denied",
                    "group_member_openid": "member-1"
                })),
                id: Some("evt-denied".into()),
            })
            .unwrap();
        assert!(!denied.accepted);
        assert_eq!(denied.reason_code, "group_not_allowed");

        let allowed = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-allowed",
                    "content": "bot-openid allowed",
                    "group_openid": "group-allowed",
                    "group_member_openid": "member-2"
                })),
                id: Some("evt-allowed".into()),
            })
            .unwrap();
        assert!(allowed.accepted);

        let denied_while_full = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(3),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-denied-while-full",
                    "content": "bot-openid denied while queue is full",
                    "group_openid": "group-denied",
                    "group_member_openid": "member-3"
                })),
                id: Some("evt-denied-while-full".into()),
            })
            .unwrap();
        assert!(!denied_while_full.accepted);
        assert_eq!(denied_while_full.reason_code, "group_not_allowed");
        assert_eq!(
            denied_while_full
                .policy
                .as_ref()
                .map(|policy| policy.reason_code),
            Some("group_not_allowed")
        );
        assert_eq!(denied_while_full.runtime.queue_depth, 1);
        assert_eq!(denied_while_full.runtime.accepted_events, 1);

        let overflow = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(4),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-overflow",
                    "content": "bot-openid overflow",
                    "group_openid": "group-allowed",
                    "group_member_openid": "member-4"
                })),
                id: Some("evt-overflow".into()),
            })
            .unwrap();
        assert!(!overflow.accepted);
        assert_eq!(overflow.reason_code, "queue_full");
    }

    #[test]
    fn gateway_runtime_enforces_per_peer_queue_bounds() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 3,
            max_peer_queue_depth: 1,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.group_require_mention = false;
        let mut runtime = QqGatewayRuntime::new(config);

        let first_peer_event = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-peer-first",
                    "content": "first group message",
                    "group_openid": "group-a",
                    "group_member_openid": "member-1"
                })),
                id: Some("evt-peer-first".into()),
            })
            .unwrap();
        assert!(first_peer_event.accepted);
        assert_eq!(first_peer_event.runtime.queue_depth, 1);
        assert_eq!(first_peer_event.runtime.peer_queue_count, 1);
        assert_eq!(first_peer_event.runtime.largest_peer_queue_depth, 1);
        assert_eq!(first_peer_event.runtime.max_peer_queue_depth, 1);

        let same_peer_overflow = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-peer-overflow",
                    "content": "same group should not starve others",
                    "group_openid": "group-a",
                    "group_member_openid": "member-2"
                })),
                id: Some("evt-peer-overflow".into()),
            })
            .unwrap();
        assert!(!same_peer_overflow.accepted);
        assert_eq!(same_peer_overflow.reason_code, "peer_queue_full");
        assert!(same_peer_overflow.normalized.is_none());
        assert!(same_peer_overflow.policy.is_none());
        assert_eq!(same_peer_overflow.runtime.queue_depth, 1);
        assert_eq!(same_peer_overflow.runtime.peer_queue_count, 1);
        assert_eq!(same_peer_overflow.runtime.largest_peer_queue_depth, 1);

        let other_peer = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(3),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-peer-other",
                    "content": "other group still has capacity",
                    "group_openid": "group-b",
                    "group_member_openid": "member-3"
                })),
                id: Some("evt-peer-other".into()),
            })
            .unwrap();
        assert!(other_peer.accepted);
        assert_eq!(other_peer.runtime.queue_depth, 2);
        assert_eq!(other_peer.runtime.peer_queue_count, 2);
        assert_eq!(other_peer.runtime.largest_peer_queue_depth, 1);
    }

    #[test]
    fn gateway_runtime_enforces_channel_allowlist_policy() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 4,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.channel_policy = QqAccessPolicyMode::Allowlist;
        config.policy.channel_allow_from = vec!["channel-allowed".into(), "guild-allowed".into()];
        let mut runtime = QqGatewayRuntime::new(config);

        let denied = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-channel-denied",
                    "content": "channel should be denied",
                    "channel_id": "channel-denied",
                    "guild_id": "guild-denied",
                    "author": {"id": "sender-denied"}
                })),
                id: Some("evt-channel-denied".into()),
            })
            .unwrap();
        assert!(!denied.accepted);
        assert_eq!(denied.reason_code, "channel_not_allowed");
        assert_eq!(
            denied.policy.as_ref().map(|policy| policy.reason_code),
            Some("channel_not_allowed")
        );
        assert_eq!(denied.runtime.accepted_events, 0);
        assert_eq!(denied.runtime.queue_depth, 0);

        let allowed_by_channel = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some("MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-channel-allowed",
                    "content": "channel should be allowed",
                    "channel_id": "channel-allowed",
                    "guild_id": "guild-denied",
                    "author": {"id": "sender-denied"}
                })),
                id: Some("evt-channel-allowed".into()),
            })
            .unwrap();
        assert!(allowed_by_channel.accepted);
        assert_eq!(
            allowed_by_channel
                .policy
                .as_ref()
                .map(|policy| policy.reason_code),
            Some("channel_allowed")
        );
        assert_eq!(
            allowed_by_channel
                .policy
                .as_ref()
                .and_then(|policy| policy.target_id.as_deref()),
            Some("channel-allowed")
        );

        let allowed_by_guild = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(3),
                t: Some("MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-guild-allowed",
                    "content": "guild should be allowed",
                    "channel_id": "channel-other",
                    "guild_id": "guild-allowed",
                    "author": {"id": "sender-denied"}
                })),
                id: Some("evt-guild-allowed".into()),
            })
            .unwrap();
        assert!(allowed_by_guild.accepted);
        assert_eq!(allowed_by_guild.reason_code, "accepted");
    }

    #[test]
    fn gateway_runtime_enforces_channel_disabled_policy() {
        let mut disabled_config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 4,
            ..QqGatewayRuntimeConfig::default()
        };
        disabled_config.policy.channel_policy = QqAccessPolicyMode::Disabled;
        let mut disabled_runtime = QqGatewayRuntime::new(disabled_config);
        let disabled = disabled_runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-channel-disabled",
                    "content": "bot was mentioned but channel policy is disabled",
                    "channel_id": "channel-allowed",
                    "guild_id": "guild-allowed",
                    "author": {"id": "sender-allowed"}
                })),
                id: Some("evt-channel-disabled".into()),
            })
            .unwrap();
        assert!(!disabled.accepted);
        assert_eq!(disabled.reason_code, "channel_disabled");
        assert_eq!(
            disabled.policy.as_ref().map(|policy| policy.mentioned_bot),
            Some(true)
        );
    }

    #[test]
    fn gateway_runtime_accepts_structured_group_mentions() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 4,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.bot_user_id = Some("bot-openid".into());
        config.policy.group_require_mention = true;
        let mut runtime = QqGatewayRuntime::new(config);

        let projected = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-structured-mention",
                    "content": "please check this",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1",
                    "mentions": [
                        {"type": "at", "user_openid": "bot-openid"}
                    ]
                })),
                id: Some("evt-structured-mention".into()),
            })
            .unwrap();

        assert!(projected.accepted);
        assert_eq!(projected.reason_code, "accepted");
        assert_eq!(
            projected.policy.as_ref().map(|policy| policy.mentioned_bot),
            Some(true)
        );
        assert_eq!(
            projected.policy.as_ref().map(|policy| policy.reason_code),
            Some("group_allowed")
        );
    }

    #[test]
    fn gateway_runtime_rejects_untyped_message_id_as_group_mention() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 4,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.bot_user_id = Some("bot-openid".into());
        config.policy.group_require_mention = true;
        let mut runtime = QqGatewayRuntime::new(config);

        let projected = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-untyped-message-id",
                    "content": "plain message",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1",
                    "message": {
                        "id": "bot-openid",
                        "text": "not a mention segment"
                    }
                })),
                id: Some("evt-untyped-message-id".into()),
            })
            .unwrap();

        assert!(!projected.accepted);
        assert_eq!(projected.reason_code, "missing_group_mention");
        assert_eq!(
            projected.policy.as_ref().map(|policy| policy.mentioned_bot),
            Some(false)
        );

        let bare_string = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-bare-string-message",
                    "content": "plain message",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1",
                    "message": "bot-openid"
                })),
                id: Some("evt-bare-string-message".into()),
            })
            .unwrap();

        assert!(!bare_string.accepted);
        assert_eq!(bare_string.reason_code, "missing_group_mention");
        assert_eq!(
            bare_string
                .policy
                .as_ref()
                .map(|policy| policy.mentioned_bot),
            Some(false)
        );
    }

    #[test]
    fn gateway_runtime_requires_text_mention_boundaries() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 4,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.bot_user_id = Some("bot-openid".into());
        config.policy.group_require_mention = true;
        let mut runtime = QqGatewayRuntime::new(config);

        let substring = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-substring-mention",
                    "content": "prefix not-bot-openid suffix",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1"
                })),
                id: Some("evt-substring-mention".into()),
            })
            .unwrap();

        assert!(!substring.accepted);
        assert_eq!(substring.reason_code, "missing_group_mention");
        assert_eq!(
            substring.policy.as_ref().map(|policy| policy.mentioned_bot),
            Some(false)
        );

        let explicit_text = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-explicit-text-mention",
                    "content": "please @bot-openid check this",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1"
                })),
                id: Some("evt-explicit-text-mention".into()),
            })
            .unwrap();

        assert!(explicit_text.accepted);
        assert_eq!(explicit_text.reason_code, "accepted");
        assert_eq!(
            explicit_text
                .policy
                .as_ref()
                .map(|policy| policy.mentioned_bot),
            Some(true)
        );
        assert_eq!(
            explicit_text
                .policy
                .as_ref()
                .map(|policy| policy.reason_code),
            Some("group_allowed")
        );
    }

    #[test]
    fn gateway_runtime_drops_frames_when_disabled_without_mutating_session() {
        let mut runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: false,
            max_queue_depth: 4,
            ..QqGatewayRuntimeConfig::default()
        });

        let hello = runtime
            .project_event(QqGatewayEvent {
                op: 10,
                s: Some(1),
                t: None,
                d: Some(json!({"session_id": "disabled-session"})),
                id: Some("evt-disabled-hello".into()),
            })
            .unwrap();
        assert!(!hello.accepted);
        assert_eq!(hello.reason_code, "gateway_disabled");
        assert_eq!(hello.lifecycle.action, QQ_GATEWAY_ACTION_NONE);
        assert_eq!(hello.runtime.session_id, None);
        assert_eq!(hello.runtime.last_sequence, 0);

        let heartbeat = runtime
            .project_event(QqGatewayEvent {
                op: 11,
                s: Some(2),
                t: None,
                d: None,
                id: Some("evt-disabled-heartbeat".into()),
            })
            .unwrap();
        assert_eq!(heartbeat.reason_code, "gateway_disabled");
        assert_eq!(heartbeat.runtime.heartbeat_ack_count, 0);

        let dispatch = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(3),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-disabled",
                    "content": "bot-openid should not authorize",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1"
                })),
                id: Some("evt-disabled-dispatch".into()),
            })
            .unwrap();
        assert!(!dispatch.accepted);
        assert_eq!(dispatch.reason_code, "gateway_disabled");
        assert!(dispatch.normalized.is_none());
        assert!(dispatch.policy.is_none());
        assert_eq!(dispatch.runtime.last_sequence, 0);
        assert_eq!(dispatch.runtime.accepted_events, 0);
        assert_eq!(dispatch.runtime.queue_depth, 0);
    }

    #[test]
    fn gateway_runtime_rejects_messages_missing_route_bindings() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 8,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.group_require_mention = false;
        let mut runtime = QqGatewayRuntime::new(config);

        let channel_missing_target = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-channel-no-target",
                    "content": "channel without channel id",
                    "author": {"id": "user-1"}
                })),
                id: Some("evt-channel-no-target".into()),
            })
            .unwrap();
        assert!(!channel_missing_target.accepted);
        assert_eq!(channel_missing_target.reason_code, "channel_target_missing");
        assert_eq!(
            channel_missing_target
                .policy
                .as_ref()
                .map(|policy| policy.reason_code),
            Some("channel_target_missing")
        );

        let group_missing_sender = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-group-no-sender",
                    "content": "group without sender",
                    "group_openid": "group-1"
                })),
                id: Some("evt-group-no-sender".into()),
            })
            .unwrap();
        assert!(!group_missing_sender.accepted);
        assert_eq!(group_missing_sender.reason_code, "group_sender_missing");

        let c2c_missing_sender = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(3),
                t: Some("C2C_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-c2c-no-sender",
                    "content": "c2c without sender"
                })),
                id: Some("evt-c2c-no-sender".into()),
            })
            .unwrap();
        assert!(!c2c_missing_sender.accepted);
        assert_eq!(c2c_missing_sender.reason_code, "c2c_sender_missing");
        assert_eq!(c2c_missing_sender.runtime.accepted_events, 0);
        assert_eq!(c2c_missing_sender.runtime.queue_depth, 0);
    }

    #[test]
    fn gateway_runtime_rejects_messages_missing_identity_bindings() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 8,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.group_require_mention = false;
        let mut runtime = QqGatewayRuntime::new(config);

        let missing_message_id = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "content": "message without stable id",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1"
                })),
                id: Some("evt-no-message-id".into()),
            })
            .unwrap();
        assert!(!missing_message_id.accepted);
        assert_eq!(missing_message_id.reason_code, "message_id_missing");
        assert_eq!(
            missing_message_id
                .policy
                .as_ref()
                .map(|policy| policy.reason_code),
            Some("message_id_missing")
        );

        let blank_reply_target = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-blank-reply",
                    "content": "reply without target id",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1",
                    "message_reference": {"message_id": "   "}
                })),
                id: Some("evt-blank-reply".into()),
            })
            .unwrap();
        assert!(!blank_reply_target.accepted);
        assert_eq!(blank_reply_target.reason_code, "reply_target_missing");
        assert_eq!(
            blank_reply_target
                .policy
                .as_ref()
                .map(|policy| policy.reason_code),
            Some("reply_target_missing")
        );
        assert_eq!(blank_reply_target.runtime.accepted_events, 0);
        assert_eq!(blank_reply_target.runtime.queue_depth, 0);
    }

    #[test]
    fn gateway_runtime_enforces_attachment_byte_policy() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 8,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.max_attachment_bytes = Some(4_096);
        let mut runtime = QqGatewayRuntime::new(config);

        let allowed = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-attachment-ok",
                    "content": "bot see these",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1",
                    "attachments": [
                        {"url": "https://example.com/a.png", "size": 1024},
                        {"url": "https://example.com/b.png", "size": 2048}
                    ]
                })),
                id: Some("evt-attachment-ok".into()),
            })
            .unwrap();
        assert!(allowed.accepted);
        assert_eq!(
            allowed.policy.as_ref().map(|policy| policy.reason_code),
            Some("group_allowed")
        );

        let oversized = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-attachment-too-large",
                    "content": "bot see oversized",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1",
                    "attachments": [
                        {"url": "https://example.com/part-a.bin", "size": 2048},
                        {"url": "https://example.com/part-b.bin", "size": 2049}
                    ]
                })),
                id: Some("evt-attachment-too-large".into()),
            })
            .unwrap();
        assert!(!oversized.accepted);
        assert_eq!(oversized.reason_code, "attachment_bytes_exceeded");
        assert_eq!(
            oversized.policy.as_ref().map(|policy| policy.reason_code),
            Some("attachment_bytes_exceeded")
        );

        let unknown_size = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(3),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-attachment-unknown",
                    "content": "bot see unsized",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1",
                    "attachments": [
                        {"url": "https://example.com/unknown.bin"}
                    ]
                })),
                id: Some("evt-attachment-unknown".into()),
            })
            .unwrap();
        assert!(!unknown_size.accepted);
        assert_eq!(unknown_size.reason_code, "attachment_size_unknown");

        let mut uncapped_runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 8,
            ..QqGatewayRuntimeConfig::default()
        });
        let uncapped = uncapped_runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_AT_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-attachment-uncapped",
                    "content": "bot see uncapped",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1",
                    "attachments": [
                        {"url": "https://example.com/unknown.bin"}
                    ]
                })),
                id: Some("evt-attachment-uncapped".into()),
            })
            .unwrap();
        assert!(uncapped.accepted);
    }

    fn group_attachment_gateway_event(
        sequence: u64,
        message_id: &str,
        event_id: &str,
        content: &str,
        attachment: Value,
    ) -> QqGatewayEvent {
        let attachments = vec![attachment];
        QqGatewayEvent {
            op: 0,
            s: Some(sequence),
            t: Some("GROUP_AT_MESSAGE_CREATE".into()),
            d: Some(json!({
                "id": message_id,
                "content": content,
                "group_openid": "group-1",
                "group_member_openid": "member-1",
                "attachments": attachments
            })),
            id: Some(event_id.into()),
        }
    }

    #[test]
    fn gateway_runtime_enforces_attachment_content_type_policy() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 8,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.allowed_attachment_content_types = vec!["image/png".into()];
        let mut runtime = QqGatewayRuntime::new(config);

        let allowed = runtime
            .project_event(group_attachment_gateway_event(
                1,
                "msg-attachment-type-ok",
                "evt-attachment-type-ok",
                "bot see png",
                json!({
                    "url": "https://example.com/allowed.png",
                    "content_type": "IMAGE/PNG; charset=binary",
                    "size": 1024
                }),
            ))
            .unwrap();
        assert!(allowed.accepted);
        assert_eq!(
            allowed.policy.as_ref().map(|policy| policy.reason_code),
            Some("group_allowed")
        );

        let disallowed = runtime
            .project_event(group_attachment_gateway_event(
                2,
                "msg-attachment-type-denied",
                "evt-attachment-type-denied",
                "bot see exe",
                json!({
                    "url": "https://example.com/denied.exe",
                    "content_type": "application/x-msdownload",
                    "size": 1024
                }),
            ))
            .unwrap();
        assert!(!disallowed.accepted);
        assert_eq!(
            disallowed.reason_code,
            "attachment_content_type_not_allowed"
        );
        assert_eq!(
            disallowed.policy.as_ref().map(|policy| policy.reason_code),
            Some("attachment_content_type_not_allowed")
        );

        let missing = runtime
            .project_event(group_attachment_gateway_event(
                3,
                "msg-attachment-type-missing",
                "evt-attachment-type-missing",
                "bot see unknown",
                json!({
                    "url": "https://example.com/unknown.bin",
                    "size": 1024
                }),
            ))
            .unwrap();
        assert!(!missing.accepted);
        assert_eq!(missing.reason_code, "attachment_content_type_missing");

        let malformed = runtime
            .project_event(group_attachment_gateway_event(
                4,
                "msg-attachment-type-malformed",
                "evt-attachment-type-malformed",
                "bot see malformed",
                json!({
                    "url": "https://example.com/malformed.png",
                    "content_type": "image/png/extra",
                    "size": 1024
                }),
            ))
            .unwrap();
        assert!(!malformed.accepted);
        assert_eq!(malformed.reason_code, "attachment_content_type_missing");
    }

    #[test]
    fn gateway_runtime_rejects_attachment_urls_unsafe_for_fanout() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 8,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.allowed_attachment_content_types = vec!["image/png".into()];
        let mut runtime = QqGatewayRuntime::new(config);

        let unsafe_scheme = runtime
            .project_event(group_attachment_gateway_event(
                1,
                "msg-attachment-file-url",
                "evt-attachment-file-url",
                "bot see local file",
                json!({
                    "url": "file:///private/qq/trace.png",
                    "content_type": "image/png",
                    "size": 512
                }),
            ))
            .unwrap();
        assert!(!unsafe_scheme.accepted);
        assert_eq!(unsafe_scheme.reason_code, "attachment_url_not_allowed");
        assert_eq!(
            unsafe_scheme
                .policy
                .as_ref()
                .map(|policy| policy.reason_code),
            Some("attachment_url_not_allowed")
        );
        assert_eq!(unsafe_scheme.runtime.accepted_events, 0);
        assert_eq!(unsafe_scheme.runtime.queue_depth, 0);

        let credentialed_url = runtime
            .project_event(group_attachment_gateway_event(
                2,
                "msg-attachment-credential-url",
                "evt-attachment-credential-url",
                "bot see credentialed url",
                json!({
                    "url": "https://user:secret@example.com/trace.png",
                    "content_type": "image/png",
                    "size": 512
                }),
            ))
            .unwrap();
        assert!(!credentialed_url.accepted);
        assert_eq!(credentialed_url.reason_code, "attachment_url_not_allowed");
        assert_eq!(credentialed_url.runtime.accepted_events, 0);
        assert_eq!(credentialed_url.runtime.queue_depth, 0);

        let blank_url = runtime
            .project_event(group_attachment_gateway_event(
                3,
                "msg-attachment-blank-url",
                "evt-attachment-blank-url",
                "bot see blank url",
                json!({
                    "url": "   ",
                    "content_type": "image/png",
                    "size": 512
                }),
            ))
            .unwrap();
        assert!(!blank_url.accepted);
        assert_eq!(blank_url.reason_code, "attachment_url_not_allowed");
        assert_eq!(blank_url.runtime.accepted_events, 0);
        assert_eq!(blank_url.runtime.queue_depth, 0);
    }

    #[test]
    fn gateway_runtime_tracks_bounded_reply_references() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 2,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.group_require_mention = false;
        let mut runtime = QqGatewayRuntime::new(config);

        let root = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-root",
                    "content": "root message",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1"
                })),
                id: Some("evt-root".into()),
            })
            .unwrap();
        assert!(root.accepted);
        assert_eq!(root.runtime.reply_reference_count, 1);
        assert_eq!(root.runtime.max_reply_references, 2);
        assert_eq!(root.runtime.known_reply_references, 0);
        assert_eq!(root.runtime.unknown_reply_references, 0);

        let known_reply = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(2),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-known-reply",
                    "content": "known reply",
                    "group_openid": "group-1",
                    "group_member_openid": "member-2",
                    "message_reference": {"message_id": "msg-root"}
                })),
                id: Some("evt-known-reply".into()),
            })
            .unwrap();
        assert!(known_reply.accepted);
        assert_eq!(known_reply.runtime.reply_reference_count, 2);
        assert_eq!(known_reply.runtime.known_reply_references, 1);
        assert_eq!(known_reply.runtime.unknown_reply_references, 0);

        let drained = runtime.drain_accepted_events(usize::MAX);
        assert_eq!(drained.drained_count, 2);
        assert_eq!(drained.runtime.reply_reference_count, 2);

        let unknown_reply = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(3),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-unknown-reply",
                    "content": "unknown reply",
                    "group_openid": "group-1",
                    "group_member_openid": "member-3",
                    "message_reference": {"message_id": "msg-missing"}
                })),
                id: Some("evt-unknown-reply".into()),
            })
            .unwrap();
        assert!(unknown_reply.accepted);
        assert_eq!(unknown_reply.runtime.reply_reference_count, 2);
        assert_eq!(unknown_reply.runtime.known_reply_references, 1);
        assert_eq!(unknown_reply.runtime.unknown_reply_references, 1);
    }

    #[test]
    fn gateway_runtime_drains_accepted_events_and_restores_queue_capacity() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 2,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.group_require_mention = false;
        let mut runtime = QqGatewayRuntime::new(config);

        for sequence in 1..=2 {
            let projected = runtime
                .project_event(QqGatewayEvent {
                    op: 0,
                    s: Some(sequence),
                    t: Some("GROUP_MESSAGE_CREATE".into()),
                    d: Some(json!({
                        "id": format!("msg-{sequence}"),
                        "content": format!("queued message {sequence}"),
                        "group_openid": "group-1",
                        "group_member_openid": format!("member-{sequence}")
                    })),
                    id: Some(format!("evt-{sequence}")),
                })
                .unwrap();
            assert!(projected.accepted);
            assert_eq!(
                projected.runtime.queue_depth,
                usize::try_from(sequence).expect("test sequence fits usize")
            );
        }

        let queue_full = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(3),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-3",
                    "content": "queue should be full",
                    "group_openid": "group-1",
                    "group_member_openid": "member-3"
                })),
                id: Some("evt-3".into()),
            })
            .unwrap();
        assert!(!queue_full.accepted);
        assert_eq!(queue_full.reason_code, "queue_full");
        assert_eq!(queue_full.runtime.queue_depth, 2);

        let drained_one = runtime.drain_accepted_events(1);
        assert_eq!(drained_one.drained_count, 1);
        assert_eq!(drained_one.remaining_count, 1);
        assert_eq!(drained_one.runtime.queue_depth, 1);
        assert_eq!(drained_one.events[0].event_id.as_deref(), Some("evt-1"));
        assert_eq!(
            drained_one.events[0].normalized.message_id.as_deref(),
            Some("msg-1")
        );

        let accepted_after_drain = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(4),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-4",
                    "content": "capacity restored",
                    "group_openid": "group-1",
                    "group_member_openid": "member-4"
                })),
                id: Some("evt-4".into()),
            })
            .unwrap();
        assert!(accepted_after_drain.accepted);
        assert_eq!(accepted_after_drain.runtime.queue_depth, 2);

        let drained_remaining = runtime.drain_accepted_events(usize::MAX);
        assert_eq!(drained_remaining.drained_count, 2);
        assert_eq!(drained_remaining.remaining_count, 0);
        assert_eq!(drained_remaining.runtime.queue_depth, 0);
        assert_eq!(
            drained_remaining
                .events
                .iter()
                .map(|event| event.event_id.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("evt-2"), Some("evt-4")]
        );
    }

    #[test]
    fn gateway_runtime_zero_drain_is_noop() {
        let mut config = QqGatewayRuntimeConfig {
            enabled: true,
            max_queue_depth: 2,
            ..QqGatewayRuntimeConfig::default()
        };
        config.policy.group_require_mention = false;
        let mut runtime = QqGatewayRuntime::new(config);
        let accepted = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(1),
                t: Some("GROUP_MESSAGE_CREATE".into()),
                d: Some(json!({
                    "id": "msg-1",
                    "content": "queued message",
                    "group_openid": "group-1",
                    "group_member_openid": "member-1"
                })),
                id: Some("evt-1".into()),
            })
            .unwrap();
        assert!(accepted.accepted);
        let drained = runtime.drain_accepted_events(0);
        assert_eq!(drained.drained_count, 0);
        assert_eq!(drained.remaining_count, 1);
        assert!(drained.events.is_empty());
        assert_eq!(drained.runtime.queue_depth, 1);
    }

    #[test]
    fn gateway_runtime_classifies_control_and_stale_frames() {
        let mut runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: true,
            restore_sequence: Some(10),
            ..QqGatewayRuntimeConfig::default()
        });

        let stale = runtime
            .project_event(QqGatewayEvent {
                op: 0,
                s: Some(10),
                t: Some("C2C_MESSAGE_CREATE".into()),
                d: Some(json!({"id": "msg-stale", "author": {"id": "user-1"}})),
                id: Some("evt-stale".into()),
            })
            .unwrap();
        assert_eq!(stale.reason_code, "stale_sequence");
        assert_eq!(stale.runtime.stale_sequence_events, 1);

        let unmatched_heartbeat_ack = runtime
            .project_event(QqGatewayEvent {
                op: 11,
                s: None,
                t: None,
                d: None,
                id: None,
            })
            .unwrap();
        assert_eq!(
            unmatched_heartbeat_ack.reason_code,
            "heartbeat_ack_unmatched"
        );
        assert_eq!(
            unmatched_heartbeat_ack.lifecycle.action,
            QQ_GATEWAY_ACTION_NONE
        );
        assert_eq!(unmatched_heartbeat_ack.runtime.heartbeat_sent_count, 0);
        assert_eq!(unmatched_heartbeat_ack.runtime.heartbeat_ack_count, 0);

        let heartbeat_request = runtime
            .project_event(QqGatewayEvent {
                op: 1,
                s: None,
                t: None,
                d: None,
                id: None,
            })
            .unwrap();
        assert_eq!(heartbeat_request.reason_code, "heartbeat_request");
        assert_eq!(
            heartbeat_request.lifecycle.action,
            QQ_GATEWAY_ACTION_SEND_HEARTBEAT
        );
        assert_eq!(heartbeat_request.lifecycle.resume_sequence, 10);
        assert_eq!(heartbeat_request.runtime.heartbeat_sent_count, 1);
        assert_eq!(heartbeat_request.runtime.heartbeat_ack_count, 0);

        let heartbeat = runtime
            .project_event(QqGatewayEvent {
                op: 11,
                s: None,
                t: None,
                d: None,
                id: None,
            })
            .unwrap();
        assert_eq!(heartbeat.reason_code, "heartbeat_ack");
        assert_eq!(heartbeat.lifecycle.action, QQ_GATEWAY_ACTION_NONE);
        assert_eq!(heartbeat.runtime.heartbeat_sent_count, 1);
        assert_eq!(heartbeat.runtime.heartbeat_ack_count, 1);
    }

    #[test]
    fn gateway_runtime_tracks_reconnect_frames_and_caps_attempts() {
        let mut runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: true,
            max_reconnect_attempts: 2,
            reconnect_backoff_ms: 250,
            restore_session_id: Some("session-before-reconnect".into()),
            ..QqGatewayRuntimeConfig::default()
        });

        let reconnect = runtime
            .project_event(QqGatewayEvent {
                op: 7,
                s: None,
                t: None,
                d: None,
                id: Some("evt-reconnect".into()),
            })
            .unwrap();
        assert_eq!(reconnect.reason_code, "reconnect_requested");
        assert_eq!(
            reconnect.lifecycle.action,
            QQ_GATEWAY_ACTION_RECONNECT_RESUME
        );
        assert_eq!(
            reconnect.lifecycle.resume_session_id.as_deref(),
            Some("session-before-reconnect")
        );
        assert_eq!(reconnect.lifecycle.reconnect_after_ms, Some(250));
        assert_eq!(reconnect.runtime.reconnect_attempts, 1);
        assert_eq!(reconnect.runtime.max_reconnect_attempts, 2);
        assert_eq!(reconnect.runtime.terminal_reconnect_failures, 0);
        assert_eq!(reconnect.runtime.reconnect_backoff_ms, 250);
        assert_eq!(reconnect.runtime.max_reconnect_backoff_ms, 30_000);
        assert_eq!(
            reconnect.runtime.session_id.as_deref(),
            Some("session-before-reconnect")
        );

        let resumable_invalid_session = runtime
            .project_event(QqGatewayEvent {
                op: 9,
                s: None,
                t: None,
                d: Some(json!(true)),
                id: Some("evt-invalid-resumable".into()),
            })
            .unwrap();
        assert_eq!(
            resumable_invalid_session.reason_code,
            "invalid_session_resumable"
        );
        assert_eq!(
            resumable_invalid_session.lifecycle.action,
            QQ_GATEWAY_ACTION_RECONNECT_RESUME
        );
        assert_eq!(
            resumable_invalid_session.lifecycle.reconnect_after_ms,
            Some(500)
        );
        assert_eq!(resumable_invalid_session.runtime.reconnect_attempts, 2);

        let exhausted = runtime
            .project_event(QqGatewayEvent {
                op: 9,
                s: None,
                t: None,
                d: Some(json!(false)),
                id: Some("evt-invalid-exhausted".into()),
            })
            .unwrap();
        assert_eq!(exhausted.reason_code, "reconnect_attempts_exhausted");
        assert_eq!(exhausted.lifecycle.action, QQ_GATEWAY_ACTION_STOP_RECONNECT);
        assert_eq!(exhausted.lifecycle.reconnect_after_ms, None);
        assert_eq!(exhausted.runtime.reconnect_attempts, 3);
        assert_eq!(exhausted.runtime.terminal_reconnect_failures, 1);

        let hello = runtime
            .project_event(QqGatewayEvent {
                op: 10,
                s: None,
                t: None,
                d: Some(json!({"session_id": "session-after-reconnect"})),
                id: Some("evt-hello-after-reconnect".into()),
            })
            .unwrap();
        assert_eq!(hello.reason_code, "hello");
        assert_eq!(hello.lifecycle.action, QQ_GATEWAY_ACTION_RESUME);
        assert_eq!(hello.runtime.reconnect_attempts, 0);
        assert_eq!(hello.runtime.terminal_reconnect_failures, 1);
        assert_eq!(
            hello.runtime.session_id.as_deref(),
            Some("session-after-reconnect")
        );
    }

    #[test]
    fn gateway_runtime_reconnect_uses_restored_session_and_sequence() {
        let mut runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: true,
            restore_session_id: Some("restored-session".into()),
            restore_sequence: Some(44),
            reconnect_backoff_ms: 125,
            max_reconnect_backoff_ms: 500,
            max_reconnect_attempts: 3,
            ..QqGatewayRuntimeConfig::default()
        });

        let reconnect = runtime
            .project_event(QqGatewayEvent {
                op: 7,
                s: None,
                t: None,
                d: None,
                id: Some("evt-restored-reconnect".into()),
            })
            .unwrap();

        assert_eq!(reconnect.reason_code, "reconnect_requested");
        assert_eq!(
            reconnect.lifecycle.action,
            QQ_GATEWAY_ACTION_RECONNECT_RESUME
        );
        assert_eq!(
            reconnect.lifecycle.resume_session_id.as_deref(),
            Some("restored-session")
        );
        assert_eq!(reconnect.lifecycle.resume_sequence, 44);
        assert_eq!(reconnect.lifecycle.reconnect_after_ms, Some(125));
        assert_eq!(
            reconnect.runtime.session_id.as_deref(),
            Some("restored-session")
        );
        assert_eq!(reconnect.runtime.last_sequence, 44);
        assert_eq!(reconnect.runtime.reconnect_attempts, 1);
        assert_eq!(reconnect.runtime.terminal_reconnect_failures, 0);
    }

    #[test]
    fn gateway_runtime_identifies_after_nonresumable_invalid_session() {
        let mut runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: true,
            max_reconnect_attempts: 3,
            reconnect_backoff_ms: 250,
            restore_session_id: Some("session-before-invalid-session".into()),
            restore_sequence: Some(42),
            ..QqGatewayRuntimeConfig::default()
        });

        let invalid_session = runtime
            .project_event(QqGatewayEvent {
                op: 9,
                s: None,
                t: None,
                d: Some(json!(false)),
                id: Some("evt-invalid-identify-required".into()),
            })
            .unwrap();

        assert_eq!(
            invalid_session.reason_code,
            "invalid_session_identify_required"
        );
        assert_eq!(
            invalid_session.lifecycle.action,
            QQ_GATEWAY_ACTION_RECONNECT_IDENTIFY
        );
        assert_eq!(invalid_session.lifecycle.resume_session_id.as_deref(), None);
        assert_eq!(invalid_session.lifecycle.resume_sequence, 42);
        assert_eq!(invalid_session.lifecycle.reconnect_after_ms, Some(250));
        assert_eq!(invalid_session.runtime.reconnect_attempts, 1);
        assert_eq!(invalid_session.runtime.terminal_reconnect_failures, 0);
        assert_eq!(
            invalid_session.runtime.session_id.as_deref(),
            Some("session-before-invalid-session")
        );
    }

    #[test]
    fn gateway_runtime_caps_reconnect_backoff_delay() {
        let mut runtime = QqGatewayRuntime::new(QqGatewayRuntimeConfig {
            enabled: true,
            max_reconnect_attempts: 4,
            reconnect_backoff_ms: 400,
            max_reconnect_backoff_ms: 700,
            restore_session_id: Some("session-before-reconnect".into()),
            ..QqGatewayRuntimeConfig::default()
        });

        let first = runtime
            .project_event(QqGatewayEvent {
                op: 7,
                s: None,
                t: None,
                d: None,
                id: Some("evt-reconnect-1".into()),
            })
            .unwrap();
        assert_eq!(first.lifecycle.action, QQ_GATEWAY_ACTION_RECONNECT_RESUME);
        assert_eq!(first.lifecycle.reconnect_after_ms, Some(400));

        let second = runtime
            .project_event(QqGatewayEvent {
                op: 7,
                s: None,
                t: None,
                d: None,
                id: Some("evt-reconnect-2".into()),
            })
            .unwrap();
        assert_eq!(second.lifecycle.action, QQ_GATEWAY_ACTION_RECONNECT_RESUME);
        assert_eq!(second.lifecycle.reconnect_after_ms, Some(700));

        let third = runtime
            .project_event(QqGatewayEvent {
                op: 9,
                s: None,
                t: None,
                d: Some(json!(false)),
                id: Some("evt-reconnect-3".into()),
            })
            .unwrap();
        assert_eq!(third.lifecycle.action, QQ_GATEWAY_ACTION_RECONNECT_IDENTIFY);
        assert_eq!(third.lifecycle.reconnect_after_ms, Some(700));
        assert_eq!(third.runtime.reconnect_attempts, 3);
        assert_eq!(third.runtime.max_reconnect_backoff_ms, 700);
    }
}
