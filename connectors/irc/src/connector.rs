//! `IRC` connector -- `FcpConnector` implementation.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::client::with_irc_session;
use crate::types::{
    CAP_CHANNELS_WRITE, CAP_HEALTH_READ, CAP_MESSAGES_READ, CAP_MESSAGES_WRITE,
    DEFAULT_SAMPLE_LINES, IrcConfig, OP_HEALTH, OP_JOIN_CHANNEL, OP_SAMPLE_TRANSCRIPT,
    OP_SEND_MESSAGE, parse_irc_lines,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

fn default_irc_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_irc_chat_coordination_config(
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

fn irc_coordination_audit_records(
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

// ─────────────────────────────────────────────────────────────────
// Doctor types (V3 requirement)
// ─────────────────────────────────────────────────────────────────

/// Result of a connector diagnostic check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

/// A single diagnostic check within a `DoctorResult`.
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

// ─────────────────────────────────────────────────────────────────
// Connector state
// ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct IrcState {
    config: IrcConfig,
}

pub struct IrcConnector {
    base: BaseConnector,
    state: Option<IrcState>,
    verifier: Option<CapabilityVerifier>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
    started_at: Instant,
}

impl IrcConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.irc")),
            state: None,
            verifier: None,
            chat_coordination_config: default_irc_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
            started_at: Instant::now(),
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

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.state.is_some(),
            message: Some(if self.state.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: self.verifier.is_some(),
            message: Some(if self.verifier.is_some() {
                "Handshake completed".into()
            } else {
                "Handshake not completed".into()
            }),
            critical: false,
        });

        if let Some(state) = &self.state {
            checks.push(DoctorCheck {
                name: "server_configured".into(),
                passed: !state.config.server.trim().is_empty(),
                message: Some(format!(
                    "Server: {}:{} (TLS: {})",
                    state.config.server,
                    state.config.port(),
                    state.config.tls
                )),
                critical: true,
            });

            checks.push(DoctorCheck {
                name: "nick_configured".into(),
                passed: !state.config.nick.trim().is_empty(),
                message: Some(format!("Nick: {}", state.config.nick)),
                critical: true,
            });
        }

        DoctorResult::from_checks(checks)
    }

    #[allow(clippy::too_many_lines)]
    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_SEND_MESSAGE,
                "Send an IRC PRIVMSG",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["target", "message"],
                    "properties": {
                        "target": { "type": "string" },
                        "message": { "type": "string" }
                    }
                }),
                json!({
                    "type": "object",
                    "required": ["status", "target", "transcript"],
                    "properties": {
                        "status": { "type": "string" },
                        "target": { "type": "string" },
                        "transcript": { "type": "array", "items": { "type": "string" } }
                    }
                }),
                "Use for bounded IRC sends to a channel or nick.",
            ),
            operation(
                OP_JOIN_CHANNEL,
                "Join an IRC channel",
                CAP_CHANNELS_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::BestEffort,
                json!({
                    "type": "object",
                    "required": ["channel"],
                    "properties": {
                        "channel": { "type": "string" },
                        "channel_key": { "type": "string" }
                    }
                }),
                transcript_output_schema(&[
                    "status",
                    "channel",
                    "transcript",
                    "events",
                    "identity",
                ]),
                "Use to validate that a configured IRC identity can join a channel.",
            ),
            operation(
                OP_SAMPLE_TRANSCRIPT,
                "Sample a bounded IRC transcript",
                CAP_MESSAGES_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["channel"],
                    "properties": {
                        "channel": { "type": "string" },
                        "sample_lines": { "type": "integer" }
                    }
                }),
                transcript_output_schema(&["channel", "lines", "events", "identity"]),
                "Use to collect a short bounded transcript without keeping a long-lived IRC session open.",
            ),
            operation(
                OP_HEALTH,
                "Verify IRC connectivity and registration",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "properties": {}
                }),
                transcript_output_schema(&[
                    "status",
                    "server",
                    "port",
                    "tls",
                    "nick",
                    "transcript",
                    "events",
                    "identity",
                    "manifest_hash",
                ]),
                "Use before joining or sending to make sure registration succeeds.",
            ),
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])?;

        let output = match req.operation.as_str() {
            OP_SEND_MESSAGE => self.send_message_output(state, &req.input).await?,
            OP_JOIN_CHANNEL => {
                let channel = required_string(&req.input, "channel")?;
                let channel_key = req.input.get("channel_key").and_then(Value::as_str);
                let transcript = with_irc_session(&state.config, |mut session| async move {
                    session.join(channel, channel_key, 5).await?;
                    session.quit().await?;
                    Ok::<_, FcpError>(session.lines)
                })
                .await?;
                let events = parse_irc_lines(&transcript, &state.config.nick);
                json!({
                    "status": "joined",
                    "channel": channel,
                    "transcript": transcript,
                    "events": events,
                    "identity": state.config.identity(),
                })
            }
            OP_SAMPLE_TRANSCRIPT => {
                let channel = required_string(&req.input, "channel")?;
                let sample_lines = req
                    .input
                    .get("sample_lines")
                    .and_then(Value::as_u64)
                    .unwrap_or(DEFAULT_SAMPLE_LINES as u64)
                    .clamp(1, 200) as usize;
                let transcript = with_irc_session(&state.config, |mut session| async move {
                    session.join(channel, None, 0).await?;
                    let sample_start = session.lines.len();
                    session.read_up_to(sample_lines).await?;
                    session.quit().await?;
                    Ok::<_, FcpError>(session.lines.into_iter().skip(sample_start).collect())
                })
                .await?;
                let events = parse_irc_lines(&transcript, &state.config.nick);
                json!({
                    "channel": channel,
                    "lines": transcript,
                    "events": events,
                    "identity": state.config.identity(),
                })
            }
            OP_HEALTH => {
                let transcript = with_irc_session(&state.config, |mut session| async move {
                    session.quit().await?;
                    Ok::<_, FcpError>(session.lines)
                })
                .await?;
                let events = parse_irc_lines(&transcript, &state.config.nick);
                json!({
                    "status": "ok",
                    "server": state.config.server,
                    "port": state.config.port(),
                    "tls": state.config.tls,
                    "nick": state.config.nick,
                    "transcript": transcript,
                    "events": events,
                    "identity": state.config.identity(),
                    "manifest_hash": Self::manifest_hash(),
                })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("unknown operation: {}", req.operation),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }

    async fn send_message_output(&self, state: &IrcState, input: &Value) -> FcpResult<Value> {
        let target = required_string(input, "target")?;
        let message = required_string(input, "message")?;
        let (zone_id, claimant_agent_id) = self.chat_coordination_context();
        let coordination = self
            .claim_before_irc_send(zone_id, target, claimant_agent_id.clone())
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                error = %error,
                "IRC send_message denied by chat coordination"
            );
            return Err(error.clone());
        }

        let transcript = with_irc_session(&state.config, |mut session| async move {
            session.send_privmsg(target, message).await?;
            session.quit().await?;
            Ok::<_, FcpError>(session.lines)
        })
        .await?;
        Ok(json!({
            "status": "sent",
            "target": target,
            "transcript": transcript,
            "coordination": irc_coordination_audit_records(
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

    async fn claim_before_irc_send(
        &self,
        zone_id: ZoneId,
        target: &str,
        claimant_agent_id: AgentId,
    ) -> ChatCoordinationSendDecision {
        let channel_id = ChannelId::new(target.trim().to_ascii_lowercase());
        let cx = fcp_async_core::compatibility_cx();
        self.chat_coordination_config
            .claim_before_send(
                &cx,
                self.thread_ownership_checker.as_ref(),
                ChatCoordinationSendRequest::new(
                    zone_id,
                    self.base.id.clone(),
                    channel_id,
                    None,
                    claimant_agent_id,
                ),
            )
            .await
    }
}

impl Default for IrcConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(IrcConnector);

#[async_trait]
impl FcpConnector for IrcConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let chat_coordination_config = parse_irc_chat_coordination_config(
            config.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;
        let config: IrcConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid IRC configuration: {error}"),
            })?;
        config.validate()?;
        self.state = Some(IrcState { config });
        self.chat_coordination_config = chat_coordination_config;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if let Some(requested_instance_id) = req.requested_instance_id.clone() {
            self.base.instance_id = requested_instance_id;
        }
        self.base.set_handshaken(true);
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
        let handshake_completed = self.verifier.is_some();
        HealthSnapshot {
            status: match self.state {
                Some(_) if handshake_completed => HealthState::Ready,
                Some(_) => HealthState::Degraded {
                    reason: "handshake pending".into(),
                },
                None => HealthState::Starting,
            },
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: self.state.as_ref().map(|state| {
                json!({
                    "server": state.config.server,
                    "port": state.config.port(),
                    "tls": state.config.tls,
                    "nick": state.config.nick,
                    "handshake_completed": handshake_completed,
                })
            }),
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(state) = self.state.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before IRC self_check",
            ));
        };
        match with_irc_session(&state.config, |mut session| async move {
            session.quit().await?;
            Ok::<_, FcpError>(session.lines)
        })
        .await
        {
            Ok(_) => Ok(SelfCheckReport::ok()),
            Err(error) => Ok(SelfCheckReport::from_error(&error)),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.state = None;
        self.verifier = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations(),
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
        if self.state.is_none() {
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

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

// ── Helper functions ──

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_SEND_MESSAGE => CAP_MESSAGES_WRITE,
        OP_JOIN_CHANNEL => CAP_CHANNELS_WRITE,
        OP_SAMPLE_TRANSCRIPT => CAP_MESSAGES_READ,
        OP_HEALTH => CAP_HEALTH_READ,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| {
            matches!(
                capability.as_str(),
                CAP_MESSAGES_WRITE | CAP_CHANNELS_WRITE | CAP_MESSAGES_READ | CAP_HEALTH_READ
            )
        })
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

fn required_string<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} is required"),
        })
}

#[allow(clippy::too_many_arguments)]
fn operation(
    id: &'static str,
    summary: &str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: Value,
    output_schema: Value,
    when_to_use: &str,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(summary.into()),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: vec![
                "This first slice opens short-lived IRC sessions and does not maintain a persistent subscription."
                    .into(),
            ],
            examples: Vec::new(),
            related: vec![CapabilityId::from_static(CAP_HEALTH_READ)],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn transcript_output_schema(required: &[&str]) -> Value {
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "status": { "type": "string" },
            "channel": { "type": "string" },
            "lines": { "type": "array", "items": { "type": "string" } },
            "transcript": { "type": "array", "items": { "type": "string" } },
            "events": { "type": "array", "items": normalized_event_schema() },
            "identity": identity_schema(),
            "server": { "type": "string" },
            "port": { "type": "integer" },
            "tls": { "type": "boolean" },
            "nick": { "type": "string" },
            "manifest_hash": { "type": "string" }
        }
    })
}

fn identity_schema() -> Value {
    json!({
        "type": "object",
        "required": ["nick", "username", "realname"],
        "properties": {
            "nick": { "type": "string" },
            "username": { "type": "string" },
            "realname": { "type": "string" }
        }
    })
}

fn normalized_event_schema() -> Value {
    json!({
        "type": "object",
        "required": ["raw", "kind", "command", "route"],
        "properties": {
            "raw": { "type": "string" },
            "kind": { "type": "string" },
            "command": { "type": "string" },
            "numeric": { "type": "integer" },
            "prefix": {
                "type": "object",
                "required": ["raw"],
                "properties": {
                    "raw": { "type": "string" },
                    "nick": { "type": "string" },
                    "user": { "type": "string" },
                    "host": { "type": "string" },
                    "server": { "type": "string" }
                }
            },
            "params": { "type": "array", "items": { "type": "string" } },
            "trailing": { "type": "string" },
            "route": {
                "type": "object",
                "required": ["kind"],
                "properties": {
                    "kind": { "type": "string" },
                    "conversation": { "type": "string" },
                    "peer_nick": { "type": "string" }
                }
            },
            "target": { "type": "string" },
            "channel": { "type": "string" },
            "message": { "type": "string" }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DEFAULT_PORT_PLAIN, DEFAULT_PORT_TLS};
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{
        CapabilityConstraints, CapabilityToken, InstanceId, RequestId, SelfCheckStatus, ZoneId,
    };
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener as StdTcpListener,
        sync::Mutex,
        thread,
        time::{Duration, Instant},
    };

    fn handshake_request_for(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [9u8; 32],
            capabilities_requested: vec![],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn handshake_request() -> HandshakeRequest {
        handshake_request_for([7u8; 32])
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
        instance_id: &InstanceId,
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
            .target_instance(instance_id.as_str())
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    fn invoke_request(
        operation: &'static str,
        input: Value,
        capability_token: CapabilityToken,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("irc-invoke"),
            connector_id: ConnectorId::from_static("fcp.irc"),
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

    async fn configure_handshaken_connector(
        connector: &mut IrcConnector,
        config: Value,
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
    ) -> CapabilityToken {
        connector
            .configure(config)
            .await
            .expect("configure should succeed");
        connector
            .handshake(handshake_request_for(
                signing_key.verifying_key().to_bytes(),
            ))
            .await
            .expect("handshake should succeed");
        capability_token(
            signing_key,
            capability,
            operation,
            &connector.base.instance_id,
        )
    }

    struct IrcTestServer {
        port: u16,
        lines: Arc<Mutex<Vec<String>>>,
        handle: thread::JoinHandle<()>,
    }

    impl IrcTestServer {
        fn spawn() -> Self {
            let listener =
                StdTcpListener::bind("127.0.0.1:0").expect("loopback IRC listener should bind");
            let port = listener
                .local_addr()
                .expect("loopback listener should expose local addr")
                .port();
            let lines = Arc::new(Mutex::new(Vec::new()));
            let captured_lines = Arc::clone(&lines);
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener
                    .accept()
                    .expect("loopback IRC server should accept one client");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .expect("set read timeout");
                let mut reader = BufReader::new(
                    stream
                        .try_clone()
                        .expect("loopback IRC stream should be cloneable"),
                );
                let mut welcomed = false;
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                            captured_lines
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(trimmed.clone());
                            if trimmed.starts_with("USER ") && !welcomed {
                                welcomed = true;
                                stream
                                    .write_all(b":irc.test 001 testbot :welcome\r\n")
                                    .expect("write welcome");
                                stream.flush().expect("flush welcome");
                            }
                            if trimmed.starts_with("QUIT ") {
                                break;
                            }
                        }
                    }
                }
            });
            Self {
                port,
                lines,
                handle,
            }
        }

        fn config(&self) -> Value {
            json!({
                "server": "127.0.0.1",
                "port": self.port,
                "nick": "testbot",
                "tls": false,
                "request_timeout_ms": 1000
            })
        }

        fn received_lines(&self) -> Vec<String> {
            self.lines
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn wait_for_line(&self, expected: &str) -> Vec<String> {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let lines = self.received_lines();
                if lines.iter().any(|line| line == expected) || Instant::now() >= deadline {
                    return lines;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn join(self) {
            self.handle.join().expect("loopback IRC server thread");
        }
    }

    fn simulate_request(
        operation: &'static str,
        capability_token: CapabilityToken,
    ) -> SimulateRequest {
        SimulateRequest {
            r#type: "simulate".into(),
            id: RequestId::new("irc-simulate"),
            connector_id: ConnectorId::from_static("fcp.irc"),
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

    #[test]
    fn config_requires_server() {
        let error = serde_json::from_value::<IrcConfig>(json!({
            "server": "",
            "nick": "flywheel"
        }))
        .expect("config should deserialize")
        .validate()
        .expect_err("server must be required");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn port_defaults_follow_tls_setting() {
        let tls_config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "tls": true
        }))
        .expect("config should deserialize");
        let plain_config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "flywheel",
            "tls": false
        }))
        .expect("config should deserialize");
        assert_eq!(tls_config.port(), DEFAULT_PORT_TLS);
        assert_eq!(plain_config.port(), DEFAULT_PORT_PLAIN);
    }

    #[test]
    fn required_fields_reject_empty_strings() {
        let error = required_string(&json!({ "message": "" }), "message")
            .expect_err("empty message should be rejected");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn operations_count() {
        let ops = IrcConnector::operations();
        assert_eq!(ops.len(), 4);
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = IrcConnector::operations();
        let ids: Vec<&str> = ops.iter().map(|op| op.id.as_str()).collect();
        assert!(ids.contains(&OP_SEND_MESSAGE));
        assert!(ids.contains(&OP_JOIN_CHANNEL));
        assert!(ids.contains(&OP_SAMPLE_TRANSCRIPT));
        assert!(ids.contains(&OP_HEALTH));
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let h1 = IrcConnector::manifest_hash();
        let h2 = IrcConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn connector_id_is_fcp_irc() {
        let connector = IrcConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.irc");
    }

    #[test]
    fn default_connector_has_no_state() {
        let connector = IrcConnector::new();
        assert!(connector.state.is_none());
        assert!(connector.verifier.is_none());
    }

    #[test]
    fn doctor_unconfigured() {
        let connector = IrcConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
        assert!(!result.checks.is_empty());
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "configuration" && !c.passed)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_sets_state() {
        let mut connector = IrcConnector::new();
        connector
            .configure(json!({
                "server": "irc.libera.chat",
                "nick": "flywheel"
            }))
            .await
            .expect("configure should succeed");
        assert!(connector.state.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid() {
        let mut connector = IrcConnector::new();
        let result = connector.configure(json!({ "not_server": true })).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured() {
        let mut connector = IrcConnector::new();
        connector
            .configure(json!({
                "server": "irc.libera.chat",
                "nick": "flywheel"
            }))
            .await
            .unwrap();
        let result = connector.doctor();
        assert!(result.passed);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "configuration" && c.passed)
        );
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "server_configured" && c.passed)
        );
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "nick_configured" && c.passed)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_starting_when_unconfigured() {
        let connector = IrcConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Starting));
    }

    #[fcp_async_core::runtime::test]
    async fn health_degraded_when_handshake_pending() {
        let mut connector = IrcConnector::new();
        connector
            .configure(json!({
                "server": "irc.libera.chat",
                "nick": "flywheel"
            }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(
            health.status,
            HealthState::Degraded { ref reason } if reason == "handshake pending"
        ));
        let details = health.details.unwrap();
        assert_eq!(details["server"], "irc.libera.chat");
        assert_eq!(details["handshake_completed"], json!(false));
    }

    #[fcp_async_core::runtime::test]
    async fn health_ready_after_handshake() {
        let mut connector = IrcConnector::new();
        connector
            .configure(json!({
                "server": "irc.libera.chat",
                "nick": "flywheel"
            }))
            .await
            .unwrap();
        connector.handshake(handshake_request()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
        let details = health.details.unwrap();
        assert_eq!(details["handshake_completed"], json!(true));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_checks_capability_operation_grant() {
        let mut connector = IrcConnector::new();
        connector
            .configure(json!({
                "server": "irc.libera.chat",
                "nick": "flywheel"
            }))
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
            .simulate(simulate_request(
                OP_SEND_MESSAGE,
                capability_token(
                    &signing_key,
                    CAP_MESSAGES_READ,
                    OP_SEND_MESSAGE,
                    &connector.base.instance_id,
                ),
            ))
            .await
            .expect("simulate should return a policy result");

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-3003"));
        assert!(response.missing_capabilities.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_granted_includes_coordination_audit() {
        let server = IrcTestServer::spawn();
        let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
        let mut connector = IrcConnector::new()
            .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
        let signing_key = Ed25519SigningKey::generate();
        let authorization = configure_handshaken_connector(
            &mut connector,
            server.config(),
            &signing_key,
            CAP_MESSAGES_WRITE,
            OP_SEND_MESSAGE,
        )
        .await;

        let response = connector
            .invoke(invoke_request(
                OP_SEND_MESSAGE,
                json!({
                    "target": "#Ops",
                    "message": "hello from coordination"
                }),
                authorization,
            ))
            .await
            .expect("send should claim and execute");

        let result = response.result.expect("invoke should include result");
        assert_eq!(result["status"], "sent");
        assert_eq!(result["target"], "#Ops");
        let coordination = result["coordination"]
            .as_array()
            .expect("coordination audit records");
        assert_eq!(coordination[0]["event"], "claim_attempt");
        assert_eq!(coordination[1]["event"], "claim_outcome");
        assert_eq!(coordination[1]["outcome"], "granted");
        assert_eq!(coordination[2]["event"], "send_executed");

        let lines = server.wait_for_line("PRIVMSG #Ops :hello from coordination");
        assert!(
            lines
                .iter()
                .any(|line| line == "PRIVMSG #Ops :hello from coordination"),
            "loopback server should observe IRC PRIVMSG, got {lines:?}"
        );
        server.join();
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_denies_duplicate_owner_before_irc_session() {
        let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
        let claim_key = ClaimKey::for_chat_message(
            ZoneId::work(),
            ConnectorId::from_static("fcp.irc"),
            ChannelId::new("#ops"),
            None,
            DmMode::TreatAsThread,
        )
        .expect("IRC target should become a coordination thread");
        assert!(
            checker
                .claim_now(claim_key, AgentId::new("peer-agent"), Instant::now())
                .is_granted()
        );

        let mut connector = IrcConnector::new()
            .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
        let signing_key = Ed25519SigningKey::generate();
        let authorization = configure_handshaken_connector(
            &mut connector,
            json!({
                "server": "127.0.0.1",
                "port": 1,
                "nick": "testbot",
                "tls": false,
                "request_timeout_ms": 50
            }),
            &signing_key,
            CAP_MESSAGES_WRITE,
            OP_SEND_MESSAGE,
        )
        .await;

        let denied = connector
            .invoke(invoke_request(
                OP_SEND_MESSAGE,
                json!({
                    "target": "#Ops",
                    "message": "blocked duplicate"
                }),
                authorization,
            ))
            .await
            .expect_err("duplicate owner should be denied before TCP connect");

        assert!(matches!(denied, FcpError::Unauthorized { code: 4090, .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_state() {
        let mut connector = IrcConnector::new();
        connector
            .configure(json!({
                "server": "irc.libera.chat",
                "nick": "flywheel"
            }))
            .await
            .unwrap();
        let shutdown_req: ShutdownRequest = serde_json::from_value(json!({
            "type": "shutdown"
        }))
        .unwrap();
        connector.shutdown(shutdown_req).await.unwrap();
        assert!(connector.state.is_none());
        assert!(connector.verifier.is_none());
    }

    #[test]
    fn introspect_returns_four_operations() {
        let connector = IrcConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 4);
        assert!(intro.events.is_empty());
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn subscribe_returns_not_supported() {
        let connector = IrcConnector::new();
        let req: SubscribeRequest = serde_json::from_value(json!({
            "type": "subscribe",
            "id": "sub-1",
            "topics": ["test.topic"]
        }))
        .unwrap();
        let result = connector.subscribe(req).await;
        assert!(matches!(result, Err(FcpError::StreamingNotSupported)));
    }

    #[fcp_async_core::runtime::test]
    async fn unsubscribe_returns_not_supported() {
        let connector = IrcConnector::new();
        let req: UnsubscribeRequest = serde_json::from_value(json!({
            "type": "unsubscribe",
            "id": "unsub-1",
            "topics": ["test.topic"]
        }))
        .unwrap();
        let result = connector.unsubscribe(req).await;
        assert!(matches!(result, Err(FcpError::StreamingNotSupported)));
    }

    #[test]
    fn required_capability_maps_operations() {
        assert_eq!(
            required_capability(OP_SEND_MESSAGE).unwrap().as_str(),
            CAP_MESSAGES_WRITE
        );
        assert_eq!(
            required_capability(OP_JOIN_CHANNEL).unwrap().as_str(),
            CAP_CHANNELS_WRITE
        );
        assert_eq!(
            required_capability(OP_SAMPLE_TRANSCRIPT).unwrap().as_str(),
            CAP_MESSAGES_READ
        );
        assert_eq!(
            required_capability(OP_HEALTH).unwrap().as_str(),
            CAP_HEALTH_READ
        );
    }

    #[test]
    fn required_capability_rejects_unknown() {
        let result = required_capability("unknown.op");
        assert!(result.is_err());
    }

    #[test]
    fn granted_capabilities_filters_known() {
        let requested = vec![
            CapabilityId::from_static(CAP_MESSAGES_WRITE),
            CapabilityId::from_static("unknown.cap"),
            CapabilityId::from_static(CAP_HEALTH_READ),
        ];
        let grants = granted_capabilities(requested);
        assert_eq!(grants.len(), 2);
    }

    #[test]
    fn required_string_accepts_non_empty() {
        let val = json!({ "target": "#channel" });
        assert_eq!(required_string(&val, "target").unwrap(), "#channel");
    }

    #[test]
    fn required_string_rejects_missing() {
        let val = json!({});
        assert!(required_string(&val, "target").is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_not_configured() {
        let connector = IrcConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_ne!(report.status, SelfCheckStatus::Ok);
    }

    #[test]
    fn doctor_result_from_checks_all_pass() {
        let checks = vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: true,
        }];
        let result = DoctorResult::from_checks(checks);
        assert!(result.passed);
    }

    #[test]
    fn doctor_result_from_checks_critical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "test".into(),
                passed: false,
                message: Some("failed".into()),
                critical: true,
            },
            DoctorCheck {
                name: "optional".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert!(!result.passed);
    }

    #[test]
    fn doctor_result_from_checks_non_critical_fail_still_passes() {
        let checks = vec![
            DoctorCheck {
                name: "critical".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "optional".into(),
                passed: false,
                message: Some("non-critical failure".into()),
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert!(result.passed);
    }

    #[test]
    fn default_impl_creates_new() {
        let connector = IrcConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.irc");
    }

    #[test]
    fn metrics_initial() {
        let connector = IrcConnector::new();
        let metrics = connector.metrics();
        assert_eq!(metrics.requests_total, 0);
    }

    #[test]
    fn transcript_sample_schema_advertises_normalized_events() {
        let op = IrcConnector::operations()
            .into_iter()
            .find(|op| op.id.as_str() == OP_SAMPLE_TRANSCRIPT)
            .expect("sample op should exist");
        let required = op.output_schema["required"]
            .as_array()
            .expect("required should be an array");
        assert!(required.iter().any(|value| value == "events"));
        assert_eq!(
            op.output_schema["properties"]["identity"]["required"],
            json!(["nick", "username", "realname"])
        );
    }
}
