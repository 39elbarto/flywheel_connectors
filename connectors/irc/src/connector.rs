//! IRC connector.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_async_core::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    tls::TlsConnectorBuilder,
};
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport,
    SessionId, ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest,
    SubscribeResponse, UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const DEFAULT_PORT_TLS: u16 = 6697;
const DEFAULT_PORT_PLAIN: u16 = 6667;
const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_SAMPLE_LINES: usize = 20;

const OP_SEND_MESSAGE: &str = "irc.messages.send";
const OP_JOIN_CHANNEL: &str = "irc.channels.join";
const OP_SAMPLE_TRANSCRIPT: &str = "irc.transcript.sample";
const OP_HEALTH: &str = "irc.health";

const CAP_MESSAGES_WRITE: &str = "irc.messages.write";
const CAP_CHANNELS_WRITE: &str = "irc.channels.write";
const CAP_MESSAGES_READ: &str = "irc.messages.read";
const CAP_HEALTH_READ: &str = "irc.health.read";

#[derive(Debug, Clone, Deserialize)]
struct IrcConfig {
    server: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default = "default_true")]
    tls: bool,
    nick: String,
    #[serde(default = "default_username")]
    username: String,
    #[serde(default = "default_realname")]
    realname: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default = "default_timeout_ms")]
    request_timeout_ms: u64,
}

#[derive(Debug)]
struct IrcState {
    config: IrcConfig,
}

#[derive(Debug)]
pub struct IrcConnector {
    base: BaseConnector,
    state: Option<IrcState>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
}

const fn default_true() -> bool {
    true
}

fn default_username() -> String {
    "flywheel".into()
}

fn default_realname() -> String {
    "Flywheel Connector".into()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

impl IrcConfig {
    fn validate(&self) -> FcpResult<()> {
        if self.server.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "server must not be empty".into(),
            });
        }
        if self.nick.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "nick must not be empty".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        self.port
            .unwrap_or(if self.tls { DEFAULT_PORT_TLS } else { DEFAULT_PORT_PLAIN })
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }
}

impl IrcConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.irc")),
            state: None,
            verifier: None,
            started_at: Instant::now(),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

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
                "Use to collect a short bounded transcript without keeping a long-lived IRC session open.",
            ),
            operation(
                OP_HEALTH,
                "Verify IRC connectivity and registration",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use before joining or sending to make sure registration succeeds.",
            ),
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        verifier.verify(&req.capability_token, &capability, &req.operation, &[])?;

        let output = match req.operation.as_str() {
            OP_SEND_MESSAGE => {
                let target = required_string(&req.input, "target")?;
                let message = required_string(&req.input, "message")?;
                let transcript = with_irc_session(&state.config, |session| async move {
                    session.send_privmsg(target, message).await?;
                    session.quit().await?;
                    Ok::<_, FcpError>(Vec::<String>::new())
                })
                .await?;
                json!({
                    "status": "sent",
                    "target": target,
                    "transcript": transcript,
                })
            }
            OP_JOIN_CHANNEL => {
                let channel = required_string(&req.input, "channel")?;
                let channel_key = req.input.get("channel_key").and_then(Value::as_str);
                let transcript = with_irc_session(&state.config, |session| async move {
                    session.join(channel, channel_key).await?;
                    session.quit().await?;
                    Ok::<_, FcpError>(session.lines)
                })
                .await?;
                json!({
                    "status": "joined",
                    "channel": channel,
                    "transcript": transcript,
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
                let transcript = with_irc_session(&state.config, |session| async move {
                    session.join(channel, None).await?;
                    session.read_until(sample_lines).await?;
                    session.quit().await?;
                    Ok::<_, FcpError>(session.lines)
                })
                .await?;
                json!({
                    "channel": channel,
                    "lines": transcript,
                })
            }
            OP_HEALTH => {
                let transcript = with_irc_session(&state.config, |session| async move {
                    session.quit().await?;
                    Ok::<_, FcpError>(session.lines)
                })
                .await?;
                json!({
                    "status": "ok",
                    "server": state.config.server,
                    "port": state.config.port(),
                    "tls": state.config.tls,
                    "nick": state.config.nick,
                    "transcript": transcript,
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
}

impl Default for IrcConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FcpConnector for IrcConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let config: IrcConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid IRC configuration: {error}"),
            })?;
        config.validate()?;
        self.state = Some(IrcState { config });
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
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: req
                .capabilities_requested
                .into_iter()
                .map(|capability| CapabilityGrant {
                    capability,
                    operation: None,
                })
                .collect(),
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
        HealthSnapshot {
            status: if self.state.is_some() {
                HealthState::Ready
            } else {
                HealthState::Starting
            },
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: self.state.as_ref().map(|state| {
                json!({
                    "server": state.config.server,
                    "port": state.config.port(),
                    "tls": state.config.tls,
                    "nick": state.config.nick,
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
        match with_irc_session(&state.config, |session| async move {
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
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

struct IrcSession {
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
    timeout: Duration,
    lines: Vec<String>,
}

impl IrcSession {
    async fn send_line(&mut self, line: &str) -> FcpResult<()> {
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(io_error("irc write"))?;
        self.writer
            .write_all(b"\r\n")
            .await
            .map_err(io_error("irc write"))?;
        self.writer.flush().await.map_err(io_error("irc flush"))?;
        Ok(())
    }

    async fn read_line(&mut self) -> FcpResult<Option<String>> {
        let mut line = String::new();
        let bytes = fcp_async_core::time::timeout(self.timeout, self.reader.read_line(&mut line))
            .await
            .map_err(|_| FcpError::Timeout {
                operation: "irc read".into(),
                timeout_ms: self.timeout.as_millis().try_into().unwrap_or(u64::MAX),
            })?
            .map_err(io_error("irc read"))?;
        if bytes == 0 {
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if let Some(payload) = trimmed.strip_prefix("PING :") {
            self.send_line(&format!("PONG :{payload}")).await?;
        }
        self.lines.push(trimmed.clone());
        Ok(Some(trimmed))
    }

    async fn await_welcome(&mut self) -> FcpResult<()> {
        loop {
            let Some(line) = self.read_line().await? else {
                return Err(FcpError::Upstream {
                    service: "irc".into(),
                    message: "IRC server closed connection before welcome".into(),
                    retryable: true,
                });
            };
            if line.contains(" 001 ") {
                return Ok(());
            }
            if line.contains(" 433 ") {
                return Err(FcpError::Upstream {
                    service: "irc".into(),
                    message: "IRC nickname already in use".into(),
                    retryable: false,
                });
            }
        }
    }

    async fn join(&mut self, channel: &str, channel_key: Option<&str>) -> FcpResult<()> {
        let cmd = match channel_key {
            Some(channel_key) => format!("JOIN {channel} {channel_key}"),
            None => format!("JOIN {channel}"),
        };
        self.send_line(&cmd).await?;
        self.read_until(5).await?;
        Ok(())
    }

    async fn send_privmsg(&mut self, target: &str, message: &str) -> FcpResult<()> {
        self.send_line(&format!("PRIVMSG {target} :{message}")).await
    }

    async fn read_until(&mut self, sample_lines: usize) -> FcpResult<()> {
        while self.lines.len() < sample_lines {
            let Some(_) = self.read_line().await? else {
                break;
            };
        }
        Ok(())
    }

    async fn quit(&mut self) -> FcpResult<()> {
        self.send_line("QUIT :fcp").await
    }
}

async fn with_irc_session<F, Fut>(config: &IrcConfig, f: F) -> FcpResult<Vec<String>>
where
    F: FnOnce(IrcSession) -> Fut,
    Fut: std::future::Future<Output = FcpResult<Vec<String>>>,
{
    let address = format!("{}:{}", config.server, config.port());
    let tcp = fcp_async_core::time::timeout(config.timeout(), TcpStream::connect(&address))
        .await
        .map_err(|_| FcpError::Timeout {
            operation: "irc connect".into(),
            timeout_ms: config.timeout().as_millis().try_into().unwrap_or(u64::MAX),
        })?
        .map_err(io_error("irc connect"))?;
    let _ = tcp.set_nodelay(true);

    let (reader, writer): (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>) =
        if config.tls {
            let connector = TlsConnectorBuilder::new()
                .with_native_roots()
                .map_err(|error| FcpError::Internal {
                    message: format!("failed to initialize IRC TLS roots: {error}"),
                })?
                .build()
                .map_err(|error| FcpError::Internal {
                    message: format!("failed to build IRC TLS connector: {error}"),
                })?;
            let tls = fcp_async_core::time::timeout(config.timeout(), connector.connect(&config.server, tcp))
                .await
                .map_err(|_| FcpError::Timeout {
                    operation: "irc tls handshake".into(),
                    timeout_ms: config.timeout().as_millis().try_into().unwrap_or(u64::MAX),
                })?
                .map_err(|error| FcpError::Upstream {
                    service: "irc".into(),
                    message: format!("IRC TLS handshake failed: {error}"),
                    retryable: true,
                })?;
            let (read_half, write_half) = fcp_async_core::io::split(tls);
            (Box::new(read_half), Box::new(write_half))
        } else {
            let (read_half, write_half) = fcp_async_core::io::split(tcp);
            (Box::new(read_half), Box::new(write_half))
        };

    let mut session = IrcSession {
        writer,
        reader: BufReader::new(reader),
        timeout: config.timeout(),
        lines: Vec::new(),
    };

    if let Some(password) = config.password.as_deref() {
        session.send_line(&format!("PASS {password}")).await?;
    }
    session.send_line(&format!("NICK {}", config.nick)).await?;
    session
        .send_line(&format!("USER {} 0 * :{}", config.username, config.realname))
        .await?;
    session.await_welcome().await?;
    f(session).await
}

fn io_error(context: &'static str) -> impl Fn(std::io::Error) -> FcpError {
    move |error| FcpError::Upstream {
        service: "irc".into(),
        message: format!("{context} failed: {error}"),
        retryable: true,
    }
}

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
    Ok(CapabilityId::from(capability.to_string()))
}

fn required_string<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} is required"),
        })
}

fn operation(
    id: &str,
    summary: &str,
    capability: &str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: Value,
    when_to_use: &str,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from(id.to_string()),
        summary: summary.into(),
        description: Some(summary.into()),
        input_schema,
        output_schema: json!({ "type": "object" }),
        capability: CapabilityId::from(capability.to_string()),
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
            related: vec![CapabilityId::from(OP_HEALTH.to_string())],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
