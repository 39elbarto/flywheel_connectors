//! `IRC` connector -- `FcpConnector` implementation.

use std::time::Instant;

use async_trait::async_trait;
use fcp_core::{
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

use crate::client::with_irc_session;
use crate::types::{
    CAP_CHANNELS_WRITE, CAP_HEALTH_READ, CAP_MESSAGES_READ, CAP_MESSAGES_WRITE,
    DEFAULT_SAMPLE_LINES, IrcConfig, OP_HEALTH, OP_JOIN_CHANNEL, OP_SAMPLE_TRANSCRIPT,
    OP_SEND_MESSAGE,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

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

#[derive(Debug)]
pub struct IrcConnector {
    base: BaseConnector,
    state: Option<IrcState>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
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
                let transcript = with_irc_session(&state.config, |mut session| async move {
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
                let transcript = with_irc_session(&state.config, |mut session| async move {
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
                let transcript = with_irc_session(&state.config, |mut session| async move {
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
                let transcript = with_irc_session(&state.config, |mut session| async move {
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
        self.base.set_handshaken(false);
        self.verifier = None;
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
        if let Err(error) = verifier.verify(&req.capability_token, &capability, &req.operation, &[])
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
    when_to_use: &str,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(summary.into()),
        input_schema,
        output_schema: json!({ "type": "object" }),
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
            related: vec![CapabilityId::from_static(OP_HEALTH)],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DEFAULT_PORT_PLAIN, DEFAULT_PORT_TLS};
    use fcp_core::SelfCheckStatus;

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
    async fn health_ready_when_configured() {
        let mut connector = IrcConnector::new();
        connector
            .configure(json!({
                "server": "irc.libera.chat",
                "nick": "flywheel"
            }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
        let details = health.details.unwrap();
        assert_eq!(details["server"], "irc.libera.chat");
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
}
