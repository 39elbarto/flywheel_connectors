//! Tencent `QQ` bot connector.

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

use crate::client::{
    QqClient, channel_message_body, direct_message_body, normalize_message_event,
    sanitize_path_segment,
};
use crate::types::{
    CAP_EVENTS_READ, CAP_GATEWAY_READ, CAP_HEALTH_READ, CAP_MESSAGES_WRITE, OP_EVENTS_NORMALIZE,
    OP_GET_GATEWAY, OP_HEALTH, OP_SEND_C2C, OP_SEND_CHANNEL, OP_SEND_GROUP, QqConfig,
    QqGatewayEvent,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// ─────────────────────────────────────────────────────────────────
// Doctor types (V3 requirement)
// ─────────────────────────────────────────────────────────────────
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

#[derive(Debug)]
pub struct QqConnector {
    base: BaseConnector,
    client: Option<QqClient>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
}

impl QqConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.qq")),
            client: None,
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
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing - configure first".into()
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

        DoctorResult::from_checks(checks)
    }

    #[allow(clippy::too_many_lines)]
    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_SEND_CHANNEL,
                "Send a QQ channel message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["channel_id", "content"],
                    "properties": {
                        "channel_id": { "type": "string" },
                        "content": { "type": "string" },
                        "msg_id": { "type": "string" }
                    }
                }),
                "Use for QQ channel deliveries when you already know the target channel_id.",
            ),
            operation(
                OP_SEND_GROUP,
                "Send a QQ group message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["group_openid", "content"],
                    "properties": {
                        "group_openid": { "type": "string" },
                        "content": { "type": "string" },
                        "msg_id": { "type": "string" }
                    }
                }),
                "Use for QQ group deliveries to a known group_openid target.",
            ),
            operation(
                OP_SEND_C2C,
                "Send a QQ C2C message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["openid", "content"],
                    "properties": {
                        "openid": { "type": "string" },
                        "content": { "type": "string" },
                        "msg_id": { "type": "string" }
                    }
                }),
                "Use for one-to-one QQ bot messages directed at a specific openid.",
            ),
            operation(
                OP_GET_GATEWAY,
                "Get the QQ gateway websocket URL",
                CAP_GATEWAY_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use when a higher-level runtime needs the official QQ gateway URL for event intake.",
            ),
            operation(
                OP_HEALTH,
                "Verify QQ credentials and gateway discovery",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use before higher-risk send operations when you need a bounded auth and connectivity check.",
            ),
            operation(
                OP_EVENTS_NORMALIZE,
                "Normalize a raw QQ gateway event into a structured event with routing",
                CAP_EVENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["event"],
                    "properties": {
                        "event": {
                            "type": "object",
                            "description": "Raw QQ gateway event payload",
                            "required": ["op"],
                            "properties": {
                                "op": { "type": "integer" },
                                "s": { "type": "integer" },
                                "t": { "type": "string" },
                                "d": { "type": "object" },
                                "id": { "type": "string" }
                            }
                        }
                    }
                }),
                "Use to normalize raw QQ Bot WebSocket gateway events into structured events with routing classification (channel/group/c2c), quote context, and attachment detection.",
            ),
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        verifier.verify(req.capability_token, &capability, &req.operation, &[])?;

        let output = match req.operation.as_str() {
            OP_SEND_CHANNEL => {
                let channel_id = required_string(&req.input, "channel_id")?;
                let path = message_path("/channels/", channel_id, "channel_id")?;
                let content = required_string(&req.input, "content")?;
                let msg_id = optional_string(&req.input, "msg_id")?;
                client
                    .api_request(
                        reqwest::Method::POST,
                        &path,
                        Some(channel_message_body(content, msg_id)),
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_SEND_GROUP => {
                let group_openid = required_string(&req.input, "group_openid")?;
                let path = message_path("/v2/groups/", group_openid, "group_openid")?;
                let content = required_string(&req.input, "content")?;
                let msg_id = optional_string(&req.input, "msg_id")?;
                client
                    .api_request(
                        reqwest::Method::POST,
                        &path,
                        Some(direct_message_body(content, msg_id)),
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_SEND_C2C => {
                let openid = required_string(&req.input, "openid")?;
                let path = message_path("/v2/users/", openid, "openid")?;
                let content = required_string(&req.input, "content")?;
                let msg_id = optional_string(&req.input, "msg_id")?;
                client
                    .api_request(
                        reqwest::Method::POST,
                        &path,
                        Some(direct_message_body(content, msg_id)),
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_GET_GATEWAY => client
                .api_request(reqwest::Method::GET, "/gateway", None)
                .await
                .map_err(|e| e.to_fcp_error())?,
            OP_HEALTH => {
                let _token = client.access_token().await.map_err(|e| e.to_fcp_error())?;
                let gateway = client
                    .api_request(reqwest::Method::GET, "/gateway", None)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": "ok",
                    "base_url": client.config().base_url,
                    "gateway": gateway.get("url").cloned().unwrap_or(Value::Null),
                    "manifest_hash": Self::manifest_hash(),
                })
            }
            OP_EVENTS_NORMALIZE => {
                let event_value =
                    req.input
                        .get("event")
                        .ok_or_else(|| FcpError::InvalidRequest {
                            code: 1005,
                            message: "event is required".into(),
                        })?;
                let gateway_event: QqGatewayEvent = serde_json::from_value(event_value.clone())
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("invalid gateway event: {e}"),
                    })?;
                let normalized =
                    normalize_message_event(&gateway_event).map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&normalized).map_err(|e| FcpError::Internal {
                    message: format!("failed to serialize normalized event: {e}"),
                })?
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

impl Default for QqConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(QqConnector);

#[async_trait]
impl FcpConnector for QqConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let config: QqConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid QQ configuration: {error}"),
            })?;
        self.client = Some(QqClient::new(config).map_err(|e| e.to_fcp_error())?);
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
            status: if self.client.is_some() {
                HealthState::Ready
            } else {
                HealthState::Starting
            },
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: self.client.as_ref().map(|c| {
                json!({
                    "base_url": c.config().base_url,
                    "token_base_url": c.config().token_base_url,
                    "app_id": c.config().app_id,
                })
            }),
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = self.client.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before QQ self_check",
            ));
        };
        match client.access_token().await {
            Ok(_) => Ok(SelfCheckReport::ok()),
            Err(error) => {
                let fcp_err = error.to_fcp_error();
                Ok(SelfCheckReport::from_error(&fcp_err))
            }
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(client) = self.client.as_ref() {
            client.shutdown();
        }
        self.client = None;
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
        if self.client.is_none() {
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
        if let Err(error) = verifier.verify(req.capability_token, &capability, &req.operation, &[])
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

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_SEND_CHANNEL | OP_SEND_GROUP | OP_SEND_C2C => CAP_MESSAGES_WRITE,
        OP_GET_GATEWAY => CAP_GATEWAY_READ,
        OP_HEALTH => CAP_HEALTH_READ,
        OP_EVENTS_NORMALIZE => CAP_EVENTS_READ,
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
                CAP_MESSAGES_WRITE | CAP_GATEWAY_READ | CAP_HEALTH_READ | CAP_EVENTS_READ
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

fn optional_string<'a>(value: &'a Value, field: &str) -> FcpResult<Option<&'a str>> {
    match value.get(field) {
        None => Ok(None),
        Some(Value::String(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed))
            }
        }
        Some(_) => Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a string"),
        }),
    }
}

fn message_path(prefix: &str, target_id: &str, field: &str) -> FcpResult<String> {
    let safe_id = sanitize_path_segment(target_id, field).map_err(|e| e.to_fcp_error())?;
    Ok(format!("{prefix}{safe_id}/messages"))
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
                "QQ channel sends use channel_id, while group and C2C sends require group_openid or openid."
                    .into(),
            ],
            examples: Vec::new(),
            related: vec![CapabilityId::from_static(CAP_HEALTH_READ)],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_default_creates_instance() {
        let connector = QqConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.qq");
    }

    #[test]
    fn introspect_returns_six_operations() {
        let connector = QqConnector::new();
        let introspection = connector.introspect();
        assert_eq!(introspection.operations.len(), 6);
    }

    #[test]
    fn introspect_operation_ids() {
        let connector = QqConnector::new();
        let introspection = connector.introspect();
        let ids: Vec<&str> = introspection
            .operations
            .iter()
            .map(|op| op.id.as_str())
            .collect();
        assert!(ids.contains(&"qq.messages.send_channel"));
        assert!(ids.contains(&"qq.messages.send_group"));
        assert!(ids.contains(&"qq.messages.send_c2c"));
        assert!(ids.contains(&"qq.gateway.get"));
        assert!(ids.contains(&"qq.health"));
        assert!(ids.contains(&"qq.events.normalize"));
    }

    #[test]
    fn manifest_hash_is_stable() {
        let a = QqConnector::manifest_hash();
        let b = QqConnector::manifest_hash();
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn doctor_unconfigured_fails_critical() {
        let connector = QqConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
        assert_eq!(result.checks.len(), 3);
        // configuration is critical, should fail
        assert!(!result.checks[0].passed);
        assert!(result.checks[0].critical);
    }

    #[fcp_async_core::runtime::test]
    async fn health_starting_when_unconfigured() {
        let connector = QqConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Starting));
        assert!(health.details.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn health_ready_when_configured() {
        let mut connector = QqConnector::new();
        let config = serde_json::json!({
            "app_id": "test-app",
            "client_secret": "test-secret",
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999"
        });
        connector.configure(config).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
        assert!(health.details.is_some());
        let details = health.details.unwrap();
        assert_eq!(details["app_id"], "test-app");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_without_config_reports_failed() {
        let connector = QqConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_ne!(report.status, fcp_core::SelfCheckStatus::Ok);
    }

    #[fcp_async_core::runtime::test]
    async fn configure_validates_empty_app_id() {
        let mut connector = QqConnector::new();
        let config = serde_json::json!({
            "app_id": "",
            "client_secret": "test-secret",
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999"
        });
        let err = connector.configure(config).await;
        assert!(err.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_validates_bad_host() {
        let mut connector = QqConnector::new();
        let config = serde_json::json!({
            "app_id": "test-app",
            "client_secret": "test-secret",
            "base_url": "https://evil.example.com",
            "token_base_url": "http://localhost:9999"
        });
        let err = connector.configure(config).await;
        assert!(err.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_state() {
        let mut connector = QqConnector::new();
        let config = serde_json::json!({
            "app_id": "test-app",
            "client_secret": "test-secret",
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999"
        });
        connector.configure(config).await.unwrap();
        assert!(connector.client.is_some());

        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 5000,
                drain: false,
                reason: Some("test".into()),
            })
            .await
            .unwrap();
        assert!(connector.client.is_none());
        assert!(connector.verifier.is_none());
    }

    #[test]
    fn doctor_configured_passes_critical() {
        let mut connector = QqConnector::new();
        // Manually configure via direct field assignment to avoid async
        let config = QqConfig {
            base_url: "http://localhost:9999".into(),
            token_base_url: "http://localhost:9999".into(),
            app_id: "test-app".into(),
            client_secret: "test-secret".into(),
            request_timeout_ms: 30_000,
        };
        connector.client = Some(QqClient::new(config).unwrap());
        let result = connector.doctor();
        assert!(result.passed);
        // handshake check is non-critical, so overall passes
        assert!(!result.checks[2].passed);
        assert!(!result.checks[2].critical);
    }

    #[test]
    fn required_capability_known_ops() {
        assert!(required_capability(OP_SEND_CHANNEL).is_ok());
        assert!(required_capability(OP_SEND_GROUP).is_ok());
        assert!(required_capability(OP_SEND_C2C).is_ok());
        assert!(required_capability(OP_GET_GATEWAY).is_ok());
        assert!(required_capability(OP_HEALTH).is_ok());
        assert!(required_capability(OP_EVENTS_NORMALIZE).is_ok());
    }

    #[test]
    fn required_capability_unknown_op() {
        let err = required_capability("qq.unknown").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn granted_capabilities_filters_known() {
        let requested = vec![
            CapabilityId::from_static(CAP_MESSAGES_WRITE),
            CapabilityId::from_static(CAP_GATEWAY_READ),
            CapabilityId::from_static(CAP_EVENTS_READ),
            CapabilityId::from_static("qq.unknown.cap"),
        ];
        let granted = granted_capabilities(requested);
        assert_eq!(granted.len(), 3);
    }

    #[test]
    fn required_string_extracts_value() {
        let val = serde_json::json!({"key": "value"});
        assert_eq!(required_string(&val, "key").unwrap(), "value");
    }

    #[test]
    fn required_string_rejects_empty() {
        let val = serde_json::json!({"key": ""});
        assert!(required_string(&val, "key").is_err());
    }

    #[test]
    fn required_string_rejects_missing() {
        let val = serde_json::json!({});
        assert!(required_string(&val, "key").is_err());
    }

    #[test]
    fn required_string_rejects_whitespace_only() {
        let val = serde_json::json!({"key": "   "});
        assert!(required_string(&val, "key").is_err());
    }

    #[test]
    fn message_path_uses_validated_target_id() {
        assert_eq!(
            message_path("/channels/", "channel-42", "channel_id").unwrap(),
            "/channels/channel-42/messages"
        );
        assert_eq!(
            message_path("/v2/groups/", "group-42", "group_openid").unwrap(),
            "/v2/groups/group-42/messages"
        );
        assert_eq!(
            message_path("/v2/users/", "user-42", "openid").unwrap(),
            "/v2/users/user-42/messages"
        );
    }

    #[test]
    fn message_path_rejects_traversal_targets() {
        assert!(message_path("/channels/", "../admin", "channel_id").is_err());
        assert!(message_path("/v2/groups/", "group/other", "group_openid").is_err());
        assert!(message_path("/v2/users/", "user%2Fother", "openid").is_err());
    }

    #[test]
    fn optional_string_rejects_non_string_values() {
        let err = optional_string(&serde_json::json!({"msg_id": 7}), "msg_id").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        assert!(err.to_string().contains("msg_id must be a string"));
    }

    #[test]
    fn optional_string_trims_blank_values_to_none() {
        assert_eq!(
            optional_string(&serde_json::json!({"msg_id": "   "}), "msg_id").unwrap(),
            None
        );
        assert_eq!(
            optional_string(&serde_json::json!({"msg_id": " abc-123 "}), "msg_id").unwrap(),
            Some("abc-123")
        );
    }

    #[test]
    fn streaming_not_supported() {
        // The connector does not support streaming (subscribe/unsubscribe return StreamingNotSupported).
        // Verified via event_caps: streaming=false, replay=false.
        let connector = QqConnector::new();
        let intro = connector.introspect();
        let caps = intro.event_caps.unwrap();
        assert!(!caps.streaming);
        assert!(!caps.replay);
    }

    #[test]
    fn event_caps_disabled() {
        let connector = QqConnector::new();
        let intro = connector.introspect();
        let caps = intro.event_caps.unwrap();
        assert!(!caps.streaming);
        assert!(!caps.replay);
        assert!(!caps.requires_ack);
        assert_eq!(caps.min_buffer_events, 0);
    }

    #[test]
    fn operations_have_correct_capabilities() {
        let ops = QqConnector::operations();
        let send_ops: Vec<_> = ops
            .iter()
            .filter(|op| op.id.as_str().starts_with("qq.messages."))
            .collect();
        for op in &send_ops {
            assert_eq!(op.capability.as_str(), CAP_MESSAGES_WRITE);
            assert_eq!(op.safety_tier, SafetyTier::Risky);
            assert_eq!(op.risk_level, RiskLevel::Medium);
        }
        let gateway = ops
            .iter()
            .find(|op| op.id.as_str() == OP_GET_GATEWAY)
            .unwrap();
        assert_eq!(gateway.capability.as_str(), CAP_GATEWAY_READ);
        assert_eq!(gateway.safety_tier, SafetyTier::Safe);

        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.capability.as_str(), CAP_HEALTH_READ);
        assert_eq!(health.safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn operations_have_agent_hints() {
        let ops = QqConnector::operations();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
            assert!(!op.ai_hints.common_mistakes.is_empty());
        }
    }

    #[test]
    fn metrics_initial_state() {
        let connector = QqConnector::new();
        let metrics = connector.metrics();
        assert_eq!(metrics.requests_total, 0);
        assert_eq!(metrics.requests_error, 0);
    }

    #[test]
    fn events_normalize_operation_has_correct_properties() {
        let ops = QqConnector::operations();
        let normalize_op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_EVENTS_NORMALIZE)
            .expect("events.normalize operation should exist");
        assert_eq!(normalize_op.capability.as_str(), CAP_EVENTS_READ);
        assert_eq!(normalize_op.safety_tier, SafetyTier::Safe);
        assert_eq!(normalize_op.risk_level, RiskLevel::Low);
        assert_eq!(normalize_op.idempotency, IdempotencyClass::Strict);
        assert!(!normalize_op.ai_hints.when_to_use.is_empty());
    }

    #[test]
    fn events_normalize_capability_maps_correctly() {
        let cap = required_capability(OP_EVENTS_NORMALIZE).unwrap();
        assert_eq!(cap.as_str(), CAP_EVENTS_READ);
    }
}
