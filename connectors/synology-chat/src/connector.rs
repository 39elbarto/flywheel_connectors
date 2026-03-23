//! `Synology Chat` connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_sdk::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::{SynologyChatClient, SynologyChatMessageRequest, SynologyChatPayload};
use crate::types::{SynologyChatConfig, SynologyChatStateModel};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "synology_chat.read";
const CAP_WRITE: &str = "synology_chat.write";
const OP_SEND_MESSAGE: &str = "synology_chat.send_message";
const OP_SEND_PAYLOAD: &str = "synology_chat.send_payload";
const OP_HEALTH: &str = "synology_chat.health";

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: String,
    critical: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    passed: bool,
    checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    fn new(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().all(|check| !check.critical || check.passed);
        Self { passed, checks }
    }
}

#[derive(Debug)]
struct SynologyChatState {
    model: SynologyChatStateModel,
    client: SynologyChatClient,
    runtime: ConnectorRuntime,
}

#[derive(Debug)]
pub struct SynologyChatConnector {
    base: BaseConnector,
    state: Option<SynologyChatState>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl SynologyChatConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.synology-chat")),
            state: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = vec![DoctorCheck {
            name: "configured".into(),
            passed: self.state.is_some(),
            message: if self.state.is_some() {
                "Configuration loaded".into()
            } else {
                "Connector is not configured".into()
            },
            critical: true,
        }];

        if let Some(state) = &self.state {
            checks.push(DoctorCheck {
                name: "delivery_target".into(),
                passed: true,
                message: state.model.delivery_target.incoming_url_redacted.clone(),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "receive_path".into(),
                passed: true,
                message: "disabled".into(),
                critical: false,
            });
        }

        DoctorResult::new(checks)
    }

    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        vec![
            OperationInfo {
                id: OperationId::from_static(OP_SEND_MESSAGE),
                summary: "Send a Synology Chat message".into(),
                description: Some("Deliver a message through a Synology Chat incoming webhook.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["text"],
                    "properties": {
                        "text": { "type": "string" },
                        "user_id": { "type": "string" },
                        "user_ids": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "bot_name": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use this to deliver a message to a Synology Chat webhook target.".into(),
                    common_mistakes: vec![
                        "This connector delivers outbound webhook requests; it does not yet host the outgoing-webhook receive path.".into()
                    ],
                    examples: vec!["{\"text\":\"Hello from Flywheel\"}".into()],
                    related: vec![CapabilityId::from_static(OP_HEALTH)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEND_PAYLOAD),
                summary: "Send a raw Synology Chat webhook payload".into(),
                description: Some("Forward an arbitrary JSON object to a Synology Chat incoming webhook for advanced card or attachment use cases.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["payload"],
                    "properties": {
                        "payload": { "type": "object" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use this when the simple text operation is too limited and you need to pass a Synology Chat webhook payload through directly.".into(),
                    common_mistakes: vec![
                        "payload must be a JSON object that the Synology Chat webhook endpoint understands.".into()
                    ],
                    examples: vec!["{\"payload\":{\"text\":\"Hello\",\"attachments\":[{\"text\":\"Details\"}]}}".into()],
                    related: vec![CapabilityId::from_static(OP_SEND_MESSAGE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_HEALTH),
                summary: "Report connector health".into(),
                description: Some("Return configured webhook target details.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this before attempting outbound delivery.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_SEND_MESSAGE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let required_cap = match req.operation.as_str() {
            OP_SEND_MESSAGE | OP_SEND_PAYLOAD => CapabilityId::from_static(CAP_WRITE),
            OP_HEALTH => CapabilityId::from_static(CAP_READ),
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let output = match req.operation.as_str() {
            OP_SEND_MESSAGE => {
                let text = req
                    .input
                    .get("text")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing text".into(),
                    })?;
                let user_ids = optional_user_ids(&req.input)?;
                let bot_name = req.input.get("bot_name").and_then(|value| value.as_str());
                let request = SynologyChatMessageRequest::new(text, &user_ids, bot_name)
                    .map_err(|error| error.to_fcp_error())?;
                state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?
                    .into_json()
            }
            OP_SEND_PAYLOAD => {
                let payload = req
                    .input
                    .get("payload")
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing payload".into(),
                    })?;
                let payload = SynologyChatPayload::from_value(payload)
                    .map_err(|error| error.to_fcp_error())?;
                state
                    .client
                    .send_payload(&payload)
                    .await
                    .map_err(|error| error.to_fcp_error())?
                    .into_json()
            }
            OP_HEALTH => json!({
                "status": "ok",
                "delivery_target": &state.model.delivery_target,
                "request_timeout_ms": state.model.request_timeout_ms,
                "allow_insecure_ssl": state.model.allow_insecure_ssl,
                "outgoing_token_configured": state.model.outgoing_token_configured,
                "receive_path": &state.model.receive_path,
                "reply_semantics": &state.model.reply_semantics,
                "manifest_hash": Self::manifest_hash(),
            }),
            _ => unreachable!(),
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for SynologyChatConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn optional_user_ids(input: &serde_json::Value) -> FcpResult<Vec<String>> {
    if let Some(user_ids) = input.get("user_ids") {
        let values = user_ids
            .as_array()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "user_ids must be an array of strings".into(),
            })?;
        let mut result = Vec::with_capacity(values.len());
        for value in values {
            let user_id = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "user_ids must contain only strings".into(),
            })?;
            if user_id.trim().is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "user_ids must not contain empty strings".into(),
                });
            }
            let trimmed = user_id.trim();
            if !result.iter().any(|existing| existing == trimmed) {
                result.push(trimmed.to_string());
            }
        }
        return Ok(result);
    }

    Ok(input
        .get("user_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| vec![value.to_string()])
        .unwrap_or_default())
}

#[async_trait]
impl FcpConnector for SynologyChatConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = SynologyChatConfig::from_value(config)?;
        let model = config.state_model();
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms())),
        );
        let client =
            SynologyChatClient::from_config(&config).map_err(|error| error.to_fcp_error())?;
        self.state = Some(SynologyChatState {
            model,
            client,
            runtime,
        });
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
        let mut snapshot = if self.state.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.state.is_some(),
            "delivery_target": self.state.as_ref().map(|state| &state.model.delivery_target),
            "request_timeout_ms": self.state.as_ref().map(|state| state.model.request_timeout_ms),
            "allow_insecure_ssl": self.state.as_ref().map(|state| state.model.allow_insecure_ssl),
            "outgoing_token_configured": self.state.as_ref().map(|state| state.model.outgoing_token_configured),
            "receive_path": self.state.as_ref().map(|state| &state.model.receive_path),
            "reply_semantics": self.state.as_ref().map(|state| &state.model.reply_semantics),
            "manifest_hash": Self::manifest_hash(),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(state) = &self.state else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };
        let report = SelfCheckReport::ok();
        Ok(SelfCheckReport {
            details: Some(json!({
                "delivery_target": &state.model.delivery_target,
                "request_timeout_ms": state.model.request_timeout_ms,
                "allow_insecure_ssl": state.model.allow_insecure_ssl,
                "outgoing_token_configured": state.model.outgoing_token_configured,
                "receive_path": &state.model.receive_path,
                "reply_semantics": &state.model.reply_semantics,
            })),
            ..report
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(state) = &self.state {
            state.runtime.shutdown();
        }
        self.state = None;
        self.verifier = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations_info(),
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

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| matches!(capability.as_str(), CAP_READ | CAP_WRITE))
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_SEND_MESSAGE | OP_SEND_PAYLOAD => Ok(CapabilityId::from_static(CAP_WRITE)),
        OP_HEALTH => Ok(CapabilityId::from_static(CAP_READ)),
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("Unknown operation: {operation}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_core::{CapabilityToken, RequestId, ZoneId};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};

    use super::*;

    fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [4u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken { raw }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_returns_configured_surface() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi"
            }))
            .await
            .expect("configure should succeed");
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");
        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("synology-health"),
                connector_id: ConnectorId::from_static("fcp.synology-chat"),
                operation: OperationId::from_static(OP_HEALTH),
                zone_id: ZoneId::work(),
                input: json!({}),
                capability_token: capability_token(&signing_key, CAP_READ, OP_HEALTH),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("health should succeed");
        let result = response.result.expect("result");
        assert_eq!(result["status"], "ok");
        assert_eq!(
            result["delivery_target"]["incoming_url_redacted"],
            "https://nas.example.com:443/webapi/..."
        );
        assert_eq!(result["reply_semantics"], "outbound_only");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_reports_state_model_details() {
        let mut connector = SynologyChatConnector::new();
        connector
            .configure(json!({
                "incoming_url": "https://nas.example.com/webapi/entry.cgi",
                "request_timeout_ms": 25_000,
                "allow_insecure_ssl": true,
                "outgoing_token": "top-secret"
            }))
            .await
            .expect("configure should succeed");

        let report = connector.self_check().await.expect("self_check should succeed");
        let details = report.details.expect("details should be present");
        assert_eq!(
            details["delivery_target"]["incoming_url_redacted"],
            "https://nas.example.com:443/webapi/..."
        );
        assert_eq!(details["request_timeout_ms"], 25_000);
        assert_eq!(details["allow_insecure_ssl"], true);
        assert_eq!(details["outgoing_token_configured"], true);
        assert_eq!(details["receive_path"], "disabled");
        assert_eq!(details["reply_semantics"], "outbound_only");
    }

    #[test]
    fn introspection_reports_expected_operations_and_event_caps() {
        let introspection = SynologyChatConnector::new().introspect();
        let operation_ids = introspection
            .operations
            .iter()
            .map(|operation| operation.id.as_str().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            operation_ids,
            vec![
                OP_SEND_MESSAGE.to_string(),
                OP_SEND_PAYLOAD.to_string(),
                OP_HEALTH.to_string()
            ]
        );

        let event_caps = introspection.event_caps.expect("event caps should be present");
        assert!(!event_caps.streaming);
        assert!(!event_caps.replay);
        assert_eq!(event_caps.min_buffer_events, 0);
        assert!(!event_caps.requires_ack);
    }

    #[test]
    fn optional_user_ids_prefers_array_over_single_id() {
        let user_ids = optional_user_ids(&json!({
            "user_id": "legacy",
            "user_ids": ["one", " two ", "one"]
        }))
        .expect("user IDs should parse");
        assert_eq!(user_ids, vec!["one".to_string(), "two".to_string()]);
    }
}
