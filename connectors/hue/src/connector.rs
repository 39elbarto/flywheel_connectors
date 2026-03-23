//! `Hue` connector implementation.

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

use crate::client::HueClient;
use crate::types::HueConfig;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "hue.read";
const CAP_WRITE: &str = "hue.write";
const OP_HEALTH: &str = "hue.health";
const OP_LIST_LIGHTS: &str = "hue.list_lights";
const OP_LIST_SCENES: &str = "hue.list_scenes";
const OP_SET_LIGHT_STATE: &str = "hue.set_light_state";
const OP_RECALL_SCENE: &str = "hue.recall_scene";

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
struct HueState {
    config: HueConfig,
    client: HueClient,
    runtime: ConnectorRuntime,
}

#[derive(Debug)]
pub struct HueConnector {
    base: BaseConnector,
    state: Option<HueState>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl HueConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.hue")),
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
                name: "bridge_url".into(),
                passed: true,
                message: state.config.normalized_bridge_url(),
                critical: false,
            });
        }
        DoctorResult::new(checks)
    }

    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        vec![
            OperationInfo {
                id: OperationId::from_static(OP_HEALTH),
                summary: "Report Hue bridge health".into(),
                description: Some("Probe the bridge health surface.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this before issuing bridge inventory or control requests."
                        .into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_LIGHTS)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_LIST_LIGHTS),
                summary: "List Hue lights".into(),
                description: Some("Return the bridge light inventory.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this to inspect available light resources.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_SET_LIGHT_STATE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_LIST_SCENES),
                summary: "List Hue scenes".into(),
                description: Some("Return bridge scene inventory.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this to inspect scene resources before recall.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_RECALL_SCENE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SET_LIGHT_STATE),
                summary: "Set Hue light state".into(),
                description: Some("Set a Hue light on/off and optional brightness.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["light_id", "on"],
                    "properties": {
                        "light_id": { "type": "string" },
                        "on": { "type": "boolean" },
                        "brightness": { "type": "number" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::BestEffort,
                ai_hints: AgentHint {
                    when_to_use: "Use this to toggle a specific light or set brightness.".into(),
                    common_mistakes: vec![
                        "Brightness should be in the Hue API's 0-100 percentage range.".into(),
                    ],
                    examples: vec![
                        "{\"light_id\":\"light-1\",\"on\":true,\"brightness\":50.0}".into(),
                    ],
                    related: vec![CapabilityId::from_static(OP_LIST_LIGHTS)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_RECALL_SCENE),
                summary: "Recall a Hue scene".into(),
                description: Some("Tell the bridge to activate a scene.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["scene_id"],
                    "properties": {
                        "scene_id": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::BestEffort,
                ai_hints: AgentHint {
                    when_to_use: "Use this to activate a preconfigured Hue scene.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{\"scene_id\":\"scene-1\"}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_SCENES)],
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
            OP_HEALTH | OP_LIST_LIGHTS | OP_LIST_SCENES => CapabilityId::from_static(CAP_READ),
            OP_SET_LIGHT_STATE | OP_RECALL_SCENE => CapabilityId::from_static(CAP_WRITE),
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
            OP_HEALTH => json!({
                "status": "ok",
                "bridge_url": state.client.bridge_url(),
                "manifest_hash": Self::manifest_hash(),
            }),
            OP_LIST_LIGHTS => state
                .client
                .list_lights()
                .await
                .map_err(|error| error.to_fcp_error())?,
            OP_LIST_SCENES => state
                .client
                .list_scenes()
                .await
                .map_err(|error| error.to_fcp_error())?,
            OP_SET_LIGHT_STATE => {
                let light_id = req
                    .input
                    .get("light_id")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing light_id".into(),
                    })?;
                let on = req
                    .input
                    .get("on")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing on".into(),
                    })?;
                let brightness = req
                    .input
                    .get("brightness")
                    .and_then(serde_json::Value::as_f64);
                state
                    .client
                    .set_light_state(light_id, on, brightness)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_RECALL_SCENE => {
                let scene_id = req
                    .input
                    .get("scene_id")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing scene_id".into(),
                    })?;
                state
                    .client
                    .recall_scene(scene_id)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            _ => unreachable!(),
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for HueConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FcpConnector for HueConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = HueConfig::from_value(config)?;
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        );
        let client = HueClient::from_config(&config).map_err(|error| error.to_fcp_error())?;
        self.state = Some(HueState {
            config,
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
            "bridge_url": self.state.as_ref().map(|state| state.config.normalized_bridge_url()),
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
        let report = state
            .client
            .health()
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(SelfCheckReport {
            details: Some(json!({
                "bridge_url": state.client.bridge_url(),
                "bridge_health": report,
            })),
            ..SelfCheckReport::ok()
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
        OP_HEALTH | OP_LIST_LIGHTS | OP_LIST_SCENES => Ok(CapabilityId::from_static(CAP_READ)),
        OP_SET_LIGHT_STATE | OP_RECALL_SCENE => Ok(CapabilityId::from_static(CAP_WRITE)),
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
            nonce: [12u8; 32],
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

    #[test]
    fn operations_catalog_contains_expected_entries() {
        let operations = HueConnector::operations_info();
        assert_eq!(operations.len(), 5);
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_SET_LIGHT_STATE)
        );
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_RECALL_SCENE)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_returns_configured_state() {
        let mut connector = HueConnector::new();
        connector
            .configure(json!({
                "bridge_url": "https://bridge.local",
                "app_key": "app-key"
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
                id: RequestId::new("hue-health"),
                connector_id: ConnectorId::from_static("fcp.hue"),
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
        assert!(response.result.is_some());
    }
}
