//! `Hue` connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::{ConnectorErrorMapping, ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_sdk::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::HueClient;
use crate::types::{HueConfig, RecallSceneInput, SetLightStateInput};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "hue.read";
const CAP_WRITE: &str = "hue.write";
const OP_HEALTH: &str = "hue.health";
const OP_LIST_LIGHTS: &str = "hue.list_lights";
const OP_LIST_SCENES: &str = "hue.list_scenes";
const OP_SET_LIGHT_STATE: &str = "hue.set_light_state";
const OP_RECALL_SCENE: &str = "hue.recall_scene";

fn empty_input_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false
    })
}

fn hue_response_envelope_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": true,
        "properties": {
            "data": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": true
                }
            },
            "errors": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": true
                }
            },
            "body": { "type": "string" }
        }
    })
}

fn health_output_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": [
            "status",
            "bridge_url",
            "manifest_hash",
            "transport",
            "allow_insecure_ssl",
            "app_key_configured"
        ],
        "additionalProperties": false,
        "properties": {
            "status": { "type": "string", "enum": ["ok"] },
            "bridge_url": { "type": "string", "format": "uri" },
            "manifest_hash": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$"
            },
            "transport": { "type": "string", "enum": ["http-loopback", "https"] },
            "allow_insecure_ssl": { "type": "boolean" },
            "app_key_configured": { "type": "boolean" }
        }
    })
}

fn set_light_state_input_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["light_id", "on"],
        "additionalProperties": false,
        "properties": {
            "light_id": {
                "type": "string",
                "minLength": 1,
                "pattern": "\\S"
            },
            "on": { "type": "boolean" },
            "brightness": {
                "type": "number",
                "minimum": 0,
                "maximum": 100
            }
        }
    })
}

fn recall_scene_input_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["scene_id"],
        "additionalProperties": false,
        "properties": {
            "scene_id": {
                "type": "string",
                "minLength": 1,
                "pattern": "\\S"
            }
        }
    })
}

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
            checks.push(DoctorCheck {
                name: "app_key".into(),
                passed: !state.config.app_key.trim().is_empty(),
                message: "Application key configured".into(),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "transport".into(),
                passed: true,
                message: if state.config.uses_plain_http_for_local_testing() {
                    "HTTP (loopback/test only)".into()
                } else if state.config.allow_insecure_ssl {
                    "HTTPS (certificate validation disabled)".into()
                } else {
                    "HTTPS".into()
                },
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
                input_schema: empty_input_schema(),
                output_schema: health_output_schema(),
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
                input_schema: empty_input_schema(),
                output_schema: hue_response_envelope_schema(),
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
                input_schema: empty_input_schema(),
                output_schema: hue_response_envelope_schema(),
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
                input_schema: set_light_state_input_schema(),
                output_schema: hue_response_envelope_schema(),
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
                input_schema: recall_scene_input_schema(),
                output_schema: hue_response_envelope_schema(),
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
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let output = match req.operation.as_str() {
            OP_HEALTH => json!({
                "status": "ok",
                "bridge_url": state.client.bridge_url(),
                "manifest_hash": Self::manifest_hash(),
                "transport": if state.config.uses_plain_http_for_local_testing() {
                    "http-loopback"
                } else {
                    "https"
                },
                "allow_insecure_ssl": state.config.allow_insecure_ssl,
                "app_key_configured": true,
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
                let input = SetLightStateInput::from_value(req.input.clone())?;
                state
                    .client
                    .set_light_state(&input)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_RECALL_SCENE => {
                let input = RecallSceneInput::from_value(req.input.clone())?;
                state
                    .client
                    .recall_scene(&input)
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

fcp_core::impl_fcp_sealed!(HueConnector);

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
            "transport": self.state.as_ref().map(|state| {
                if state.config.uses_plain_http_for_local_testing() {
                    "http-loopback"
                } else {
                    "https"
                }
            }),
            "allow_insecure_ssl": self.state.as_ref().map(|state| state.config.allow_insecure_ssl),
            "app_key_configured": self.state.as_ref().map(|state| !state.config.app_key.trim().is_empty()),
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
                "transport": if state.config.uses_plain_http_for_local_testing() {
                    "http-loopback"
                } else {
                    "https"
                },
                "allow_insecure_ssl": state.config.allow_insecure_ssl,
                "app_key_configured": true,
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
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, RequestId, ZoneId};

    use super::*;

    const EXPECTED_MANIFEST_SCHEMA_OPS: [(&str, &str); 5] = [
        (OP_HEALTH, "health"),
        (OP_LIST_LIGHTS, "list_lights"),
        (OP_LIST_SCENES, "list_scenes"),
        (OP_SET_LIGHT_STATE, "set_light_state"),
        (OP_RECALL_SCENE, "recall_scene"),
    ];

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
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    fn hue_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML)
            .map_err(|err| format!("Hue manifest TOML should parse: {err}"))
    }

    fn manifest_operations(
        manifest: &toml::Value,
    ) -> Result<&toml::map::Map<String, toml::Value>, String> {
        manifest
            .get("provides")
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| "manifest should declare operation tables".to_owned())
    }

    fn operation_schema(
        manifest: &toml::Value,
        operation_key: &str,
        field: &str,
    ) -> Result<serde_json::Value, String> {
        let schema = manifest_operations(manifest)?
            .get(operation_key)
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get(field))
            .ok_or_else(|| format!("{operation_key} should declare {field}"))?;
        if schema.as_table().is_none_or(toml::map::Map::is_empty) {
            return Err(format!(
                "{operation_key}.{field} should be a non-empty schema table"
            ));
        }
        serde_json::to_value(schema)
            .map_err(|err| format!("{operation_key}.{field} should convert to JSON: {err}"))
    }

    fn validator_for(schema: &serde_json::Value) -> Result<jsonschema::Validator, String> {
        jsonschema::Validator::new(schema)
            .map_err(|err| format!("manifest operation schema should compile: {err}"))
    }

    fn assert_schema_accepts(
        schema: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let validator = validator_for(schema)?;
        let errors = validator
            .iter_errors(payload)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "schema should accept {payload}; errors: {errors:?}"
            ))
        }
    }

    fn assert_schema_rejects(
        schema: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let validator = validator_for(schema)?;
        if validator.iter_errors(payload).next().is_some() {
            Ok(())
        } else {
            Err(format!("schema should reject {payload}"))
        }
    }

    #[test]
    fn operations_catalog_contains_expected_entries() {
        let operations = HueConnector::operations_info();
        assert_eq!(operations.len(), 5);
        let set_light_state = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_SET_LIGHT_STATE)
            .expect("set_light_state op should exist");
        assert_eq!(set_light_state.capability.as_str(), CAP_WRITE);
        assert_eq!(set_light_state.risk_level, RiskLevel::Medium);
        assert_eq!(set_light_state.safety_tier, SafetyTier::Risky);
        assert_eq!(set_light_state.idempotency, IdempotencyClass::BestEffort);

        let recall_scene = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_RECALL_SCENE)
            .expect("recall_scene op should exist");
        assert_eq!(recall_scene.capability.as_str(), CAP_WRITE);
        assert_eq!(recall_scene.risk_level, RiskLevel::Medium);
        assert_eq!(recall_scene.safety_tier, SafetyTier::Risky);
        assert_eq!(recall_scene.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        let manifest = hue_manifest()?;
        let operations = manifest_operations(&manifest)?;
        let operation_catalog = HueConnector::operations_info();

        for (operation_id, manifest_key) in EXPECTED_MANIFEST_SCHEMA_OPS {
            assert!(
                operations.contains_key(manifest_key),
                "manifest should declare operation {manifest_key}"
            );
            let operation = operation_catalog
                .iter()
                .find(|operation| operation.id.as_str() == operation_id)
                .ok_or_else(|| format!("operation catalog should declare {operation_id}"))?;
            for field in ["input_schema", "output_schema"] {
                let schema = operation_schema(&manifest, manifest_key, field)?;
                let _validator = validator_for(&schema)?;
            }
            assert_eq!(
                operation.input_schema,
                operation_schema(&manifest, manifest_key, "input_schema")?,
                "{operation_id} input schema should match manifest"
            );
            assert_eq!(
                operation.output_schema,
                operation_schema(&manifest, manifest_key, "output_schema")?,
                "{operation_id} output schema should match manifest"
            );
        }

        for operation in operation_catalog {
            let _input_validator = validator_for(&operation.input_schema)?;
            let _output_validator = validator_for(&operation.output_schema)?;
        }

        let health_input = operation_schema(&manifest, "health", "input_schema")?;
        assert_schema_accepts(&health_input, &json!({}))?;
        assert_schema_rejects(&health_input, &json!({"probe": true}))?;

        let health_output = operation_schema(&manifest, "health", "output_schema")?;
        assert_schema_accepts(
            &health_output,
            &json!({
                "status": "ok",
                "bridge_url": "http://127.0.0.1:18080",
                "manifest_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "transport": "http-loopback",
                "allow_insecure_ssl": false,
                "app_key_configured": true
            }),
        )?;
        assert_schema_rejects(
            &health_output,
            &json!({
                "status": "ok",
                "bridge_url": "http://127.0.0.1:18080",
                "manifest_hash": "sha256:short",
                "transport": "http-loopback",
                "allow_insecure_ssl": false,
                "app_key_configured": true
            }),
        )?;
        assert_schema_rejects(
            &health_output,
            &json!({
                "status": "ok",
                "bridge_url": "http://127.0.0.1:18080",
                "manifest_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "transport": "http-loopback",
                "allow_insecure_ssl": false,
                "app_key_configured": true,
                "extra": true
            }),
        )?;

        for operation_key in ["list_lights", "list_scenes"] {
            let input = operation_schema(&manifest, operation_key, "input_schema")?;
            assert_schema_accepts(&input, &json!({}))?;
            assert_schema_rejects(&input, &json!({"light_id": "light-1"}))?;
        }

        let set_input = operation_schema(&manifest, "set_light_state", "input_schema")?;
        assert_schema_accepts(
            &set_input,
            &json!({"light_id": "light-1", "on": true, "brightness": 50.0}),
        )?;
        assert_schema_accepts(&set_input, &json!({"light_id": "light-1", "on": false}))?;
        assert_schema_rejects(&set_input, &json!({"light_id": "light-1"}))?;
        assert_schema_rejects(&set_input, &json!({"light_id": "   ", "on": true}))?;
        assert_schema_rejects(
            &set_input,
            &json!({"light_id": "light-1", "on": true, "brightness": 101.0}),
        )?;
        assert_schema_rejects(
            &set_input,
            &json!({"light_id": "light-1", "on": true, "extra": true}),
        )?;

        let recall_input = operation_schema(&manifest, "recall_scene", "input_schema")?;
        assert_schema_accepts(&recall_input, &json!({"scene_id": "scene-1"}))?;
        assert_schema_rejects(&recall_input, &json!({}))?;
        assert_schema_rejects(&recall_input, &json!({"scene_id": "   "}))?;
        assert_schema_rejects(
            &recall_input,
            &json!({"scene_id": "scene-1", "extra": true}),
        )?;

        for operation_key in [
            "list_lights",
            "list_scenes",
            "set_light_state",
            "recall_scene",
        ] {
            let output = operation_schema(&manifest, operation_key, "output_schema")?;
            assert_schema_accepts(&output, &json!({"data": [{"id": "light-1"}]}))?;
            assert_schema_accepts(
                &output,
                &json!({"errors": [{"description": "unauthorized user"}]}),
            )?;
            assert_schema_accepts(&output, &json!({"body": "raw non-json response"}))?;
            assert_schema_rejects(&output, &json!([{"id": "light-1"}]))?;
        }

        Ok(())
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
