//! `Sonos` connector implementation.

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
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_sdk::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::SonosClient;
use crate::types::SonosConfig;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "sonos.read";
const CAP_WRITE: &str = "sonos.write";
const OP_HEALTH: &str = "sonos.health";
const OP_GET_STATUS: &str = "sonos.get_status";
const OP_PLAY: &str = "sonos.play";
const OP_PAUSE: &str = "sonos.pause";
const OP_NEXT: &str = "sonos.next";
const OP_PREVIOUS: &str = "sonos.previous";
const OP_SET_VOLUME: &str = "sonos.set_volume";

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
struct SonosState {
    config: SonosConfig,
    client: SonosClient,
    runtime: ConnectorRuntime,
}

#[derive(Debug)]
pub struct SonosConnector {
    base: BaseConnector,
    state: Option<SonosState>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl SonosConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.sonos")),
            state: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    /// Return this connector instance identifier for bound capability tokens.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
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
                name: "device_url".into(),
                passed: true,
                message: state.config.normalized_device_url(),
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
                summary: "Report Sonos device health".into(),
                description: Some("Fetch speaker identity details.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this before playback control when you need to confirm the configured Sonos device endpoint is reachable and identifies as the expected speaker.".into(),
                    common_mistakes: vec![
                        "Treating a successful manifest load as proof that the local speaker is reachable; health performs the device-description probe.".into(),
                        "Running playback controls before checking the configured room or speaker identity, which can affect the wrong local device.".into(),
                    ],
                    examples: vec![
                        r#"{"device_url":"http://living-room-speaker.local:1400","expected":{"status":"ok","friendly_name":"Living Room"}}"#.into(),
                    ],
                    related: vec![CapabilityId::from_static(OP_GET_STATUS)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_GET_STATUS),
                summary: "Get Sonos transport and volume status".into(),
                description: Some("Fetch playback state and volume.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this when you need the current transport state and volume before deciding whether to play, pause, skip, or change loudness.".into(),
                    common_mistakes: vec![
                        "Assuming the speaker is already playing; inspect transport_state before sending pause or next.".into(),
                        "Using stale volume from a prior run; Sonos volume may have changed outside FCP.".into(),
                    ],
                    examples: vec![
                        r#"{"request":{},"expected":{"transport_state":"PLAYING","transport_status":"OK","volume":18}}"#.into(),
                    ],
                    related: vec![CapabilityId::from_static(OP_PLAY)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_PLAY),
                summary: "Play or resume playback".into(),
                description: Some("Send the Sonos Play action.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::BestEffort,
                ai_hints: AgentHint {
                    when_to_use: "Use this to resume playback on the configured Sonos device after confirming the target room and queue state.".into(),
                    common_mistakes: vec![
                        "Calling play on the wrong configured local endpoint; run health when speaker identity matters.".into(),
                        "Expecting play to choose media; this only resumes or starts the current Sonos queue.".into(),
                    ],
                    examples: vec![r#"{"request":{},"expected":{"status":"ok","action":"play"}}"#.into()],
                    related: vec![CapabilityId::from_static(OP_PAUSE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_PAUSE),
                summary: "Pause playback".into(),
                description: Some("Send the Sonos Pause action.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::BestEffort,
                ai_hints: AgentHint {
                    when_to_use: "Use this to pause the currently configured Sonos device after verifying playback is active or the user explicitly asked to stop audio.".into(),
                    common_mistakes: vec![
                        "Using pause as a mute operation; it stops transport rather than preserving playback with zero volume.".into(),
                        "Assuming pause is harmless in shared rooms; it interrupts all listeners on that speaker or group.".into(),
                    ],
                    examples: vec![r#"{"request":{},"expected":{"status":"ok","action":"pause"}}"#.into()],
                    related: vec![CapabilityId::from_static(OP_PLAY)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_NEXT),
                summary: "Skip to next track".into(),
                description: Some("Send the Sonos Next action.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::BestEffort,
                ai_hints: AgentHint {
                    when_to_use: "Use this when the user asks to skip forward in the active Sonos queue on the configured device.".into(),
                    common_mistakes: vec![
                        "Assuming every stream supports next; some live radio or external sources may reject queue navigation.".into(),
                        "Sending repeated skips without reading status, which can advance farther than the user intended.".into(),
                    ],
                    examples: vec![r#"{"request":{},"expected":{"status":"ok","action":"next"}}"#.into()],
                    related: vec![CapabilityId::from_static(OP_PREVIOUS)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_PREVIOUS),
                summary: "Go to previous track".into(),
                description: Some("Send the Sonos Previous action.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::BestEffort,
                ai_hints: AgentHint {
                    when_to_use: "Use this when the user asks to return to the previous item in the active Sonos queue.".into(),
                    common_mistakes: vec![
                        "Expecting previous to rewind within the current track; Sonos may restart or move to the previous queue item depending on source behavior.".into(),
                        "Calling previous on a live stream or single-item queue without handling provider rejection.".into(),
                    ],
                    examples: vec![r#"{"request":{},"expected":{"status":"ok","action":"previous"}}"#.into()],
                    related: vec![CapabilityId::from_static(OP_NEXT)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SET_VOLUME),
                summary: "Set Sonos volume".into(),
                description: Some("Set the Sonos master volume.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["volume"],
                    "properties": {
                        "volume": { "type": "integer" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::BestEffort,
                ai_hints: AgentHint {
                    when_to_use: "Use this to set an explicit 0-100 volume level on the configured Sonos device when the user gives a target loudness.".into(),
                    common_mistakes: vec![
                        "Passing a relative adjustment such as +5; this operation expects an absolute integer volume.".into(),
                        "Sending values outside 0-100; the connector rejects them before making the SOAP call.".into(),
                        "Changing volume without confirming the target speaker in shared spaces.".into(),
                    ],
                    examples: vec![r#"{"volume":18,"expected":{"status":"ok","volume":18}}"#.into()],
                    related: vec![CapabilityId::from_static(OP_GET_STATUS)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let required_cap = required_capability(req.operation.as_str())?;
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let output = match req.operation.as_str() {
            OP_HEALTH => json!({
                "status": "ok",
                "device_url": state.client.device_url(),
                "manifest_hash": Self::manifest_hash(),
            }),
            OP_GET_STATUS => state
                .client
                .get_status()
                .await
                .map_err(|error| error.to_fcp_error())?,
            OP_PLAY => state
                .client
                .play()
                .await
                .map_err(|error| error.to_fcp_error())?,
            OP_PAUSE => state
                .client
                .pause()
                .await
                .map_err(|error| error.to_fcp_error())?,
            OP_NEXT => state
                .client
                .next()
                .await
                .map_err(|error| error.to_fcp_error())?,
            OP_PREVIOUS => state
                .client
                .previous()
                .await
                .map_err(|error| error.to_fcp_error())?,
            OP_SET_VOLUME => {
                let volume = req
                    .input
                    .get("volume")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing or invalid volume".into(),
                    })?;
                if volume > 100 {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: "volume must be between 0 and 100".into(),
                    });
                }
                state
                    .client
                    .set_volume(volume)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for SonosConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(SonosConnector);

#[async_trait]
impl FcpConnector for SonosConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = SonosConfig::from_value(config)?;
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        );
        let client = SonosClient::from_config(&config).map_err(|error| error.to_fcp_error())?;
        self.state = Some(SonosState {
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
            "device_url": self.state.as_ref().map(|state| state.config.normalized_device_url()),
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
        let probe = state
            .client
            .health()
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(SelfCheckReport {
            details: Some(json!({
                "device_url": state.client.device_url(),
                "probe": probe,
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
        OP_HEALTH | OP_GET_STATUS => Ok(CapabilityId::from_static(CAP_READ)),
        OP_PLAY | OP_PAUSE | OP_NEXT | OP_PREVIOUS | OP_SET_VOLUME => {
            Ok(CapabilityId::from_static(CAP_WRITE))
        }
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

    fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [22u8; 32],
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
        instance_id: &str,
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
            .target_instance(instance_id)
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    fn simulate_request(
        operation: &'static str,
        capability_token: CapabilityToken,
    ) -> SimulateRequest {
        SimulateRequest {
            r#type: "simulate".into(),
            id: RequestId::new("sonos-simulate"),
            connector_id: ConnectorId::from_static("fcp.sonos"),
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
    fn operations_catalog_contains_transport_and_volume_entries() {
        let operations = SonosConnector::operations_info();
        assert_eq!(operations.len(), 7);
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_PLAY)
        );
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_SET_VOLUME)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_returns_configured_state() {
        let mut connector = SonosConnector::new();
        connector
            .configure(json!({
                "device_url": "http://speaker.local:1400"
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
                id: RequestId::new("sonos-health"),
                connector_id: ConnectorId::from_static("fcp.sonos"),
                operation: OperationId::from_static(OP_HEALTH),
                zone_id: ZoneId::work(),
                input: json!({}),
                capability_token: capability_token(
                    &signing_key,
                    CAP_READ,
                    OP_HEALTH,
                    connector.instance_id(),
                ),
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

    #[fcp_async_core::runtime::test]
    async fn simulate_checks_capability_operation_grant() {
        let mut connector = SonosConnector::new();
        connector
            .configure(json!({
                "device_url": "http://speaker.local:1400"
            }))
            .await
            .expect("configure should succeed");
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");

        let response = connector
            .simulate(simulate_request(
                OP_PLAY,
                capability_token(&signing_key, CAP_READ, OP_PLAY, connector.instance_id()),
            ))
            .await
            .expect("simulate should return a policy result");

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-3003"));
        assert!(response.missing_capabilities.is_empty());
    }
}
