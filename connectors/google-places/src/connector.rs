//! `Google Places` connector implementation.

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

use crate::client::GooglePlacesClient;
use crate::types::GooglePlacesConfig;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "google_places.read";
const OP_SEARCH_TEXT: &str = "google_places.search_text";
const OP_AUTOCOMPLETE: &str = "google_places.autocomplete";
const OP_GET_PLACE: &str = "google_places.get_place";
const OP_HEALTH: &str = "google_places.health";

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
struct GooglePlacesState {
    config: GooglePlacesConfig,
    client: GooglePlacesClient,
    runtime: ConnectorRuntime,
}

#[derive(Debug)]
pub struct GooglePlacesConnector {
    base: BaseConnector,
    state: Option<GooglePlacesState>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl GooglePlacesConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.google-places")),
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
                name: "base_url".into(),
                passed: true,
                message: format!("Base URL: {}", state.config.normalized_base_url()),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "api_key".into(),
                passed: !state.config.api_key.trim().is_empty(),
                message: "API key present".into(),
                critical: true,
            });
        }

        DoctorResult::new(checks)
    }

    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        vec![
            OperationInfo {
                id: OperationId::from_static(OP_SEARCH_TEXT),
                summary: "Search places by text query".into(),
                description: Some("Call Google Places text search.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": { "type": "string" },
                        "max_result_count": { "type": "integer" },
                        "open_now": { "type": "boolean" },
                        "field_mask": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this for ranked free-form place search.".into(),
                    common_mistakes: vec![
                        "Use Google Places resource names like places/abc123 for get_place, not raw map URLs.".into(),
                    ],
                    examples: vec![
                        "{\"query\":\"coffee near Bryant Park\",\"max_result_count\":5}".into(),
                    ],
                    related: vec![CapabilityId::from_static(OP_GET_PLACE)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_AUTOCOMPLETE),
                summary: "Autocomplete place predictions".into(),
                description: Some("Call Google Places autocomplete.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["input"],
                    "properties": {
                        "input": { "type": "string" },
                        "session_token": { "type": "string" },
                        "field_mask": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this while narrowing down an in-progress place search.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{\"input\":\"sushi soho london\"}".into()],
                    related: vec![CapabilityId::from_static(OP_SEARCH_TEXT)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_GET_PLACE),
                summary: "Get one place resource".into(),
                description: Some("Fetch structured details for a place resource name.".into()),
                input_schema: json!({
                    "type": "object",
                    "required": ["place"],
                    "properties": {
                        "place": { "type": "string" },
                        "language_code": { "type": "string" },
                        "field_mask": { "type": "string" }
                    }
                }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this after selecting a specific place resource.".into(),
                    common_mistakes: vec!["Pass a resource name like places/abc123.".into()],
                    examples: vec![
                        "{\"place\":\"places/ChIJN1t_tDeuEmsRUsoyG83frY4\"}".into(),
                    ],
                    related: vec![CapabilityId::from_static(OP_SEARCH_TEXT)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_HEALTH),
                summary: "Report connector health details".into(),
                description: Some("Return connector configuration and upstream target details.".into()),
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this before operational place queries.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_SEARCH_TEXT)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let required_cap = CapabilityId::from_static(CAP_READ);
        verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;

        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let output = match req.operation.as_str() {
            OP_SEARCH_TEXT => {
                let query = req
                    .input
                    .get("query")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing query".into(),
                    })?;
                let max_result_count = req
                    .input
                    .get("max_result_count")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok());
                let open_now = req
                    .input
                    .get("open_now")
                    .and_then(serde_json::Value::as_bool);
                let field_mask = req.input.get("field_mask").and_then(|value| value.as_str());
                state
                    .client
                    .search_text(query, max_result_count, open_now, field_mask)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_AUTOCOMPLETE => {
                let input = req
                    .input
                    .get("input")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing input".into(),
                    })?;
                let session_token = req
                    .input
                    .get("session_token")
                    .and_then(|value| value.as_str());
                let field_mask = req.input.get("field_mask").and_then(|value| value.as_str());
                state
                    .client
                    .autocomplete(input, session_token, field_mask)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_GET_PLACE => {
                let place = req
                    .input
                    .get("place")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing place".into(),
                    })?;
                let language_code = req
                    .input
                    .get("language_code")
                    .and_then(|value| value.as_str());
                let field_mask = req.input.get("field_mask").and_then(|value| value.as_str());
                state
                    .client
                    .get_place(place, language_code, field_mask)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_HEALTH => json!({
                "status": "ok",
                "base_url": state.client.base_url(),
                "manifest_hash": Self::manifest_hash(),
            }),
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

impl Default for GooglePlacesConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FcpConnector for GooglePlacesConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = GooglePlacesConfig::from_value(config)?;
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        );
        let client =
            GooglePlacesClient::from_config(&config).map_err(|error| error.to_fcp_error())?;
        self.state = Some(GooglePlacesState {
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
            "manifest_hash": Self::manifest_hash(),
            "base_url": self.state.as_ref().map(|state| state.config.normalized_base_url()),
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
        let details = json!({
            "base_url": state.config.normalized_base_url(),
            "request_timeout_ms": state.config.request_timeout_ms,
            "field_mask": state.config.default_field_mask,
        });
        Ok(SelfCheckReport {
            details: Some(details),
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

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_SEARCH_TEXT | OP_AUTOCOMPLETE | OP_GET_PLACE | OP_HEALTH => {
            Ok(CapabilityId::from_static(CAP_READ))
        }
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("Unknown operation: {operation}"),
        }),
    }
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| capability.as_str() == CAP_READ)
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
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
            nonce: [9u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        operation: &'static str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(CAP_READ)
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
    async fn configure_and_invoke_health() {
        let mut connector = GooglePlacesConnector::new();
        connector
            .configure(json!({
                "api_key": "test-key",
                "base_url": "https://places.googleapis.com"
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
                id: RequestId::new("places-health"),
                connector_id: ConnectorId::from_static("fcp.google-places"),
                operation: OperationId::from_static(OP_HEALTH),
                zone_id: ZoneId::work(),
                input: json!({}),
                capability_token: capability_token(&signing_key, OP_HEALTH),
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
            .expect("health invoke should succeed");
        assert_eq!(response.result.expect("result")["status"], "ok");
    }

    #[test]
    fn operations_catalog_contains_expected_operations() {
        let operations = GooglePlacesConnector::operations_info();
        assert_eq!(operations.len(), 4);
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_SEARCH_TEXT)
        );
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_AUTOCOMPLETE)
        );
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_GET_PLACE)
        );
    }
}
