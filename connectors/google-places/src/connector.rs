//! `Google Places` connector implementation.

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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::client::GooglePlacesClient;
use crate::types::{AutocompleteInput, GetPlaceInput, GooglePlacesConfig, SearchTextInput};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "google_places.read";
const OP_SEARCH_TEXT: &str = "google_places.search_text";
const OP_AUTOCOMPLETE: &str = "google_places.autocomplete";
const OP_GET_PLACE: &str = "google_places.get_place";
const OP_HEALTH: &str = "google_places.health";

fn nonblank_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "\\S"
    })
}

fn unsigned_integer_schema() -> Value {
    json!({
        "type": "integer",
        "minimum": 0,
        "maximum": i64::from(u32::MAX)
    })
}

fn localized_text_schema() -> Value {
    json!({
        "type": ["object", "null"],
        "additionalProperties": true,
        "properties": {
            "text": { "type": ["string", "null"] },
            "languageCode": { "type": ["string", "null"] }
        }
    })
}

fn suggestion_text_schema() -> Value {
    json!({
        "type": ["object", "null"],
        "additionalProperties": true,
        "properties": {
            "text": { "type": ["string", "null"] }
        }
    })
}

fn place_record_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": true,
        "properties": {
            "id": { "type": ["string", "null"] },
            "name": { "type": ["string", "null"] },
            "displayName": localized_text_schema(),
            "formattedAddress": { "type": ["string", "null"] },
            "types": {
                "type": "array",
                "items": { "type": "string" }
            },
            "googleMapsUri": { "type": ["string", "null"], "format": "uri" }
        }
    })
}

fn place_prediction_schema() -> Value {
    json!({
        "type": ["object", "null"],
        "additionalProperties": true,
        "properties": {
            "place": { "type": ["string", "null"] },
            "placeId": { "type": ["string", "null"] },
            "text": suggestion_text_schema()
        }
    })
}

fn query_prediction_schema() -> Value {
    json!({
        "type": ["object", "null"],
        "additionalProperties": true,
        "properties": {
            "text": suggestion_text_schema()
        }
    })
}

fn search_text_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["query"],
        "additionalProperties": false,
        "properties": {
            "query": nonblank_string_schema(),
            "max_result_count": unsigned_integer_schema(),
            "open_now": { "type": "boolean" },
            "field_mask": nonblank_string_schema()
        }
    })
}

fn autocomplete_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["input"],
        "additionalProperties": false,
        "properties": {
            "input": nonblank_string_schema(),
            "session_token": nonblank_string_schema(),
            "field_mask": nonblank_string_schema()
        }
    })
}

fn get_place_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["place"],
        "additionalProperties": false,
        "properties": {
            "place": nonblank_string_schema(),
            "language_code": nonblank_string_schema(),
            "field_mask": nonblank_string_schema()
        }
    })
}

fn empty_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "maxProperties": 0
    })
}

fn search_text_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["places"],
        "additionalProperties": true,
        "properties": {
            "places": {
                "type": "array",
                "items": place_record_schema()
            }
        }
    })
}

fn autocomplete_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["suggestions"],
        "additionalProperties": true,
        "properties": {
            "suggestions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "placePrediction": place_prediction_schema(),
                        "queryPrediction": query_prediction_schema()
                    }
                }
            }
        }
    })
}

fn health_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["status", "base_url", "manifest_hash", "field_masks"],
        "additionalProperties": false,
        "properties": {
            "status": { "type": "string", "enum": ["ok"] },
            "base_url": { "type": "string", "format": "uri" },
            "manifest_hash": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
            "field_masks": {
                "type": "object",
                "required": ["search_text", "autocomplete", "place_details"],
                "additionalProperties": false,
                "properties": {
                    "search_text": nonblank_string_schema(),
                    "autocomplete": nonblank_string_schema(),
                    "place_details": nonblank_string_schema()
                }
            }
        }
    })
}

fn input_schema_for(operation_id: &str) -> Value {
    match operation_id {
        OP_SEARCH_TEXT => search_text_input_schema(),
        OP_AUTOCOMPLETE => autocomplete_input_schema(),
        OP_GET_PLACE => get_place_input_schema(),
        _ => empty_input_schema(),
    }
}

fn output_schema_for(operation_id: &str) -> Value {
    match operation_id {
        OP_SEARCH_TEXT => search_text_output_schema(),
        OP_AUTOCOMPLETE => autocomplete_output_schema(),
        OP_GET_PLACE => place_record_schema(),
        OP_HEALTH => health_output_schema(),
        _ => json!({ "type": "object", "additionalProperties": true }),
    }
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

    fn serialize_output<T: serde::Serialize>(value: T) -> FcpResult<serde_json::Value> {
        serde_json::to_value(value).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize Google Places response: {error}"),
        })
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
                input_schema: input_schema_for(OP_SEARCH_TEXT),
                output_schema: output_schema_for(OP_SEARCH_TEXT),
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
                    related: vec![CapabilityId::from_static(CAP_READ)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_AUTOCOMPLETE),
                summary: "Autocomplete place predictions".into(),
                description: Some("Call Google Places autocomplete.".into()),
                input_schema: input_schema_for(OP_AUTOCOMPLETE),
                output_schema: output_schema_for(OP_AUTOCOMPLETE),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this while narrowing down an in-progress place search.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{\"input\":\"sushi soho london\"}".into()],
                    related: vec![CapabilityId::from_static(CAP_READ)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_GET_PLACE),
                summary: "Get one place resource".into(),
                description: Some("Fetch structured details for a place resource name.".into()),
                input_schema: input_schema_for(OP_GET_PLACE),
                output_schema: output_schema_for(OP_GET_PLACE),
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
                    related: vec![CapabilityId::from_static(CAP_READ)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_HEALTH),
                summary: "Report connector health details".into(),
                description: Some("Return connector configuration and upstream target details.".into()),
                input_schema: input_schema_for(OP_HEALTH),
                output_schema: output_schema_for(OP_HEALTH),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this before operational place queries.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(CAP_READ)],
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
        let InvokeRequest {
            id,
            operation,
            input,
            capability_token,
            ..
        } = req;
        verifier.verify_bound(capability_token, &required_cap, &operation, &[])?;

        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let output = match operation.as_str() {
            OP_SEARCH_TEXT => {
                let input = SearchTextInput::from_value(input)?;
                Self::serialize_output(
                    state
                        .client
                        .search_text(&input)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )?
            }
            OP_AUTOCOMPLETE => {
                let input = AutocompleteInput::from_value(input)?;
                Self::serialize_output(
                    state
                        .client
                        .autocomplete(&input)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )?
            }
            OP_GET_PLACE => {
                let input = GetPlaceInput::from_value(input)?;
                Self::serialize_output(
                    state
                        .client
                        .get_place(&input)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )?
            }
            OP_HEALTH => json!({
                "status": "ok",
                "base_url": state.client.base_url(),
                "manifest_hash": Self::manifest_hash(),
                "field_masks": {
                    "search_text": state.config.search_text_field_mask.as_str(),
                    "autocomplete": state.config.autocomplete_field_mask.as_str(),
                    "place_details": state.config.place_details_field_mask.as_str(),
                }
            }),
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(InvokeResponse::ok(id, output))
    }
}

impl Default for GooglePlacesConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(GooglePlacesConnector);

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
            "field_masks": {
                "search_text": state.config.search_text_field_mask.as_str(),
                "autocomplete": state.config.autocomplete_field_mask.as_str(),
                "place_details": state.config.place_details_field_mask.as_str(),
            },
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
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, RequestId, ZoneId};

    use super::*;

    const EXPECTED_MANIFEST_SCHEMA_OPS: &[(&str, &str)] = &[
        (OP_SEARCH_TEXT, "search_text"),
        (OP_AUTOCOMPLETE, "autocomplete"),
        (OP_GET_PLACE, "get_place"),
        (OP_HEALTH, "health"),
    ];

    fn places_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML)
            .map_err(|err| format!("Google Places manifest TOML should parse: {err}"))
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
    ) -> Result<Value, String> {
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

    fn validator_for(schema: &Value) -> Result<jsonschema::Validator, String> {
        jsonschema::Validator::new(schema)
            .map_err(|err| format!("manifest operation schema should compile: {err}"))
    }

    fn assert_schema_accepts(schema: &Value, payload: &Value) -> Result<(), String> {
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

    fn assert_schema_rejects(schema: &Value, payload: &Value) -> Result<(), String> {
        let validator = validator_for(schema)?;
        if validator.iter_errors(payload).next().is_some() {
            Ok(())
        } else {
            Err(format!("schema should reject {payload}"))
        }
    }

    fn sample_search_text_output() -> Value {
        json!({
            "places": [
                {
                    "id": "abc123",
                    "name": "places/abc123",
                    "displayName": {
                        "text": "Coffee Shop",
                        "languageCode": "en"
                    },
                    "formattedAddress": "123 Main St",
                    "types": ["cafe", "food"],
                    "googleMapsUri": "https://maps.google.com/?cid=123"
                }
            ],
            "contextualContents": [{ "rank": 1 }]
        })
    }

    fn sample_autocomplete_output() -> Value {
        json!({
            "suggestions": [
                {
                    "placePrediction": {
                        "place": "places/abc123",
                        "placeId": "abc123",
                        "text": { "text": "Coffee Shop" }
                    }
                },
                {
                    "queryPrediction": {
                        "text": { "text": "coffee near me" }
                    }
                }
            ]
        })
    }

    fn sample_get_place_output() -> Value {
        json!({
            "id": "abc123",
            "name": "places/abc123",
            "displayName": {
                "text": "Coffee Shop",
                "languageCode": "en"
            },
            "formattedAddress": "123 Main St",
            "types": ["cafe"],
            "googleMapsUri": "https://maps.google.com/?cid=123"
        })
    }

    fn sample_health_output() -> Value {
        json!({
            "status": "ok",
            "base_url": "https://places.googleapis.com",
            "manifest_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "field_masks": {
                "search_text": "places.id,places.name",
                "autocomplete": "suggestions.placePrediction.place",
                "place_details": "id,name"
            }
        })
    }

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
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(CAP_READ)
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        let manifest = places_manifest()?;
        let operations = manifest_operations(&manifest)?;
        let operation_catalog = GooglePlacesConnector::new().introspect().operations;

        assert_eq!(
            operations.len(),
            EXPECTED_MANIFEST_SCHEMA_OPS.len(),
            "manifest should declare only the expected operations"
        );
        assert_eq!(
            operation_catalog.len(),
            EXPECTED_MANIFEST_SCHEMA_OPS.len(),
            "runtime operation catalog should declare only the expected operations"
        );

        for (operation_id, manifest_key) in EXPECTED_MANIFEST_SCHEMA_OPS {
            assert!(
                operations.contains_key(*manifest_key),
                "manifest should declare operation {manifest_key}"
            );
            let operation = operation_catalog
                .iter()
                .find(|operation| operation.id.as_str() == *operation_id)
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

        let search_input = operation_schema(&manifest, "search_text", "input_schema")?;
        assert_schema_accepts(
            &search_input,
            &json!({
                "query": "coffee near Bryant Park",
                "max_result_count": 5,
                "open_now": true,
                "field_mask": "places.id,places.displayName"
            }),
        )?;
        assert_schema_rejects(&search_input, &json!({ "query": "   " }))?;
        assert_schema_rejects(
            &search_input,
            &json!({
                "query": "coffee",
                "unexpected": true
            }),
        )?;

        let autocomplete_input = operation_schema(&manifest, "autocomplete", "input_schema")?;
        assert_schema_accepts(
            &autocomplete_input,
            &json!({
                "input": "sushi soho london",
                "session_token": "session-123",
                "field_mask": "suggestions.placePrediction.place"
            }),
        )?;
        assert_schema_rejects(&autocomplete_input, &json!({ "input": "" }))?;
        assert_schema_rejects(
            &autocomplete_input,
            &json!({
                "input": "sushi",
                "extra": "ignored-by-serde-but-not-by-schema"
            }),
        )?;

        let get_place_input = operation_schema(&manifest, "get_place", "input_schema")?;
        assert_schema_accepts(
            &get_place_input,
            &json!({
                "place": "places/ChIJN1t_tDeuEmsRUsoyG83frY4",
                "language_code": "en",
                "field_mask": "id,name,displayName"
            }),
        )?;
        assert_schema_rejects(&get_place_input, &json!({ "place": " " }))?;

        let health_input = operation_schema(&manifest, "health", "input_schema")?;
        assert_schema_accepts(&health_input, &json!({}))?;
        assert_schema_rejects(&health_input, &json!({ "probe": true }))?;

        assert_schema_accepts(
            &operation_schema(&manifest, "search_text", "output_schema")?,
            &sample_search_text_output(),
        )?;
        assert_schema_accepts(
            &operation_schema(&manifest, "autocomplete", "output_schema")?,
            &sample_autocomplete_output(),
        )?;
        assert_schema_accepts(
            &operation_schema(&manifest, "get_place", "output_schema")?,
            &sample_get_place_output(),
        )?;
        assert_schema_accepts(
            &operation_schema(&manifest, "health", "output_schema")?,
            &sample_health_output(),
        )?;

        Ok(())
    }
}
