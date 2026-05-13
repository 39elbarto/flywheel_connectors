//! Adversarial connector implementation.

use std::sync::atomic::Ordering;
use std::time::Instant;

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, ConnectorId, EventCaps,
    FcpConnector, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId,
    OperationInfo, RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

/// Connector identifier for the adversarial test connector.
pub const CONNECTOR_ID: &str = "fcp.adversarial";
/// Operation used to emit one hostile provider-response scenario.
pub const OP_ADVERSARIAL_EMIT: &str = "adversarial.emit";

const CAP_ADVERSARIAL_EMIT: &str = "adversarial.emit";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const PRODUCTION_DEPLOY_MODE: &str = "production";
const LAYER_CAUGHT_IT: &str = "adversarial_connector";
const OVERSIZED_PAYLOAD_SENTINEL_BYTES: u64 = 1_073_741_825;
const DEEPLY_NESTED_JSON_LEVELS: u16 = 1_001;
const OVERSIZED_JSON_KEY_BYTES: u64 = 1_048_577;

/// Deployment/load errors for the adversarial connector.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AdversarialConnectorError {
    /// Production mode refused the intentionally hostile connector.
    #[error("ConnectorTrustError: production deploy mode refuses adversarial connector")]
    ConnectorTrustError,
}

/// Hostile provider-response scenarios emitted by the adversarial connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialScenario {
    /// Provider reports a payload larger than one GiB without allocating it.
    OversizedPayload,
    /// Provider disconnects mid-stream.
    MidStreamDisconnect,
    /// Provider timestamp is one year in the future.
    TimeSkewPlus1y,
    /// Provider timestamp is one year in the past.
    TimeSkewMinus1y,
    /// Provider sends header bytes that are not valid UTF-8.
    InvalidUtf8Header,
    /// Provider sends JSON nesting beyond the supported boundary.
    DeeplyNestedJson,
    /// Provider sends a JSON object key larger than one MiB.
    OversizedJsonKey,
    /// Provider injects a null byte into a response field.
    NullByteInjection,
    /// Provider attempts header smuggling.
    HeaderSmuggling,
    /// Provider injects CRLF into a header value.
    CrlfInjection,
}

impl AdversarialScenario {
    /// Return the canonical scenario ID used in input and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OversizedPayload => "oversized_payload",
            Self::MidStreamDisconnect => "mid_stream_disconnect",
            Self::TimeSkewPlus1y => "time_skew_plus_1y",
            Self::TimeSkewMinus1y => "time_skew_minus_1y",
            Self::InvalidUtf8Header => "invalid_utf8_header",
            Self::DeeplyNestedJson => "deeply_nested_json",
            Self::OversizedJsonKey => "oversized_json_key",
            Self::NullByteInjection => "null_byte_injection",
            Self::HeaderSmuggling => "header_smuggling",
            Self::CrlfInjection => "crlf_injection",
        }
    }

    /// Parse a scenario ID.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Some(match id {
            "oversized_payload" => Self::OversizedPayload,
            "mid_stream_disconnect" => Self::MidStreamDisconnect,
            "time_skew_plus_1y" => Self::TimeSkewPlus1y,
            "time_skew_minus_1y" => Self::TimeSkewMinus1y,
            "invalid_utf8_header" => Self::InvalidUtf8Header,
            "deeply_nested_json" => Self::DeeplyNestedJson,
            "oversized_json_key" => Self::OversizedJsonKey,
            "null_byte_injection" => Self::NullByteInjection,
            "header_smuggling" => Self::HeaderSmuggling,
            "crlf_injection" => Self::CrlfInjection,
            _ => return None,
        })
    }

    fn fcp_error(self) -> FcpError {
        match self {
            Self::OversizedPayload => FcpError::ResourceExhausted {
                resource: format!("provider_payload>{OVERSIZED_PAYLOAD_SENTINEL_BYTES}B"),
            },
            Self::MidStreamDisconnect => FcpError::ConnectorUnavailable {
                code: 5001,
                message: "provider disconnected before completing response stream".into(),
            },
            Self::TimeSkewPlus1y => FcpError::InvalidRequest {
                code: 1008,
                message: "provider timestamp is more than one year in the future".into(),
            },
            Self::TimeSkewMinus1y => FcpError::InvalidRequest {
                code: 1008,
                message: "provider timestamp is more than one year in the past".into(),
            },
            Self::InvalidUtf8Header => FcpError::MalformedFrame {
                code: 1011,
                message: "provider header contained invalid UTF-8 bytes".into(),
            },
            Self::DeeplyNestedJson => FcpError::ResourceExhausted {
                resource: format!("json_nesting>{DEEPLY_NESTED_JSON_LEVELS}"),
            },
            Self::OversizedJsonKey => FcpError::ResourceExhausted {
                resource: format!("json_key>{OVERSIZED_JSON_KEY_BYTES}B"),
            },
            Self::NullByteInjection => FcpError::MalformedFrame {
                code: 1012,
                message: "provider response field contained a null byte".into(),
            },
            Self::HeaderSmuggling => FcpError::MalformedFrame {
                code: 1013,
                message: "provider response attempted header smuggling".into(),
            },
            Self::CrlfInjection => FcpError::MalformedFrame {
                code: 1014,
                message: "provider response attempted CRLF injection".into(),
            },
        }
    }

    fn response(self, request_id: RequestId, started_at: Instant) -> InvokeResponse {
        let error = self.fcp_error();
        log_structured_adversarial_response(self, &error, started_at);
        InvokeResponse::error(request_id, error)
    }
}

/// Opt-in connector that deterministically returns structured hostile-input errors.
#[derive(Debug)]
pub struct AdversarialConnector {
    base: BaseConnector,
    started_at: Instant,
}

impl AdversarialConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID)),
            started_at: Instant::now(),
        }
    }

    /// Create the connector for an explicit deployment mode.
    ///
    /// # Errors
    ///
    /// Returns `ConnectorTrustError` for `production`, because this connector
    /// intentionally emits hostile payload shapes and must be explicit opt-in.
    pub fn try_new_for_deploy_mode(deploy_mode: &str) -> Result<Self, AdversarialConnectorError> {
        if deploy_mode.eq_ignore_ascii_case(PRODUCTION_DEPLOY_MODE) {
            return Err(AdversarialConnectorError::ConnectorTrustError);
        }
        Ok(Self::new())
    }

    /// Create the connector from the `FCP_DEPLOY_MODE` environment value.
    ///
    /// # Errors
    ///
    /// Returns `ConnectorTrustError` when `FCP_DEPLOY_MODE=production`.
    pub fn try_new_from_env() -> Result<Self, AdversarialConnectorError> {
        let deploy_mode = std::env::var("FCP_DEPLOY_MODE").unwrap_or_else(|_| "test".into());
        Self::try_new_for_deploy_mode(&deploy_mode)
    }

    /// Return a structured error response for a single adversarial scenario.
    #[must_use]
    pub fn emit_scenario(
        &self,
        scenario: AdversarialScenario,
        request_id: RequestId,
    ) -> InvokeResponse {
        let _ = self.id();
        scenario.response(request_id, Instant::now())
    }

    fn manifest_hash() -> String {
        let digest = blake3::hash(MANIFEST_TOML.as_bytes());
        format!("blake3:{}", digest.to_hex())
    }

    fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        if req.operation.as_str() != OP_ADVERSARIAL_EMIT {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown adversarial operation: {}", req.operation),
            });
        }
        let scenario_id = req
            .input
            .get("scenario")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::MissingField {
                field: "scenario".into(),
            })?;
        let scenario =
            AdversarialScenario::from_id(scenario_id).ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("unknown adversarial scenario: {scenario_id}"),
            })?;
        Ok(scenario.response(req.id, Instant::now()))
    }
}

impl Default for AdversarialConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(AdversarialConnector);

#[async_trait]
impl FcpConnector for AdversarialConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let deploy_mode = config
            .get("deploy_mode")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("test");
        Self::try_new_for_deploy_mode(deploy_mode).map_err(|_| FcpError::Unauthorized {
            code: 2009,
            message: "ConnectorTrustError: production deploy mode refuses adversarial connector"
                .into(),
        })?;
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: Some(OperationId::from_static(OP_ADVERSARIAL_EMIT)),
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
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
        let mut snapshot = if self.base.configured.load(Ordering::Acquire) {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "manifest_hash": Self::manifest_hash(),
            "status": "ADVERSARIAL",
            "production_load_policy": "refuse",
            "scenario_count": scenarios().len(),
        }));
        snapshot
    }

    fn metrics(&self) -> fcp_prelude::ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
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
        let result = self.invoke_inner(req);
        self.base.record_request(
            result
                .as_ref()
                .is_ok_and(|response| response.status == InvokeStatus::Ok),
        );
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        if req.operation.as_str() == OP_ADVERSARIAL_EMIT {
            return Ok(SimulateResponse::allowed(req.id));
        }
        Ok(SimulateResponse::denied(
            req.id,
            "unknown adversarial operation",
            "FCP-1004",
        ))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

fn operations_info() -> Vec<OperationInfo> {
    vec![OperationInfo {
        id: OperationId::from_static(OP_ADVERSARIAL_EMIT),
        summary: "Emit an adversarial provider-response scenario".into(),
        description: Some(
            "Deterministically returns a structured FCP error for one hostile input shape.".into(),
        ),
        input_schema: json!({
            "type": "object",
            "required": ["scenario"],
            "additionalProperties": false,
            "properties": {
                "scenario": {
                    "type": "string",
                    "enum": scenarios().iter().map(|scenario| scenario.as_str()).collect::<Vec<_>>()
                }
            }
        }),
        output_schema: json!({
            "type": "object",
            "required": ["scenario", "fcp_error", "layer_caught_it"],
            "additionalProperties": false
        }),
        capability: CapabilityId::from_static(CAP_ADVERSARIAL_EMIT),
        risk_level: RiskLevel::High,
        safety_tier: SafetyTier::Safe,
        idempotency: IdempotencyClass::Strict,
        ai_hints: AgentHint {
            when_to_use: "Use in layer tests that need a deterministic hostile provider response."
                .into(),
            common_mistakes: vec![
                "Do not load this connector in production deploy mode.".into(),
                "Do not allocate the sentinel oversized payload.".into(),
            ],
            examples: vec![
                json!({
                    "operation": OP_ADVERSARIAL_EMIT,
                    "input": { "scenario": "oversized_payload" }
                })
                .to_string(),
            ],
            related: Vec::new(),
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::Interactive),
    }]
}

const fn scenarios() -> &'static [AdversarialScenario] {
    &[
        AdversarialScenario::OversizedPayload,
        AdversarialScenario::MidStreamDisconnect,
        AdversarialScenario::TimeSkewPlus1y,
        AdversarialScenario::TimeSkewMinus1y,
        AdversarialScenario::InvalidUtf8Header,
        AdversarialScenario::DeeplyNestedJson,
        AdversarialScenario::OversizedJsonKey,
        AdversarialScenario::NullByteInjection,
        AdversarialScenario::HeaderSmuggling,
        AdversarialScenario::CrlfInjection,
    ]
}

fn log_structured_adversarial_response(
    scenario: AdversarialScenario,
    error: &FcpError,
    started_at: Instant,
) {
    let latency_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    let fcp_error = error.to_string();
    tracing::info_span!(
        "fcp.adversarial.scenario",
        scenario = scenario.as_str(),
        fcp_error = %fcp_error,
        layer_caught_it = LAYER_CAUGHT_IT,
        latency_ms
    )
    .in_scope(|| {
        tracing::info!(
            scenario = scenario.as_str(),
            fcp_error = %fcp_error,
            layer_caught_it = LAYER_CAUGHT_IT,
            latency_ms,
            "adversarial response handled"
        );
    });
}
