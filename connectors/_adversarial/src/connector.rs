use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use fcp_manifest::ConnectorManifest;
use fcp_prelude::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tracing::info;

pub const CONNECTOR_ID: &str = "fcp.adversarial";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_ADVERSARIAL: &str = "adversarial.inject";
const OP_TRIGGER: &str = "adversarial.trigger";
const PRODUCTION_DEPLOY_MODE: &str = "production";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AdversarialConnectorError {
    #[error("ConnectorTrustError: adversarial connector refused in deploy mode '{deploy_mode}'")]
    ConnectorTrustError { deploy_mode: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialScenario {
    OversizedPayload,
    MidStreamDisconnect,
    TimeSkewPlus1y,
    TimeSkewMinus1y,
    InvalidUtf8Header,
    DeeplyNestedJson,
    OversizedJsonKey,
    NullByteInResponseField,
    HeaderSmuggling,
    CrlfInjection,
}

impl AdversarialScenario {
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::OversizedPayload,
            Self::MidStreamDisconnect,
            Self::TimeSkewPlus1y,
            Self::TimeSkewMinus1y,
            Self::InvalidUtf8Header,
            Self::DeeplyNestedJson,
            Self::OversizedJsonKey,
            Self::NullByteInResponseField,
            Self::HeaderSmuggling,
            Self::CrlfInjection,
        ]
    }

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
            Self::NullByteInResponseField => "null_byte_in_response_field",
            Self::HeaderSmuggling => "header_smuggling",
            Self::CrlfInjection => "crlf_injection",
        }
    }

    #[must_use]
    pub const fn layer_caught_it(self) -> &'static str {
        match self {
            Self::OversizedPayload | Self::OversizedJsonKey => "resource_budget_guard",
            Self::MidStreamDisconnect => "streaming_transport_guard",
            Self::TimeSkewPlus1y | Self::TimeSkewMinus1y => "timestamp_policy_guard",
            Self::InvalidUtf8Header
            | Self::NullByteInResponseField
            | Self::HeaderSmuggling
            | Self::CrlfInjection => "frame_sanitizer",
            Self::DeeplyNestedJson => "json_depth_guard",
        }
    }

    #[must_use]
    pub fn structured_error(self) -> FcpError {
        match self {
            Self::OversizedPayload => FcpError::ResourceExhausted {
                resource: "adversarial oversized_payload sentinel exceeded 1GiB".to_string(),
            },
            Self::MidStreamDisconnect => FcpError::External {
                service: "adversarial-mid-stream".to_string(),
                message: "upstream stream ended before a complete FCP frame".to_string(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::TimeSkewPlus1y => FcpError::InvalidRequest {
                code: 1003,
                message: "adversarial time_skew_plus_1y rejected at timestamp policy guard"
                    .to_string(),
            },
            Self::TimeSkewMinus1y => FcpError::InvalidRequest {
                code: 1003,
                message: "adversarial time_skew_minus_1y rejected at timestamp policy guard"
                    .to_string(),
            },
            Self::InvalidUtf8Header => FcpError::MalformedFrame {
                code: 1004,
                message: "adversarial invalid_utf8_header rejected before header materialization"
                    .to_string(),
            },
            Self::DeeplyNestedJson => FcpError::InvalidRequest {
                code: 1003,
                message: "adversarial deeply_nested_json rejected at depth 1001".to_string(),
            },
            Self::OversizedJsonKey => FcpError::ResourceExhausted {
                resource: "adversarial oversized_json_key exceeded 1MiB".to_string(),
            },
            Self::NullByteInResponseField => FcpError::MalformedFrame {
                code: 1004,
                message: "adversarial null_byte_in_response_field rejected".to_string(),
            },
            Self::HeaderSmuggling => FcpError::MalformedFrame {
                code: 1004,
                message: "adversarial header_smuggling rejected".to_string(),
            },
            Self::CrlfInjection => FcpError::MalformedFrame {
                code: 1004,
                message: "adversarial crlf_injection rejected".to_string(),
            },
        }
    }
}

impl TryFrom<&str> for AdversarialScenario {
    type Error = FcpError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "oversized_payload" => Ok(Self::OversizedPayload),
            "mid_stream_disconnect" => Ok(Self::MidStreamDisconnect),
            "time_skew_plus_1y" => Ok(Self::TimeSkewPlus1y),
            "time_skew_minus_1y" => Ok(Self::TimeSkewMinus1y),
            "invalid_utf8_header" => Ok(Self::InvalidUtf8Header),
            "deeply_nested_json" => Ok(Self::DeeplyNestedJson),
            "oversized_json_key" => Ok(Self::OversizedJsonKey),
            "null_byte_in_response_field" => Ok(Self::NullByteInResponseField),
            "header_smuggling" => Ok(Self::HeaderSmuggling),
            "crlf_injection" => Ok(Self::CrlfInjection),
            _ => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("unknown adversarial scenario: {value}"),
            }),
        }
    }
}

#[derive(Debug)]
pub struct AdversarialConnector {
    base: Arc<BaseConnector>,
    deploy_mode: String,
    configured: bool,
    handshaken: bool,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl AdversarialConnector {
    pub fn new() -> Result<Self, AdversarialConnectorError> {
        let deploy_mode = std::env::var("FCP_DEPLOY_MODE").unwrap_or_else(|_| "test".to_string());
        Self::new_for_deploy_mode(&deploy_mode)
    }

    pub fn new_for_deploy_mode(deploy_mode: &str) -> Result<Self, AdversarialConnectorError> {
        if deploy_mode
            .trim()
            .eq_ignore_ascii_case(PRODUCTION_DEPLOY_MODE)
        {
            return Err(AdversarialConnectorError::ConnectorTrustError {
                deploy_mode: deploy_mode.to_string(),
            });
        }
        Ok(Self::from_non_production_mode(deploy_mode))
    }

    fn from_non_production_mode(deploy_mode: &str) -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            deploy_mode: deploy_mode.to_string(),
            configured: false,
            handshaken: false,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        if !params
            .get("allow_adversarial")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "adversarial connector requires allow_adversarial=true".to_string(),
            });
        }
        self.configured = true;
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "surface_status": "adversarial",
            "deploy_mode": self.deploy_mode,
            "production_loadable": false,
        }))
    }

    pub async fn handle_handshake(&mut self, _params: Value) -> FcpResult<Value> {
        if !self.configured {
            return Err(FcpError::NotConfigured);
        }
        self.handshaken = true;
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "surface_status": "adversarial",
            "capabilities": [CAP_ADVERSARIAL],
            "streaming_supported": false,
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": health_status(self.configured, self.handshaken),
            "surface_status": "adversarial",
            "configured": self.configured,
            "handshaken": self.handshaken,
            "production_loadable": false,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.configured && self.handshaken { "healthy" } else { "degraded" },
            "surface_status": "adversarial",
            "checks": [
                {"name": "operator_opt_in", "passed": self.configured, "critical": true},
                {"name": "handshake", "passed": self.handshaken, "critical": true},
                {"name": "production_refusal", "passed": true, "critical": true, "message": "FCP_DEPLOY_MODE=production refuses this connector at construction."},
                {"name": "no_network", "passed": true, "critical": true},
                {"name": "structured_errors_only", "passed": true, "critical": true}
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": "ok",
            "surface_status": "adversarial",
            "scenario_count": AdversarialScenario::all().len(),
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "surface_status": "adversarial",
            "operations": operations_info(),
            "scenarios": AdversarialScenario::all()
                .iter()
                .map(|scenario| scenario.as_str())
                .collect::<Vec<_>>(),
            "events": ["SecretLeakAlert"],
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let started = Instant::now();
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".to_string(),
            })?;
        if operation != OP_TRIGGER {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            });
        }
        let scenario = params
            .get("input")
            .and_then(|input| input.get("scenario"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "input.scenario is required".to_string(),
            })
            .and_then(AdversarialScenario::try_from)?;
        let error = scenario.structured_error();
        self.request_count.fetch_add(1, Ordering::Relaxed);
        self.error_count.fetch_add(1, Ordering::Relaxed);
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        info!(
            scenario = scenario.as_str(),
            fcp_error = %error,
            layer_caught_it = scenario.layer_caught_it(),
            latency_ms,
            "fcp.adversarial.scenario handled"
        );
        Err(error)
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");
        Ok(json!({
            "allowed": operation == OP_TRIGGER,
            "adversarial": true,
            "reason": if operation == OP_TRIGGER {
                "Supported opt-in adversarial test operation."
            } else {
                "Unknown operation."
            }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.configured = false;
        self.handshaken = false;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }
}

fn operations_info() -> Vec<Value> {
    let manifest = ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
        .expect("embedded adversarial manifest should parse");
    manifest
        .provides
        .operations
        .into_iter()
        .map(|(id, operation)| {
            json!({
                "id": id,
                "summary": operation.description,
                "description": operation.description,
                "capability": operation.capability.as_str(),
                "risk_level": operation.risk_level,
                "safety_tier": operation.safety_tier,
                "requires_approval": operation.requires_approval,
                "idempotency": operation.idempotency,
                "input_schema": operation.input_schema,
                "output_schema": operation.output_schema,
                "network_constraints": operation.network_constraints,
                "ai_hints": operation.ai_hints
            })
        })
        .collect()
}

const fn health_status(configured: bool, handshaken: bool) -> &'static str {
    if configured && handshaken {
        "healthy"
    } else if configured {
        "degraded"
    } else {
        "unconfigured"
    }
}
