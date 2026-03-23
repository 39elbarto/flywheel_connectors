use std::sync::Arc;

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "fcp.mistral";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str =
    "This first slice is request-response only and starts with chat completions, embeddings, transcription, and model discovery.";

pub struct MistralConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    handshaken: bool,
}

impl MistralConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            configured: false,
            handshaken: false,
        }
    }

    pub async fn handle_configure(&mut self, _params: Value) -> FcpResult<Value> {
        self.configured = true;
        self.base.set_configured(true);
        Ok(json!({"connector_id": CONNECTOR_ID, "configured": true}))
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
            "capabilities": ["mistral.chat", "mistral.embeddings", "mistral.audio", "mistral.models"]
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.configured && self.handshaken { "healthy" } else if self.configured { "degraded" } else { "unconfigured" },
            "configured": self.configured,
            "handshaken": self.handshaken,
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.configured { "healthy" } else { "unhealthy" },
            "checks": [
                { "name": "configuration", "passed": self.configured, "critical": true },
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.configured { "ok" } else { "degraded" },
            "reason_code": if self.configured { Value::Null } else { json!("not_configured") },
            "message": BOUNDARY
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": [
                { "id": "mistral.chat.completions", "summary": "Create a Mistral chat completion", "capability": "mistral.chat", "risk_level": "medium", "safety_tier": "safe", "idempotency": "none" },
                { "id": "mistral.embeddings.create", "summary": "Create Mistral embeddings", "capability": "mistral.embeddings", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
                { "id": "mistral.audio.transcriptions", "summary": "Create a Mistral transcription", "capability": "mistral.audio", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
                { "id": "mistral.models.list", "summary": "List Mistral models", "capability": "mistral.models", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" }
            ],
            "events": [],
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        Ok(json!({
            "status": "not_implemented",
            "operation_id": operation,
            "connector_id": CONNECTOR_ID,
            "boundary": BOUNDARY
        }))
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");

        Ok(json!({
            "allowed": matches!(
                operation,
                "mistral.chat.completions"
                    | "mistral.embeddings.create"
                    | "mistral.audio.transcriptions"
                    | "mistral.models.list"
            ),
            "reason": BOUNDARY
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

impl Default for MistralConnector {
    fn default() -> Self {
        Self::new()
    }
}

