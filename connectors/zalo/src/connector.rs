use std::sync::Arc;

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "fcp.zalo";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str =
    "This first slice covers bot identity, message send, photo send, long-poll updates, webhook setup, and webhook token verification.";

pub struct ZaloConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    handshaken: bool,
}

impl ZaloConnector {
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
            "capabilities": ["zalo.messages", "zalo.updates", "zalo.webhook"]
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
                { "id": "zalo.self.get_me", "summary": "Get Zalo bot identity", "capability": "zalo.messages", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
                { "id": "zalo.messages.send", "summary": "Send a Zalo text message", "capability": "zalo.messages", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort" },
                { "id": "zalo.messages.send_photo", "summary": "Send a Zalo photo message", "capability": "zalo.messages", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort" },
                { "id": "zalo.updates.poll", "summary": "Long-poll one Zalo update", "capability": "zalo.updates", "risk_level": "low", "safety_tier": "safe", "idempotency": "none" },
                { "id": "zalo.webhook.set", "summary": "Set the Zalo webhook URL", "capability": "zalo.webhook", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort" },
                { "id": "zalo.webhook.delete", "summary": "Delete the Zalo webhook", "capability": "zalo.webhook", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort" },
                { "id": "zalo.webhook.info", "summary": "Get Zalo webhook info", "capability": "zalo.webhook", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
                { "id": "zalo.webhook.verify", "summary": "Verify a webhook secret token against local config", "capability": "zalo.webhook", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" }
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
                "zalo.self.get_me"
                    | "zalo.messages.send"
                    | "zalo.messages.send_photo"
                    | "zalo.updates.poll"
                    | "zalo.webhook.set"
                    | "zalo.webhook.delete"
                    | "zalo.webhook.info"
                    | "zalo.webhook.verify"
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

impl Default for ZaloConnector {
    fn default() -> Self {
        Self::new()
    }
}

