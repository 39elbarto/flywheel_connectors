use std::sync::Arc;

use fcp_prelude::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "fcp.tlon";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str = "This first slice covers authenticated DM and channel send flows with explicit SSRF-safe base URL validation.";
const NOT_HANDSHAKEN_REASON_CODE: &str = "not_handshaken";
const NOT_HANDSHAKEN_MESSAGE: &str = "Connector configured, but handshake has not completed yet.";
const UNIMPLEMENTED_REASON_CODE: &str = "invoke_surface_unimplemented";
const UNIMPLEMENTED_MESSAGE: &str = "This connector scaffold only declares planned operations. Live invoke support is not implemented yet.";
const DM_SEND_OPERATION: &str = "tlon.dm.send";
const CHANNEL_SEND_OPERATION: &str = "tlon.channel.send";
const TARGET_RESOLVE_OPERATION: &str = "tlon.target.resolve";
const DM_CAPABILITY: &str = "tlon.dm";
const CHANNEL_CAPABILITY: &str = "tlon.channel";

fn dm_send_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["ship", "message"],
        "additionalProperties": false,
        "properties": {
            "ship": {
                "type": "string",
                "description": "Target ship name (e.g. ~zod)"
            },
            "message": {
                "type": "string",
                "description": "Message text to send"
            }
        }
    })
}

fn channel_send_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["channel", "message"],
        "additionalProperties": false,
        "properties": {
            "channel": {
                "type": "string",
                "description": "Target channel path or identifier"
            },
            "message": {
                "type": "string",
                "description": "Message text to send"
            }
        }
    })
}

fn target_resolve_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["target"],
        "additionalProperties": false,
        "properties": {
            "target": {
                "type": "string",
                "description": "Human-friendly DM or channel target to resolve"
            }
        }
    })
}

fn ok_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["ok"],
        "additionalProperties": false,
        "properties": {
            "ok": {
                "type": "boolean"
            }
        }
    })
}

fn target_resolve_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["resolved"],
        "additionalProperties": false,
        "properties": {
            "resolved": {
                "type": "boolean"
            }
        }
    })
}

pub struct TlonConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    handshaken: bool,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl TlonConnector {
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
            "capabilities": [],
            "planned_capabilities": ["tlon.dm", "tlon.channel"],
            "surface_status": "incubating",
            "surface_status_rationale": "Runtime path is incomplete or lacks production evidence"
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.configured { "degraded" } else { "unconfigured" },
            "configured": self.configured,
            "handshaken": self.handshaken,
            "live_requests_supported": false,
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.configured { "degraded" } else { "unhealthy" },
            "checks": [
                { "name": "configuration", "passed": self.configured, "critical": true },
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "invoke_surface", "passed": false, "critical": false, "message": UNIMPLEMENTED_MESSAGE },
                { "name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let (status, reason_code, message) = if !self.configured {
            ("degraded", json!("not_configured"), json!(BOUNDARY))
        } else if !self.handshaken {
            (
                "degraded",
                json!(NOT_HANDSHAKEN_REASON_CODE),
                json!(NOT_HANDSHAKEN_MESSAGE),
            )
        } else {
            (
                "unsupported",
                json!(UNIMPLEMENTED_REASON_CODE),
                json!(UNIMPLEMENTED_MESSAGE),
            )
        };
        Ok(json!({
            "status": status,
            "reason_code": reason_code,
            "message": message
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": [
                {
                    "id": DM_SEND_OPERATION,
                    "summary": "Send a Tlon DM",
                    "capability": DM_CAPABILITY,
                    "risk_level": "medium",
                    "safety_tier": "safe",
                    "idempotency": "best_effort",
                    "implemented": false,
                    "input_schema": dm_send_input_schema(),
                    "output_schema": ok_output_schema(),
                    "ai_hints": {
                        "when_to_use": "When you need to send a direct message to a ship on the Tlon/Urbit network.",
                        "common_mistakes": ["Omitting the ~ prefix on ship names."],
                        "examples": [],
                        "related": []
                    }
                },
                {
                    "id": CHANNEL_SEND_OPERATION,
                    "summary": "Send a Tlon channel message",
                    "capability": CHANNEL_CAPABILITY,
                    "risk_level": "medium",
                    "safety_tier": "safe",
                    "idempotency": "best_effort",
                    "implemented": false,
                    "input_schema": channel_send_input_schema(),
                    "output_schema": ok_output_schema(),
                    "ai_hints": {
                        "when_to_use": "When you need to send a message into a Tlon/Urbit channel.",
                        "common_mistakes": ["Using a DM target where a channel path is required."],
                        "examples": [],
                        "related": []
                    }
                },
                {
                    "id": TARGET_RESOLVE_OPERATION,
                    "summary": "Resolve a Tlon DM or channel target",
                    "capability": CHANNEL_CAPABILITY,
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "implemented": false,
                    "input_schema": target_resolve_input_schema(),
                    "output_schema": target_resolve_output_schema(),
                    "ai_hints": {
                        "when_to_use": "When you need to normalize or validate a Tlon target before sending.",
                        "common_mistakes": [],
                        "examples": [],
                        "related": []
                    }
                }
            ],
            "surface_status": "incubating",
            "surface_status_rationale": "Runtime path is incomplete or lacks production evidence",
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

        Err(FcpError::InvalidRequest {
            code: 1002,
            message: if matches!(
                operation,
                DM_SEND_OPERATION | CHANNEL_SEND_OPERATION | TARGET_RESOLVE_OPERATION
            ) {
                format!(
                    "Operation {operation} is planned but not implemented in this connector slice"
                )
            } else {
                format!("Unknown operation: {operation}")
            },
        })
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");

        Ok(json!({
            "allowed": false,
            "simulate_capability": "unsupported",
            "reason": if matches!(operation, DM_SEND_OPERATION | CHANNEL_SEND_OPERATION | TARGET_RESOLVE_OPERATION) {
                UNIMPLEMENTED_MESSAGE
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

impl Default for TlonConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[fcp_async_core::runtime::test]
    async fn planned_only_connector_reports_degraded_readiness() {
        let mut connector = TlonConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");

        let pre_handshake = connector
            .handle_self_check()
            .await
            .expect("self_check before handshake should succeed");
        assert_eq!(pre_handshake["status"], "degraded");
        assert_eq!(pre_handshake["reason_code"], NOT_HANDSHAKEN_REASON_CODE);

        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let health = connector
            .handle_health()
            .await
            .expect("health should succeed");
        assert_eq!(health["status"], "degraded");
        assert_eq!(health["live_requests_supported"], false);

        let doctor = connector
            .handle_doctor()
            .await
            .expect("doctor should succeed");
        assert_eq!(doctor["status"], "degraded");
        assert_eq!(doctor["checks"][2]["passed"], false);

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        assert_eq!(introspect["surface_status"], "incubating");
        assert!(
            introspect["operations"]
                .as_array()
                .expect("operations should be an array")
                .iter()
                .all(|operation| {
                    operation.get("implemented").and_then(Value::as_bool) == Some(false)
                })
        );

        let self_check = connector
            .handle_self_check()
            .await
            .expect("self_check should succeed");
        assert_eq!(self_check["status"], "unsupported");
        assert_eq!(self_check["reason_code"], UNIMPLEMENTED_REASON_CODE);
    }

    #[fcp_async_core::runtime::test]
    async fn planned_operation_invoke_and_simulate_refuse_execution() {
        let mut connector = TlonConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let error = connector
            .handle_invoke(json!({"operation_id": "tlon.dm.send"}))
            .await
            .expect_err("invoke should refuse planned operation");
        assert!(error.to_string().contains("not implemented"));

        let simulate = connector
            .handle_simulate(json!({"operation_id": "tlon.dm.send"}))
            .await
            .expect("simulate should succeed");
        assert_eq!(simulate["allowed"], false);
        assert_eq!(simulate["simulate_capability"], "unsupported");
    }
}
