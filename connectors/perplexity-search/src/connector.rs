use std::sync::Arc;

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "fcp.perplexity-search";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str = "This first slice is request-response only and starts with one grounded research query surface.";
const NOT_HANDSHAKEN_REASON_CODE: &str = "not_handshaken";
const NOT_HANDSHAKEN_MESSAGE: &str = "Connector configured, but handshake has not completed yet.";
const UNIMPLEMENTED_REASON_CODE: &str = "invoke_surface_unimplemented";
const UNIMPLEMENTED_MESSAGE: &str = "This connector scaffold only declares planned operations. Live invoke support is not implemented yet.";

pub struct PerplexitySearchConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    handshaken: bool,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl PerplexitySearchConnector {
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
            "planned_capabilities": ["perplexity-search.query"],
            "surface_status": "planned_only"
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
                { "id": "perplexity-search.query", "summary": "Execute one grounded Perplexity research query", "capability": "perplexity-search.query", "risk_level": "medium", "safety_tier": "safe", "idempotency": "none", "implemented": false }
            ],
            "surface_status": "planned_only",
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
            message: if operation == "perplexity-search.query" {
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
            "reason": if operation == "perplexity-search.query" {
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

impl Default for PerplexitySearchConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[fcp_async_core::runtime::test]
    async fn planned_only_connector_reports_degraded_readiness() {
        let mut connector = PerplexitySearchConnector::new();
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

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        assert_eq!(introspect["surface_status"], "planned_only");
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
        let mut connector = PerplexitySearchConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let error = connector
            .handle_invoke(json!({"operation_id": "perplexity-search.query"}))
            .await
            .expect_err("invoke should refuse planned operation");
        assert!(error.to_string().contains("not implemented"));

        let simulate = connector
            .handle_simulate(json!({"operation_id": "perplexity-search.query"}))
            .await
            .expect("simulate should succeed");
        assert_eq!(simulate["allowed"], false);
        assert_eq!(simulate["simulate_capability"], "unsupported");
    }
}
