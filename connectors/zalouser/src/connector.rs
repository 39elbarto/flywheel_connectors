use std::sync::Arc;

use fcp_prelude::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "fcp.zalouser";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str = "This first slice is a planned-only helper-process contract. It does not bundle or emulate the upstream personal-account runtime.";
const PLANNED_HELPER_OPERATION_ID: &str = "zalouser.helper.exec";
const NOT_HANDSHAKEN_REASON_CODE: &str = "not_handshaken";
const NOT_HANDSHAKEN_MESSAGE: &str = "Connector configured, but handshake has not completed yet.";
const UNIMPLEMENTED_REASON_CODE: &str = "invoke_surface_unimplemented";
const UNIMPLEMENTED_MESSAGE: &str = "This connector scaffold only declares planned operations. Live invoke support is not implemented yet.";
const EXEC_DISABLED_REASON_CODE: &str = "helper_exec_disabled";

pub struct ZalouserConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    handshaken: bool,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl ZalouserConnector {
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
            "planned_capabilities": ["zalouser.helper"],
            "execution_enabled": false,
            "surface_status": "quarantined",
            "surface_status_rationale": "High-risk surface requiring explicit operator approval"
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.configured { "degraded" } else { "unconfigured" },
            "configured": self.configured,
            "handshaken": self.handshaken,
            "execution_enabled": false,
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
                { "name": "helper_exec", "passed": false, "critical": false, "reason_code": EXEC_DISABLED_REASON_CODE, "message": "No helper process policy is implemented; manifest forbids system.exec." },
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
            "message": message,
            "execution_enabled": false
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": [
                { "id": PLANNED_HELPER_OPERATION_ID, "summary": "Planned guarded helper operation", "capability": "zalouser.helper", "risk_level": "high", "safety_tier": "risky", "requires_approval": "policy", "idempotency": "none", "implemented": false, "execution_enabled": false, "reason_code": EXEC_DISABLED_REASON_CODE }
            ],
            "surface_status": "quarantined",
            "surface_status_rationale": "High-risk surface requiring explicit operator approval",
            "helper_process_policy": null,
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
            message: if operation == PLANNED_HELPER_OPERATION_ID {
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
            "reason_code": if operation == PLANNED_HELPER_OPERATION_ID {
                UNIMPLEMENTED_REASON_CODE
            } else {
                "unknown_operation"
            },
            "execution_enabled": false,
            "reason": if operation == PLANNED_HELPER_OPERATION_ID {
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

impl Default for ZalouserConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_manifest::ConnectorManifest;

    #[test]
    fn manifest_declares_no_egress_for_planned_helper() {
        let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let unchecked =
            ConnectorManifest::parse_str_unchecked(&raw).expect("manifest should parse");
        let computed_hash = unchecked
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(
            unchecked.manifest.interface_hash.to_string(),
            computed_hash.to_string()
        );

        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let operation = manifest
            .provides
            .operations
            .get(PLANNED_HELPER_OPERATION_ID)
            .expect("planned helper operation");
        let constraints = operation
            .network_constraints
            .as_ref()
            .expect("planned helper network constraints");

        assert_eq!(constraints.host_allow.as_slice(), ["none.invalid"]);
        assert_eq!(constraints.port_allow.as_slice(), [0]);
        assert!(constraints.ip_allow.is_empty());
        assert!(constraints.cidr_deny.is_empty());
        assert!(constraints.deny_localhost);
        assert!(constraints.deny_private_ranges);
        assert!(constraints.deny_tailnet_ranges);
        assert!(!constraints.require_sni);
        assert!(constraints.spki_pins.is_empty());
        assert!(constraints.deny_ip_literals);
        assert!(constraints.require_host_canonicalization);
        assert_eq!(constraints.dns_max_ips, 0);
        assert_eq!(constraints.max_redirects, 0);
        assert_eq!(constraints.connect_timeout_ms, 1_000);
        assert_eq!(constraints.total_timeout_ms, 15_000);
        assert_eq!(constraints.max_response_bytes, 1_048_576);
    }

    #[fcp_async_core::runtime::test]
    async fn planned_only_connector_reports_degraded_readiness() {
        let mut connector = ZalouserConnector::new();
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
        assert!(!health["execution_enabled"].as_bool().expect("bool"));
        assert!(!health["live_requests_supported"].as_bool().expect("bool"));

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        assert_eq!(introspect["surface_status"], "quarantined");
        assert_eq!(introspect["helper_process_policy"], Value::Null);
        assert!(
            introspect["operations"]
                .as_array()
                .expect("operations should be an array")
                .iter()
                .all(|operation| {
                    operation.get("implemented").and_then(Value::as_bool) == Some(false)
                        && operation.get("execution_enabled").and_then(Value::as_bool)
                            == Some(false)
                        && operation.get("requires_approval").and_then(Value::as_str)
                            == Some("policy")
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
        let mut connector = ZalouserConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let error = connector
            .handle_invoke(json!({"operation_id": PLANNED_HELPER_OPERATION_ID}))
            .await
            .expect_err("invoke should refuse planned operation");
        assert!(error.to_string().contains("not implemented"));

        let simulate = connector
            .handle_simulate(json!({"operation_id": PLANNED_HELPER_OPERATION_ID}))
            .await
            .expect("simulate should succeed");
        assert!(!simulate["allowed"].as_bool().expect("bool"));
        assert_eq!(simulate["simulate_capability"], "unsupported");
        assert_eq!(simulate["reason_code"], UNIMPLEMENTED_REASON_CODE);
        assert!(!simulate["execution_enabled"].as_bool().expect("bool"));
    }

    #[fcp_async_core::runtime::test]
    async fn every_introspected_operation_denies_invoke_and_simulate() {
        let mut connector = ZalouserConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        let operations = introspect["operations"]
            .as_array()
            .expect("operations should be an array");
        assert!(!operations.is_empty());

        for operation in operations {
            let operation_id = operation["id"].as_str().expect("operation id");
            let error = connector
                .handle_invoke(json!({"operation_id": operation_id}))
                .await
                .expect_err("planned operation should deny invoke");
            assert!(error.to_string().contains("not implemented"));

            let simulate = connector
                .handle_simulate(json!({"operation_id": operation_id}))
                .await
                .expect("simulate should succeed");
            assert!(!simulate["allowed"].as_bool().expect("bool"));
            assert_eq!(simulate["reason_code"], UNIMPLEMENTED_REASON_CODE);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn malformed_and_unknown_operations_are_denied_without_execution() {
        let mut connector = ZalouserConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let malformed = connector
            .handle_invoke(json!({"operation_id": 7}))
            .await
            .expect_err("malformed operation id should fail");
        assert!(malformed.to_string().contains("Missing operation_id"));

        let unknown = connector
            .handle_invoke(json!({"operation_id": "zalouser.unknown"}))
            .await
            .expect_err("unknown operation should fail");
        assert!(unknown.to_string().contains("Unknown operation"));

        let simulate = connector
            .handle_simulate(json!({"operation_id": "zalouser.unknown"}))
            .await
            .expect("simulate should succeed");
        assert!(!simulate["allowed"].as_bool().expect("bool"));
        assert_eq!(simulate["reason_code"], "unknown_operation");
        assert!(!simulate["execution_enabled"].as_bool().expect("bool"));
    }
}
