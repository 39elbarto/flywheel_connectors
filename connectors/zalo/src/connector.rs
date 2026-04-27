use std::sync::Arc;

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "fcp.zalo";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str = "This first slice covers bot identity, message send, photo send, long-poll updates, webhook setup, and webhook token verification.";
const NOT_HANDSHAKEN_REASON_CODE: &str = "not_handshaken";
const NOT_HANDSHAKEN_MESSAGE: &str = "Connector configured, but handshake has not completed yet.";
const UNIMPLEMENTED_MESSAGE: &str = "This connector scaffold only declares planned operations. Live invoke support is not implemented yet.";
const PARTIAL_SURFACE_REASON_CODE: &str = "partial_invoke_surface";

pub struct ZaloConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    handshaken: bool,
    webhook_verify_challenge: Option<String>,
}

// Zalo's planned FCP handlers share async signatures before live invoke support lands.
#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl ZaloConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            configured: false,
            handshaken: false,
            webhook_verify_challenge: None,
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        self.webhook_verify_challenge =
            if let Some(token) = optional_trimmed_string(&params, "webhook_verify_challenge")? {
                Some(token)
            } else {
                optional_trimmed_string(&params, "webhook_token")?
            };
        self.configured = true;
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "webhook_verify_configured": self.webhook_verify_challenge.is_some()
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
            "capabilities": [],
            "planned_capabilities": ["zalo.messages", "zalo.updates", "zalo.webhook"],
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
                { "name": "webhook_verify", "passed": self.webhook_verify_challenge.is_some(), "critical": false, "message": "Local webhook token verification is implemented when webhook_verify_challenge is configured." },
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
                "degraded",
                json!(PARTIAL_SURFACE_REASON_CODE),
                json!(
                    "Only local webhook token verification is implemented in this connector slice; upstream Zalo invoke operations remain planned."
                ),
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
                { "id": "zalo.self.get_me", "summary": "Get Zalo bot identity", "capability": "zalo.messages", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict", "implemented": false },
                { "id": "zalo.messages.send", "summary": "Send a Zalo text message", "capability": "zalo.messages", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort", "implemented": false },
                { "id": "zalo.messages.send_photo", "summary": "Send a Zalo photo message", "capability": "zalo.messages", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort", "implemented": false },
                { "id": "zalo.updates.poll", "summary": "Long-poll one Zalo update", "capability": "zalo.updates", "risk_level": "low", "safety_tier": "safe", "idempotency": "none", "implemented": false },
                { "id": "zalo.webhook.set", "summary": "Set the Zalo webhook URL", "capability": "zalo.webhook", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort", "implemented": false },
                { "id": "zalo.webhook.delete", "summary": "Delete the Zalo webhook", "capability": "zalo.webhook", "risk_level": "medium", "safety_tier": "safe", "idempotency": "best_effort", "implemented": false },
                { "id": "zalo.webhook.info", "summary": "Get Zalo webhook info", "capability": "zalo.webhook", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict", "implemented": false },
                { "id": "zalo.webhook.verify", "summary": "Verify a webhook secret token against local config", "capability": "zalo.webhook", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict", "implemented": true }
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

        if operation == "zalo.webhook.verify" {
            return self.invoke_webhook_verify(params.get("input").unwrap_or(&params));
        }

        Err(FcpError::InvalidRequest {
            code: 1002,
            message: if matches!(
                operation,
                "zalo.self.get_me"
                    | "zalo.messages.send"
                    | "zalo.messages.send_photo"
                    | "zalo.updates.poll"
                    | "zalo.webhook.set"
                    | "zalo.webhook.delete"
                    | "zalo.webhook.info"
                    | "zalo.webhook.verify"
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

        if operation == "zalo.webhook.verify" {
            let input = params.get("input").unwrap_or(&params);
            let supplied_challenge = input
                .get("token")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|token| !token.is_empty());
            let configured =
                self.configured && self.handshaken && self.webhook_verify_challenge.is_some();
            let token_matches = configured
                && supplied_challenge.is_some_and(|token| {
                    self.webhook_verify_challenge
                        .as_deref()
                        .is_some_and(|expected| {
                            constant_time_eq(expected.as_bytes(), token.as_bytes())
                        })
                });
            return Ok(json!({
                "allowed": token_matches,
                "simulate_capability": "local_validation",
                "reason": if token_matches {
                    "Webhook verification token matches configured challenge."
                } else if !self.configured {
                    "Connector is not configured."
                } else if !self.handshaken {
                    NOT_HANDSHAKEN_MESSAGE
                } else if self.webhook_verify_challenge.is_none() {
                    "webhook_verify_challenge is not configured."
                } else if supplied_challenge.is_none() {
                    "Missing token."
                } else {
                    "Webhook verification token would not match configured challenge."
                }
            }));
        }

        Ok(json!({
            "allowed": false,
            "simulate_capability": "unsupported",
            "reason": if matches!(
                operation,
                "zalo.self.get_me"
                    | "zalo.messages.send"
                    | "zalo.messages.send_photo"
                    | "zalo.updates.poll"
                    | "zalo.webhook.set"
                    | "zalo.webhook.delete"
                    | "zalo.webhook.info"
                    | "zalo.webhook.verify"
            ) {
                UNIMPLEMENTED_MESSAGE
            } else {
                "Unknown operation."
            }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.configured = false;
        self.handshaken = false;
        self.webhook_verify_challenge = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn invoke_webhook_verify(&self, input: &Value) -> FcpResult<Value> {
        let expected_challenge =
            self.webhook_verify_challenge
                .as_deref()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1004,
                    message: "webhook_verify_challenge is not configured".into(),
                })?;
        let supplied_challenge = input
            .get("token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing token".into(),
            })?;

        Ok(json!({
            "verified": constant_time_eq(expected_challenge.as_bytes(), supplied_challenge.as_bytes())
        }))
    }
}

fn optional_trimmed_string(params: &Value, key: &str) -> FcpResult<Option<String>> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must be a string"),
        });
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must not be empty"),
        });
    }
    Ok(Some(trimmed.to_string()))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(a ^ b);
    }
    diff == 0
}

impl Default for ZaloConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[fcp_async_core::runtime::test]
    async fn planned_only_connector_reports_degraded_readiness() {
        let mut connector = ZaloConnector::new();
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
        assert_eq!(introspect["surface_status"], "incubating");
        assert!(
            introspect["operations"]
                .as_array()
                .expect("operations should be an array")
                .iter()
                .any(|operation| operation["id"] == "zalo.webhook.verify"
                    && operation.get("implemented").and_then(Value::as_bool) == Some(true))
        );

        let self_check = connector
            .handle_self_check()
            .await
            .expect("self_check should succeed");
        assert_eq!(self_check["status"], "degraded");
        assert_eq!(self_check["reason_code"], PARTIAL_SURFACE_REASON_CODE);
    }

    #[fcp_async_core::runtime::test]
    async fn planned_operation_invoke_and_simulate_refuse_execution() {
        let mut connector = ZaloConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let error = connector
            .handle_invoke(json!({"operation_id": "zalo.messages.send"}))
            .await
            .expect_err("invoke should refuse planned operation");
        assert!(error.to_string().contains("not implemented"));

        let simulate = connector
            .handle_simulate(json!({"operation_id": "zalo.messages.send"}))
            .await
            .expect("simulate should succeed");
        assert_eq!(simulate["allowed"], false);
        assert_eq!(simulate["simulate_capability"], "unsupported");
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_verify_uses_configured_challenge_without_upstream_stub() {
        let mut connector = ZaloConnector::new();
        let configure = connector
            .handle_configure(json!({"webhook_verify_challenge": "expected-challenge"}))
            .await
            .expect("configure should succeed");
        assert_eq!(configure["webhook_verify_configured"], true);
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let good = connector
            .handle_invoke(json!({
                "operation_id": "zalo.webhook.verify",
                "input": { "token": "expected-challenge" }
            }))
            .await
            .expect("matching token should verify");
        assert_eq!(good["verified"], true);

        let bad = connector
            .handle_invoke(json!({
                "operation_id": "zalo.webhook.verify",
                "input": { "token": "wrong-challenge" }
            }))
            .await
            .expect("mismatched token should return a negative verification result");
        assert_eq!(bad["verified"], false);

        let simulate = connector
            .handle_simulate(json!({
                "operation_id": "zalo.webhook.verify",
                "input": { "token": "expected-challenge" }
            }))
            .await
            .expect("simulate should succeed");
        assert_eq!(simulate["allowed"], true);
        assert_eq!(simulate["simulate_capability"], "local_validation");

        let bad_simulate = connector
            .handle_simulate(json!({
                "operation_id": "zalo.webhook.verify",
                "input": { "token": "wrong-challenge" }
            }))
            .await
            .expect("simulate should succeed for mismatched token");
        assert_eq!(bad_simulate["allowed"], false);
        assert!(
            bad_simulate["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("would not match"))
        );
    }

    #[test]
    fn constant_time_eq_matches_equal_byte_strings_only() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"Secret"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
        assert!(!constant_time_eq(b"secret", b""));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_error_paths_are_ordered_and_specific() {
        let mut connector = ZaloConnector::new();

        let unconfigured = connector
            .handle_invoke(json!({"operation_id": "zalo.messages.send"}))
            .await
            .expect_err("invoke should require configure first");
        assert!(matches!(unconfigured, FcpError::NotConfigured));

        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        let not_handshaken = connector
            .handle_invoke(json!({"operation_id": "zalo.messages.send"}))
            .await
            .expect_err("invoke should require handshake after configure");
        assert!(matches!(not_handshaken, FcpError::NotHandshaken));

        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");
        let missing_operation = connector
            .handle_invoke(json!({}))
            .await
            .expect_err("invoke should reject missing operation id");
        assert!(matches!(
            missing_operation,
            FcpError::InvalidRequest { code: 1003, ref message }
                if message.contains("Missing operation_id")
        ));

        let unknown_operation = connector
            .handle_invoke(json!({"operation_id": "zalo.unknown"}))
            .await
            .expect_err("invoke should reject unknown operations");
        assert!(matches!(
            unknown_operation,
            FcpError::InvalidRequest { code: 1002, ref message }
                if message.contains("Unknown operation: zalo.unknown")
        ));
    }
}
