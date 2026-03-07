//! FCP Zapier Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, ZapierAuth, ZapierClient},
    error::ZapierError,
};

/// Parsed and validated Zapier connector configuration.
#[derive(Debug, Clone)]
struct ZapierConfig {
    auth: ZapierAuth,
    base_url: String,
}

impl ZapierConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "credential_id must be a string".into(),
                })?;
                Some(
                    CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?,
                )
            }
            None => None,
        };

        let auth = match (api_key, credential_id) {
            (Some(key), None) => ZapierAuth::BearerToken(key),
            (None, Some(cred_id)) => ZapierAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self { auth, base_url })
    }
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP Zapier Connector.
pub struct ZapierConnector {
    base: Arc<BaseConnector>,
    config: Option<ZapierConfig>,
    client: Option<Arc<ZapierClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl ZapierConnector {
    /// Create a new Zapier connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("zapier"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for ZapierConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl ZapierConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = ZapierConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Zapier connector");

        let client = ZapierClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        let session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.zapier",
            "connector_version": "0.1.0",
            "capabilities": [
                "zapier.zaps.read",
                "zapier.zaps.write"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();

        let status = if configured && handshaken {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured -- call configure first".into())
            } else {
                None
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_none() {
                Some("API client not initialized".into())
            } else {
                None
            },
            critical: true,
        });

        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: if handshaken {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.zapier",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.zapier",
            "version": "0.1.0",
            "operations": operations_info(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "zapier.zaps.list" => self.invoke_zaps_list(client).await,
            "zapier.zaps.execute" => self.invoke_zaps_execute(client, &input).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|e| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(serde_json::Value::as_str) == Some(operation))
        });

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Zapier connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_zaps_list(
        &self,
        client: &ZapierClient,
    ) -> Result<serde_json::Value, ZapierError> {
        let resp = client.list_zaps().await?;
        // Zapier may return the zaps as a top-level array or under a "zaps" key.
        let zaps = if resp.is_array() {
            resp
        } else {
            resp.get("zaps").cloned().unwrap_or_else(|| json!([]))
        };
        Ok(json!({ "zaps": zaps }))
    }

    async fn invoke_zaps_execute(
        &self,
        client: &ZapierClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ZapierError> {
        let action_id = require_str(input, "action_id")?;
        let params = input.get("params").cloned().unwrap_or_else(|| json!({}));
        let resp = client.execute_action(action_id, &params).await?;
        Ok(json!({ "result": resp }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, ZapierError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ZapierError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "zapier.zaps.list",
            "summary": "List zaps for the authenticated user",
            "capability": "zapier.zaps.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
            "input_schema": {
                "type": "object",
                "required": [],
                "properties": {}
            },
            "output_schema": {
                "type": "object",
                "required": ["zaps"],
                "properties": {
                    "zaps": {"type": "array"}
                }
            }
        },
        {
            "id": "zapier.zaps.execute",
            "summary": "Execute a zap action",
            "capability": "zapier.zaps.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
            "input_schema": {
                "type": "object",
                "required": ["action_id", "params"],
                "properties": {
                    "action_id": {"type": "string", "description": "NLA action ID"},
                    "params": {"type": "object", "description": "Action parameters"}
                }
            },
            "output_schema": {
                "type": "object",
                "required": ["result"],
                "properties": {
                    "result": {"type": "object"}
                }
            }
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_api_key() {
        let config = ZapierConfig::from_params(&json!({
            "api_key": "test-api-key",
        }))
        .unwrap();
        assert!(matches!(config.auth, ZapierAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = ZapierConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = ZapierConfig::from_params(&json!({
            "api_key": "tok",
            "base_url": "https://zapier.example.com/v1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://zapier.example.com/v1");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = ZapierConfig::from_params(&json!({
            "api_key": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = ZapierConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = ZapierConfig::from_params(&json!({
            "api_key": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = ZapierConfig::from_params(&json!({
            "api_key": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = ZapierConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = ZapierConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_api_key() {
        let config = ZapierConfig::from_params(&json!({ "api_key": "  sk_test  " })).unwrap();
        match &config.auth {
            ZapierAuth::BearerToken(t) => assert_eq!(t, "sk_test"),
            ZapierAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn config_default_base_url_when_absent() {
        let config = ZapierConfig::from_params(&json!({ "api_key": "tok" })).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn require_str_present() {
        let input = json!({"action_id": "act_abc"});
        assert_eq!(require_str(&input, "action_id").unwrap(), "act_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "action_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"action_id": 42});
        assert!(require_str(&input, "action_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"action_id": null});
        assert!(require_str(&input, "action_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"action_id": true});
        assert!(require_str(&input, "action_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"action_id": [1, 2, 3]});
        assert!(require_str(&input, "action_id").is_err());
    }

    #[test]
    fn operations_info_has_2_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(op.get("id").is_some(), "missing id");
            assert!(op.get("summary").is_some(), "missing summary");
            assert!(op.get("capability").is_some(), "missing capability");
            assert!(op.get("risk_level").is_some(), "missing risk_level");
            assert!(op.get("safety_tier").is_some(), "missing safety_tier");
        }
    }

    #[test]
    fn operations_all_have_schemas() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("input_schema").is_some(),
                "missing input_schema for {:?}",
                op["id"]
            );
            assert!(
                op.get("output_schema").is_some(),
                "missing output_schema for {:?}",
                op["id"]
            );
            assert_eq!(
                op["input_schema"]["type"].as_str().unwrap(),
                "object",
                "input_schema type should be object"
            );
            assert_eq!(
                op["output_schema"]["type"].as_str().unwrap(),
                "object",
                "output_schema type should be object"
            );
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "read op {} should be low risk",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"zapier.zaps.list"));
        assert!(ids.contains(&"zapier.zaps.execute"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_list_is_strict_idempotent() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "zapier.zaps.list")
            .unwrap();
        assert_eq!(list_op["idempotency"].as_str().unwrap(), "strict");
    }

    #[test]
    fn operations_execute_is_not_idempotent() {
        let ops = operations_info();
        let exec_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "zapier.zaps.execute")
            .unwrap();
        assert_eq!(exec_op["idempotency"].as_str().unwrap(), "none");
    }

    #[test]
    fn operations_execute_has_required_input_fields() {
        let ops = operations_info();
        let exec_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "zapier.zaps.execute")
            .unwrap();
        let required = exec_op["input_schema"]["required"].as_array().unwrap();
        let req_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(req_strs.contains(&"action_id"));
        assert!(req_strs.contains(&"params"));
    }

    #[test]
    fn operations_list_has_no_required_input() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "zapier.zaps.list")
            .unwrap();
        let required = list_op["input_schema"]["required"].as_array().unwrap();
        assert!(required.is_empty());
    }

    #[test]
    fn operations_list_output_has_zaps() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "zapier.zaps.list")
            .unwrap();
        let required = list_op["output_schema"]["required"].as_array().unwrap();
        assert!(
            required
                .iter()
                .filter_map(|v| v.as_str())
                .any(|s| s == "zaps")
        );
    }

    #[test]
    fn operations_execute_output_has_result() {
        let ops = operations_info();
        let exec_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "zapier.zaps.execute")
            .unwrap();
        let required = exec_op["output_schema"]["required"].as_array().unwrap();
        assert!(
            required
                .iter()
                .filter_map(|v| v.as_str())
                .any(|s| s == "result")
        );
    }

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_when_non_critical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_check_skips_none_message_in_serialization() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_includes_some_message_in_serialization() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failed");
    }

    #[test]
    fn connector_default() {
        let c = ZapierConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = ZapierConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn operations_write_ops_are_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".write") {
                assert_ne!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "write op {} should not be safe",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_capabilities_match_manifest() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "zapier.zaps.list")
            .unwrap();
        assert_eq!(list_op["capability"].as_str().unwrap(), "zapier.zaps.read");
        let exec_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "zapier.zaps.execute")
            .unwrap();
        assert_eq!(exec_op["capability"].as_str().unwrap(), "zapier.zaps.write");
    }

    #[test]
    fn doctor_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            "healthy"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            "degraded"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            "unhealthy"
        );
    }

    #[test]
    fn doctor_status_deserializes() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
    }

    #[test]
    fn require_str_nested_object() {
        let input = json!({"action_id": {"nested": true}});
        assert!(require_str(&input, "action_id").is_err());
    }

    #[test]
    fn require_str_empty_string_is_valid() {
        let input = json!({"action_id": ""});
        assert_eq!(require_str(&input, "action_id").unwrap(), "");
    }

    #[test]
    fn operations_execute_is_risky() {
        let ops = operations_info();
        let exec_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "zapier.zaps.execute")
            .unwrap();
        assert_eq!(exec_op["safety_tier"], "risky");
        assert_eq!(exec_op["risk_level"], "medium");
    }

    #[test]
    fn operations_list_is_safe() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "zapier.zaps.list")
            .unwrap();
        assert_eq!(list_op["safety_tier"], "safe");
        assert_eq!(list_op["risk_level"], "low");
    }

    #[test]
    fn doctor_check_debug_format() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_result_debug_format() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn connector_new_session_is_none() {
        let c = ZapierConnector::new();
        assert!(c.session_id.is_none());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "config".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let cloned = check.clone();
        assert_eq!(check.name, "config");
        assert!(cloned.passed);
        assert_eq!(cloned.message, Some("ok".into()));
        assert!(cloned.critical);
    }

    #[test]
    fn doctor_status_copy_trait() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
        assert_eq!(s, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_debug_format() {
        let dbg = format!("{:?}", DoctorStatus::Unhealthy);
        assert!(dbg.contains("Unhealthy"));
    }

    #[test]
    fn doctor_result_unhealthy_overrides_degraded() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: None,
                critical: false,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "c1".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }
}
