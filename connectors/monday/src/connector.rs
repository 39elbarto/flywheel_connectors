//! FCP Monday.com Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{MondayAuth, MondayClient, DEFAULT_BASE_URL},
    error::MondayError,
};

/// Parsed and validated Monday.com connector configuration.
#[derive(Debug, Clone)]
struct MondayConfig {
    auth: MondayAuth,
    base_url: String,
}

impl MondayConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_token = params
            .get("api_token")
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

        let auth = match (api_token, credential_id) {
            (Some(key), None) => MondayAuth::ApiToken(key),
            (None, Some(cred_id)) => MondayAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_token or credential_id in configuration".into(),
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

/// FCP Monday.com Connector.
pub struct MondayConnector {
    base: Arc<BaseConnector>,
    config: Option<MondayConfig>,
    client: Option<Arc<MondayClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl MondayConnector {
    /// Create a new Monday.com connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("monday"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for MondayConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl MondayConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = MondayConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Monday.com connector");

        let client = MondayClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.monday",
            "connector_version": "0.1.0",
            "capabilities": [
                "monday.boards.read",
                "monday.items.read",
                "monday.items.write",
                "monday.updates.read",
                "monday.updates.write"
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
                Some("Not configured — call configure first".into())
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
            "connector_id": "fcp.monday",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.monday",
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
            "monday.boards.list" => self.invoke_boards_list(client, &input).await,
            "monday.boards.get" => self.invoke_boards_get(client, &input).await,
            "monday.items.list" => self.invoke_items_list(client, &input).await,
            "monday.items.create" => self.invoke_items_create(client, &input).await,
            "monday.items.delete" => self.invoke_items_delete(client, &input).await,
            "monday.updates.list" => self.invoke_updates_list(client, &input).await,
            "monday.updates.create" => self.invoke_updates_create(client, &input).await,
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
        info!("Monday.com connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_boards_list(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(25);
        let resp = client.list_boards(limit).await?;
        let boards = resp.get("boards").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "boards": boards }))
    }

    async fn invoke_items_list(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let board_id = require_str(input, "board_id")?;
        let resp = client.list_items(board_id).await?;
        let items = resp
            .get("boards")
            .and_then(|b| b.as_array())
            .and_then(|a| a.first())
            .and_then(|b| b.get("items_page"))
            .and_then(|ip| ip.get("items"))
            .cloned()
            .unwrap_or_else(|| json!([]));
        Ok(json!({ "items": items }))
    }

    async fn invoke_items_create(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let board_id = require_str(input, "board_id")?;
        let item_name = require_str(input, "item_name")?;
        let column_values = input
            .get("column_values")
            .map(|v| v.to_string());
        let resp = client
            .create_item(board_id, item_name, column_values.as_deref())
            .await?;
        let item_id = resp
            .get("create_item")
            .and_then(|ci| ci.get("id"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Ok(json!({ "id": item_id }))
    }

    async fn invoke_items_delete(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let item_id = require_str(input, "item_id")?;
        client.delete_item(item_id).await?;
        Ok(json!({}))
    }

    async fn invoke_boards_get(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let board_id = require_str(input, "board_id")?;
        let resp = client.get_board(board_id).await?;
        let board = resp
            .get("boards")
            .and_then(|b| b.as_array())
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Ok(json!({ "board": board }))
    }

    async fn invoke_updates_list(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let item_id = require_str(input, "item_id")?;
        let resp = client.list_updates(item_id).await?;
        let updates = resp
            .get("items")
            .and_then(|i| i.as_array())
            .and_then(|a| a.first())
            .and_then(|i| i.get("updates"))
            .cloned()
            .unwrap_or_else(|| json!([]));
        Ok(json!({ "updates": updates }))
    }

    async fn invoke_updates_create(
        &self,
        client: &MondayClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MondayError> {
        let item_id = require_str(input, "item_id")?;
        let body = require_str(input, "body")?;
        let resp = client.create_update(item_id, body).await?;
        let update = resp
            .get("create_update")
            .cloned()
            .unwrap_or_else(|| json!({}));
        Ok(update)
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, MondayError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MondayError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "monday.boards.list",
            "summary": "List boards",
            "capability": "monday.boards.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "monday.boards.get",
            "summary": "Get a board by ID",
            "capability": "monday.boards.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "monday.items.list",
            "summary": "List items on a board",
            "capability": "monday.items.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "monday.items.create",
            "summary": "Create a new item on a board",
            "capability": "monday.items.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "monday.items.delete",
            "summary": "Delete an item",
            "capability": "monday.items.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
        {
            "id": "monday.updates.list",
            "summary": "List updates on an item",
            "capability": "monday.updates.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "monday.updates.create",
            "summary": "Create an update on an item",
            "capability": "monday.updates.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_api_token() {
        let config = MondayConfig::from_params(&json!({
            "api_token": "test-api-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, MondayAuth::ApiToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = MondayConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = MondayConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://monday.example.com/v2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://monday.example.com/v2");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = MondayConfig::from_params(&json!({
            "api_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = MondayConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_token() {
        let result = MondayConfig::from_params(&json!({
            "api_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_token() {
        let result = MondayConfig::from_params(&json!({
            "api_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = MondayConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = MondayConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_api_token() {
        let config = MondayConfig::from_params(&json!({ "api_token": "  tok_test  " })).unwrap();
        match &config.auth {
            MondayAuth::ApiToken(t) => assert_eq!(t, "tok_test"),
            MondayAuth::CredentialId(_) => panic!("expected ApiToken"),
        }
    }

    #[test]
    fn require_str_present() {
        let input = json!({"board_id": "123"});
        assert_eq!(require_str(&input, "board_id").unwrap(), "123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "board_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"board_id": 42});
        assert!(require_str(&input, "board_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"board_id": null});
        assert!(require_str(&input, "board_id").is_err());
    }

    #[test]
    fn operations_info_has_7_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 7);
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
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
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
        assert!(ids.contains(&"monday.boards.list"));
        assert!(ids.contains(&"monday.boards.get"));
        assert!(ids.contains(&"monday.items.list"));
        assert!(ids.contains(&"monday.items.create"));
        assert!(ids.contains(&"monday.items.delete"));
        assert!(ids.contains(&"monday.updates.list"));
        assert!(ids.contains(&"monday.updates.create"));
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
    fn connector_default() {
        let c = MondayConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_request_count_zero() {
        let c = MondayConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_check_skip_serializing_none_message() {
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
    fn doctor_check_includes_message_when_present() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failure reason".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failure reason");
    }

    #[test]
    fn doctor_check_serde_roundtrip() {
        let check = DoctorCheck {
            name: "config".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let s = serde_json::to_string(&check).unwrap();
        let check2: DoctorCheck = serde_json::from_str(&s).unwrap();
        assert_eq!(check2.name, "config");
        assert!(check2.passed);
        assert_eq!(check2.message, Some("ok".into()));
        assert!(check2.critical);
    }

    #[test]
    fn doctor_status_serde_healthy() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let ds: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(ds, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_serde_degraded() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let ds: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(ds, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_serde_unhealthy() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
        let ds: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(ds, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serde_roundtrip() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("issue".into()),
                critical: false,
            },
        ]);
        let s = serde_json::to_string(&r).unwrap();
        let r2: DoctorResult = serde_json::from_str(&s).unwrap();
        assert_eq!(r2.status, DoctorStatus::Degraded);
        assert_eq!(r2.checks.len(), 2);
    }

    #[test]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let check2 = check.clone();
        assert_eq!(check.name, check2.name);
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "y".into(),
            passed: false,
            message: None,
            critical: true,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![]);
        let r2 = r.clone();
        assert_eq!(r.status, r2.status);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"board_id": [1, 2, 3]});
        assert!(require_str(&input, "board_id").is_err());
    }

    #[test]
    fn require_str_bool_value() {
        let input = json!({"board_id": true});
        assert!(require_str(&input, "board_id").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"board_id": ""});
        assert_eq!(require_str(&input, "board_id").unwrap(), "");
    }

    #[test]
    fn operations_boards_list_capability() {
        let ops = operations_info();
        let bl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.boards.list")
            .unwrap();
        assert_eq!(bl["capability"], "monday.boards.read");
    }

    #[test]
    fn operations_boards_get_capability() {
        let ops = operations_info();
        let bg = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.boards.get")
            .unwrap();
        assert_eq!(bg["capability"], "monday.boards.read");
    }

    #[test]
    fn operations_items_create_capability() {
        let ops = operations_info();
        let ic = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.items.create")
            .unwrap();
        assert_eq!(ic["capability"], "monday.items.write");
    }

    #[test]
    fn operations_items_delete_is_dangerous() {
        let ops = operations_info();
        let id = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.items.delete")
            .unwrap();
        assert_eq!(id["safety_tier"], "dangerous");
        assert_eq!(id["risk_level"], "high");
    }

    #[test]
    fn operations_items_create_is_risky() {
        let ops = operations_info();
        let ic = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.items.create")
            .unwrap();
        assert_eq!(ic["safety_tier"], "risky");
        assert_eq!(ic["risk_level"], "medium");
    }

    #[test]
    fn operations_updates_create_is_risky() {
        let ops = operations_info();
        let uc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "monday.updates.create")
            .unwrap();
        assert_eq!(uc["safety_tier"], "risky");
        assert_eq!(uc["risk_level"], "medium");
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn operations_read_ops_are_strict_idempotent() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["idempotency"], "strict",
                    "read op {} should be strict",
                    op["id"]
                );
            }
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn operations_write_ops_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".write") {
                let idem = op["idempotency"].as_str().unwrap();
                // Write ops should have idempotency specified (none or strict)
                assert!(
                    idem == "none" || idem == "strict",
                    "write op {} has unexpected idempotency: {idem}",
                    op["id"]
                );
            }
        }
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
    fn doctor_result_mixed_critical_and_non_critical_failures() {
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
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_status_eq() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn write_operations_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
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
}
