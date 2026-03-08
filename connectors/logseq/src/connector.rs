//! FCP `Logseq` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, LogseqAuth, LogseqClient},
    error::LogseqError,
};

/// Parsed and validated `Logseq` connector configuration.
#[derive(Debug, Clone)]
struct LogseqConfig {
    auth: LogseqAuth,
    base_url: String,
}

impl LogseqConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
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

        let auth = match (access_token, credential_id) {
            (Some(token), None) => LogseqAuth::BearerToken(token),
            (None, Some(cred_id)) => LogseqAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of access_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing access_token or credential_id in configuration".into(),
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

/// FCP `Logseq` Connector.
pub struct LogseqConnector {
    base: Arc<BaseConnector>,
    config: Option<LogseqConfig>,
    client: Option<Arc<LogseqClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl LogseqConnector {
    /// Create a new `Logseq` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("logseq"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for LogseqConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl LogseqConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = LogseqConfig::from_params(&params)?;
        info!(
            auth = %config.auth.redacted_label(),
            base_url = %config.base_url,
            "Configuring Logseq connector"
        );

        let client = LogseqClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.logseq",
            "connector_version": "0.1.0",
            "capabilities": [
                "logseq.pages.read",
                "logseq.blocks.read",
                "logseq.blocks.write"
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
            "connector_id": "fcp.logseq",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.logseq",
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
            "logseq.pages.list" => self.invoke_pages_list(client).await,
            "logseq.pages.get" => self.invoke_pages_get(client, &input).await,
            "logseq.blocks.list" => self.invoke_blocks_list(client, &input).await,
            "logseq.blocks.create" => self.invoke_blocks_create(client, &input).await,
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
        info!("Logseq connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_pages_list(
        &self,
        client: &LogseqClient,
    ) -> Result<serde_json::Value, LogseqError> {
        let data = client.list_pages().await?;
        Ok(data)
    }

    async fn invoke_pages_get(
        &self,
        client: &LogseqClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LogseqError> {
        let name = require_str(input, "name")?;
        let data = client.get_page(name).await?;
        Ok(data)
    }

    async fn invoke_blocks_list(
        &self,
        client: &LogseqClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LogseqError> {
        let page = require_str(input, "page")?;
        let data = client.list_blocks(page).await?;
        Ok(data)
    }

    async fn invoke_blocks_create(
        &self,
        client: &LogseqClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LogseqError> {
        let page = require_str(input, "page")?;
        let content = require_str(input, "content")?;
        let data = client.create_block(page, content).await?;
        Ok(data)
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, LogseqError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| LogseqError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "logseq.pages.list",
            "summary": "List all pages in the graph",
            "capability": "logseq.pages.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "logseq.pages.get",
            "summary": "Get a page by name",
            "capability": "logseq.pages.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "logseq.blocks.list",
            "summary": "List blocks on a page",
            "capability": "logseq.blocks.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "logseq.blocks.create",
            "summary": "Create a block on a page",
            "capability": "logseq.blocks.write",
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
    fn config_from_access_token() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, LogseqAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = LogseqConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://localhost:9999/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "http://localhost:9999/api");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = LogseqConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = LogseqConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = LogseqConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = LogseqConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = LogseqConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = LogseqConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config = LogseqConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            LogseqAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            LogseqAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn require_str_present() {
        let input = json!({"name": "Daily Notes"});
        assert_eq!(require_str(&input, "name").unwrap(), "Daily Notes");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"name": 42});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"name": null});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"name": true});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"name": ["a", "b"]});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"name": ""});
        assert_eq!(require_str(&input, "name").unwrap(), "");
    }

    #[test]
    fn operations_info_has_4_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 4);
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
        assert!(ids.contains(&"logseq.pages.list"));
        assert!(ids.contains(&"logseq.pages.get"));
        assert!(ids.contains(&"logseq.blocks.list"));
        assert!(ids.contains(&"logseq.blocks.create"));
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
    fn operations_pages_list_capability() {
        let ops = operations_info();
        let pages_list = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.pages.list")
            .unwrap();
        assert_eq!(pages_list["capability"], "logseq.pages.read");
    }

    #[test]
    fn operations_blocks_create_capability() {
        let ops = operations_info();
        let bc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.blocks.create")
            .unwrap();
        assert_eq!(bc["capability"], "logseq.blocks.write");
    }

    #[test]
    fn operations_pages_get_capability() {
        let ops = operations_info();
        let pg = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.pages.get")
            .unwrap();
        assert_eq!(pg["capability"], "logseq.pages.read");
    }

    #[test]
    fn operations_blocks_list_capability() {
        let ops = operations_info();
        let bl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.blocks.list")
            .unwrap();
        assert_eq!(bl["capability"], "logseq.blocks.read");
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
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(!v.contains("message"));
    }

    #[test]
    fn doctor_check_serializes_message_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(v.contains("failed"));
    }

    #[test]
    fn connector_default() {
        let c = LogseqConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = LogseqConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_default_base_url() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn doctor_status_serializes_lowercase() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v2 = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v2, "degraded");
        let v3 = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v3, "unhealthy");
    }

    #[test]
    fn doctor_status_deserializes() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_check_debug_format() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("test_check"));
    }

    #[test]
    fn doctor_result_debug_format() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn require_str_nested_object() {
        let input = json!({"name": {"nested": true}});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn operations_blocks_create_is_risky() {
        let ops = operations_info();
        let bc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.blocks.create")
            .unwrap();
        assert_eq!(bc["safety_tier"], "risky");
        assert_eq!(bc["risk_level"], "medium");
    }

    #[test]
    fn operations_blocks_create_not_idempotent() {
        let ops = operations_info();
        let bc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.blocks.create")
            .unwrap();
        assert_eq!(bc["idempotency"], "none");
    }

    #[test]
    fn operations_pages_list_is_strict() {
        let ops = operations_info();
        let pl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "logseq.pages.list")
            .unwrap();
        assert_eq!(pl["idempotency"], "strict");
    }

    #[test]
    fn connector_new_request_count_zero() {
        let c = LogseqConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_new_error_count_zero() {
        let c = LogseqConnector::new();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_clone_preserves_base_url() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://custom:9999/api",
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, "http://custom:9999/api");
        assert_eq!(cloned.base_url, "http://custom:9999/api");
    }

    #[test]
    fn config_debug_does_not_leak_token() {
        let config = LogseqConfig::from_params(&json!({
            "access_token": "super-secret-logseq-token",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("LogseqConfig"));
        assert!(!dbg.contains("super-secret-logseq-token"));
    }

    #[test]
    fn operations_summaries_are_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_capabilities_have_logseq_prefix() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("logseq."),
                "capability {cap} missing logseq prefix for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn doctor_status_copy_semantics() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
        assert_eq!(s, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_deserialize_unhealthy() {
        let v = json!({"status": "unhealthy", "checks": [{"name": "cfg", "passed": false, "critical": true}]});
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert!(!r.checks[0].passed);
        assert!(r.checks[0].critical);
    }

    #[test]
    fn doctor_check_clone_preserves_message() {
        let check = DoctorCheck {
            name: "connectivity".into(),
            passed: false,
            message: Some("server not reachable".into()),
            critical: true,
        };
        let cloned = check.clone();
        assert_eq!(check.name, "connectivity");
        assert_eq!(cloned.message, Some("server not reachable".into()));
    }

    #[test]
    fn doctor_result_clone_preserves_checks() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
        assert_eq!(cloned.checks[0].name, "a");
    }

    #[test]
    fn require_str_with_float_value() {
        let input = json!({"page": 1.23});
        assert!(require_str(&input, "page").is_err());
    }

    #[test]
    fn operations_all_ids_have_logseq_prefix() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("logseq."),
                "op id {id} missing logseq prefix"
            );
        }
    }

    #[test]
    fn operations_idempotency_values_valid() {
        let valid = ["strict", "none", "idempotent"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idem),
                "invalid idempotency {idem} for {:?}",
                op["id"]
            );
        }
    }
}
