//! FCP `Pulumi` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, PulumiAuth, PulumiClient},
    error::PulumiError,
};

/// Parsed and validated `Pulumi` connector configuration.
#[derive(Debug, Clone)]
struct PulumiConfig {
    auth: PulumiAuth,
    base_url: String,
}

impl PulumiConfig {
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
            (Some(key), None) => PulumiAuth::BearerToken(key),
            (None, Some(cred_id)) => PulumiAuth::CredentialId(cred_id),
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

/// FCP `Pulumi` Connector.
pub struct PulumiConnector {
    base: Arc<BaseConnector>,
    config: Option<PulumiConfig>,
    client: Option<Arc<PulumiClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl PulumiConnector {
    /// Create a new `Pulumi` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("pulumi"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for PulumiConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PulumiConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = PulumiConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Pulumi connector");

        let client = PulumiClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.pulumi",
            "connector_version": "0.1.0",
            "capabilities": [
                "pulumi.stacks.read",
                "pulumi.stacks.write",
                "pulumi.deployments.read"
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
            "connector_id": "fcp.pulumi",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.pulumi",
            "version": "0.1.0",
            "operations": operations_info(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params.get("operation_id").and_then(serde_json::Value::as_str).ok_or_else(|| {
            FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            }
        })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "pulumi.stacks.list" => self.invoke_stacks_list(client, &input).await,
            "pulumi.stacks.get" => self.invoke_stacks_get(client, &input).await,
            "pulumi.stacks.create" => self.invoke_stacks_create(client, &input).await,
            "pulumi.stacks.delete" => self.invoke_stacks_delete(client, &input).await,
            "pulumi.stacks.export" => self.invoke_stacks_export(client, &input).await,
            "pulumi.deployments.list" => self.invoke_deployments_list(client, &input).await,
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
        info!("Pulumi connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_stacks_list(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = input.get("organization").and_then(serde_json::Value::as_str);
        let project = input.get("project").and_then(serde_json::Value::as_str);
        client.list_stacks(organization, project).await
    }

    async fn invoke_stacks_get(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = require_str(input, "organization")?;
        let project = require_str(input, "project")?;
        let stack = require_str(input, "stack")?;
        client.get_stack(organization, project, stack).await
    }

    async fn invoke_stacks_create(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = require_str(input, "organization")?;
        let project = require_str(input, "project")?;
        let stack = require_str(input, "stack")?;
        client.create_stack(organization, project, stack).await
    }

    async fn invoke_stacks_delete(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = require_str(input, "organization")?;
        let project = require_str(input, "project")?;
        let stack = require_str(input, "stack")?;
        client.delete_stack(organization, project, stack).await
    }

    async fn invoke_stacks_export(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = require_str(input, "organization")?;
        let project = require_str(input, "project")?;
        let stack = require_str(input, "stack")?;
        client.export_stack(organization, project, stack).await
    }

    async fn invoke_deployments_list(
        &self,
        client: &PulumiClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PulumiError> {
        let organization = require_str(input, "organization")?;
        let project = require_str(input, "project")?;
        let stack = require_str(input, "stack")?;
        client.list_deployments(organization, project, stack).await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, PulumiError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PulumiError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "pulumi.stacks.list",
            "summary": "List stacks in an organization",
            "capability": "pulumi.stacks.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "pulumi.stacks.get",
            "summary": "Get stack details including outputs",
            "capability": "pulumi.stacks.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "pulumi.stacks.create",
            "summary": "Create a new stack",
            "capability": "pulumi.stacks.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "pulumi.stacks.delete",
            "summary": "Delete a stack",
            "capability": "pulumi.stacks.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
        {
            "id": "pulumi.stacks.export",
            "summary": "Export stack state as a deployment checkpoint",
            "capability": "pulumi.stacks.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "pulumi.deployments.list",
            "summary": "List recent deployments for a stack",
            "capability": "pulumi.deployments.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_access_token() {
        let config = PulumiConfig::from_params(&json!({
            "access_token": "pul-abc123",
        }))
        .unwrap();
        assert!(matches!(config.auth, PulumiAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = PulumiConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = PulumiConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://pulumi.example.com/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://pulumi.example.com/api");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = PulumiConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = PulumiConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = PulumiConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = PulumiConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = PulumiConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = PulumiConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"organization": "myorg"});
        assert_eq!(require_str(&input, "organization").unwrap(), "myorg");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"organization": 42});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"organization": null});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn operations_info_has_6_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 6);
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
        assert!(ids.contains(&"pulumi.stacks.list"));
        assert!(ids.contains(&"pulumi.stacks.get"));
        assert!(ids.contains(&"pulumi.stacks.create"));
        assert!(ids.contains(&"pulumi.stacks.delete"));
        assert!(ids.contains(&"pulumi.stacks.export"));
        assert!(ids.contains(&"pulumi.deployments.list"));
    }

    #[test]
    fn operations_capabilities_match_manifest() {
        let ops = operations_info();
        let caps: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["capability"].as_str())
            .collect();
        assert!(caps.contains(&"pulumi.stacks.read"));
        assert!(caps.contains(&"pulumi.stacks.write"));
        assert!(caps.contains(&"pulumi.deployments.read"));
    }

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
            DoctorCheck { name: "a".into(), passed: true, message: None, critical: true },
            DoctorCheck { name: "b".into(), passed: true, message: None, critical: false },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_when_non_critical_fails() {
        let checks = vec![
            DoctorCheck { name: "a".into(), passed: true, message: None, critical: true },
            DoctorCheck { name: "b".into(), passed: false, message: Some("warn".into()), critical: false },
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
    fn connector_default() {
        let c = PulumiConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_equals_default() {
        let c = PulumiConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(v.get("message").is_none(), "message should be skipped when None");
    }

    #[test]
    fn doctor_check_serializes_message_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("error detail".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "error detail");
    }

    #[test]
    fn doctor_check_roundtrip() {
        let check = DoctorCheck {
            name: "connectivity".into(),
            passed: true,
            message: Some("All good".into()),
            critical: false,
        };
        let serialized = serde_json::to_string(&check).unwrap();
        let back: DoctorCheck = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.name, "connectivity");
        assert_eq!(back.message, Some("All good".into()));
    }

    #[test]
    fn doctor_status_values_serialize_lowercase() {
        assert_eq!(serde_json::to_value(DoctorStatus::Healthy).unwrap(), "healthy");
        assert_eq!(serde_json::to_value(DoctorStatus::Degraded).unwrap(), "degraded");
        assert_eq!(serde_json::to_value(DoctorStatus::Unhealthy).unwrap(), "unhealthy");
    }

    #[test]
    fn doctor_status_debug() {
        assert!(format!("{:?}", DoctorStatus::Healthy).contains("Healthy"));
        assert!(format!("{:?}", DoctorStatus::Degraded).contains("Degraded"));
        assert!(format!("{:?}", DoctorStatus::Unhealthy).contains("Unhealthy"));
    }

    #[test]
    fn doctor_status_clone_copy() {
        let s = DoctorStatus::Healthy;
        let c = s;
        assert_eq!(s, c);
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        for status in [DoctorStatus::Healthy, DoctorStatus::Degraded, DoctorStatus::Unhealthy] {
            let s = serde_json::to_string(&status).unwrap();
            let back: DoctorStatus = serde_json::from_str(&s).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck { name: "a".into(), passed: false, message: None, critical: true },
            DoctorCheck { name: "b".into(), passed: false, message: None, critical: true },
        ]);
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_serializes_with_message() {
        let result = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: false,
            message: Some("detail".into()),
            critical: false,
        }]);
        let v = serde_json::to_value(&result).unwrap();
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["checks"][0]["message"], "detail");
    }

    #[test]
    fn operations_delete_is_dangerous() {
        let ops = operations_info();
        let delete_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "pulumi.stacks.delete")
            .unwrap();
        assert_eq!(delete_op["safety_tier"], "dangerous");
        assert_eq!(delete_op["risk_level"], "high");
    }

    #[test]
    fn operations_create_is_risky() {
        let ops = operations_info();
        let create_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "pulumi.stacks.create")
            .unwrap();
        assert_eq!(create_op["safety_tier"], "risky");
        assert_eq!(create_op["risk_level"], "medium");
    }

    #[test]
    fn operations_export_capability() {
        let ops = operations_info();
        let export_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "pulumi.stacks.export")
            .unwrap();
        assert_eq!(export_op["capability"], "pulumi.stacks.read");
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(op.get("idempotency").is_some(), "op {:?} missing idempotency", op["id"]);
        }
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"organization": ""});
        assert_eq!(require_str(&input, "organization").unwrap(), "");
    }

    #[test]
    fn require_str_with_array_value() {
        let input = json!({"organization": [1, 2, 3]});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"organization": {"nested": true}});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn require_str_with_bool_value() {
        let input = json!({"organization": true});
        assert!(require_str(&input, "organization").is_err());
    }

    #[test]
    fn require_str_error_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "project").unwrap_err();
        match err {
            PulumiError::Api { message, .. } => {
                assert!(message.contains("project"));
            }
            e => panic!("expected Api, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_both_auth_error_message() {
        let result = PulumiConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_no_auth_error_message() {
        let result = PulumiConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("access_token") || message.contains("credential_id"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_non_string_credential_error_message() {
        let result = PulumiConfig::from_params(&json!({"credential_id": 42}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("must be a string"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_invalid_uuid_credential_error_message() {
        let result = PulumiConfig::from_params(&json!({"credential_id": "not-valid"}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("valid UUID"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_default_base_url_when_absent() {
        let config = PulumiConfig::from_params(&json!({"access_token": "tok"})).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_trims_access_token() {
        let config = PulumiConfig::from_params(&json!({"access_token": "  pul-abc  "})).unwrap();
        match &config.auth {
            PulumiAuth::BearerToken(t) => assert_eq!(t, "pul-abc"),
            PulumiAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }
}
