//! FCP `Retool` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    Introspection, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{RetoolAuth, RetoolClient},
    error::RetoolError,
};

/// Parsed and validated `Retool` connector configuration.
#[derive(Debug, Clone)]
struct RetoolConfig {
    auth: RetoolAuth,
    subdomain: Option<String>,
    base_url: Option<String>,
}

impl RetoolConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_token = params
            .get("api_token")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty api_token in configuration".into(),
            })?
            .to_string();

        let subdomain = params
            .get("subdomain")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        Ok(Self {
            auth: RetoolAuth { api_token },
            subdomain,
            base_url,
        })
    }

    /// Resolve the effective base URL for policy checks.
    fn effective_base_url(&self) -> String {
        if let Some(ref url) = self.base_url {
            url.clone()
        } else {
            let sub = self.subdomain.as_deref().unwrap_or("app");
            format!("https://{sub}.retool.com/api/v1")
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let effective_url = self.effective_base_url();
        let (network_ok, network_message) = base_url_policy(&effective_url);

        ProvisioningReadiness {
            token_configured: true,
            network_ok,
            network_message,
            base_url: effective_url,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    token_configured: bool,
    network_ok: bool,
    network_message: String,
    base_url: String,
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

/// FCP `Retool` Connector.
pub struct RetoolConnector {
    base: Arc<BaseConnector>,
    config: Option<RetoolConfig>,
    client: Option<Arc<RetoolClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl RetoolConnector {
    /// Create a new `Retool` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("retool"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for RetoolConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl RetoolConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = RetoolConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), "Configuring Retool connector");

        let client = RetoolClient::new(
            config.auth.clone(),
            config.subdomain.as_deref(),
            config.base_url.as_deref(),
        )
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
            "connector_id": "fcp.retool",
            "connector_version": "0.1.0",
            "capabilities": [
                "retool.workflows.read",
                "retool.workflows.write"
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
        Ok(serde_json::to_value(result).unwrap_or(serde_json::Value::Null))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return Self::serialize_self_check_report(report);
        };

        let readiness = config.provisioning_readiness();
        if !readiness.network_ok {
            let mut report = SelfCheckReport::failed(
                "network_constraints_invalid",
                readiness.network_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let Some(_client) = &self.client else {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("retool.workflows.list"),
                    summary: "List workflows".into(),
                    input_schema: json!({"type": "object", "required": []}),
                    output_schema: json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "array"}}}),
                    capability: CapabilityId::from_static("retool.workflows.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List all Retool workflows.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("retool.workflows.run")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("retool.workflows.run"),
                    summary: "Trigger a workflow".into(),
                    input_schema: json!({"type": "object", "required": ["workflow_id"], "properties": {"workflow_id": {"type": "string", "description": "Workflow ID to trigger"}}}),
                    output_schema: json!({"type": "object", "required": ["data"], "properties": {"data": {"type": "object"}}}),
                    capability: CapabilityId::from_static("retool.workflows.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Trigger a Retool workflow to run.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"workflow_id": "wf_abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("retool.workflows.list")],
                    },
                },
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
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

        let input = params
            .get("input")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "retool.workflows.list" => self.invoke_workflows_list(client).await,
            "retool.workflows.run" => self.invoke_workflows_run(client, &input).await,
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
        info!("Retool connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "retool.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Retool self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // -- Operation implementations --

    async fn invoke_workflows_list(
        &self,
        client: &RetoolClient,
    ) -> Result<serde_json::Value, RetoolError> {
        let data = client.list_workflows().await?;
        Ok(data)
    }

    async fn invoke_workflows_run(
        &self,
        client: &RetoolClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RetoolError> {
        let workflow_id = require_str(input, "workflow_id")?;
        let body_data = input.get("body");
        let data = client.run_workflow(workflow_id, body_data).await?;
        Ok(data)
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, RetoolError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RetoolError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "retool.workflows.list",
            "summary": "List workflows",
            "capability": "retool.workflows.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "retool.workflows.run",
            "summary": "Trigger a workflow",
            "capability": "retool.workflows.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
    ])
}

/// Build the provisioning recipe for the `Retool` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("retool.api_key"),
        "1",
        "Provision `Retool` connector with an API key",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_api_key"),
        ProvisioningStepType::PromptSecret {
            message: "Paste your Retool API key".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_token".into(),
                value_from: StepId::new("enter_api_key"),
                scope: "connector:fcp.retool".into(),
            },
        )
        .depends_on(StepId::new("enter_api_key")),
    )
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("base_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    let local = is_local_test_host(host);
    let allowed_host =
        host.eq_ignore_ascii_case("retool.com") || host.ends_with(".retool.com") || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https and *.retool.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_valid_params() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok_abc123",
        }))
        .unwrap();
        assert_eq!(config.auth.api_token, "tok_abc123");
        assert!(config.subdomain.is_none());
        assert!(config.base_url.is_none());
    }

    #[test]
    fn config_with_subdomain() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok",
            "subdomain": "myorg",
        }))
        .unwrap();
        assert_eq!(config.subdomain, Some("myorg".into()));
    }

    #[test]
    fn config_with_custom_base_url() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://test.retool.com/api/v1",
        }))
        .unwrap();
        assert_eq!(
            config.base_url,
            Some("https://test.retool.com/api/v1".into())
        );
    }

    #[test]
    fn config_rejects_missing_api_token() {
        let result = RetoolConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_token() {
        let result = RetoolConfig::from_params(&json!({
            "api_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_token() {
        let result = RetoolConfig::from_params(&json!({
            "api_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_api_token() {
        let result = RetoolConfig::from_params(&json!({
            "api_token": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_api_token() {
        let result = RetoolConfig::from_params(&json!({
            "api_token": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_api_token() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "  tok  ",
        }))
        .unwrap();
        assert_eq!(config.auth.api_token, "tok");
    }

    #[test]
    fn config_rejects_boolean_api_token() {
        let result = RetoolConfig::from_params(&json!({
            "api_token": true,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_array_api_token() {
        let result = RetoolConfig::from_params(&json!({
            "api_token": ["tok1", "tok2"],
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_with_all_fields() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok_xyz",
            "subdomain": "acme",
            "base_url": "https://custom.retool.com/api/v1",
        }))
        .unwrap();
        assert_eq!(config.auth.api_token, "tok_xyz");
        assert_eq!(config.subdomain, Some("acme".into()));
        assert_eq!(
            config.base_url,
            Some("https://custom.retool.com/api/v1".into())
        );
    }

    #[test]
    fn require_str_present() {
        let input = json!({"workflow_id": "wf_abc"});
        assert_eq!(require_str(&input, "workflow_id").unwrap(), "wf_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "workflow_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"workflow_id": 42});
        assert!(require_str(&input, "workflow_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"workflow_id": null});
        assert!(require_str(&input, "workflow_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"workflow_id": true});
        assert!(require_str(&input, "workflow_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"workflow_id": ["a", "b"]});
        assert!(require_str(&input, "workflow_id").is_err());
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
        assert!(ids.contains(&"retool.workflows.list"));
        assert!(ids.contains(&"retool.workflows.run"));
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
    fn operations_list_is_safe() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "retool.workflows.list")
            .unwrap();
        assert_eq!(list_op["safety_tier"], "safe");
        assert_eq!(list_op["risk_level"], "low");
        assert_eq!(list_op["capability"], "retool.workflows.read");
    }

    #[test]
    fn operations_run_is_risky() {
        let ops = operations_info();
        let run_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "retool.workflows.run")
            .unwrap();
        assert_eq!(run_op["safety_tier"], "risky");
        assert_eq!(run_op["risk_level"], "medium");
        assert_eq!(run_op["capability"], "retool.workflows.write");
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
                message: Some("fail a".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail b".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn connector_default() {
        let c = RetoolConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = RetoolConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let c = check.clone();
        assert_eq!(c.name, "test");
        assert!(c.passed);
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "check1".into(),
            passed: false,
            message: None,
            critical: true,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![]);
        let c = r.clone();
        assert_eq!(c.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_status_serialize_all_variants() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            json!("healthy")
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            json!("degraded")
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            json!("unhealthy")
        );
    }

    #[test]
    fn doctor_status_deserialize_all_variants() {
        let h: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
        let u: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(u, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_check_skip_none_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(v.get("message").is_none());
    }

    #[test]
    fn doctor_check_with_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failure".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failure");
    }

    #[test]
    fn require_str_empty_string_returns_ok() {
        let input = json!({"field": ""});
        assert_eq!(require_str(&input, "field").unwrap(), "");
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"field": {"nested": true}});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn connector_new_equals_default() {
        let c1 = RetoolConnector::new();
        let c2 = RetoolConnector::default();
        assert!(c1.config.is_none());
        assert!(c2.config.is_none());
    }

    #[test]
    fn doctor_check_deserialize() {
        let v = json!({
            "name": "config",
            "passed": true,
            "message": "ok",
            "critical": false
        });
        let check: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(check.name, "config");
        assert!(check.passed);
    }

    #[test]
    fn doctor_status_eq() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_copy() {
        let status = DoctorStatus::Unhealthy;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn workflows_run_is_risky() {
        let ops = operations_info();
        let run = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "retool.workflows.run")
            .unwrap();
        assert_eq!(run["safety_tier"], "risky");
        assert_eq!(run["idempotency"], "none");
    }

    #[test]
    fn workflows_list_is_strict_idempotent() {
        let ops = operations_info();
        let list = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "retool.workflows.list")
            .unwrap();
        assert_eq!(list["idempotency"], "strict");
    }

    #[test]
    fn config_with_subdomain_and_base_url() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok",
            "subdomain": "myorg",
            "base_url": "https://custom.retool.com/api/v1",
        }))
        .unwrap();
        assert_eq!(config.subdomain, Some("myorg".into()));
        assert_eq!(
            config.base_url,
            Some("https://custom.retool.com/api/v1".into())
        );
    }

    #[test]
    fn doctor_result_all_non_critical_fail() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("warn a".into()),
                critical: false,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn b".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    // ── require_str additional edge cases ────────────────────────────

    #[test]
    fn require_str_float_value() {
        let input = json!({"val": 1.23});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_nested_object() {
        let input = json!({"val": {"a": {"b": "c"}}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_error_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "my_field").unwrap_err();
        assert!(err.to_string().contains("my_field"));
    }

    // ── DoctorResult / DoctorCheck additional tests ─────────────────

    #[test]
    fn doctor_result_deserializes_from_json() {
        let v = json!({
            "status": "healthy",
            "checks": [{
                "name": "api",
                "passed": true,
                "critical": false
            }]
        });
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn doctor_check_serde_json_roundtrip() {
        let c = DoctorCheck {
            name: "round".into(),
            passed: true,
            message: Some("msg".into()),
            critical: false,
        };
        let v = serde_json::to_value(&c).unwrap();
        let c2: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c2.name, "round");
        assert_eq!(c2.message, Some("msg".into()));
    }

    #[test]
    fn doctor_status_serde_roundtrip_degraded() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let s: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_debug_format() {
        let dbg = format!("{:?}", DoctorStatus::Unhealthy);
        assert!(dbg.contains("Unhealthy"));
    }

    #[test]
    fn doctor_result_unhealthy_overrides_degraded() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "crit".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "opt".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    // ── Config additional tests ─────────────────────────────────────

    #[test]
    fn config_debug_format() {
        let config = RetoolConfig::from_params(&json!({"api_token": "tok"})).unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("RetoolConfig"));
    }

    #[test]
    fn config_clone_preserves_fields() {
        let config = RetoolConfig::from_params(&json!({"api_token": "tok"})).unwrap();
        let config2 = config.clone();
        assert_eq!(config.subdomain, config2.subdomain);
        assert_eq!(config.base_url, config2.base_url);
    }

    #[test]
    fn config_no_subdomain_no_base_url_defaults() {
        let config = RetoolConfig::from_params(&json!({"api_token": "tok"})).unwrap();
        assert!(config.subdomain.is_none());
        assert!(config.base_url.is_none());
    }

    #[test]
    fn config_error_code_is_1003_for_missing_token() {
        let result = RetoolConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1003),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_message_mentions_api_token() {
        let result = RetoolConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("api_token")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── operations_info additional tests ─────────────────────────────

    #[test]
    fn operations_all_ids_prefixed_with_retool() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("retool."),
                "op id {id} should start with retool."
            );
        }
    }

    #[test]
    fn operations_all_have_summaries() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "empty summary for {}", op["id"]);
        }
    }

    #[test]
    fn operations_valid_idempotency_values() {
        let valid = ["strict", "best_effort", "none"];
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

    #[test]
    fn doctor_status_serde_all_three_variants() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let v = serde_json::to_value(status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(back, status);
        }
    }

    // ── provisioning_recipe tests ──────────────────────────────────

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "retool.api_key");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_api_key");
        assert_eq!(recipe.steps[1].id.as_str(), "store_api_key");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_api_key");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "retool.api_key");
        assert!(v["steps"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn provisioning_recipe_description_mentions_retool() {
        let recipe = provisioning_recipe();
        assert!(recipe.description.contains("Retool"));
    }

    #[test]
    fn provisioning_recipe_store_step_key_is_api_token() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[1];
        match &store_step.kind {
            ProvisioningStepType::StoreSecret { key, scope, .. } => {
                assert_eq!(key, "api_token");
                assert_eq!(scope, "connector:fcp.retool");
            }
            other => panic!("expected StoreSecret, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_prompt_step_has_message() {
        let recipe = provisioning_recipe();
        let prompt_step = &recipe.steps[0];
        match &prompt_step.kind {
            ProvisioningStepType::PromptSecret { message } => {
                assert!(message.contains("Retool"));
                assert!(message.contains("API key"));
            }
            other => panic!("expected PromptSecret, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_store_value_from_matches_prompt_id() {
        let recipe = provisioning_recipe();
        let prompt_id = recipe.steps[0].id.clone();
        match &recipe.steps[1].kind {
            ProvisioningStepType::StoreSecret { value_from, .. } => {
                assert_eq!(value_from.as_str(), prompt_id.as_str());
            }
            other => panic!("expected StoreSecret, got {other:?}"),
        }
    }

    // ── base_url_policy tests ──────────────────────────────────────

    #[test]
    fn base_url_policy_accepts_retool_https() {
        let (ok, message) = base_url_policy("https://app.retool.com/api/v1");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_custom_subdomain() {
        let (ok, message) = base_url_policy("https://myorg.retool.com/api/v1");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_bare_retool_domain() {
        let (ok, _) = base_url_policy("https://retool.com/api/v1");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9090");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, _) = base_url_policy("http://[::1]:9090");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://app.retool.com/api/v1");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("retool.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_rejects_no_host() {
        let (ok, _message) = base_url_policy("file:///etc/passwd");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_rejects_retool_like_subdomain_on_other_domain() {
        let (ok, _) = base_url_policy("https://retool.com.evil.com");
        assert!(!ok);
    }

    // ── provisioning_readiness tests ───────────────────────────────

    #[test]
    fn provisioning_readiness_default_base_url() {
        let config = RetoolConfig::from_params(&json!({"api_token": "tok"})).unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.token_configured);
        assert!(readiness.network_ok);
        assert!(readiness.base_url.contains("retool.com"));
    }

    #[test]
    fn provisioning_readiness_custom_subdomain() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok",
            "subdomain": "myorg",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
        assert!(readiness.base_url.contains("myorg.retool.com"));
    }

    #[test]
    fn provisioning_readiness_custom_base_url_accepted() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://custom.retool.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("retool.com"));
    }

    #[test]
    fn provisioning_readiness_localhost_accepted() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "http://localhost:3000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = RetoolConfig::from_params(&json!({"api_token": "tok"})).unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    // ── effective_base_url tests ───────────────────────────────────

    #[test]
    fn effective_base_url_no_overrides() {
        let config = RetoolConfig::from_params(&json!({"api_token": "tok"})).unwrap();
        assert_eq!(config.effective_base_url(), "https://app.retool.com/api/v1");
    }

    #[test]
    fn effective_base_url_with_subdomain() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok",
            "subdomain": "acme",
        }))
        .unwrap();
        assert_eq!(
            config.effective_base_url(),
            "https://acme.retool.com/api/v1"
        );
    }

    #[test]
    fn effective_base_url_explicit_overrides_subdomain() {
        let config = RetoolConfig::from_params(&json!({
            "api_token": "tok",
            "subdomain": "acme",
            "base_url": "https://custom.retool.com/api/v2",
        }))
        .unwrap();
        assert_eq!(
            config.effective_base_url(),
            "https://custom.retool.com/api/v2"
        );
    }

    // ── is_local_test_host tests ───────────────────────────────────

    #[test]
    fn is_local_test_host_localhost() {
        assert!(is_local_test_host("localhost"));
    }

    #[test]
    fn is_local_test_host_ipv4_loopback() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_ipv6_loopback() {
        assert!(is_local_test_host("::1"));
        assert!(is_local_test_host("[::1]"));
    }

    #[test]
    fn is_local_test_host_rejects_random() {
        assert!(!is_local_test_host("example.com"));
    }

    #[test]
    fn is_local_test_host_rejects_empty() {
        assert!(!is_local_test_host(""));
    }
}
