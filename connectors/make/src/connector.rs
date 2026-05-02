//! FCP `Make` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, MakeAuth, MakeClient},
    error::MakeError,
};

/// Parsed and validated `Make` connector configuration.
#[derive(Debug, Clone)]
struct MakeConfig {
    auth: MakeAuth,
    base_url: String,
}

impl MakeConfig {
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
            (Some(key), None) => MakeAuth::ApiToken(key),
            (None, Some(cred_id)) => MakeAuth::CredentialId(cred_id),
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

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                MakeAuth::ApiToken(_) => "api_token",
                MakeAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, MakeAuth::ApiToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    token_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
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

/// FCP `Make` Connector.
pub struct MakeConnector {
    base: Arc<BaseConnector>,
    config: Option<MakeConfig>,
    client: Option<Arc<MakeClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl MakeConnector {
    /// Create a new `Make` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("make"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for MakeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl MakeConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = MakeConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Make connector");

        let client = MakeClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.make",
            "connector_version": "0.1.0",
            "capabilities": [
                "make.scenarios.read",
                "make.scenarios.write",
                "make.executions.read"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.base.handshaken.load(Ordering::Acquire);

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

        let handshaken = self.base.handshaken.load(Ordering::Acquire);
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
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
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

        if readiness.requires_credential_injection {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires egress proxy injection; skipping live probe",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "make.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Make self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = serde_json::to_value(operations_info()).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize operations: {e}"),
        })?;
        Ok(json!({
            "connector_id": "fcp.make",
            "version": "0.1.0",
            "operations": ops,
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

        let input = params.get("input").cloned().unwrap_or(json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "make.scenarios.list" => self.invoke_scenarios_list(client).await,
            "make.scenarios.run" => self.invoke_scenarios_run(client, &input).await,
            "make.executions.list" => self.invoke_executions_list(client, &input).await,
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

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

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
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Make connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_scenarios_list(
        &self,
        client: &MakeClient,
    ) -> Result<serde_json::Value, MakeError> {
        let resp = client.list_scenarios().await?;
        let scenarios = resp.get("scenarios").cloned().unwrap_or(json!([]));
        Ok(json!({ "scenarios": scenarios }))
    }

    async fn invoke_scenarios_run(
        &self,
        client: &MakeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MakeError> {
        let scenario_id = require_str(input, "scenario_id")?;
        let resp = client.run_scenario(scenario_id).await?;
        let execution_id = resp
            .get("executionId")
            .or_else(|| resp.get("execution_id"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Ok(json!({ "execution_id": execution_id }))
    }

    async fn invoke_executions_list(
        &self,
        client: &MakeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MakeError> {
        let scenario_id = require_str(input, "scenario_id")?;
        let resp = client.list_executions(scenario_id).await?;
        let executions = resp.get("executions").cloned().unwrap_or(json!([]));
        Ok(json!({ "executions": executions }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, MakeError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MakeError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the provisioning recipe for the `Make` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("make.api_token"),
        "1",
        "Provision Make connector with an API token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("open_settings"),
        ProvisioningStepType::OpenUrl {
            url: "https://www.make.com/en/api/documentation".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_token"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your Make API token".into(),
            },
        )
        .depends_on(StepId::new("open_settings")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "api_token".into(),
                value_from: StepId::new("enter_token"),
                scope: "connector:fcp.make".into(),
            },
        )
        .depends_on(StepId::new("enter_token")),
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
    let allowed_host = host.eq_ignore_ascii_case("make.com")
        || host.ends_with(".make.com")
        || host.eq_ignore_ascii_case("integromat.com")
        || host.ends_with(".integromat.com")
        || local;
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
                "Endpoint must use https and *.make.com or *.integromat.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Build a single [`OperationInfo`].
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "make.scenarios.list",
            "List scenarios in a team",
            json!({"type": "object", "required": [], "properties": {}}),
            json!({"type": "object", "required": ["scenarios"], "properties": {"scenarios": {"type": "array"}}}),
            "make.scenarios.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all scenarios in a Make team.".into(),
                common_mistakes: vec![
                    "Forgetting that the team ID is configured at the connector level — scenarios from other teams are not returned.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("make.scenarios.run"),
                    CapabilityId::from_static("make.executions.list"),
                ],
            },
        ),
        op_info(
            "make.scenarios.run",
            "Trigger a scenario run",
            json!({"type": "object", "required": ["scenario_id"], "properties": {"scenario_id": {"type": "string", "description": "Scenario ID to trigger"}}}),
            json!({"type": "object", "required": ["execution_id"], "properties": {"execution_id": {"type": "string"}}}),
            "make.scenarios.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Trigger a Make scenario to run.".into(),
                common_mistakes: vec![
                    "Triggering a scenario that is turned off — it must be active in Make to accept API-triggered runs.".into(),
                    "Running a scenario without checking remaining operations quota in the Make plan.".into(),
                ],
                examples: vec![r#"{"scenario_id": "12345"}"#.into()],
                related: vec![
                    CapabilityId::from_static("make.scenarios.list"),
                    CapabilityId::from_static("make.executions.list"),
                ],
            },
        ),
        op_info(
            "make.executions.list",
            "List recent executions for a scenario",
            json!({"type": "object", "required": ["scenario_id"], "properties": {"scenario_id": {"type": "string", "description": "Scenario ID"}}}),
            json!({"type": "object", "required": ["executions"], "properties": {"executions": {"type": "array"}}}),
            "make.executions.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List recent executions for a Make scenario.".into(),
                common_mistakes: vec![
                    "Using the scenario name instead of the numeric scenario_id.".into(),
                    "Expecting executions from all scenarios — you must specify a single scenario_id.".into(),
                ],
                examples: vec![r#"{"scenario_id": "12345"}"#.into()],
                related: vec![
                    CapabilityId::from_static("make.scenarios.list"),
                    CapabilityId::from_static("make.scenarios.run"),
                ],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_api_token() {
        let config = MakeConfig::from_params(&json!({
            "api_token": "test-api-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, MakeAuth::ApiToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = MakeConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = MakeConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://eu1.make.com/api/v2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://eu1.make.com/api/v2");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = MakeConfig::from_params(&json!({
            "api_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = MakeConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_token() {
        let result = MakeConfig::from_params(&json!({
            "api_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_token() {
        let result = MakeConfig::from_params(&json!({
            "api_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = MakeConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = MakeConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"scenario_id": "12345"});
        assert_eq!(require_str(&input, "scenario_id").unwrap(), "12345");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "scenario_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"scenario_id": 42});
        assert!(require_str(&input, "scenario_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"scenario_id": null});
        assert!(require_str(&input, "scenario_id").is_err());
    }

    #[test]
    fn operations_info_has_3_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.id.as_ref().is_empty(), "missing id");
            assert!(!op.summary.is_empty(), "missing summary");
            assert!(!op.capability.as_ref().is_empty(), "missing capability");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.risk_level).unwrap();
            let rl = v.as_str().unwrap();
            assert!(
                ["low", "medium", "high", "critical"].contains(&rl),
                "invalid risk_level: {rl}"
            );
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.safety_tier).unwrap();
            let st = v.as_str().unwrap();
            assert!(
                ["safe", "risky", "dangerous"].contains(&st),
                "invalid safety_tier: {st}"
            );
        }
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".read") {
                assert_eq!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "read op {} should be safe",
                    op.id.as_ref()
                );
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "read op {} should be low risk",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        assert!(ids.contains(&"make.scenarios.list"));
        assert!(ids.contains(&"make.scenarios.run"));
        assert!(ids.contains(&"make.executions.list"));
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
    fn config_trims_api_token() {
        let config = MakeConfig::from_params(&json!({ "api_token": "  tok_test  " })).unwrap();
        match &config.auth {
            MakeAuth::ApiToken(t) => assert_eq!(t, "tok_test"),
            MakeAuth::CredentialId(_) => panic!("expected ApiToken"),
        }
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.idempotency).unwrap();
            assert!(
                v.is_string(),
                "op {} idempotency should serialize",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = MakeConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_counters_zero() {
        let c = MakeConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn request_count_increments() {
        let c = MakeConnector::new();
        c.request_count.fetch_add(1, Ordering::Relaxed);
        c.request_count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(c.request_count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn error_count_increments() {
        let c = MakeConnector::new();
        c.error_count.fetch_add(3, Ordering::Relaxed);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_api_token() {
        let mut c = MakeConnector::new();
        let resp = c
            .handle_configure(json!({"api_token": "tok_test"}))
            .await
            .unwrap();
        assert_eq!(resp, json!({}));
        assert!(c.config.is_some());
        assert!(c.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_credential_id() {
        let mut c = MakeConnector::new();
        let resp = c
            .handle_configure(json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}))
            .await
            .unwrap();
        assert_eq!(resp, json!({}));
        assert!(c.config.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_no_auth() {
        let mut c = MakeConnector::new();
        let err = c.handle_configure(json!({})).await.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_both_auth() {
        let mut c = MakeConnector::new();
        let err = c
            .handle_configure(json!({
                "api_token": "tok",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_custom_url() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({
            "api_token": "tok",
            "base_url": "https://eu1.make.com/api/v2"
        }))
        .await
        .unwrap();
        let cfg = c.config.as_ref().unwrap();
        assert_eq!(cfg.base_url, "https://eu1.make.com/api/v2");
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_before_configure_fails() {
        let mut c = MakeConnector::new();
        let err = c.handle_handshake(json!({})).await.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_after_configure_succeeds() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        let resp = c.handle_handshake(json!({})).await.unwrap();
        assert_eq!(resp["protocol_version"], "2.0");
        assert_eq!(resp["connector_id"], "fcp.make");
        assert_eq!(resp["connector_version"], "0.1.0");
        let caps = resp["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_stores_session_id() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        c.handle_handshake(json!({"session_id": "sess-42"}))
            .await
            .unwrap();
        assert_eq!(c.session_id.as_deref(), Some("sess-42"));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_no_session_id() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        assert!(c.session_id.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn health_unconfigured() {
        let c = MakeConnector::new();
        let resp = c.handle_health().await.unwrap();
        assert_eq!(resp["status"], "unconfigured");
        assert_eq!(resp["configured"], false);
        assert_eq!(resp["handshaken"], false);
        assert_eq!(resp["requests"], 0);
        assert_eq!(resp["errors"], 0);
    }

    #[fcp_async_core::runtime::test]
    async fn health_configured_not_handshaken() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        let resp = c.handle_health().await.unwrap();
        assert_eq!(resp["status"], "degraded");
        assert_eq!(resp["configured"], true);
        assert_eq!(resp["handshaken"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn health_fully_ready() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        let resp = c.handle_health().await.unwrap();
        assert_eq!(resp["status"], "healthy");
        assert_eq!(resp["configured"], true);
        assert_eq!(resp["handshaken"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_unconfigured() {
        let c = MakeConnector::new();
        let resp = c.handle_doctor().await.unwrap();
        assert_eq!(resp["status"], "unhealthy");
        let checks = resp["checks"].as_array().unwrap();
        assert!(checks.len() >= 2);
        let config_check = &checks[0];
        assert_eq!(config_check["passed"], false);
        assert_eq!(config_check["critical"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured_not_handshaken() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        let resp = c.handle_doctor().await.unwrap();
        assert_eq!(resp["status"], "degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_fully_ready() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        let resp = c.handle_doctor().await.unwrap();
        assert_eq!(resp["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let c = MakeConnector::new();
        let resp = c.handle_self_check().await.unwrap();
        assert_eq!(resp["status"], "degraded");
        assert_eq!(resp["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_configured_with_token() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        let resp = c.handle_self_check().await.unwrap();
        assert_eq!(resp["status"], "ok");
        let prov = &resp["details"]["provisioning"];
        assert_eq!(prov["auth_mode"], "api_token");
        assert_eq!(prov["token_configured"], true);
        assert_eq!(prov["network_ok"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_credential_id_mode() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}))
            .await
            .unwrap();
        let resp = c.handle_self_check().await.unwrap();
        assert_eq!(resp["status"], "degraded");
        assert_eq!(resp["reason_code"], "credential_injection_required");
        let prov = &resp["details"]["provisioning"];
        assert_eq!(prov["auth_mode"], "credential_id");
        assert_eq!(prov["requires_credential_injection"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_bad_base_url() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({
            "api_token": "tok",
            "base_url": "https://evil.example.com"
        }))
        .await
        .unwrap();
        let resp = c.handle_self_check().await.unwrap();
        assert_eq!(resp["status"], "failed");
        assert_eq!(resp["reason_code"], "network_constraints_invalid");
        let prov = &resp["details"]["provisioning"];
        assert_eq!(prov["network_ok"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_returns_operations() {
        let c = MakeConnector::new();
        let resp = c.handle_introspect().await.unwrap();
        assert_eq!(resp["connector_id"], "fcp.make");
        let ops = resp["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_ready() {
        let c = MakeConnector::new();
        let err = c
            .handle_invoke(json!({"operation_id": "make.scenarios.list"}))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FcpError::NotConfigured | FcpError::NotHandshaken
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_missing_operation_id() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        let err = c.handle_invoke(json!({"input": {}})).await.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_unknown_operation() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        let err = c
            .handle_invoke(json!({"operation_id": "make.nonexistent"}))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_known_operations() {
        let c = MakeConnector::new();
        for op in [
            "make.scenarios.list",
            "make.scenarios.run",
            "make.executions.list",
        ] {
            let resp = c
                .handle_simulate(json!({"operation_id": op}))
                .await
                .unwrap();
            assert_eq!(resp["allowed"], true, "op {op} should be allowed");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation() {
        let c = MakeConnector::new();
        let resp = c
            .handle_simulate(json!({"operation_id": "make.unknown"}))
            .await
            .unwrap();
        assert_eq!(resp["allowed"], false);
        assert_eq!(resp["reason"], "Unknown operation");
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_empty_operation() {
        let c = MakeConnector::new();
        let resp = c.handle_simulate(json!({})).await.unwrap();
        assert_eq!(resp["allowed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_state() {
        let mut c = MakeConnector::new();
        c.handle_configure(json!({"api_token": "tok"}))
            .await
            .unwrap();
        c.handle_handshake(json!({"session_id": "s1"}))
            .await
            .unwrap();
        assert!(c.config.is_some());
        assert!(c.client.is_some());

        c.handle_shutdown(json!({})).await.unwrap();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_idempotent() {
        let mut c = MakeConnector::new();
        c.handle_shutdown(json!({})).await.unwrap();
        c.handle_shutdown(json!({})).await.unwrap();
        assert!(c.config.is_none());
    }

    #[test]
    fn doctor_check_serde_skips_none_message() {
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
    fn doctor_check_serde_includes_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("not ok".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "not ok");
    }

    #[test]
    fn doctor_status_serde_values() {
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
    fn doctor_status_deserialize() {
        let h: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
        let u: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(u, DoctorStatus::Unhealthy);
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
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let c = r.clone();
        assert_eq!(c.status, r.status);
        assert_eq!(c.checks.len(), r.checks.len());
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn config_api_token_trimmed() {
        let c = MakeConfig::from_params(&json!({"api_token": "  key  "})).unwrap();
        match &c.auth {
            MakeAuth::ApiToken(k) => assert_eq!(k, "key"),
            MakeAuth::CredentialId(_) => panic!("expected ApiToken"),
        }
    }

    #[test]
    fn config_default_base_url_when_absent() {
        let c = MakeConfig::from_params(&json!({"api_token": "tok"})).unwrap();
        assert_eq!(c.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"scenario_id": [1, 2]});
        assert!(require_str(&input, "scenario_id").is_err());
    }

    #[test]
    fn require_str_bool_value() {
        let input = json!({"scenario_id": true});
        assert!(require_str(&input, "scenario_id").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"scenario_id": {"nested": "val"}});
        assert!(require_str(&input, "scenario_id").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"scenario_id": ""});
        assert_eq!(require_str(&input, "scenario_id").unwrap(), "");
    }

    #[test]
    fn operations_write_ops_are_risky() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            if cap.as_bytes().ends_with(b".write") {
                assert_eq!(
                    op.safety_tier,
                    SafetyTier::Risky,
                    "write op {} should be risky",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn operations_scenarios_run_is_not_idempotent() {
        let ops = operations_info();
        let run_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "make.scenarios.run")
            .unwrap();
        assert_eq!(run_op.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn operations_list_ops_are_strict_idempotent() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            if id.contains("list") {
                assert_eq!(
                    op.idempotency,
                    IdempotencyClass::Strict,
                    "list op {id} should be strict"
                );
            }
        }
    }

    // ── require_str additional edge cases ────────────────────────────

    #[test]
    fn require_str_float_value() {
        let input = json!({"scenario_id": 1.23});
        assert!(require_str(&input, "scenario_id").is_err());
    }

    #[test]
    fn require_str_nested_key_not_found() {
        let input = json!({"outer": {"inner": "val"}});
        assert!(require_str(&input, "inner").is_err());
    }

    #[test]
    fn require_str_error_message_content() {
        let input = json!({});
        match require_str(&input, "team_id").unwrap_err() {
            MakeError::InvalidInput(msg) => {
                assert!(msg.contains("team_id"));
            }
            e => panic!("expected InvalidInput, got {e:?}"),
        }
    }

    // ── DoctorResult / DoctorCheck / DoctorStatus tests ─────────────

    #[test]
    fn doctor_status_serde_roundtrip() {
        let statuses = [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ];
        for s in &statuses {
            let json = serde_json::to_value(s).unwrap();
            let back: DoctorStatus = serde_json::from_value(json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn doctor_status_debug() {
        assert!(format!("{:?}", DoctorStatus::Healthy).contains("Healthy"));
        assert!(format!("{:?}", DoctorStatus::Degraded).contains("Degraded"));
        assert!(format!("{:?}", DoctorStatus::Unhealthy).contains("Unhealthy"));
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_check_serde_roundtrip() {
        let check = DoctorCheck {
            name: "connectivity".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let json = serde_json::to_value(&check).unwrap();
        assert_eq!(json["name"], "connectivity");
        assert_eq!(json["passed"], true);
        let back: DoctorCheck = serde_json::from_value(json).unwrap();
        assert_eq!(back.message.as_deref(), Some("ok"));
    }

    #[test]
    fn doctor_check_debug_clone() {
        let check = DoctorCheck {
            name: "auth".into(),
            passed: false,
            message: Some("expired".into()),
            critical: true,
        };
        let cloned = check.clone();
        assert_eq!(check.name, "auth");
        assert!(cloned.critical);
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_result_healthy_all_pass() {
        let r = DoctorResult::from_checks(vec![
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
        ]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_non_critical_fail() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "optional".into(),
            passed: false,
            message: Some("warning".into()),
            critical: false,
        }]);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_critical_fail() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "auth".into(),
            passed: false,
            message: None,
            critical: true,
        }]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serde_roundtrip_healthy() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let json = serde_json::to_value(&r).unwrap();
        let back: DoctorResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_clone_preserves_checks() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "c".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(r.status, cloned.status);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug_format() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    // ── Config tests ────────────────────────────────────────────────

    #[test]
    fn config_debug_format() {
        let config = MakeConfig::from_params(&json!({
            "api_token": "tok"
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("MakeConfig"));
    }

    #[test]
    fn config_clone_preserves_url() {
        let config = MakeConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://custom.make.com/api/v2"
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, cloned.base_url);
    }

    // ── Connector initial state ─────────────────────────────────────

    #[test]
    fn connector_initial_counts() {
        let c = MakeConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    // ── Provisioning recipe tests ─────────────────────────────────────

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "make.api_token");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "open_settings");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_token");
        assert_eq!(recipe.steps[2].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "open_settings");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_token");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "make.api_token");
        assert!(v["steps"].as_array().unwrap().len() == 3);
    }

    // ── base_url_policy tests ─────────────────────────────────────────

    #[test]
    fn base_url_policy_accepts_make_https() {
        let (ok, message) = base_url_policy("https://us1.make.com/api/v2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_make_root_domain() {
        let (ok, message) = base_url_policy("https://make.com/api/v2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_eu_make() {
        let (ok, message) = base_url_policy("https://eu1.make.com/api/v2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_integromat_https() {
        let (ok, message) = base_url_policy("https://api.integromat.com/v2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_integromat_root() {
        let (ok, message) = base_url_policy("https://integromat.com/api");
        assert!(ok);
        assert!(message.contains("accepted"));
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
        let (ok, _) = base_url_policy("http://[::1]:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://us1.make.com/api/v2");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("make.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_rejects_http_integromat() {
        let (ok, message) = base_url_policy("http://api.integromat.com/v2");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    // ── Provisioning readiness tests ──────────────────────────────────

    #[test]
    fn provisioning_readiness_api_token_mode() {
        let config = MakeConfig::from_params(&json!({
            "api_token": "tok"
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = MakeConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = MakeConfig::from_params(&json!({
            "api_token": "tok",
            "base_url": "https://evil.example.com"
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("make.com"));
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = MakeConfig::from_params(&json!({
            "api_token": "tok"
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_debug() {
        let config = MakeConfig::from_params(&json!({
            "api_token": "tok"
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let config = MakeConfig::from_params(&json!({
            "api_token": "tok"
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = readiness.clone();
        assert_eq!(readiness.auth_mode, cloned.auth_mode);
        assert_eq!(readiness.network_ok, cloned.network_ok);
    }

    #[test]
    fn base_url_policy_default_url() {
        let (ok, message) = base_url_policy(DEFAULT_BASE_URL);
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn is_local_test_host_values() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
        assert!(!is_local_test_host("make.com"));
        assert!(!is_local_test_host("example.com"));
    }
}
