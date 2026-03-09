//! FCP Zapier Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
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

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                ZapierAuth::BearerToken(_) => "api_key",
                ZapierAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, ZapierAuth::BearerToken(_)),
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
        let Some(config) = &self.config else {
            let report =
                SelfCheckReport::degraded("not_configured", "Connector is not configured");
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

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = serde_json::to_value(operations_info()).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize operations: {e}"),
        })?;
        Ok(json!({
            "connector_id": "fcp.zapier",
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

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "zapier.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Zapier self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Build the provisioning recipe for the `Zapier` NLA connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("zapier.api_key"),
        "1",
        "Provision `Zapier` NLA connector with an API key",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("open_developer_settings"),
        ProvisioningStepType::OpenUrl {
            url: "https://nla.zapier.com/credentials/".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_api_key"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your Zapier NLA API key".into(),
            },
        )
        .depends_on(StepId::new("open_developer_settings")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_key".into(),
                value_from: StepId::new("enter_api_key"),
                scope: "connector:fcp.zapier".into(),
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
    let allowed_host = host.eq_ignore_ascii_case("nla.zapier.com")
        || host.eq_ignore_ascii_case("api.zapier.com")
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
                "Endpoint must use https and nla.zapier.com or api.zapier.com (localhost/127.0.0.1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1")
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

/// Build a single [`OperationInfo`].
#[allow(clippy::fn_params_excessive_bools)]
#[allow(clippy::too_many_arguments)]
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
            "zapier.zaps.list",
            "List zaps for the authenticated user",
            json!({
                "type": "object",
                "required": [],
                "properties": {}
            }),
            json!({
                "type": "object",
                "required": ["zaps"],
                "properties": {
                    "zaps": {"type": "array"}
                }
            }),
            "zapier.zaps.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all zaps for the authenticated Zapier user.".into(),
                common_mistakes: vec![
                    "Expecting detailed trigger/action configuration in the list response — use individual zap details for full step definitions.".into(),
                    "Assuming only active zaps are returned — paused and draft zaps are also included.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("zapier.zaps.execute")],
            },
        ),
        op_info(
            "zapier.zaps.execute",
            "Execute a zap action",
            json!({
                "type": "object",
                "required": ["action_id", "params"],
                "properties": {
                    "action_id": {"type": "string", "description": "NLA action ID"},
                    "params": {"type": "object", "description": "Action parameters"}
                }
            }),
            json!({
                "type": "object",
                "required": ["result"],
                "properties": {
                    "result": {"type": "object"}
                }
            }),
            "zapier.zaps.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Execute a Zapier NLA action.".into(),
                common_mistakes: vec![
                    "Forgetting to include required params for the action".into(),
                ],
                examples: vec![
                    r#"{"action_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "params": {"body": "Hello from FCP"}}"#.into(),
                ],
                related: vec![CapabilityId::from_static("zapier.zaps.list")],
            },
        ),
    ]
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
        assert_eq!(ops.len(), 2);
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
    fn operations_all_have_schemas() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.input_schema["type"].as_str().unwrap(),
                "object",
                "input_schema type should be object"
            );
            assert_eq!(
                op.output_schema["type"].as_str().unwrap(),
                "object",
                "output_schema type should be object"
            );
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
        assert!(ids.contains(&"zapier.zaps.list"));
        assert!(ids.contains(&"zapier.zaps.execute"));
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
    fn operations_list_is_strict_idempotent() {
        let ops = operations_info();
        let list_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "zapier.zaps.list")
            .unwrap();
        assert_eq!(list_op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn operations_execute_is_not_idempotent() {
        let ops = operations_info();
        let exec_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "zapier.zaps.execute")
            .unwrap();
        assert_eq!(exec_op.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn operations_execute_has_required_input_fields() {
        let ops = operations_info();
        let exec_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "zapier.zaps.execute")
            .unwrap();
        let required = exec_op.input_schema["required"].as_array().unwrap();
        let req_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(req_strs.contains(&"action_id"));
        assert!(req_strs.contains(&"params"));
    }

    #[test]
    fn operations_list_has_no_required_input() {
        let ops = operations_info();
        let list_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "zapier.zaps.list")
            .unwrap();
        let required = list_op.input_schema["required"].as_array().unwrap();
        assert!(required.is_empty());
    }

    #[test]
    fn operations_list_output_has_zaps() {
        let ops = operations_info();
        let list_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "zapier.zaps.list")
            .unwrap();
        let required = list_op.output_schema["required"].as_array().unwrap();
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
            .iter()
            .find(|o| o.id.as_ref() == "zapier.zaps.execute")
            .unwrap();
        let required = exec_op.output_schema["required"].as_array().unwrap();
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
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".write") {
                assert_ne!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "write op {} should not be safe",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn operations_capabilities_match_manifest() {
        let ops = operations_info();
        let list_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "zapier.zaps.list")
            .unwrap();
        assert_eq!(list_op.capability.as_ref(), "zapier.zaps.read");
        let exec_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "zapier.zaps.execute")
            .unwrap();
        assert_eq!(exec_op.capability.as_ref(), "zapier.zaps.write");
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
            .iter()
            .find(|o| o.id.as_ref() == "zapier.zaps.execute")
            .unwrap();
        assert_eq!(exec_op.safety_tier, SafetyTier::Risky);
        assert_eq!(exec_op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn operations_list_is_safe() {
        let ops = operations_info();
        let list_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "zapier.zaps.list")
            .unwrap();
        assert_eq!(list_op.safety_tier, SafetyTier::Safe);
        assert_eq!(list_op.risk_level, RiskLevel::Low);
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

    // -- Provisioning recipe --

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "zapier.api_key");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "open_developer_settings");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_api_key");
        assert_eq!(recipe.steps[2].id.as_str(), "store_api_key");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(
            recipe.steps[1].depends_on[0].as_str(),
            "open_developer_settings"
        );
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_api_key");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "zapier.api_key");
        assert!(v["steps"].as_array().unwrap().len() == 3);
    }

    #[test]
    fn provisioning_recipe_description() {
        let recipe = provisioning_recipe();
        assert!(recipe.description.contains("Zapier"));
        assert!(recipe.description.contains("API key"));
    }

    #[test]
    fn provisioning_recipe_store_secret_scope() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[2];
        if let ProvisioningStepType::StoreSecret { key, scope, .. } = &store_step.kind {
            assert_eq!(key, "api_key");
            assert_eq!(scope, "connector:fcp.zapier");
        } else {
            panic!("expected StoreSecret step type");
        }
    }

    #[test]
    fn provisioning_recipe_store_secret_value_from() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[2];
        if let ProvisioningStepType::StoreSecret { value_from, .. } = &store_step.kind {
            assert_eq!(value_from.as_str(), "enter_api_key");
        } else {
            panic!("expected StoreSecret step type");
        }
    }

    #[test]
    fn provisioning_recipe_open_url_step() {
        let recipe = provisioning_recipe();
        let open_step = &recipe.steps[0];
        if let ProvisioningStepType::OpenUrl { url } = &open_step.kind {
            assert!(url.contains("zapier.com"));
        } else {
            panic!("expected OpenUrl step type");
        }
    }

    #[test]
    fn provisioning_recipe_prompt_secret_step() {
        let recipe = provisioning_recipe();
        let prompt_step = &recipe.steps[1];
        if let ProvisioningStepType::PromptSecret { message } = &prompt_step.kind {
            assert!(message.contains("API key"));
        } else {
            panic!("expected PromptSecret step type");
        }
    }

    // -- base_url_policy --

    #[test]
    fn base_url_policy_accepts_nla_zapier_https() {
        let (ok, message) = base_url_policy("https://nla.zapier.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_api_zapier_https() {
        let (ok, message) = base_url_policy("https://api.zapier.com/v1");
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
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://nla.zapier.com");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("zapier.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_rejects_http_api_zapier() {
        let (ok, _) = base_url_policy("http://api.zapier.com");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_case_insensitive_host() {
        let (ok, _) = base_url_policy("https://NLA.ZAPIER.COM");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_localhost_http_ok() {
        let (ok, _) = base_url_policy("http://localhost:3000/v1");
        assert!(ok);
    }

    // -- ProvisioningReadiness --

    #[test]
    fn provisioning_readiness_bearer_token() {
        let config =
            ZapierConfig::from_params(&json!({ "api_key": "tok" })).unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_key");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let config = ZapierConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
    }

    #[test]
    fn provisioning_readiness_network_ok_with_default_url() {
        let config =
            ZapierConfig::from_params(&json!({ "api_key": "tok" })).unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_network_rejected_custom_url() {
        let config = ZapierConfig::from_params(&json!({
            "api_key": "tok",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("zapier.com"));
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config =
            ZapierConfig::from_params(&json!({ "api_key": "tok" })).unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_key");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn is_local_test_host_checks() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(!is_local_test_host("example.com"));
        assert!(!is_local_test_host("nla.zapier.com"));
    }
}
