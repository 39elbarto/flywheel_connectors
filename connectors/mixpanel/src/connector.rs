//! FCP Mixpanel Connector implementation.

#![allow(clippy::doc_markdown)]

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
    client::{DEFAULT_BASE_URL, MixpanelAuth, MixpanelClient},
    error::MixpanelError,
};

/// Parsed and validated Mixpanel connector configuration.
#[derive(Debug, Clone)]
struct MixpanelConfig {
    auth: MixpanelAuth,
    base_url: String,
    project_id: String,
}

impl MixpanelConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let username = params
            .get("username")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let secret = params
            .get("secret")
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

        let auth = match (username, secret, credential_id) {
            (Some(u), Some(s), None) => MixpanelAuth::ServiceAccount {
                username: u,
                secret: s,
            },
            (None, None, Some(cred_id)) => MixpanelAuth::CredentialId(cred_id),
            (Some(_), Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide either username/secret or credential_id, not both".into(),
                });
            }
            (Some(_), None, None) | (None, Some(_), None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Both username and secret are required for service account auth"
                        .into(),
                });
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing authentication: provide username/secret or credential_id"
                        .into(),
                });
            }
        };

        let project_id = params
            .get("project_id")
            .and_then(|v| {
                v.as_str()
                    .map(str::to_string)
                    .or_else(|| v.as_u64().map(|n| n.to_string()))
            })
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: project_id".into(),
            })?;

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self {
            auth,
            base_url,
            project_id,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                MixpanelAuth::ServiceAccount { .. } => "service_account",
                MixpanelAuth::CredentialId(_) => "credential_id",
            },
            username_configured: matches!(&self.auth, MixpanelAuth::ServiceAccount { .. }),
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
    username_configured: bool,
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

/// FCP Mixpanel Connector.
pub struct MixpanelConnector {
    base: Arc<BaseConnector>,
    config: Option<MixpanelConfig>,
    client: Option<Arc<MixpanelClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl MixpanelConnector {
    /// Create a new Mixpanel connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("mixpanel"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for MixpanelConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl MixpanelConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = MixpanelConfig::from_params(&params)?;
        info!(
            auth = %config.auth.redacted_label(),
            base_url = %config.base_url,
            project_id = %config.project_id,
            "Configuring Mixpanel connector"
        );

        let client = MixpanelClient::new(
            config.auth.clone(),
            &config.project_id,
            Some(&config.base_url),
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
            "connector_id": "fcp.mixpanel",
            "connector_version": "0.1.0",
            "capabilities": [
                "mixpanel.events.read",
                "mixpanel.funnels.read",
                "mixpanel.insights.read"
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

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.mixpanel",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
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
            "mixpanel.events.query" => self.invoke_events_query(client, &input).await,
            "mixpanel.funnels.list" => self.invoke_funnels_list(client).await,
            "mixpanel.insights.query" => self.invoke_insights_query(client, &input).await,
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
        info!("Mixpanel connector shutting down");
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
            event = "mixpanel.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "`Mixpanel` self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // -- Operation implementations --

    async fn invoke_events_query(
        &self,
        client: &MixpanelClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MixpanelError> {
        let from_date = require_str(input, "from_date")?;
        let to_date = require_str(input, "to_date")?;
        let event = input.get("event").and_then(serde_json::Value::as_str);
        let resp = client.query_events(from_date, to_date, event).await?;
        let data = resp.get("data").cloned().unwrap_or(serde_json::Value::Null);
        Ok(json!({ "data": data }))
    }

    async fn invoke_funnels_list(
        &self,
        client: &MixpanelClient,
    ) -> Result<serde_json::Value, MixpanelError> {
        let resp = client.list_funnels().await?;
        // The response is the array directly or wrapped in an object.
        let funnels = if resp.is_array() {
            resp
        } else {
            resp.get("funnels").cloned().unwrap_or_else(|| json!([]))
        };
        Ok(json!({ "funnels": funnels }))
    }

    async fn invoke_insights_query(
        &self,
        client: &MixpanelClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MixpanelError> {
        let bookmark_id = require_str(input, "bookmark_id")?;
        let resp = client.query_insights(bookmark_id).await?;
        let data = resp.get("data").cloned().unwrap_or(serde_json::Value::Null);
        Ok(json!({ "data": data }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, MixpanelError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MixpanelError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the provisioning recipe for the `Mixpanel` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("mixpanel.service_account"),
        "1",
        "Provision `Mixpanel` connector with service account credentials (Basic auth)",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_username"),
        ProvisioningStepType::PromptSecret {
            message: "Enter your `Mixpanel` service account username".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_secret"),
            ProvisioningStepType::PromptSecret {
                message: "Enter your `Mixpanel` service account secret".into(),
            },
        )
        .depends_on(StepId::new("enter_username")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_credentials"),
            ProvisioningStepType::StoreSecret {
                key: "service_account".into(),
                value_from: StepId::new("enter_secret"),
                scope: "connector:fcp.mixpanel".into(),
            },
        )
        .depends_on(StepId::new("enter_secret")),
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
    let allowed_host = host.eq_ignore_ascii_case("mixpanel.com")
        || host.eq_ignore_ascii_case("data.mixpanel.com")
        || host.eq_ignore_ascii_case("eu.mixpanel.com")
        || host.to_ascii_lowercase().ends_with(".mixpanel.com")
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
                "Endpoint must use https and mixpanel.com / *.mixpanel.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Construct a single [`OperationInfo`].
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
            "mixpanel.events.query",
            "Query events with the Insights API",
            json!({
                "type": "object",
                "required": ["from_date", "to_date"],
                "properties": {
                    "from_date": {"type": "string", "description": "Start date (YYYY-MM-DD)"},
                    "to_date": {"type": "string", "description": "End date (YYYY-MM-DD)"},
                    "event": {"type": "string", "description": "Event name filter"}
                }
            }),
            json!({
                "type": "object",
                "required": ["data"],
                "properties": {"data": {"type": "object"}}
            }),
            "mixpanel.events.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Query Mixpanel events for a date range.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"from_date": "2025-01-01", "to_date": "2025-01-31", "event": "signup"}"#
                        .into(),
                ],
                related: vec![
                    CapabilityId::from_static("mixpanel.funnels.list"),
                    CapabilityId::from_static("mixpanel.insights.query"),
                ],
            },
        ),
        op_info(
            "mixpanel.funnels.list",
            "List saved funnels",
            json!({"type": "object", "required": []}),
            json!({
                "type": "object",
                "required": ["funnels"],
                "properties": {"funnels": {"type": "array"}}
            }),
            "mixpanel.funnels.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List saved funnels in Mixpanel.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("mixpanel.events.query")],
            },
        ),
        op_info(
            "mixpanel.insights.query",
            "Run an Insights query by bookmark ID",
            json!({
                "type": "object",
                "required": ["bookmark_id"],
                "properties": {
                    "bookmark_id": {"type": "string", "description": "Saved report bookmark ID"}
                }
            }),
            json!({
                "type": "object",
                "required": ["data"],
                "properties": {"data": {"type": "object"}}
            }),
            "mixpanel.insights.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Run a saved Insights report in Mixpanel.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"bookmark_id": "12345"}"#.into()],
                related: vec![
                    CapabilityId::from_static("mixpanel.events.query"),
                    CapabilityId::from_static("mixpanel.funnels.list"),
                ],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn config_from_service_account() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "sa_user",
            "secret": "sa_secret",
            "project_id": "12345",
        }))
        .unwrap();
        assert!(matches!(config.auth, MixpanelAuth::ServiceAccount { .. }));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.project_id, "12345");
    }

    #[test]
    fn config_from_credential_id() {
        let config = MixpanelConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "project_id": "99",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_project_id_as_number() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "s",
            "project_id": 12345,
        }))
        .unwrap();
        assert_eq!(config.project_id, "12345");
    }

    #[test]
    fn config_custom_base_url() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "s",
            "project_id": "1",
            "base_url": "https://mixpanel.example.com/v2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://mixpanel.example.com/v2");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "s",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "project_id": "1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = MixpanelConfig::from_params(&json!({
            "project_id": "1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_username_without_secret() {
        let result = MixpanelConfig::from_params(&json!({
            "username": "u",
            "project_id": "1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_secret_without_username() {
        let result = MixpanelConfig::from_params(&json!({
            "secret": "s",
            "project_id": "1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_username() {
        let result = MixpanelConfig::from_params(&json!({
            "username": "",
            "secret": "s",
            "project_id": "1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_secret() {
        let result = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "",
            "project_id": "1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_username() {
        let result = MixpanelConfig::from_params(&json!({
            "username": "   ",
            "secret": "s",
            "project_id": "1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_project_id() {
        let result = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "s",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = MixpanelConfig::from_params(&json!({
            "credential_id": 12345,
            "project_id": "1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = MixpanelConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
            "project_id": "1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"from_date": "2025-01-01"});
        assert_eq!(require_str(&input, "from_date").unwrap(), "2025-01-01");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "from_date").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"from_date": 42});
        assert!(require_str(&input, "from_date").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"from_date": null});
        assert!(require_str(&input, "from_date").is_err());
    }

    #[test]
    fn operations_info_has_3_operations() {
        let ops = ops_json();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = ops_json();
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
        let ops = ops_json();
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
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = ops_json();
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
        let ops = ops_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"mixpanel.events.query"));
        assert!(ids.contains(&"mixpanel.funnels.list"));
        assert!(ids.contains(&"mixpanel.insights.query"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = ops_json();
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
    fn config_trims_username() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "  myuser  ",
            "secret": "s",
            "project_id": "1",
        }))
        .unwrap();
        match &config.auth {
            MixpanelAuth::ServiceAccount { username, .. } => assert_eq!(username, "myuser"),
            MixpanelAuth::CredentialId(_) => panic!("expected ServiceAccount"),
        }
    }

    #[test]
    fn connector_default() {
        let c = MixpanelConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_request_count_zero() {
        let c = MixpanelConnector::new();
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
        // skip_serializing_if means the key should not appear
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
        let input = json!({"from_date": [1, 2, 3]});
        assert!(require_str(&input, "from_date").is_err());
    }

    #[test]
    fn require_str_bool_value() {
        let input = json!({"from_date": true});
        assert!(require_str(&input, "from_date").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"from_date": ""});
        // Empty string is still a valid string; require_str just checks for string presence
        assert_eq!(require_str(&input, "from_date").unwrap(), "");
    }

    #[test]
    fn operations_events_query_has_correct_capability() {
        let ops = ops_json();
        let eq = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mixpanel.events.query")
            .unwrap();
        assert_eq!(eq["capability"], "mixpanel.events.read");
    }

    #[test]
    fn operations_funnels_list_has_correct_capability() {
        let ops = ops_json();
        let fl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mixpanel.funnels.list")
            .unwrap();
        assert_eq!(fl["capability"], "mixpanel.funnels.read");
    }

    #[test]
    fn operations_insights_query_has_correct_capability() {
        let ops = ops_json();
        let iq = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mixpanel.insights.query")
            .unwrap();
        assert_eq!(iq["capability"], "mixpanel.insights.read");
    }

    #[test]
    fn operations_all_strict_idempotency() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert_eq!(
                op["idempotency"], "strict",
                "op {} should be strict",
                op["id"]
            );
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
        // Critical failure takes priority
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn config_whitespace_secret_rejected() {
        let result = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "   ",
            "project_id": "1",
        }));
        assert!(result.is_err());
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
    fn require_str_object_value() {
        let input = json!({"val": {"nested": true}});
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
    fn doctor_result_deserializes() {
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
    fn doctor_status_serde_roundtrip() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let s: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Unhealthy);
        assert!(dbg.contains("Unhealthy"));
    }

    #[test]
    fn doctor_result_empty_checks_is_healthy() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    // ── Config additional tests ─────────────────────────────────────

    #[test]
    fn config_debug() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "s",
            "project_id": "123"
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("MixpanelConfig"));
    }

    #[test]
    fn config_clone() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "s",
            "project_id": "123"
        }))
        .unwrap();
        let config2 = config.clone();
        assert_eq!(config.base_url, config2.base_url);
        assert_eq!(config.project_id, config2.project_id);
    }

    // ── operations_info additional tests ─────────────────────────────

    #[test]
    fn operations_all_ids_prefixed_with_mixpanel() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("mixpanel."),
                "op id {id} should start with mixpanel."
            );
        }
    }

    #[test]
    fn operations_all_have_summaries() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "empty summary for {}", op["id"]);
        }
    }

    #[test]
    fn operations_valid_idempotency_values() {
        let valid = ["strict", "best_effort", "none"];
        let ops = ops_json();
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
    fn doctor_status_serde_all_variants() {
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

    #[test]
    fn doctor_check_skip_none_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_includes_some_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failure".into()),
            critical: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["message"], "failure");
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_service_account_mode() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "sa_user",
            "secret": "sa_secret",
            "project_id": "12345",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "service_account");
        assert!(readiness.username_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = MixpanelConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "project_id": "99",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.username_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "s",
            "project_id": "1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "service_account");
        assert_eq!(v["username_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "s",
            "project_id": "1",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("mixpanel.com"));
    }

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "mixpanel.service_account");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_username");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_secret");
        assert_eq!(recipe.steps[2].id.as_str(), "store_credentials");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_username");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_secret");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "mixpanel.service_account");
        assert!(v["steps"].as_array().unwrap().len() == 3);
    }

    #[test]
    fn base_url_policy_accepts_mixpanel_https() {
        let (ok, message) = base_url_policy("https://mixpanel.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_data_mixpanel() {
        let (ok, message) = base_url_policy("https://data.mixpanel.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_eu_mixpanel() {
        let (ok, message) = base_url_policy("https://eu.mixpanel.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_wildcard_subdomain() {
        let (ok, message) = base_url_policy("https://custom.mixpanel.com");
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
        let (ok, message) = base_url_policy("http://mixpanel.com");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("mixpanel.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn is_local_test_host_localhost() {
        assert!(is_local_test_host("localhost"));
    }

    #[test]
    fn is_local_test_host_loopback_v4() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_rejects_remote() {
        assert!(!is_local_test_host("example.com"));
    }

    #[test]
    fn provisioning_readiness_debug() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "s",
            "project_id": "1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let config = MixpanelConfig::from_params(&json!({
            "username": "u",
            "secret": "s",
            "project_id": "1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let readiness2 = readiness.clone();
        assert_eq!(readiness.auth_mode, readiness2.auth_mode);
        assert_eq!(readiness.network_ok, readiness2.network_ok);
    }
}
