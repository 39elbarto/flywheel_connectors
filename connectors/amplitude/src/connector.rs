//! FCP `Amplitude` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    Introspection, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use fcp_sdk::migration::ConnectorRuntime;

use crate::{
    client::{AmplitudeAuth, AmplitudeClient, DEFAULT_BASE_URL},
    error::AmplitudeError,
};

/// Parsed and validated `Amplitude` connector configuration.
#[derive(Debug, Clone)]
struct AmplitudeConfig {
    auth: AmplitudeAuth,
    base_url: String,
}

impl AmplitudeConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty api_key in configuration".into(),
            })?
            .to_string();

        let secret_key = params
            .get("secret_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty secret_key in configuration".into(),
            })?
            .to_string();

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self {
            auth: AmplitudeAuth {
                api_key,
                secret_key,
            },
            base_url,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            api_key_configured: true,
            secret_key_configured: true,
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

/// Provisioning readiness state for the `Amplitude` connector.
#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    api_key_configured: bool,
    secret_key_configured: bool,
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

/// FCP `Amplitude` Connector.
pub struct AmplitudeConnector {
    base: Arc<BaseConnector>,
    config: Option<AmplitudeConfig>,
    client: Option<Arc<AmplitudeClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
    runtime: Option<ConnectorRuntime>,
}

impl AmplitudeConnector {
    /// Create a new `Amplitude` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("amplitude"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            runtime: None,
        }
    }
}

impl Default for AmplitudeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl AmplitudeConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = AmplitudeConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Amplitude connector");

        let client = AmplitudeClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        let runtime = ConnectorRuntime::new(
            fcp_sdk::migration::ConnectorRuntimeConfig::default(),
        );

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.runtime = Some(runtime);
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
            "connector_id": "fcp.amplitude",
            "connector_version": "0.1.0",
            "capabilities": [
                "amplitude.charts.read",
                "amplitude.cohorts.read",
                "amplitude.events.read"
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

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("amplitude.charts.query"),
                    summary: "Query a chart by ID".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["chart_id"],
                        "properties": {
                            "chart_id": {"type": "string", "description": "Chart ID to query"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["data"],
                        "properties": {"data": {"type": "object"}}
                    }),
                    capability: CapabilityId::from_static("amplitude.charts.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Query chart data from Amplitude by chart ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"chart_id": "abc123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("amplitude.events.export"),
                            CapabilityId::from_static("amplitude.cohorts.list"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("amplitude.cohorts.list"),
                    summary: "List cohorts".into(),
                    input_schema: json!({"type": "object", "required": []}),
                    output_schema: json!({
                        "type": "object",
                        "required": ["cohorts"],
                        "properties": {"cohorts": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("amplitude.cohorts.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List all cohorts in Amplitude.".into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("amplitude.events.export")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("amplitude.events.export"),
                    summary: "Export events for a date range".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["start", "end"],
                        "properties": {
                            "start": {"type": "string", "description": "Start date (YYYYMMDDTHH)"},
                            "end": {"type": "string", "description": "End date (YYYYMMDDTHH)"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["data"],
                        "properties": {"data": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("amplitude.events.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Export raw events from Amplitude for a date range.".into(),
                        common_mistakes: vec!["Date format must be YYYYMMDDTHH".into()],
                        examples: vec![r#"{"start": "20250101T00", "end": "20250102T00"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("amplitude.cohorts.list"),
                            CapabilityId::from_static("amplitude.charts.query"),
                        ],
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
            "amplitude.charts.query" => self.invoke_charts_query(client, &input).await,
            "amplitude.cohorts.list" => self.invoke_cohorts_list(client).await,
            "amplitude.events.export" => self.invoke_events_export(client, &input).await,
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
        info!("Amplitude connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.client = None;
        self.config = None;
        self.runtime = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "amplitude.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Amplitude self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // -- Operation implementations --

    async fn invoke_charts_query(
        &self,
        client: &AmplitudeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AmplitudeError> {
        let chart_id = require_str(input, "chart_id")?;
        client.query_chart(chart_id).await
    }

    async fn invoke_cohorts_list(
        &self,
        client: &AmplitudeClient,
    ) -> Result<serde_json::Value, AmplitudeError> {
        client.list_cohorts().await
    }

    async fn invoke_events_export(
        &self,
        client: &AmplitudeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AmplitudeError> {
        let start = require_str(input, "start")?;
        let end = require_str(input, "end")?;
        client.export_events(start, end).await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, AmplitudeError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AmplitudeError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "amplitude.charts.query",
            "summary": "Query a chart by ID",
            "capability": "amplitude.charts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "amplitude.cohorts.list",
            "summary": "List cohorts",
            "capability": "amplitude.cohorts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "amplitude.events.export",
            "summary": "Export events for a date range",
            "capability": "amplitude.events.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

/// Build the provisioning recipe for the `Amplitude` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("amplitude.basic_auth"),
        "1",
        "Provision `Amplitude` connector with API key and secret key (Basic auth)",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_api_key"),
        ProvisioningStepType::PromptSecret {
            message: "Paste your `Amplitude` API key".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_secret_key"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your `Amplitude` secret key".into(),
            },
        )
        .depends_on(StepId::new("enter_api_key")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_key".into(),
                value_from: StepId::new("enter_api_key"),
                scope: "connector:fcp.amplitude".into(),
            },
        )
        .depends_on(StepId::new("enter_api_key")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_secret_key"),
            ProvisioningStepType::StoreSecret {
                key: "secret_key".into(),
                value_from: StepId::new("enter_secret_key"),
                scope: "connector:fcp.amplitude".into(),
            },
        )
        .depends_on(StepId::new("enter_secret_key")),
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
    let allowed_host = host.eq_ignore_ascii_case("analytics.amplitude.com")
        || host.eq_ignore_ascii_case("amplitude.com")
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
                "Endpoint must use https and analytics.amplitude.com or amplitude.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
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
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "test-api-key",
            "secret_key": "test-secret",
        }))
        .unwrap();
        assert_eq!(config.auth.api_key, "test-api-key");
        assert_eq!(config.auth.secret_key, "test-secret");
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_with_custom_base_url() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "KEY",
            "secret_key": "SECRET",
            "base_url": "https://test.amplitude.com/api/2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://test.amplitude.com/api/2");
    }

    #[test]
    fn config_rejects_missing_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "",
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "   ",
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_params() {
        let result = AmplitudeConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": 12345,
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_api_key() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "  KEY  ",
            "secret_key": "secret",
        }))
        .unwrap();
        assert_eq!(config.auth.api_key, "KEY");
    }

    #[test]
    fn config_trims_secret_key() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "  SECRET  ",
        }))
        .unwrap();
        assert_eq!(config.auth.secret_key, "SECRET");
    }

    #[test]
    fn config_rejects_null_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": null,
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_boolean_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": true,
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_array_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": ["a", "b"],
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"chart_id": "chart123"});
        assert_eq!(require_str(&input, "chart_id").unwrap(), "chart123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"chart_id": 42});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"chart_id": null});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"chart_id": true});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"chart_id": ["a", "b"]});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"chart_id": {"nested": true}});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn operations_info_has_3_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 3);
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
        assert!(ids.contains(&"amplitude.charts.query"));
        assert!(ids.contains(&"amplitude.cohorts.list"));
        assert!(ids.contains(&"amplitude.events.export"));
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
    fn operations_all_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert_eq!(op["safety_tier"], "safe");
            assert_eq!(op["risk_level"], "low");
        }
    }

    #[test]
    fn operations_charts_query_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "amplitude.charts.query")
            .unwrap();
        assert_eq!(op["capability"], "amplitude.charts.read");
    }

    #[test]
    fn operations_cohorts_list_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "amplitude.cohorts.list")
            .unwrap();
        assert_eq!(op["capability"], "amplitude.cohorts.read");
    }

    #[test]
    fn operations_events_export_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "amplitude.events.export")
            .unwrap();
        assert_eq!(op["capability"], "amplitude.events.read");
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
        let c = AmplitudeConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = AmplitudeConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn doctor_check_serializes_with_message() {
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
    fn doctor_check_omits_null_message() {
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
    fn doctor_status_serde_roundtrip() {
        let healthy = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(healthy, "healthy");
        let degraded = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(degraded, "degraded");
        let unhealthy = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(unhealthy, "unhealthy");
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
    fn doctor_status_copy_and_eq() {
        let s = DoctorStatus::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_result_preserves_check_count() {
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
            DoctorCheck {
                name: "c".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.checks.len(), 3);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_new_zero_counters() {
        let c = AmplitudeConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_debug_format() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "test-key",
            "secret_key": "test-secret",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("AmplitudeConfig"));
        assert!(!dbg.contains("test-key"));
        assert!(!dbg.contains("test-secret"));
    }

    #[test]
    fn config_clone() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
            "base_url": "https://custom.com",
        }))
        .unwrap();
        let cloned = config.clone();
        // Use original after clone
        assert_eq!(config.auth.api_key, "key");
        assert_eq!(cloned.auth.api_key, "key");
        assert_eq!(cloned.base_url, "https://custom.com");
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"chart_id": ""});
        assert_eq!(require_str(&input, "chart_id").unwrap(), "");
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"chart_id": 9.876});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn operations_all_have_summary() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_all_strict_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert_eq!(
                op["idempotency"], "strict",
                "op {:?} should be strict",
                op["id"]
            );
        }
    }

    #[test]
    fn config_base_url_defaults_when_not_provided() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_basic_auth_mode() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "test-api-key",
            "secret_key": "test-secret",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.api_key_configured);
        assert!(readiness.secret_key_configured);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["api_key_configured"], true);
        assert_eq!(v["secret_key_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("amplitude.com"));
    }

    #[test]
    fn provisioning_recipe_has_4_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "amplitude.basic_auth");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 4);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_api_key");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_secret_key");
        assert_eq!(recipe.steps[2].id.as_str(), "store_api_key");
        assert_eq!(recipe.steps[3].id.as_str(), "store_secret_key");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_api_key");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_api_key");
        assert_eq!(recipe.steps[3].depends_on.len(), 1);
        assert_eq!(recipe.steps[3].depends_on[0].as_str(), "enter_secret_key");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "amplitude.basic_auth");
        assert_eq!(v["steps"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn provisioning_recipe_prompt_steps_are_secret() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let steps = v["steps"].as_array().unwrap();
        assert_eq!(steps[0]["type"], "prompt_secret");
        assert_eq!(steps[1]["type"], "prompt_secret");
    }

    #[test]
    fn provisioning_recipe_store_steps_have_scope() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let steps = v["steps"].as_array().unwrap();
        assert_eq!(steps[2]["scope"], "connector:fcp.amplitude");
        assert_eq!(steps[3]["scope"], "connector:fcp.amplitude");
    }

    #[test]
    fn provisioning_recipe_store_api_key_references_prompt() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let steps = v["steps"].as_array().unwrap();
        assert_eq!(steps[2]["key"], "api_key");
        assert_eq!(steps[2]["value_from"], "enter_api_key");
    }

    #[test]
    fn provisioning_recipe_store_secret_key_references_prompt() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let steps = v["steps"].as_array().unwrap();
        assert_eq!(steps[3]["key"], "secret_key");
        assert_eq!(steps[3]["value_from"], "enter_secret_key");
    }

    #[test]
    fn base_url_policy_accepts_amplitude_https() {
        let (ok, message) = base_url_policy("https://amplitude.com/api/2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_analytics_amplitude_https() {
        let (ok, message) = base_url_policy("https://analytics.amplitude.com");
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
        let (ok, message) = base_url_policy("http://amplitude.com");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("amplitude.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, _) = base_url_policy("http://[::1]:3000");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_subdomain() {
        let (ok, _) = base_url_policy("https://evil.amplitude.com.evil.com");
        assert!(!ok);
    }

    #[test]
    fn is_local_test_host_true_cases() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_false_cases() {
        assert!(!is_local_test_host("amplitude.com"));
        assert!(!is_local_test_host("192.168.1.1"));
        assert!(!is_local_test_host(""));
    }
}
