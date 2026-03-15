//! FCP `PostHog` Connector implementation.

#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use fcp_sdk::migration::ConnectorRuntime;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, PostHogAuth, PostHogClient},
    error::PostHogError,
};

/// Parsed and validated `PostHog` connector configuration.
#[derive(Debug, Clone)]
struct PostHogConfig {
    auth: PostHogAuth,
    project_id: String,
    base_url: String,
}

impl PostHogConfig {
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
            (Some(key), None) => PostHogAuth::ApiKey(key),
            (None, Some(cred_id)) => PostHogAuth::CredentialId(cred_id),
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

        let project_id = params
            .get("project_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: project_id".into(),
            })?
            .to_string();

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self {
            auth,
            project_id,
            base_url,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                PostHogAuth::ApiKey(_) => "api_key",
                PostHogAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, PostHogAuth::ApiKey(_)),
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

/// FCP `PostHog` Connector.
pub struct PostHogConnector {
    base: Arc<BaseConnector>,
    config: Option<PostHogConfig>,
    client: Option<Arc<PostHogClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
    runtime: Option<ConnectorRuntime>,
}

impl PostHogConnector {
    /// Create a new `PostHog` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("posthog"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            runtime: None,
        }
    }
}

impl Default for PostHogConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PostHogConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = PostHogConfig::from_params(&params)?;
        info!(
            auth = %config.auth.redacted_label(),
            project_id = %config.project_id,
            base_url = %config.base_url,
            "Configuring PostHog connector"
        );

        let client = PostHogClient::new(
            config.auth.clone(),
            &config.project_id,
            Some(&config.base_url),
        )
        .map_err(|e| e.to_fcp_error())?;

        self.runtime = Some(ConnectorRuntime::new(
            fcp_sdk::migration::ConnectorRuntimeConfig::default(),
        ));
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
            "connector_id": "fcp.posthog",
            "connector_version": "0.1.0",
            "capabilities": [
                "posthog.events.read",
                "posthog.insights.read",
                "posthog.feature_flags.read"
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
            "connector_id": "fcp.posthog",
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
            "posthog.events.query" => self.invoke_events_query(client, &input).await,
            "posthog.insights.list" => self.invoke_insights_list(client).await,
            "posthog.feature_flags.list" => self.invoke_feature_flags_list(client).await,
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
        info!("PostHog connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_events_query(
        &self,
        client: &PostHogClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostHogError> {
        let query = require_str(input, "query")?;
        let resp = client.query_events(query).await?;
        let results = resp
            .get("results")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Ok(json!({ "results": results }))
    }

    async fn invoke_insights_list(
        &self,
        client: &PostHogClient,
    ) -> Result<serde_json::Value, PostHogError> {
        let resp = client.list_insights().await?;
        let results = resp.get("results").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "results": results }))
    }

    async fn invoke_feature_flags_list(
        &self,
        client: &PostHogClient,
    ) -> Result<serde_json::Value, PostHogError> {
        let resp = client.list_feature_flags().await?;
        let results = resp.get("results").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "results": results }))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "posthog.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "`PostHog` self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, PostHogError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PostHogError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the provisioning recipe for the `PostHog` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("posthog.api_key"),
        "1",
        "Provision `PostHog` connector with a personal or project API key",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_api_key"),
        ProvisioningStepType::PromptSecret {
            message: "Paste your PostHog personal or project API key".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_key".into(),
                value_from: StepId::new("enter_api_key"),
                scope: "connector:fcp.posthog".into(),
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
    let allowed_host = host.eq_ignore_ascii_case("app.posthog.com")
        || host.eq_ignore_ascii_case("us.posthog.com")
        || host.eq_ignore_ascii_case("eu.posthog.com")
        || host.ends_with(".posthog.com")
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
                "Endpoint must use https and a `PostHog` domain \
                 (app.posthog.com, us.posthog.com, eu.posthog.com, \
                 or *.posthog.com; localhost/127.0.0.1/::1 allowed for tests): {base_url}"
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
            "posthog.events.query",
            "Query events using HogQL",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "description": "HogQL query string"}
                }
            }),
            json!({
                "type": "object",
                "required": ["results"],
                "properties": {"results": {"type": "array"}}
            }),
            "posthog.events.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Query PostHog events using HogQL.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"query": "SELECT event, count() FROM events GROUP BY event ORDER BY count() DESC LIMIT 10"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("posthog.insights.list"),
                    CapabilityId::from_static("posthog.feature_flags.list"),
                ],
            },
        ),
        op_info(
            "posthog.insights.list",
            "List saved insights",
            json!({"type": "object", "required": []}),
            json!({
                "type": "object",
                "required": ["results"],
                "properties": {"results": {"type": "array"}}
            }),
            "posthog.insights.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List saved insights in PostHog.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("posthog.events.query"),
                    CapabilityId::from_static("posthog.feature_flags.list"),
                ],
            },
        ),
        op_info(
            "posthog.feature_flags.list",
            "List feature flags",
            json!({"type": "object", "required": []}),
            json!({
                "type": "object",
                "required": ["results"],
                "properties": {"results": {"type": "array"}}
            }),
            "posthog.feature_flags.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List feature flags in PostHog.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("posthog.events.query"),
                    CapabilityId::from_static("posthog.insights.list"),
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
    fn config_from_api_key() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "phx_test_key",
            "project_id": "12345",
        }))
        .unwrap();
        assert!(matches!(config.auth, PostHogAuth::ApiKey(_)));
        assert_eq!(config.project_id, "12345");
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = PostHogConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "project_id": "12345",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "phx_key",
            "project_id": "12345",
            "base_url": "https://posthog.example.com/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://posthog.example.com/api");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = PostHogConfig::from_params(&json!({
            "api_key": "phx_key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "project_id": "12345",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = PostHogConfig::from_params(&json!({
            "project_id": "12345",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = PostHogConfig::from_params(&json!({
            "api_key": "",
            "project_id": "12345",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = PostHogConfig::from_params(&json!({
            "api_key": "   ",
            "project_id": "12345",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = PostHogConfig::from_params(&json!({
            "credential_id": 12345,
            "project_id": "12345",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = PostHogConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
            "project_id": "12345",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_project_id() {
        let result = PostHogConfig::from_params(&json!({
            "api_key": "phx_key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_project_id() {
        let result = PostHogConfig::from_params(&json!({
            "api_key": "phx_key",
            "project_id": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_project_id() {
        let result = PostHogConfig::from_params(&json!({
            "api_key": "phx_key",
            "project_id": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"query": "SELECT event FROM events"});
        assert_eq!(
            require_str(&input, "query").unwrap(),
            "SELECT event FROM events"
        );
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"query": 42});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"query": null});
        assert!(require_str(&input, "query").is_err());
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
        assert!(ids.contains(&"posthog.events.query"));
        assert!(ids.contains(&"posthog.insights.list"));
        assert!(ids.contains(&"posthog.feature_flags.list"));
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
    fn config_trims_api_key() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "  phx_test  ",
            "project_id": "12345",
        }))
        .unwrap();
        match &config.auth {
            PostHogAuth::ApiKey(t) => assert_eq!(t, "phx_test"),
            PostHogAuth::CredentialId(_) => panic!("expected ApiKey"),
        }
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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = PostHogConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    // -- Additional connector tests --

    #[test]
    fn connector_new_matches_default() {
        let c = PostHogConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let statuses = [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ];
        for s in &statuses {
            let v = serde_json::to_value(s).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn doctor_status_lowercase_serialization() {
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
    fn doctor_check_serializes_some_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failed");
        assert_eq!(v["critical"], true);
    }

    #[test]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let cloned = check.clone();
        assert!(check.passed);
        assert_eq!(cloned.name, "x");
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert!(cloned.checks.is_empty());
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_result_deserialize() {
        let v = json!({"status": "degraded", "checks": [{"name": "a", "passed": false, "critical": false}]});
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Degraded);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn operations_all_have_posthog_prefix() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(id.starts_with("posthog."), "op {id} missing posthog prefix");
        }
    }

    #[test]
    fn config_error_message_both_auth() {
        let result = PostHogConfig::from_params(&json!({
            "api_key": "phx_key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "project_id": "12345",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("exactly one")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_message_no_auth() {
        let result = PostHogConfig::from_params(&json!({"project_id": "12345"}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("Missing")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_message_missing_project_id() {
        let result = PostHogConfig::from_params(&json!({"api_key": "phx_key"}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("project_id")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_non_string_credential() {
        let result = PostHogConfig::from_params(&json!({
            "credential_id": 12345,
            "project_id": "12345",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("string")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_invalid_uuid() {
        let result = PostHogConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
            "project_id": "12345",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("UUID")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn require_str_empty_string_is_valid() {
        let input = json!({"query": ""});
        assert_eq!(require_str(&input, "query").unwrap(), "");
    }

    #[test]
    fn require_str_error_message_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "my_field").unwrap_err();
        match err {
            PostHogError::Api { message, .. } => assert!(message.contains("my_field")),
            _ => panic!("expected Api error"),
        }
    }

    #[test]
    fn doctor_result_unhealthy_overrides_degraded() {
        let r = DoctorResult::from_checks(vec![
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
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_multiple_critical_all_pass() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "config".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "client".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "handshake".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(r.checks.len(), 3);
    }

    #[test]
    fn doctor_check_roundtrip_with_message() {
        let check = DoctorCheck {
            name: "connectivity".into(),
            passed: false,
            message: Some("Cannot reach PostHog API".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        let back: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(back.name, "connectivity");
        assert!(!back.passed);
        assert_eq!(back.message, Some("Cannot reach PostHog API".into()));
        assert!(back.critical);
    }

    #[test]
    fn operations_summaries_are_non_empty() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "empty summary for op {:?}", op["id"]);
        }
    }

    #[test]
    fn require_str_boolean_value_returns_error() {
        let input = json!({"field": true});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_array_value_returns_error() {
        let input = json!({"field": [1, 2, 3]});
        assert!(require_str(&input, "field").is_err());
    }

    // ── require_str additional edge cases ────────────────────────────

    #[test]
    fn require_str_float_value() {
        let input = json!({"query": 1.23});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"query": {"nested": true}});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_nested_key_not_found() {
        let input = json!({"outer": {"inner": "val"}});
        assert!(require_str(&input, "inner").is_err());
    }

    // ── DoctorStatus additional coverage ────────────────────────────

    #[test]
    fn doctor_status_serde_all_variants_roundtrip() {
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
    fn doctor_status_copy_semantics() {
        let s = DoctorStatus::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_status_ne_comparison() {
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    // ── DoctorCheck additional coverage ─────────────────────────────

    #[test]
    fn doctor_check_debug_clone_roundtrip() {
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

    // ── DoctorResult additional coverage ────────────────────────────

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

    // ── Config / Connector tests ────────────────────────────────────

    #[test]
    fn config_debug_format() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "phx_test",
            "project_id": "1"
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("PostHogConfig"));
    }

    #[test]
    fn config_clone_preserves_url() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "phx_test",
            "project_id": "1",
            "base_url": "https://custom.posthog.com"
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, cloned.base_url);
    }

    #[test]
    fn connector_initial_counts() {
        let c = PostHogConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    // ── operations_info additional checks ───────────────────────────

    #[test]
    fn operations_all_prefixed_posthog() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("posthog."),
                "op {id} missing posthog. prefix"
            );
        }
    }

    #[test]
    fn operations_valid_risk_levels() {
        let valid = ["low", "medium", "high", "critical"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_valid_safety_tiers() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    // ── Provisioning recipe tests ─────────────────────────────────

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "posthog.api_key");
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
        assert_eq!(v["id"], "posthog.api_key");
        assert_eq!(v["steps"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn provisioning_recipe_description_mentions_posthog() {
        let recipe = provisioning_recipe();
        assert!(recipe.description.contains("PostHog"));
    }

    #[test]
    fn provisioning_recipe_first_step_is_prompt_secret() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            recipe.steps[0].kind,
            ProvisioningStepType::PromptSecret { .. }
        ));
    }

    #[test]
    fn provisioning_recipe_second_step_is_store_secret() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            recipe.steps[1].kind,
            ProvisioningStepType::StoreSecret { .. }
        ));
    }

    // ── base_url_policy tests ─────────────────────────────────────

    #[test]
    fn base_url_policy_accepts_app_posthog_https() {
        let (ok, message) = base_url_policy("https://app.posthog.com/api");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_us_posthog_https() {
        let (ok, message) = base_url_policy("https://us.posthog.com/api");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_eu_posthog_https() {
        let (ok, message) = base_url_policy("https://eu.posthog.com/api");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_self_hosted_posthog() {
        let (ok, _) = base_url_policy("https://custom.posthog.com");
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
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://app.posthog.com");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("PostHog"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    // ── Provisioning readiness tests ──────────────────────────────

    #[test]
    fn provisioning_readiness_api_key() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "phx_test",
            "project_id": "1",
            "base_url": "https://app.posthog.com/api",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_key");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let config = PostHogConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "project_id": "1",
            "base_url": "https://app.posthog.com/api",
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
    fn provisioning_readiness_serializes() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "phx_test",
            "project_id": "1",
            "base_url": "https://app.posthog.com/api",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_key");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "phx_test",
            "project_id": "1",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("PostHog"));
    }

    #[test]
    fn provisioning_readiness_localhost_ok() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "phx_test",
            "project_id": "1",
            "base_url": "http://localhost:8000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_debug() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "phx_test",
            "project_id": "1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let config = PostHogConfig::from_params(&json!({
            "api_key": "phx_test",
            "project_id": "1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = readiness.clone();
        assert_eq!(readiness.auth_mode, cloned.auth_mode);
        assert_eq!(readiness.network_ok, cloned.network_ok);
    }
}
