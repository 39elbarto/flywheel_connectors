//! FCP `BigQuery` Connector implementation.

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

use crate::{
    client::{DEFAULT_BASE_URL, BigQueryAuth, BigQueryClient},
    error::BigQueryError,
};

/// Parsed and validated `BigQuery` connector configuration.
#[derive(Debug, Clone)]
struct BigQueryConfig {
    auth: BigQueryAuth,
    project_id: Option<String>,
    base_url: Option<String>,
}

impl BigQueryConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty access_token in configuration".into(),
            })?
            .to_string();

        let project_id = params
            .get("project_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        Ok(Self {
            auth: BigQueryAuth { access_token },
            project_id,
            base_url,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let effective_url = self
            .base_url
            .as_deref()
            .unwrap_or(DEFAULT_BASE_URL);
        let (network_ok, network_message) = base_url_policy(effective_url);

        ProvisioningReadiness {
            auth_mode: "bearer_token",
            token_configured: true,
            project_id_configured: self.project_id.is_some(),
            network_ok,
            network_message,
            base_url: effective_url.to_string(),
        }
    }
}

/// Provisioning readiness assessment.
#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    token_configured: bool,
    project_id_configured: bool,
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

/// FCP `BigQuery` Connector.
pub struct BigQueryConnector {
    base: Arc<BaseConnector>,
    config: Option<BigQueryConfig>,
    client: Option<Arc<BigQueryClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl BigQueryConnector {
    /// Create a new `BigQuery` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("bigquery"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for BigQueryConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl BigQueryConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = BigQueryConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), "Configuring BigQuery connector");

        let client = BigQueryClient::new(
            config.auth.clone(),
            config.project_id.clone(),
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
            "connector_id": "fcp.bigquery",
            "connector_version": "0.1.0",
            "capabilities": [
                "bigquery.datasets.read",
                "bigquery.tables.read",
                "bigquery.jobs.read",
                "bigquery.jobs.write"
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

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "bigquery.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "BigQuery self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("bigquery.datasets.list"),
                    summary: "List datasets in a project".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["project_id"],
                        "properties": {"project_id": {"type": "string"}}
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["datasets"],
                        "properties": {"datasets": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("bigquery.datasets.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List BigQuery datasets in a GCP project.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"project_id": "my-gcp-project"}"#.into()],
                        related: vec![CapabilityId::from_static("bigquery.tables.list")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("bigquery.tables.list"),
                    summary: "List tables in a dataset".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["project_id", "dataset_id"],
                        "properties": {
                            "project_id": {"type": "string"},
                            "dataset_id": {"type": "string"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["tables"],
                        "properties": {"tables": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("bigquery.tables.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List tables in a BigQuery dataset.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"project_id": "my-gcp-project", "dataset_id": "analytics"}"#
                                .into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("bigquery.datasets.list"),
                            CapabilityId::from_static("bigquery.jobs.query"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("bigquery.jobs.list"),
                    summary: "List recent jobs".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["project_id"],
                        "properties": {"project_id": {"type": "string"}}
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["jobs"],
                        "properties": {"jobs": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("bigquery.jobs.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List recent BigQuery jobs.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"project_id": "my-gcp-project"}"#.into()],
                        related: vec![CapabilityId::from_static("bigquery.jobs.query")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("bigquery.jobs.query"),
                    summary: "Run a SQL query".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["project_id", "query"],
                        "properties": {
                            "project_id": {"type": "string"},
                            "query": {"type": "string", "description": "SQL query string"},
                            "use_legacy_sql": {"type": "boolean"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["rows"],
                        "properties": {"rows": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("bigquery.jobs.write"),
                    risk_level: RiskLevel::High,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Run a SQL query against BigQuery.".into(),
                        common_mistakes: vec![
                            "Using legacy SQL syntax without setting use_legacy_sql.".into(),
                        ],
                        examples: vec![
                            r#"{"project_id": "my-gcp-project", "query": "SELECT * FROM analytics.events LIMIT 10"}"#
                                .into(),
                        ],
                        related: vec![CapabilityId::from_static("bigquery.tables.list")],
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
            "bigquery.datasets.list" => self.invoke_datasets_list(client, &input).await,
            "bigquery.tables.list" => self.invoke_tables_list(client, &input).await,
            "bigquery.jobs.list" => self.invoke_jobs_list(client, &input).await,
            "bigquery.jobs.query" => self.invoke_jobs_query(client, &input).await,
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
        info!("BigQuery connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    /// Resolve the `project_id` from input or config, erroring if neither is set.
    fn resolve_project_id<'a>(
        &'a self,
        input: &'a serde_json::Value,
    ) -> Result<&'a str, BigQueryError> {
        input
            .get("project_id")
            .and_then(serde_json::Value::as_str)
            .or_else(|| self.config.as_ref().and_then(|c| c.project_id.as_deref()))
            .ok_or_else(|| BigQueryError::Api {
                status_code: 400,
                message: "Missing required field: project_id (not in input or config)".into(),
            })
    }

    async fn invoke_datasets_list(
        &self,
        client: &BigQueryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BigQueryError> {
        let project_id = self.resolve_project_id(input)?;
        client.list_datasets(project_id).await
    }

    async fn invoke_tables_list(
        &self,
        client: &BigQueryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BigQueryError> {
        let project_id = self.resolve_project_id(input)?;
        let dataset_id = require_str(input, "dataset_id")?;
        client.list_tables(project_id, dataset_id).await
    }

    async fn invoke_jobs_list(
        &self,
        client: &BigQueryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BigQueryError> {
        let project_id = self.resolve_project_id(input)?;
        client.list_jobs(project_id).await
    }

    async fn invoke_jobs_query(
        &self,
        client: &BigQueryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, BigQueryError> {
        let project_id = self.resolve_project_id(input)?;
        let query_str = require_str(input, "query")?;
        let use_legacy_sql = input
            .get("use_legacy_sql")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        client.query(project_id, query_str, use_legacy_sql).await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, BigQueryError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BigQueryError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the provisioning recipe for the `BigQuery` connector.
///
/// `BigQuery` uses a service account JSON key (or OAuth access token). The recipe
/// captures: (1) prompt for the service account key, (2) store the secret, and
/// (3) prompt for a default project ID.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("bigquery.service_account"),
        "1",
        "Provision BigQuery connector with a service account key or OAuth token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_service_account_key"),
        ProvisioningStepType::PromptSecret {
            message: "Paste your BigQuery service account JSON key or OAuth access token".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_service_account_key"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("enter_service_account_key"),
                scope: "connector:fcp.bigquery".into(),
            },
        )
        .depends_on(StepId::new("enter_service_account_key")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_project_id"),
            ProvisioningStepType::PromptUser {
                message: "Enter the default GCP project ID for BigQuery operations".into(),
            },
        )
        .depends_on(StepId::new("enter_service_account_key")),
    )
}

/// Validate a base URL against the `BigQuery` connector's network policy.
///
/// Accepts:
///   - `bigquery.googleapis.com` (primary)
///   - `*.googleapis.com` (other Google endpoints)
///   - `localhost`, `127.0.0.1`, `::1` (local testing)
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
    let allowed_host = host.eq_ignore_ascii_case("bigquery.googleapis.com")
        || host
            .to_ascii_lowercase()
            .ends_with(".googleapis.com")
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
                "Endpoint must use https and googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "bigquery.datasets.list",
            "summary": "List datasets in a project",
            "capability": "bigquery.datasets.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bigquery.tables.list",
            "summary": "List tables in a dataset",
            "capability": "bigquery.tables.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bigquery.jobs.list",
            "summary": "List recent jobs",
            "capability": "bigquery.jobs.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "bigquery.jobs.query",
            "summary": "Run a SQL query",
            "capability": "bigquery.jobs.write",
            "risk_level": "high",
            "safety_tier": "risky",
            "idempotency": "none",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_valid_params() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "ya29.abc123",
        }))
        .unwrap();
        assert_eq!(config.auth.access_token, "ya29.abc123");
        assert!(config.project_id.is_none());
        assert!(config.base_url.is_none());
    }

    #[test]
    fn config_with_project_id() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "ya29.abc",
            "project_id": "my-gcp-project",
        }))
        .unwrap();
        assert_eq!(config.project_id, Some("my-gcp-project".into()));
    }

    #[test]
    fn config_with_custom_base_url() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://test.bq.example.com/v2",
        }))
        .unwrap();
        assert_eq!(
            config.base_url,
            Some("https://test.bq.example.com/v2".into())
        );
    }

    #[test]
    fn config_rejects_missing_access_token() {
        let result = BigQueryConfig::from_params(&json!({
            "project_id": "proj",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = BigQueryConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = BigQueryConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_params() {
        let result = BigQueryConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_access_token() {
        let result = BigQueryConfig::from_params(&json!({
            "access_token": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_access_token() {
        let result = BigQueryConfig::from_params(&json!({
            "access_token": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "  ya29.tok  ",
        }))
        .unwrap();
        assert_eq!(config.auth.access_token, "ya29.tok");
    }

    #[test]
    fn config_trims_project_id() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "tok",
            "project_id": "  my-proj  ",
        }))
        .unwrap();
        assert_eq!(config.project_id, Some("my-proj".into()));
    }

    #[test]
    fn config_ignores_empty_project_id() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "tok",
            "project_id": "",
        }))
        .unwrap();
        assert!(config.project_id.is_none());
    }

    #[test]
    fn config_ignores_whitespace_project_id() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "tok",
            "project_id": "   ",
        }))
        .unwrap();
        assert!(config.project_id.is_none());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"project_id": "my-proj"});
        assert_eq!(require_str(&input, "project_id").unwrap(), "my-proj");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "project_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"project_id": 42});
        assert!(require_str(&input, "project_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"project_id": null});
        assert!(require_str(&input, "project_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"project_id": true});
        assert!(require_str(&input, "project_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"project_id": ["a", "b"]});
        assert!(require_str(&input, "project_id").is_err());
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
        assert!(ids.contains(&"bigquery.datasets.list"));
        assert!(ids.contains(&"bigquery.tables.list"));
        assert!(ids.contains(&"bigquery.jobs.list"));
        assert!(ids.contains(&"bigquery.jobs.query"));
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
    fn operations_query_is_risky() {
        let ops = operations_info();
        let query_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "bigquery.jobs.query")
            .unwrap();
        assert_eq!(query_op["safety_tier"], "risky");
        assert_eq!(query_op["risk_level"], "high");
    }

    #[test]
    fn operations_query_not_idempotent() {
        let ops = operations_info();
        let query_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "bigquery.jobs.query")
            .unwrap();
        assert_eq!(query_op["idempotency"], "none");
    }

    #[test]
    fn operations_datasets_list_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "bigquery.datasets.list")
            .unwrap();
        assert_eq!(op["capability"], "bigquery.datasets.read");
    }

    #[test]
    fn operations_tables_list_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "bigquery.tables.list")
            .unwrap();
        assert_eq!(op["capability"], "bigquery.tables.read");
    }

    #[test]
    fn operations_jobs_list_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "bigquery.jobs.list")
            .unwrap();
        assert_eq!(op["capability"], "bigquery.jobs.read");
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
        let c = BigQueryConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = BigQueryConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn config_with_all_params() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "ya29.abc",
            "project_id": "proj-123",
            "base_url": "https://custom.example.com/bq",
        }))
        .unwrap();
        assert_eq!(config.auth.access_token, "ya29.abc");
        assert_eq!(config.project_id, Some("proj-123".into()));
        assert_eq!(
            config.base_url,
            Some("https://custom.example.com/bq".into())
        );
    }

    #[test]
    fn config_rejects_boolean_access_token() {
        let result = BigQueryConfig::from_params(&json!({
            "access_token": false,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_array_access_token() {
        let result = BigQueryConfig::from_params(&json!({
            "access_token": ["tok"],
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"f": {"nested": true}});
        assert!(require_str(&input, "f").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"f": 3.15});
        assert!(require_str(&input, "f").is_err());
    }

    #[test]
    fn operations_list_ops_strict_idempotent() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.contains("list") {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "strict",
                    "list op {id} should be strict idempotent"
                );
            }
        }
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
    fn doctor_status_deserializes_lowercase() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_eq() {
        let s = DoctorStatus::Healthy;
        let s2 = s; // Copy
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_check_message_none_omitted() {
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
    fn doctor_check_message_some_present() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("err".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "err");
    }

    #[test]
    fn doctor_result_roundtrip() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "c1".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "c2".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "degraded");
        let back: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(back.status, DoctorStatus::Degraded);
        assert_eq!(back.checks.len(), 2);
    }

    #[test]
    fn doctor_check_clone_and_debug() {
        let check = DoctorCheck {
            name: "my_check".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let cloned = check.clone();
        assert_eq!(check.name, "my_check");
        assert_eq!(cloned.message.as_deref(), Some("ok"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn config_debug_and_clone() {
        let config = BigQueryConfig::from_params(&json!({"access_token": "tok"})).unwrap();
        let cloned = config.clone();
        assert!(config.project_id.is_none());
        assert!(cloned.project_id.is_none());
        let dbg = format!("{config:?}");
        assert!(dbg.contains("BigQueryConfig"));
    }

    #[test]
    fn operations_all_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_all_capabilities_prefixed() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("bigquery."),
                "capability {cap} should start with bigquery."
            );
        }
    }

    #[test]
    fn connector_new_counters_zero() {
        let c = BigQueryConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_result_debug_and_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "c".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    // -- Provisioning readiness tests --

    #[test]
    fn provisioning_readiness_default_base_url() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "ya29.tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "bearer_token");
        assert!(readiness.token_configured);
        assert!(!readiness.project_id_configured);
        assert!(readiness.network_ok);
        assert!(readiness.base_url.contains("googleapis.com"));
    }

    #[test]
    fn provisioning_readiness_with_project_id() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "tok",
            "project_id": "my-proj",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.project_id_configured);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "tok",
            "project_id": "proj-1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["project_id_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("googleapis.com"));
    }

    #[test]
    fn provisioning_readiness_debug() {
        let config = BigQueryConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }

    // -- Provisioning recipe tests --

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "bigquery.service_account");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_service_account_key");
        assert_eq!(recipe.steps[1].id.as_str(), "store_service_account_key");
        assert_eq!(recipe.steps[2].id.as_str(), "enter_project_id");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(
            recipe.steps[1].depends_on[0].as_str(),
            "enter_service_account_key"
        );
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(
            recipe.steps[2].depends_on[0].as_str(),
            "enter_service_account_key"
        );
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "bigquery.service_account");
        assert_eq!(v["steps"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn provisioning_recipe_description_non_empty() {
        let recipe = provisioning_recipe();
        assert!(!recipe.description.is_empty());
    }

    #[test]
    fn provisioning_recipe_step_types() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            &recipe.steps[0].kind,
            ProvisioningStepType::PromptSecret { .. }
        ));
        assert!(matches!(
            &recipe.steps[1].kind,
            ProvisioningStepType::StoreSecret { .. }
        ));
        assert!(matches!(
            &recipe.steps[2].kind,
            ProvisioningStepType::PromptUser { .. }
        ));
    }

    #[test]
    fn provisioning_recipe_store_secret_scope() {
        let recipe = provisioning_recipe();
        if let ProvisioningStepType::StoreSecret { key, scope, .. } = &recipe.steps[1].kind {
            assert_eq!(key, "access_token");
            assert_eq!(scope, "connector:fcp.bigquery");
        } else {
            panic!("step 1 should be StoreSecret");
        }
    }

    // -- Base URL policy tests --

    #[test]
    fn base_url_policy_accepts_bigquery_googleapis() {
        let (ok, message) = base_url_policy("https://bigquery.googleapis.com/bigquery/v2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_other_googleapis() {
        let (ok, _) = base_url_policy("https://content-bigquery.googleapis.com/bigquery/v2");
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
        let (ok, message) = base_url_policy("http://bigquery.googleapis.com/bigquery/v2");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("googleapis.com"));
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
        // file URLs may or may not have a host depending on platform
        assert!(!ok);
    }

    #[test]
    fn is_local_test_host_known_locals() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_rejects_non_local() {
        assert!(!is_local_test_host("example.com"));
        assert!(!is_local_test_host("192.168.1.1"));
        assert!(!is_local_test_host("googleapis.com"));
    }
}
