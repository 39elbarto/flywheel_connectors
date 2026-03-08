//! FCP `BigQuery` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{BigQueryAuth, BigQueryClient},
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
        Ok(json!({
            "connector_id": "fcp.bigquery",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.bigquery",
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
}
