//! FCP Datadog Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, DatadogAuth, DatadogClient, DatadogRegion},
    error::DatadogError,
};

/// Parsed and validated Datadog connector configuration.
#[derive(Debug, Clone)]
struct DatadogConfig {
    auth: DatadogAuth,
    base_url: String,
}

impl DatadogConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let parsed_api_key = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let parsed_application_key = params
            .get("app_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
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

        let auth = match (parsed_api_key, parsed_application_key, credential_id) {
            (Some(ak), Some(apk), None) => DatadogAuth::ApiKeys {
                api_key: ak,
                app_key: apk,
            },
            (None, None, Some(cred_id)) => DatadogAuth::CredentialId(cred_id),
            (Some(_), None, None) | (None, Some(_), None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Both api_key and app_key are required".into(),
                });
            }
            (Some(_) | None, Some(_), Some(_)) | (Some(_), None, Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide either api_key+app_key or credential_id, not both".into(),
                });
            }
            (None, None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key+app_key or credential_id in configuration".into(),
                });
            }
        };

        // Resolve base URL: explicit base_url > region > default
        let base_url = if let Some(url) = params.get("base_url").and_then(|v| v.as_str()) {
            url.to_string()
        } else if let Some(region_str) = params.get("region").and_then(|v| v.as_str()) {
            DatadogRegion::parse_region(region_str).map_or_else(
                || DEFAULT_BASE_URL.to_string(),
                |r| r.api_base_url().to_string(),
            )
        } else {
            DEFAULT_BASE_URL.to_string()
        };

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

/// FCP Datadog Connector.
pub struct DatadogConnector {
    base: Arc<BaseConnector>,
    config: Option<DatadogConfig>,
    client: Option<Arc<DatadogClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl DatadogConnector {
    /// Create a new Datadog connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("datadog"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for DatadogConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl DatadogConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = DatadogConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Datadog connector");

        let client = DatadogClient::new(config.auth.clone(), Some(&config.base_url))
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
            .and_then(|v| v.as_str())
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.datadog",
            "connector_version": "0.1.0",
            "capabilities": [
                "datadog.events.read",
                "datadog.events.write",
                "datadog.metrics.read",
                "datadog.metrics.write",
                "datadog.monitors.read",
                "datadog.monitors.write",
                "datadog.logs.read"
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
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.datadog",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.datadog",
            "version": "0.1.0",
            "operations": operations_info(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params.get("operation_id").and_then(|v| v.as_str()).ok_or(
            FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            },
        )?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "datadog.events.create" => self.invoke_events_create(client, &input).await,
            "datadog.events.list" => self.invoke_events_list(client, &input).await,
            "datadog.logs.search" => self.invoke_logs_search(client, &input).await,
            "datadog.metrics.query" => self.invoke_metrics_query(client, &input).await,
            "datadog.metrics.submit" => self.invoke_metrics_submit(client, &input).await,
            "datadog.monitors.create" => self.invoke_monitors_create(client, &input).await,
            "datadog.monitors.delete" => self.invoke_monitors_delete(client, &input).await,
            "datadog.monitors.list" => self.invoke_monitors_list(client, &input).await,
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
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(|v| v.as_str()) == Some(operation))
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
        info!("Datadog connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_events_create(
        &self,
        client: &DatadogClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DatadogError> {
        let data = client.create_event(input).await?;
        Ok(json!({ "event": data.get("event").cloned().unwrap_or(data) }))
    }

    async fn invoke_events_list(
        &self,
        client: &DatadogClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DatadogError> {
        let start = require_i64(input, "start")?;
        let end = require_i64(input, "end")?;
        let priority = input.get("priority").and_then(|v| v.as_str());
        let sources = input.get("sources").and_then(|v| v.as_str());
        let tags = input.get("tags").and_then(|v| v.as_str());
        let data = client
            .list_events(start, end, priority, sources, tags)
            .await?;
        Ok(json!({ "events": data.get("events").cloned().unwrap_or(json!([])) }))
    }

    async fn invoke_logs_search(
        &self,
        client: &DatadogClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DatadogError> {
        let query = require_str(input, "query")?;
        let mut body = json!({
            "query": { "query_string": query }
        });
        if let Some(from_ts) = input.get("from_ts").and_then(|v| v.as_str()) {
            body["time"] = json!({ "from": from_ts });
            if let Some(to_ts) = input.get("to_ts").and_then(|v| v.as_str()) {
                body["time"]["to"] = json!(to_ts);
            }
        }
        if let Some(limit) = input.get("limit").and_then(|v| v.as_i64()) {
            body["limit"] = json!(limit);
        }
        let data = client.search_logs(&body).await?;
        Ok(json!({ "logs": data.get("logs").cloned().unwrap_or(json!([])) }))
    }

    async fn invoke_metrics_query(
        &self,
        client: &DatadogClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DatadogError> {
        let query = require_str(input, "query")?;
        let from_ts = require_i64(input, "from_ts")?;
        let to_ts = require_i64(input, "to_ts")?;
        let data = client.query_metrics(query, from_ts, to_ts).await?;
        Ok(json!({ "series": data.get("series").cloned().unwrap_or(json!([])) }))
    }

    async fn invoke_metrics_submit(
        &self,
        client: &DatadogClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DatadogError> {
        let series = input.get("series").ok_or_else(|| DatadogError::Api {
            status_code: 400,
            message: "Missing required field: series".into(),
        })?;
        let body = json!({ "series": series });
        let data = client.submit_metrics(&body).await?;
        Ok(json!({ "status": data.get("status").cloned().unwrap_or(json!("ok")) }))
    }

    async fn invoke_monitors_create(
        &self,
        client: &DatadogClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DatadogError> {
        let data = client.create_monitor(input).await?;
        Ok(json!({ "id": data.get("id").cloned().unwrap_or(json!(null)) }))
    }

    async fn invoke_monitors_delete(
        &self,
        client: &DatadogClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DatadogError> {
        let monitor_id = require_i64(input, "monitor_id")?;
        client.delete_monitor(monitor_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_monitors_list(
        &self,
        client: &DatadogClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DatadogError> {
        let tags = input.get("tags").and_then(|v| v.as_str());
        let monitor_tags = input.get("monitor_tags").and_then(|v| v.as_str());
        let data = client.list_monitors(tags, monitor_tags).await?;
        Ok(json!({ "monitors": data }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, DatadogError> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| DatadogError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Extract a required i64 field from input.
fn require_i64(input: &serde_json::Value, field: &str) -> Result<i64, DatadogError> {
    input
        .get(field)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| DatadogError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "datadog.events.create",
            "summary": "Post an event",
            "capability": "datadog.events.write",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "none",
        },
        {
            "id": "datadog.events.list",
            "summary": "List events in a time range",
            "capability": "datadog.events.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "datadog.logs.search",
            "summary": "Search logs",
            "capability": "datadog.logs.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "datadog.metrics.query",
            "summary": "Query time-series metrics",
            "capability": "datadog.metrics.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "datadog.metrics.submit",
            "summary": "Submit custom metrics",
            "capability": "datadog.metrics.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "datadog.monitors.create",
            "summary": "Create a monitor",
            "capability": "datadog.monitors.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "datadog.monitors.delete",
            "summary": "Delete a monitor",
            "capability": "datadog.monitors.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
        {
            "id": "datadog.monitors.list",
            "summary": "List monitors",
            "capability": "datadog.monitors.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DatadogConfig::from_params ───────────────────────────────────

    #[test]
    fn config_from_api_keys() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "my-api-key",
            "app_key": "my-app-key",
        }))
        .unwrap();
        assert!(matches!(config.auth, DatadogAuth::ApiKeys { .. }));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = DatadogConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_with_region_eu1() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "k", "app_key": "a", "region": "eu1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.datadoghq.eu/api/v1");
    }

    #[test]
    fn config_with_region_ap1() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "k", "app_key": "a", "region": "ap1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.ap1.datadoghq.com/api/v1");
    }

    #[test]
    fn config_base_url_overrides_region() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "k", "app_key": "a",
            "region": "eu1",
            "base_url": "https://custom.example.com/api/v1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://custom.example.com/api/v1");
    }

    #[test]
    fn config_invalid_region_falls_back_to_default() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "k", "app_key": "a", "region": "invalid",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_rejects_no_auth() {
        assert!(DatadogConfig::from_params(&json!({})).is_err());
    }

    #[test]
    fn config_rejects_api_key_only() {
        assert!(DatadogConfig::from_params(&json!({"api_key": "k"})).is_err());
    }

    #[test]
    fn config_rejects_app_key_only() {
        assert!(DatadogConfig::from_params(&json!({"app_key": "a"})).is_err());
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        assert!(
            DatadogConfig::from_params(&json!({
                "api_key": "k", "app_key": "a",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            }))
            .is_err()
        );
    }

    #[test]
    fn config_rejects_empty_api_key() {
        assert!(DatadogConfig::from_params(&json!({"api_key": "", "app_key": "a"})).is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        assert!(DatadogConfig::from_params(&json!({"api_key": "   ", "app_key": "a"})).is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        assert!(DatadogConfig::from_params(&json!({"credential_id": 12345})).is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        assert!(DatadogConfig::from_params(&json!({"credential_id": "not-uuid"})).is_err());
    }

    // ── require_str / require_i64 ────────────────────────────────────

    #[test]
    fn require_str_extracts_value() {
        assert_eq!(require_str(&json!({"q": "test"}), "q").unwrap(), "test");
    }

    #[test]
    fn require_str_missing() {
        assert!(require_str(&json!({}), "q").is_err());
    }

    #[test]
    fn require_str_non_string() {
        assert!(require_str(&json!({"q": 42}), "q").is_err());
    }

    #[test]
    fn require_i64_extracts_value() {
        assert_eq!(require_i64(&json!({"n": 100}), "n").unwrap(), 100);
    }

    #[test]
    fn require_i64_missing() {
        assert!(require_i64(&json!({}), "n").is_err());
    }

    #[test]
    fn require_i64_non_number() {
        assert!(require_i64(&json!({"n": "nope"}), "n").is_err());
    }

    // ── operations_info ──────────────────────────────────────────────

    #[test]
    fn operations_count() {
        assert_eq!(operations_info().as_array().unwrap().len(), 8);
    }

    #[test]
    fn operations_have_required_fields() {
        for op in operations_info().as_array().unwrap() {
            assert!(op.get("id").is_some());
            assert!(op.get("summary").is_some());
            assert!(op.get("capability").is_some());
            assert!(op.get("risk_level").is_some());
            assert!(op.get("safety_tier").is_some());
        }
    }

    #[test]
    fn operations_ids_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut uniq = ids.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(ids.len(), uniq.len());
    }

    #[test]
    fn operations_valid_risk_levels() {
        for op in operations_info().as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(["low", "medium", "high"].contains(&rl), "invalid: {rl}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_ops_are_safe() {
        for op in operations_info().as_array().unwrap() {
            if op["capability"].as_str().unwrap().ends_with(".read") {
                assert_eq!(op["safety_tier"], "safe", "{}", op["id"]);
                assert_eq!(op["risk_level"], "low", "{}", op["id"]);
            }
        }
    }

    // ── DoctorResult ─────────────────────────────────────────────────

    #[test]
    fn doctor_healthy() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_degraded() {
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
                message: Some("w".into()),
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_unhealthy() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: false,
            message: None,
            critical: true,
        }]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "t".into(),
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
        let c = DatadogConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_counters_zero() {
        let c = DatadogConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    // ── DoctorCheck skip_serializing_if ───────────────────────────

    #[test]
    fn doctor_check_message_none_omitted() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        // skip_serializing_if = "Option::is_none" means the key should not appear
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_message_some_present() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("error msg".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "error msg");
    }

    // ── DoctorStatus serde ────────────────────────────────────────

    #[test]
    fn doctor_status_serializes_lowercase() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
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

    // ── DoctorResult serialization ────────────────────────────────

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
        assert_eq!(v["checks"].as_array().unwrap().len(), 2);
        let back: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(back.status, DoctorStatus::Degraded);
        assert_eq!(back.checks.len(), 2);
    }

    // ── Config region variants ────────────────────────────────────

    #[test]
    fn config_with_region_us3() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "k", "app_key": "a", "region": "us3",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.us3.datadoghq.com/api/v1");
    }

    #[test]
    fn config_with_region_us5() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "k", "app_key": "a", "region": "us5",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.us5.datadoghq.com/api/v1");
    }

    // ── operations_info edge cases ────────────────────────────────

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"datadog.events.create"));
        assert!(ids.contains(&"datadog.events.list"));
        assert!(ids.contains(&"datadog.logs.search"));
        assert!(ids.contains(&"datadog.metrics.query"));
        assert!(ids.contains(&"datadog.metrics.submit"));
        assert!(ids.contains(&"datadog.monitors.create"));
        assert!(ids.contains(&"datadog.monitors.delete"));
        assert!(ids.contains(&"datadog.monitors.list"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        for op in operations_info().as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        for op in operations_info().as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    fn operations_delete_is_dangerous() {
        for op in operations_info().as_array().unwrap() {
            if op["id"].as_str().unwrap().contains("delete") {
                assert_eq!(
                    op["safety_tier"], "dangerous",
                    "delete ops should be dangerous"
                );
                assert_eq!(op["risk_level"], "high", "delete ops should be high risk");
            }
        }
    }

    // ── require_str / require_i64 edge cases ──────────────────────

    #[test]
    fn require_str_null_value() {
        assert!(require_str(&json!({"q": null}), "q").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        // Empty string is still a valid string
        assert_eq!(require_str(&json!({"q": ""}), "q").unwrap(), "");
    }

    #[test]
    fn require_i64_negative() {
        assert_eq!(require_i64(&json!({"n": -100}), "n").unwrap(), -100);
    }

    #[test]
    fn require_i64_zero() {
        assert_eq!(require_i64(&json!({"n": 0}), "n").unwrap(), 0);
    }

    #[test]
    fn require_i64_null_value() {
        assert!(require_i64(&json!({"n": null}), "n").is_err());
    }

    #[test]
    fn require_i64_float_truncated() {
        // serde_json as_i64 returns None for 1.5
        assert!(require_i64(&json!({"n": 1.5}), "n").is_err());
    }

    // ── DoctorResult edge cases ───────────────────────────────────

    #[test]
    fn doctor_empty_checks_healthy() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert!(r.checks.is_empty());
    }

    #[test]
    fn doctor_multiple_critical_failures() {
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
                critical: true,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }
}
