//! FCP Grafana Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, GrafanaAuth, GrafanaClient},
    error::GrafanaError,
};

/// Parsed and validated Grafana connector configuration.
#[derive(Debug, Clone)]
struct GrafanaConfig {
    auth: GrafanaAuth,
    base_url: String,
}

impl GrafanaConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let auth_token = params
            .get("auth_token")
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

        let auth = match (auth_token, credential_id) {
            (Some(token), None) => GrafanaAuth::BearerToken(token),
            (None, Some(cred_id)) => GrafanaAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of auth_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing auth_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
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

/// FCP Grafana Connector.
pub struct GrafanaConnector {
    base: Arc<BaseConnector>,
    config: Option<GrafanaConfig>,
    client: Option<Arc<GrafanaClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl GrafanaConnector {
    /// Create a new Grafana connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("grafana"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for GrafanaConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl GrafanaConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = GrafanaConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Grafana connector");

        let client = GrafanaClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.grafana",
            "connector_version": "0.1.0",
            "capabilities": [
                "grafana.dashboards.read",
                "grafana.dashboards.write",
                "grafana.datasources.read",
                "grafana.alerts.read",
                "grafana.alerts.write",
                "grafana.annotations.write"
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
            "connector_id": "fcp.grafana",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.grafana",
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
            "grafana.dashboards.list" => self.invoke_dashboards_list(client, &input).await,
            "grafana.dashboards.get" => self.invoke_dashboards_get(client, &input).await,
            "grafana.dashboards.create" => self.invoke_dashboards_create(client, &input).await,
            "grafana.dashboards.delete" => self.invoke_dashboards_delete(client, &input).await,
            "grafana.datasources.list" => self.invoke_datasources_list(client).await,
            "grafana.datasources.query" => self.invoke_datasources_query(client, &input).await,
            "grafana.alerts.list" => self.invoke_alerts_list(client, &input).await,
            "grafana.alerts.create" => self.invoke_alerts_create(client, &input).await,
            "grafana.annotations.create" => self.invoke_annotations_create(client, &input).await,
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
        info!("Grafana connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_dashboards_list(
        &self,
        client: &GrafanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GrafanaError> {
        let query = input.get("query").and_then(|v| v.as_str());
        let tag: Option<Vec<String>> = input.get("tag").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let data = client
            .search_dashboards(query, tag.as_deref(), limit)
            .await?;
        Ok(json!({ "dashboards": data }))
    }

    async fn invoke_dashboards_get(
        &self,
        client: &GrafanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GrafanaError> {
        let uid = require_str(input, "uid")?;
        let data = client.get_dashboard(uid).await?;
        Ok(json!({
            "dashboard": data.get("dashboard").cloned().unwrap_or(json!(null)),
            "meta": data.get("meta").cloned().unwrap_or(json!({})),
        }))
    }

    async fn invoke_dashboards_create(
        &self,
        client: &GrafanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GrafanaError> {
        let dashboard = input.get("dashboard").ok_or_else(|| GrafanaError::Api {
            status_code: 400,
            message: "Missing required field: dashboard".into(),
        })?;
        let overwrite = input
            .get("overwrite")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let folder_uid = input.get("folder_uid").and_then(|v| v.as_str());

        let mut body = json!({
            "dashboard": dashboard,
            "overwrite": overwrite,
        });
        if let Some(fuid) = folder_uid {
            body["folderUid"] = json!(fuid);
        }

        let data = client.save_dashboard(&body).await?;
        Ok(json!({
            "uid": data.get("uid").cloned().unwrap_or(json!(null)),
            "url": data.get("url").cloned().unwrap_or(json!(null)),
        }))
    }

    async fn invoke_dashboards_delete(
        &self,
        client: &GrafanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GrafanaError> {
        let uid = require_str(input, "uid")?;
        client.delete_dashboard(uid).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_datasources_list(
        &self,
        client: &GrafanaClient,
    ) -> Result<serde_json::Value, GrafanaError> {
        let data = client.list_datasources().await?;
        Ok(json!({ "datasources": data }))
    }

    async fn invoke_datasources_query(
        &self,
        client: &GrafanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GrafanaError> {
        let datasource_uid = require_str(input, "datasource_uid")?;
        let query_str = require_str(input, "query")?;
        let from_ts = input.get("from_ts").and_then(|v| v.as_str());
        let to_ts = input.get("to_ts").and_then(|v| v.as_str());

        let mut queries = json!([{
            "datasourceId": 0,
            "refId": "A",
            "expr": query_str,
        }]);
        if let Some(q) = queries.as_array_mut().and_then(|a| a.first_mut()) {
            q["datasource"] = json!({"uid": datasource_uid});
        }

        let mut body = json!({ "queries": queries });
        if let (Some(from), Some(to)) = (from_ts, to_ts) {
            body["from"] = json!(from);
            body["to"] = json!(to);
        }

        let data = client.query_datasource(&body).await?;
        Ok(json!({ "results": data.get("results").cloned().unwrap_or(json!({})) }))
    }

    async fn invoke_alerts_list(
        &self,
        client: &GrafanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GrafanaError> {
        let state = input.get("state").and_then(|v| v.as_str());
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let data = client.list_alert_rules(state, limit).await?;
        Ok(json!({ "rules": data }))
    }

    async fn invoke_alerts_create(
        &self,
        client: &GrafanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GrafanaError> {
        let rule = input.get("rule").ok_or_else(|| GrafanaError::Api {
            status_code: 400,
            message: "Missing required field: rule".into(),
        })?;
        let data = client.create_alert_rule(rule).await?;
        Ok(json!({ "uid": data.get("uid").cloned().unwrap_or(json!(null)) }))
    }

    async fn invoke_annotations_create(
        &self,
        client: &GrafanaClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, GrafanaError> {
        let text = require_str(input, "text")?;
        let mut body = json!({ "text": text });
        if let Some(dashboard_uid) = input.get("dashboard_uid").and_then(|v| v.as_str()) {
            body["dashboardUID"] = json!(dashboard_uid);
        }
        if let Some(tags) = input.get("tags") {
            body["tags"] = tags.clone();
        }
        if let Some(time) = input.get("time").and_then(|v| v.as_i64()) {
            body["time"] = json!(time);
        }
        let data = client.create_annotation(&body).await?;
        Ok(json!({ "id": data.get("id").cloned().unwrap_or(json!(null)) }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, GrafanaError> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| GrafanaError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "grafana.dashboards.list",
            "summary": "Search dashboards",
            "capability": "grafana.dashboards.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "grafana.dashboards.get",
            "summary": "Get a dashboard by UID",
            "capability": "grafana.dashboards.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "grafana.dashboards.create",
            "summary": "Create or update a dashboard",
            "capability": "grafana.dashboards.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "grafana.dashboards.delete",
            "summary": "Delete a dashboard by UID",
            "capability": "grafana.dashboards.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
        {
            "id": "grafana.datasources.list",
            "summary": "List all datasources",
            "capability": "grafana.datasources.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "grafana.datasources.query",
            "summary": "Query a datasource (PromQL, LogQL, etc.)",
            "capability": "grafana.datasources.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "grafana.alerts.list",
            "summary": "List alert rules",
            "capability": "grafana.alerts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "grafana.alerts.create",
            "summary": "Create an alert rule",
            "capability": "grafana.alerts.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "grafana.annotations.create",
            "summary": "Create an annotation on a dashboard or globally",
            "capability": "grafana.annotations.write",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "none",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── GrafanaConfig::from_params ──────────────────────────────

    #[test]
    fn config_with_bearer_token() {
        let config = GrafanaConfig::from_params(&json!({
            "auth_token": "glsa_test_token_123",
        }))
        .unwrap();
        assert!(matches!(config.auth, GrafanaAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_with_credential_id() {
        let config = GrafanaConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = GrafanaConfig::from_params(&json!({
            "auth_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = GrafanaConfig::from_params(&json!({}));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("auth_token") || message.contains("credential_id"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_custom_base_url() {
        let config = GrafanaConfig::from_params(&json!({
            "auth_token": "tok",
            "base_url": "http://localhost:3000/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "http://localhost:3000/api");
    }

    #[test]
    fn config_empty_token_rejected() {
        let result = GrafanaConfig::from_params(&json!({
            "auth_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_whitespace_token_rejected() {
        let result = GrafanaConfig::from_params(&json!({
            "auth_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_non_string_credential_id_rejected() {
        let result = GrafanaConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("must be a string"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_invalid_uuid_credential_id_rejected() {
        let result = GrafanaConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("valid UUID"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_default_base_url_when_absent() {
        let config = GrafanaConfig::from_params(&json!({
            "auth_token": "tok",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    // ── DoctorResult::from_checks ───────────────────────────────

    #[test]
    fn doctor_all_passed_is_healthy() {
        let result = DoctorResult::from_checks(vec![
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
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_noncritical_failure_is_degraded() {
        let result = DoctorResult::from_checks(vec![
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
        ]);
        assert_eq!(result.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_critical_failure_is_unhealthy() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_empty_checks_is_healthy() {
        let result = DoctorResult::from_checks(vec![]);
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let result = DoctorResult::from_checks(vec![DoctorCheck {
            name: "config".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&result).unwrap();
        assert_eq!(v["status"], "healthy");
        assert_eq!(v["checks"][0]["name"], "config");
        assert_eq!(v["checks"][0]["passed"], true);
        // message is None, should be absent due to skip_serializing_if
        assert!(v["checks"][0].get("message").is_none());
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let s = serde_json::to_string(&status).unwrap();
            let back: DoctorStatus = serde_json::from_str(&s).unwrap();
            assert_eq!(back, status);
        }
    }

    // ── require_str ─────────────────────────────────────────────

    #[test]
    fn require_str_present() {
        let input = json!({"uid": "abc123"});
        assert_eq!(require_str(&input, "uid").unwrap(), "abc123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        let err = require_str(&input, "uid").unwrap_err();
        match err {
            GrafanaError::Api {
                status_code,
                message,
            } => {
                assert_eq!(status_code, 400);
                assert!(message.contains("uid"));
            }
            e => panic!("expected Api, got {e:?}"),
        }
    }

    #[test]
    fn require_str_non_string() {
        let input = json!({"uid": 42});
        assert!(require_str(&input, "uid").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"uid": null});
        assert!(require_str(&input, "uid").is_err());
    }

    // ── operations_info ─────────────────────────────────────────

    #[test]
    fn operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.as_array().unwrap().len(), 9);
    }

    #[test]
    fn operations_info_required_fields() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("id").and_then(|v| v.as_str()).is_some(),
                "op missing id"
            );
            assert!(
                op.get("summary").and_then(|v| v.as_str()).is_some(),
                "op missing summary"
            );
            assert!(
                op.get("capability").and_then(|v| v.as_str()).is_some(),
                "op missing capability"
            );
            assert!(
                op.get("risk_level").and_then(|v| v.as_str()).is_some(),
                "op missing risk_level"
            );
            assert!(
                op.get("safety_tier").and_then(|v| v.as_str()).is_some(),
                "op missing safety_tier"
            );
            assert!(
                op.get("idempotency").and_then(|v| v.as_str()).is_some(),
                "op missing idempotency"
            );
        }
    }

    #[test]
    fn operations_info_unique_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_info_valid_risk_levels() {
        let valid = ["low", "medium", "high", "critical"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_info_read_ops_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            let tier = op["safety_tier"].as_str().unwrap();
            if cap.to_ascii_lowercase().ends_with(".read") {
                assert_eq!(
                    tier, "safe",
                    "read op {} should be safe, got {tier}",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_info_has_expected_ops() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"grafana.dashboards.list"));
        assert!(ids.contains(&"grafana.dashboards.get"));
        assert!(ids.contains(&"grafana.dashboards.create"));
        assert!(ids.contains(&"grafana.dashboards.delete"));
        assert!(ids.contains(&"grafana.datasources.list"));
        assert!(ids.contains(&"grafana.datasources.query"));
        assert!(ids.contains(&"grafana.alerts.list"));
        assert!(ids.contains(&"grafana.alerts.create"));
        assert!(ids.contains(&"grafana.annotations.create"));
    }

    #[test]
    fn operations_delete_is_dangerous() {
        let ops = operations_info();
        let delete_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "grafana.dashboards.delete")
            .unwrap();
        assert_eq!(delete_op["safety_tier"], "dangerous");
        assert_eq!(delete_op["risk_level"], "high");
    }

    // ── GrafanaConnector basics ─────────────────────────────────

    #[test]
    fn connector_default_works() {
        let c = GrafanaConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_new_equals_default() {
        let c = GrafanaConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
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
        assert!(
            v.get("message").is_none(),
            "message should be skipped when None"
        );
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
        assert!(!back.critical);
    }

    #[test]
    fn doctor_status_values_serialize_lowercase() {
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
    fn doctor_result_multiple_critical_failures() {
        let result = DoctorResult::from_checks(vec![
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
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_mixed_critical_and_noncritical_failures() {
        let result = DoctorResult::from_checks(vec![
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
        // critical failure takes precedence
        assert_eq!(result.status, DoctorStatus::Unhealthy);
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
    fn operations_info_idempotency_values_valid() {
        let valid = ["strict", "none", "idempotent"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let idemp = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idemp),
                "invalid idempotency: {idemp} for op {}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_info_annotations_create_is_not_idempotent() {
        let ops = operations_info();
        let ann_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "grafana.annotations.create")
            .unwrap();
        assert_eq!(ann_op["idempotency"], "none");
    }

    #[test]
    fn operations_info_datasources_list_capability() {
        let ops = operations_info();
        let ds_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "grafana.datasources.list")
            .unwrap();
        assert_eq!(ds_op["capability"], "grafana.datasources.read");
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"uid": ""});
        // Empty string is still a valid str
        assert_eq!(require_str(&input, "uid").unwrap(), "");
    }

    #[test]
    fn require_str_with_array_value() {
        let input = json!({"uid": [1, 2, 3]});
        assert!(require_str(&input, "uid").is_err());
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"uid": {"nested": true}});
        assert!(require_str(&input, "uid").is_err());
    }

    #[test]
    fn require_str_with_bool_value() {
        let input = json!({"uid": true});
        assert!(require_str(&input, "uid").is_err());
    }
}
