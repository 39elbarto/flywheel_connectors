//! FCP Grafana Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, StepId,
};
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
        let provisioning = self.provisioning_readiness();
        Ok(json!({
            "connector_id": "fcp.grafana",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ok" } else { "degraded" },
            "provisioning": provisioning,
        }))
    }

    /// Return provisioning readiness information.
    fn provisioning_readiness(&self) -> serde_json::Value {
        let (auth_mode, token_configured, credential_id_configured) = match &self.config {
            Some(cfg) => match &cfg.auth {
                GrafanaAuth::BearerToken(_) => ("bearer_token", true, false),
                GrafanaAuth::CredentialId(_) => ("credential_id", false, true),
            },
            None => ("unconfigured", false, false),
        };

        let base_url = self
            .config
            .as_ref()
            .map_or_else(|| DEFAULT_BASE_URL.to_string(), |c| c.base_url.clone());

        let network_ok = check_network_allowed(&base_url);

        json!({
            "auth_mode": auth_mode,
            "token_configured": token_configured,
            "credential_id_configured": credential_id_configured,
            "network_ok": network_ok,
            "base_url": base_url,
        })
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.grafana",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
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
        let dashboard = input
            .get("dashboard")
            .ok_or_else(|| GrafanaError::InvalidInput("Missing required field: dashboard".into()))?;
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
        let rule = input
            .get("rule")
            .ok_or_else(|| GrafanaError::InvalidInput("Missing required field: rule".into()))?;
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
        .ok_or_else(|| GrafanaError::InvalidInput(format!("Missing required field: {field}")))
}

/// Check whether a base URL's host matches the allowed Grafana manifest hosts.
///
/// The manifest allows `*.grafana.net` and `*.grafana.com`.
fn check_network_allowed(base_url: &str) -> bool {
    let host = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("");

    // Strip optional port
    let host = host.split(':').next().unwrap_or(host);

    ALLOWED_HOST_SUFFIXES.iter().any(|suffix| {
        let bare = suffix.strip_prefix('.').unwrap_or(suffix);
        host == bare || host.ends_with(suffix)
    })
}

/// Build a single [`OperationInfo`] entry.
#[allow(clippy::fn_params_excessive_bools)]
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
            "grafana.dashboards.list",
            "Search dashboards",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "query": { "type": "string", "description": "Search query" },
                    "tag": { "type": "array", "description": "Filter by tags" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 5000 }
                }
            }),
            json!({
                "type": "object",
                "required": ["dashboards"],
                "properties": {
                    "dashboards": { "type": "array" }
                }
            }),
            "grafana.dashboards.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Search and list Grafana dashboards.".into(),
                common_mistakes: vec![
                    "Expecting full dashboard JSON in the list response — only metadata is returned; use dashboards.get for panel details.".into(),
                    "Not using tag filters on large Grafana instances — the search endpoint can be slow with thousands of dashboards.".into(),
                ],
                examples: vec![
                    r#"{"query": "production", "limit": 50}"#.into(),
                ],
                related: vec![CapabilityId::from_static("grafana.dashboards.get")],
            },
        ),
        op_info(
            "grafana.dashboards.get",
            "Get a dashboard by UID",
            json!({
                "type": "object",
                "required": ["uid"],
                "properties": {
                    "uid": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["dashboard", "meta"],
                "properties": {
                    "dashboard": { "type": "object" },
                    "meta": { "type": "object" }
                }
            }),
            "grafana.dashboards.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve a specific dashboard by UID.".into(),
                common_mistakes: vec![
                    "Using the dashboard slug or numeric ID instead of the UID — the UID is the short alphanumeric identifier.".into(),
                    "Not checking the meta.version field before updating — stale version causes save conflicts.".into(),
                ],
                examples: vec![
                    r#"{"uid": "abc123def"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("grafana.dashboards.list"),
                    CapabilityId::from_static("grafana.dashboards.create"),
                ],
            },
        ),
        op_info(
            "grafana.dashboards.create",
            "Create or update a dashboard",
            json!({
                "type": "object",
                "required": ["dashboard"],
                "properties": {
                    "dashboard": { "type": "object", "description": "Dashboard JSON model" },
                    "folder_uid": { "type": "string" },
                    "overwrite": { "type": "boolean" }
                }
            }),
            json!({
                "type": "object",
                "required": ["uid", "url"],
                "properties": {
                    "uid": { "type": "string" },
                    "url": { "type": "string" }
                }
            }),
            "grafana.dashboards.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Create or update a Grafana dashboard.".into(),
                common_mistakes: vec![
                    "Not setting overwrite=true when updating — will fail if dashboard exists.".into(),
                ],
                examples: vec![
                    r#"{"dashboard": {"title": "API Metrics", "panels": []}, "overwrite": true}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("grafana.dashboards.get"),
                    CapabilityId::from_static("grafana.dashboards.delete"),
                ],
            },
        ),
        op_info(
            "grafana.dashboards.delete",
            "Delete a dashboard by UID",
            json!({
                "type": "object",
                "required": ["uid"],
                "properties": {
                    "uid": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "grafana.dashboards.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Delete a dashboard. Cannot be undone.".into(),
                common_mistakes: vec![
                    "Deleting provisioned dashboards — they will reappear on next Grafana restart or provisioning cycle.".into(),
                    "Not exporting the dashboard JSON first for backup before permanent deletion.".into(),
                ],
                examples: vec![
                    r#"{"uid": "abc123def"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("grafana.dashboards.get")],
            },
        ),
        op_info(
            "grafana.datasources.list",
            "List all datasources",
            json!({
                "type": "object",
                "required": []
            }),
            json!({
                "type": "object",
                "required": ["datasources"],
                "properties": {
                    "datasources": { "type": "array" }
                }
            }),
            "grafana.datasources.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List configured datasources.".into(),
                common_mistakes: vec![
                    "Assuming datasource names are unique across organizations — use UID for reliable references.".into(),
                    "Not checking datasource health/connectivity status before issuing queries against them.".into(),
                ],
                examples: vec![
                    r"{}".into(),
                ],
                related: vec![CapabilityId::from_static("grafana.datasources.query")],
            },
        ),
        op_info(
            "grafana.datasources.query",
            "Query a datasource (PromQL, LogQL, etc.)",
            json!({
                "type": "object",
                "required": ["datasource_uid", "query"],
                "properties": {
                    "datasource_uid": { "type": "string" },
                    "query": { "type": "string", "description": "PromQL, LogQL, or other datasource-specific query" },
                    "from_ts": { "type": "string" },
                    "to_ts": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["results"],
                "properties": {
                    "results": { "type": "object" }
                }
            }),
            "grafana.datasources.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Query a datasource with PromQL, LogQL, or other query language.".into(),
                common_mistakes: vec![
                    "Not specifying time range — defaults may return too much or too little data.".into(),
                ],
                examples: vec![
                    r#"{"datasource_uid": "prometheus", "query": "rate(http_requests_total[5m])", "from_ts": "now-1h", "to_ts": "now"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("grafana.datasources.list")],
            },
        ),
        op_info(
            "grafana.alerts.list",
            "List alert rules",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "state": { "type": "string", "description": "Filter by state: alerting, pending, normal, etc." },
                    "limit": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "required": ["rules"],
                "properties": {
                    "rules": { "type": "array" }
                }
            }),
            "grafana.alerts.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List alert rules and their current states.".into(),
                common_mistakes: vec![
                    "Filtering by state='alerting' misses rules in 'pending' state that are about to fire.".into(),
                    "Not accounting for Grafana Unified Alerting vs legacy alerting — API endpoints differ between versions.".into(),
                ],
                examples: vec![
                    r#"{"state": "alerting"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("grafana.alerts.create")],
            },
        ),
        op_info(
            "grafana.alerts.create",
            "Create an alert rule",
            json!({
                "type": "object",
                "required": ["rule"],
                "properties": {
                    "rule": { "type": "object", "description": "Alert rule definition" }
                }
            }),
            json!({
                "type": "object",
                "required": ["uid"],
                "properties": {
                    "uid": { "type": "string" }
                }
            }),
            "grafana.alerts.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new alert rule.".into(),
                common_mistakes: vec![
                    "Not specifying notification channels for the alert.".into(),
                ],
                examples: vec![
                    r#"{"rule": {"title": "High Error Rate", "condition": "A", "data": []}}"#.into(),
                ],
                related: vec![CapabilityId::from_static("grafana.alerts.list")],
            },
        ),
        op_info(
            "grafana.annotations.create",
            "Create an annotation on a dashboard or globally",
            json!({
                "type": "object",
                "required": ["text"],
                "properties": {
                    "text": { "type": "string" },
                    "dashboard_uid": { "type": "string" },
                    "tags": { "type": "array" },
                    "time": { "type": "integer", "description": "Epoch ms" }
                }
            }),
            json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "integer" }
                }
            }),
            "grafana.annotations.write",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Mark events on dashboards (deploys, incidents, etc.).".into(),
                common_mistakes: vec![
                    "Not specifying time — defaults to the server's current time, which may differ from the actual event time.".into(),
                    "Creating dashboard-scoped annotations without providing the dashboard_uid, resulting in global annotations.".into(),
                ],
                examples: vec![
                    r#"{"text": "Deploy v2.1.0", "tags": ["deploy"]}"#.into(),
                ],
                related: vec![CapabilityId::from_static("grafana.dashboards.get")],
            },
        ),
    ]
}

/// Allowed host suffixes for the Grafana manifest network policy.
const ALLOWED_HOST_SUFFIXES: &[&str] = &[".grafana.net", ".grafana.com"];

/// Build the provisioning recipe for the Grafana connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("grafana_setup"),
        "1",
        "Set up the Grafana connector with API key or credential injection",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_auth_mode"),
        ProvisioningStepType::PromptUser {
            message: "Choose authentication mode: api_key or credential_injection".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("prompt_api_key"),
            ProvisioningStepType::PromptSecret {
                message: "Enter your Grafana API key or service account token".into(),
            },
        )
        .depends_on(StepId::new("prompt_auth_mode")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "grafana_api_key".into(),
                value_from: StepId::new("prompt_api_key"),
                scope: "connector:fcp.grafana".into(),
            },
        )
        .depends_on(StepId::new("prompt_api_key")),
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_base_url"),
        ProvisioningStepType::PromptUser {
            message: "Enter Grafana base URL (optional, default https://grafana.com/api)".into(),
        },
    ))
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

    /// Helper: serialize `operations_info` to JSON for test assertions.
    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn operations_info_count() {
        let ops = ops_json();
        assert_eq!(ops.as_array().unwrap().len(), 9);
    }

    #[test]
    fn operations_info_required_fields() {
        let ops = ops_json();
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
        let ops = ops_json();
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
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_info_read_ops_are_safe() {
        let ops = ops_json();
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
        let ops = ops_json();
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
        let ops = ops_json();
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
        let ops = ops_json();
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
        let ops = ops_json();
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
        let ops = ops_json();
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

    // ── Additional connector coverage tests ───────────────────────

    #[test]
    fn config_clone_preserves_base_url() {
        let config = GrafanaConfig::from_params(&json!({
            "auth_token": "tok",
            "base_url": "https://custom.grafana.io/api"
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, "https://custom.grafana.io/api");
        assert_eq!(cloned.base_url, "https://custom.grafana.io/api");
    }

    #[test]
    fn config_debug_format() {
        let config = GrafanaConfig::from_params(&json!({
            "auth_token": "tok"
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("GrafanaConfig"));
    }

    #[test]
    fn config_trims_auth_token() {
        let config = GrafanaConfig::from_params(&json!({
            "auth_token": "  glsa_abc123  "
        }))
        .unwrap();
        match &config.auth {
            GrafanaAuth::BearerToken(t) => assert_eq!(t, "glsa_abc123"),
            GrafanaAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn connector_request_count_initial() {
        let c = GrafanaConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_error_count_initial() {
        let c = GrafanaConnector::new();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "clone_test".into(),
            passed: true,
            message: Some("cloned".into()),
            critical: false,
        };
        let c2 = c.clone();
        assert_eq!(c.name, "clone_test");
        assert_eq!(c2.message, Some("cloned".into()));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let r2 = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(r2.checks.len(), 1);
    }

    #[test]
    fn doctor_result_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.status, DoctorStatus::Healthy);
        assert_eq!(r2.checks.len(), 1);
    }

    #[test]
    fn operations_info_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    fn operations_info_dashboards_create_is_risky() {
        let ops = ops_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "grafana.dashboards.create")
            .unwrap();
        assert_eq!(op["safety_tier"], "risky");
        assert_eq!(op["risk_level"], "medium");
    }

    #[test]
    fn operations_info_alerts_create_not_idempotent() {
        let ops = ops_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "grafana.alerts.create")
            .unwrap();
        assert_eq!(op["idempotency"], "none");
    }

    #[test]
    fn operations_info_all_prefixed_grafana() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("grafana."),
                "op {id} missing grafana. prefix"
            );
        }
    }

    #[test]
    fn require_str_error_message_contains_field() {
        let input = json!({});
        match require_str(&input, "dashboard_uid").unwrap_err() {
            GrafanaError::Api {
                status_code,
                message,
            } => {
                assert_eq!(status_code, 400);
                assert!(message.contains("dashboard_uid"));
            }
            e => panic!("expected Api error, got {e:?}"),
        }
    }

    #[test]
    fn require_str_with_float_value() {
        let input = json!({"uid": 1.23});
        assert!(require_str(&input, "uid").is_err());
    }

    #[test]
    fn operations_info_dashboards_get_capability() {
        let ops = ops_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "grafana.dashboards.get")
            .unwrap();
        assert_eq!(op["capability"], "grafana.dashboards.read");
    }

    #[test]
    fn operations_info_datasources_query_is_safe() {
        let ops = ops_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "grafana.datasources.query")
            .unwrap();
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["risk_level"], "low");
    }

    #[test]
    fn operations_info_alerts_list_is_safe_and_strict() {
        let ops = ops_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "grafana.alerts.list")
            .unwrap();
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["idempotency"], "strict");
    }

    #[test]
    fn doctor_status_ne_comparison() {
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Unhealthy);
    }

    // ── Provisioning recipe ─────────────────────────────────────

    #[test]
    fn provisioning_recipe_has_expected_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps.len(), 4);
        assert_eq!(recipe.id.as_str(), "grafana_setup");
        assert_eq!(recipe.version, "1");

        // Verify step types
        assert!(
            matches!(
                recipe.steps[0].kind,
                ProvisioningStepType::PromptUser { .. }
            ),
            "step 0 should be PromptUser"
        );
        assert!(
            matches!(
                recipe.steps[1].kind,
                ProvisioningStepType::PromptSecret { .. }
            ),
            "step 1 should be PromptSecret"
        );
        assert!(
            matches!(
                recipe.steps[2].kind,
                ProvisioningStepType::StoreSecret { .. }
            ),
            "step 2 should be StoreSecret"
        );
        assert!(
            matches!(
                recipe.steps[3].kind,
                ProvisioningStepType::PromptUser { .. }
            ),
            "step 3 should be PromptUser"
        );
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();

        // prompt_auth_mode has no dependencies
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[0].id.as_str(), "prompt_auth_mode");

        // prompt_api_key depends on prompt_auth_mode
        assert_eq!(recipe.steps[1].id.as_str(), "prompt_api_key");
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "prompt_auth_mode");

        // store_api_key depends on prompt_api_key
        assert_eq!(recipe.steps[2].id.as_str(), "store_api_key");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "prompt_api_key");

        // prompt_base_url has no dependencies
        assert_eq!(recipe.steps[3].id.as_str(), "prompt_base_url");
        assert!(recipe.steps[3].depends_on.is_empty());
    }

    #[test]
    fn provisioning_recipe_store_secret_scope() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[2];
        match &store_step.kind {
            ProvisioningStepType::StoreSecret {
                scope,
                key,
                value_from,
            } => {
                assert_eq!(scope, "connector:fcp.grafana");
                assert_eq!(key, "grafana_api_key");
                assert_eq!(value_from.as_str(), "prompt_api_key");
            }
            other => panic!("expected StoreSecret, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_readiness_unconfigured() {
        let c = GrafanaConnector::new();
        let readiness = c.provisioning_readiness();
        assert_eq!(readiness["auth_mode"], "unconfigured");
        assert_eq!(readiness["token_configured"], false);
        assert_eq!(readiness["credential_id_configured"], false);
        assert_eq!(readiness["base_url"], DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_bearer_token() {
        let mut c = GrafanaConnector::new();
        c.config = Some(GrafanaConfig {
            auth: GrafanaAuth::BearerToken("glsa_test_token".into()),
            base_url: "https://my-org.grafana.net/api".into(),
        });
        let readiness = c.provisioning_readiness();
        assert_eq!(readiness["auth_mode"], "bearer_token");
        assert_eq!(readiness["token_configured"], true);
        assert_eq!(readiness["credential_id_configured"], false);
        assert_eq!(readiness["base_url"], "https://my-org.grafana.net/api");
        assert_eq!(readiness["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let mut c = GrafanaConnector::new();
        c.config = Some(GrafanaConfig {
            auth: GrafanaAuth::CredentialId(
                CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            ),
            base_url: "https://my-org.grafana.com/api".into(),
        });
        let readiness = c.provisioning_readiness();
        assert_eq!(readiness["auth_mode"], "credential_id");
        assert_eq!(readiness["token_configured"], false);
        assert_eq!(readiness["credential_id_configured"], true);
        assert_eq!(readiness["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_network_check() {
        // Valid hosts
        assert!(check_network_allowed("https://my-org.grafana.net/api"));
        assert!(check_network_allowed("https://my-org.grafana.com/api"));
        assert!(check_network_allowed("https://grafana.com/api"));
        assert!(check_network_allowed("https://grafana.net/api"));
        assert!(check_network_allowed("https://sub.domain.grafana.net/path"));

        // Invalid hosts
        assert!(!check_network_allowed("https://evil.example.com/api"));
        assert!(!check_network_allowed("http://localhost:3000/api"));
        assert!(!check_network_allowed("https://not-grafana.io/api"));
        assert!(!check_network_allowed("https://fakegrafana.com/api"));
    }

    #[test]
    fn self_check_includes_provisioning() {
        let c = GrafanaConnector::new();
        // Call provisioning_readiness directly since handle_self_check is async
        let readiness = c.provisioning_readiness();
        assert_eq!(readiness["auth_mode"], "unconfigured");
        assert!(readiness.get("token_configured").is_some());
        assert!(readiness.get("credential_id_configured").is_some());
        assert!(readiness.get("network_ok").is_some());
        assert!(readiness.get("base_url").is_some());
    }
}
