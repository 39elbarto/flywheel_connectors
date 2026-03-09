//! FCP Datadog Connector implementation.

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
            "provisioning": self.provisioning_readiness(),
        }))
    }

    /// Return provisioning readiness diagnostics.
    #[allow(clippy::similar_names)]
    pub fn provisioning_readiness(&self) -> serde_json::Value {
        let (auth_mode, has_api_key, has_app_key, has_credential) = match &self.config {
            Some(cfg) => match &cfg.auth {
                DatadogAuth::ApiKeys { .. } => ("api_keys", true, true, false),
                DatadogAuth::CredentialId(_) => ("credential_id", false, false, true),
            },
            None => ("unconfigured", false, false, false),
        };

        let base_url = self
            .config
            .as_ref()
            .map_or(DEFAULT_BASE_URL, |c| &c.base_url)
            .to_string();

        let network_ok = base_url.contains("datadoghq.com") || base_url.contains("datadoghq.eu");

        let region = if base_url.contains("us3.datadoghq") {
            "us3"
        } else if base_url.contains("us5.datadoghq") {
            "us5"
        } else if base_url.contains("ap1.datadoghq") {
            "ap1"
        } else if base_url.contains("datadoghq.eu") {
            "eu1"
        } else if base_url.contains("datadoghq.com") {
            "us1"
        } else {
            "unknown"
        };

        json!({
            "auth_mode": auth_mode,
            "api_key_configured": has_api_key,
            "app_key_configured": has_app_key,
            "credential_id_configured": has_credential,
            "network_ok": network_ok,
            "base_url": base_url,
            "region": region,
        })
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.datadog",
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

/// Build the provisioning recipe for the Datadog connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("fcp.datadog.setup"),
        "1",
        "Datadog connector provisioning — configure API keys or credential injection",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_auth_mode"),
        ProvisioningStepType::PromptUser {
            message: "Choose authentication mode: (1) API key + Application key, or (2) Credential injection (secretless via egress proxy)".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("prompt_api_key"),
            ProvisioningStepType::PromptSecret {
                message: "Enter your Datadog API key".into(),
            },
        )
        .depends_on(StepId::new("prompt_auth_mode")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("prompt_app_key"),
            ProvisioningStepType::PromptSecret {
                message: "Enter your Datadog Application key".into(),
            },
        )
        .depends_on(StepId::new("prompt_auth_mode")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_key".into(),
                value_from: StepId::new("prompt_api_key"),
                scope: "connector:fcp.datadog".into(),
            },
        )
        .depends_on(StepId::new("prompt_api_key")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_app_key"),
            ProvisioningStepType::StoreSecret {
                key: "app_key".into(),
                value_from: StepId::new("prompt_app_key"),
                scope: "connector:fcp.datadog".into(),
            },
        )
        .depends_on(StepId::new("prompt_app_key")),
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_region"),
        ProvisioningStepType::PromptUser {
            message: "Select Datadog region (us1/us3/us5/eu1/ap1, default: us1)".into(),
        },
    ))
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "datadog.events.create",
            "Post an event",
            json!({
                "type": "object",
                "required": ["title", "text"],
                "properties": {
                    "title": { "type": "string" },
                    "text": { "type": "string" },
                    "priority": { "type": "string" },
                    "alert_type": { "type": "string" },
                    "tags": { "type": "array" }
                }
            }),
            json!({
                "type": "object",
                "required": ["event"],
                "properties": {
                    "event": { "type": "object" }
                }
            }),
            "datadog.events.write",
            RiskLevel::Medium,
            SafetyTier::Safe,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Post an event to Datadog (deploys, incidents, etc.).".into(),
                common_mistakes: vec![
                    "Not including tags for filtering — events without tags are hard to correlate with services.".into(),
                    "Using invalid alert_type values (must be one of: error, warning, info, success).".into(),
                ],
                examples: vec![
                    r#"{"title": "Deploy v2.1.0", "text": "Deployed to production", "tags": ["env:production"]}"#.into(),
                ],
                related: vec![CapabilityId::from_static("datadog.events.list")],
            },
        ),
        op_info(
            "datadog.events.list",
            "List events in a time range",
            json!({
                "type": "object",
                "required": ["start", "end"],
                "properties": {
                    "start": { "type": "integer" },
                    "end": { "type": "integer" },
                    "priority": { "type": "string" },
                    "sources": { "type": "string" },
                    "tags": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["events"],
                "properties": {
                    "events": { "type": "array" }
                }
            }),
            "datadog.events.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List events in a time range.".into(),
                common_mistakes: vec![
                    "Passing ISO 8601 timestamps instead of epoch seconds for start/end parameters.".into(),
                    "Querying too wide a time range — Datadog limits event lookback to 32 days.".into(),
                ],
                examples: vec![
                    r#"{"start": 1709251200, "end": 1709337600, "tags": "env:production"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("datadog.events.create")],
            },
        ),
        op_info(
            "datadog.logs.search",
            "Search logs",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string" },
                    "from_ts": { "type": "string" },
                    "to_ts": { "type": "string" },
                    "limit": { "type": "integer", "maximum": 1000 }
                }
            }),
            json!({
                "type": "object",
                "required": ["logs"],
                "properties": {
                    "logs": { "type": "array" }
                }
            }),
            "datadog.logs.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Search and retrieve logs from Datadog.".into(),
                common_mistakes: vec![
                    "Not specifying time range — can be very slow on large volumes.".into(),
                ],
                examples: vec![
                    r#"{"query": "service:api status:error", "from_ts": "now-1h", "to_ts": "now", "limit": 100}"#.into(),
                ],
                related: vec![CapabilityId::from_static("datadog.metrics.query")],
            },
        ),
        op_info(
            "datadog.metrics.query",
            "Query time-series metrics",
            json!({
                "type": "object",
                "required": ["query", "from_ts", "to_ts"],
                "properties": {
                    "query": { "type": "string", "description": "Datadog metrics query" },
                    "from_ts": { "type": "integer", "description": "Start epoch seconds" },
                    "to_ts": { "type": "integer", "description": "End epoch seconds" }
                }
            }),
            json!({
                "type": "object",
                "required": ["series"],
                "properties": {
                    "series": { "type": "array" }
                }
            }),
            "datadog.metrics.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Query time-series metrics from Datadog.".into(),
                common_mistakes: vec![
                    "Querying too wide a time range — Datadog limits points per query.".into(),
                ],
                examples: vec![
                    r#"{"query": "avg:system.cpu.user{*}", "from_ts": 1709251200, "to_ts": 1709337600}"#.into(),
                ],
                related: vec![CapabilityId::from_static("datadog.metrics.submit")],
            },
        ),
        op_info(
            "datadog.metrics.submit",
            "Submit custom metrics",
            json!({
                "type": "object",
                "required": ["series"],
                "properties": {
                    "series": { "type": "array", "description": "Array of metric series to submit" }
                }
            }),
            json!({
                "type": "object",
                "required": ["status"],
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            "datadog.metrics.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Submit custom metrics to Datadog.".into(),
                common_mistakes: vec![
                    "Submitting metrics with future timestamps — they will be rejected.".into(),
                ],
                examples: vec![
                    r#"{"series": [{"metric": "custom.latency", "points": [[1709251200, 42.0]], "type": "gauge"}]}"#.into(),
                ],
                related: vec![CapabilityId::from_static("datadog.metrics.query")],
            },
        ),
        op_info(
            "datadog.monitors.create",
            "Create a monitor",
            json!({
                "type": "object",
                "required": ["name", "type", "query"],
                "properties": {
                    "name": { "type": "string" },
                    "type": { "type": "string", "description": "metric alert, service check, event alert, etc." },
                    "query": { "type": "string" },
                    "message": { "type": "string" },
                    "tags": { "type": "array" }
                }
            }),
            json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "integer" }
                }
            }),
            "datadog.monitors.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new monitor.".into(),
                common_mistakes: vec![
                    "Not specifying notification channels in the message field.".into(),
                ],
                examples: vec![
                    r#"{"name": "High CPU", "type": "metric alert", "query": "avg(last_5m):avg:system.cpu.user{*} > 90"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("datadog.monitors.list"),
                    CapabilityId::from_static("datadog.monitors.delete"),
                ],
            },
        ),
        op_info(
            "datadog.monitors.delete",
            "Delete a monitor",
            json!({
                "type": "object",
                "required": ["monitor_id"],
                "properties": {
                    "monitor_id": { "type": "integer" }
                }
            }),
            json!({ "type": "object" }),
            "datadog.monitors.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Delete a monitor. Cannot be undone.".into(),
                common_mistakes: vec![
                    "Deleting monitors that should be muted or disabled instead — muting preserves the monitor definition.".into(),
                    "Not checking if the monitor is referenced by composite monitors before deletion.".into(),
                ],
                examples: vec![
                    r#"{"monitor_id": 12345}"#.into(),
                ],
                related: vec![CapabilityId::from_static("datadog.monitors.list")],
            },
        ),
        op_info(
            "datadog.monitors.list",
            "List monitors",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "tags": { "type": "string" },
                    "monitor_tags": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["monitors"],
                "properties": {
                    "monitors": { "type": "array" }
                }
            }),
            "datadog.monitors.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List monitors and their current status.".into(),
                common_mistakes: vec![
                    "Not filtering by tags or monitor_tags — large organizations can have thousands of monitors.".into(),
                    "Assuming the response includes full monitor details — use the individual get endpoint for thresholds and notification settings.".into(),
                ],
                examples: vec![
                    r#"{"tags": "env:production"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("datadog.monitors.create")],
            },
        ),
    ]
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

    /// Helper: serialize `operations_info` to JSON for test assertions.
    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn operations_count() {
        assert_eq!(ops_json().as_array().unwrap().len(), 8);
    }

    #[test]
    fn operations_have_required_fields() {
        for op in ops_json().as_array().unwrap() {
            assert!(op.get("id").is_some());
            assert!(op.get("summary").is_some());
            assert!(op.get("capability").is_some());
            assert!(op.get("risk_level").is_some());
            assert!(op.get("safety_tier").is_some());
        }
    }

    #[test]
    fn operations_ids_unique() {
        let ops = ops_json();
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
        for op in ops_json().as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(["low", "medium", "high"].contains(&rl), "invalid: {rl}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_ops_are_safe() {
        for op in ops_json().as_array().unwrap() {
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
        let ops = ops_json();
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
        for op in ops_json().as_array().unwrap() {
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
        for op in ops_json().as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    fn operations_delete_is_dangerous() {
        for op in ops_json().as_array().unwrap() {
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

    // ── Additional connector / config / operations tests ─────────

    #[test]
    fn config_with_region_us1_explicit() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "k", "app_key": "a", "region": "us1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.datadoghq.com/api/v1");
    }

    #[test]
    fn config_with_region_us_alias() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "k", "app_key": "a", "region": "us",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.datadoghq.com/api/v1");
    }

    #[test]
    fn config_with_region_eu_alias() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "k", "app_key": "a", "region": "eu",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.datadoghq.eu/api/v1");
    }

    #[test]
    fn config_trims_api_key_whitespace() {
        let config = DatadogConfig::from_params(&json!({
            "api_key": "  my-key  ", "app_key": "  my-app  ",
        }))
        .unwrap();
        assert!(matches!(config.auth, DatadogAuth::ApiKeys { .. }));
    }

    #[test]
    fn config_rejects_empty_app_key() {
        assert!(DatadogConfig::from_params(&json!({"api_key": "k", "app_key": ""})).is_err());
    }

    #[test]
    fn config_rejects_whitespace_app_key() {
        assert!(DatadogConfig::from_params(&json!({"api_key": "k", "app_key": "   "})).is_err());
    }

    #[test]
    fn operations_write_ops_have_higher_risk() {
        for op in ops_json().as_array().unwrap() {
            if op["capability"]
                .as_str()
                .unwrap()
                .as_bytes()
                .ends_with(b".write")
            {
                let rl = op["risk_level"].as_str().unwrap();
                assert!(
                    rl == "medium" || rl == "high",
                    "write op {} should be medium/high risk, got {rl}",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_idempotency_values_valid() {
        let valid = ["none", "strict", "idempotent"];
        for op in ops_json().as_array().unwrap() {
            let id_val = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&id_val),
                "op {} has invalid idempotency: {id_val}",
                op["id"]
            );
        }
    }

    #[test]
    fn require_str_with_boolean_value() {
        assert!(require_str(&json!({"q": true}), "q").is_err());
    }

    #[test]
    fn require_str_with_array_value() {
        assert!(require_str(&json!({"q": [1, 2]}), "q").is_err());
    }

    #[test]
    fn require_i64_with_boolean_value() {
        assert!(require_i64(&json!({"n": false}), "n").is_err());
    }

    #[test]
    fn require_i64_with_string_number() {
        assert!(require_i64(&json!({"n": "42"}), "n").is_err());
    }

    #[test]
    fn require_i64_large_value() {
        assert_eq!(
            require_i64(&json!({"n": 1_000_000_000}), "n").unwrap(),
            1_000_000_000
        );
    }

    #[test]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let cloned = check.clone();
        assert_eq!(check.name, "test");
        assert_eq!(cloned.name, "test");
        assert!(cloned.passed);
    }

    #[test]
    fn doctor_result_clone_and_debug() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
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

    #[test]
    fn doctor_status_debug_format() {
        assert_eq!(format!("{:?}", DoctorStatus::Degraded), "Degraded");
        assert_eq!(format!("{:?}", DoctorStatus::Unhealthy), "Unhealthy");
    }

    #[test]
    fn doctor_all_noncritical_pass_is_healthy() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: false,
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
    fn doctor_critical_pass_noncritical_fail() {
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
                message: Some("warn".into()),
                critical: false,
            },
            DoctorCheck {
                name: "c".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    // ── Additional require_str / require_i64 edge cases ─────────────

    #[test]
    fn require_str_float_value() {
        assert!(require_str(&json!({"q": 1.23}), "q").is_err());
    }

    #[test]
    fn require_str_nested_object() {
        assert!(require_str(&json!({"q": {"a": {"b": "c"}}}), "q").is_err());
    }

    #[test]
    fn require_i64_nested_object() {
        assert!(require_i64(&json!({"n": {"x": 1}}), "n").is_err());
    }

    #[test]
    fn require_i64_array_value() {
        assert!(require_i64(&json!({"n": [1, 2, 3]}), "n").is_err());
    }

    #[test]
    fn require_i64_null_via_missing() {
        assert!(require_i64(&json!({}), "missing_field").is_err());
    }

    // ── operations additional ────────────────────────────────────────

    #[test]
    fn operations_all_capabilities_non_empty() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(!cap.is_empty(), "op {:?} has empty capability", op["id"]);
        }
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
    fn operations_ids_all_start_with_datadog() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("datadog."),
                "op {id} should start with datadog."
            );
        }
    }

    // ── Doctor status additional ─────────────────────────────────────

    #[test]
    fn doctor_status_serde_roundtrip() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
    }

    #[test]
    fn doctor_status_deserialize() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let status = DoctorStatus::Healthy;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn doctor_status_eq() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    // ── Provisioning recipe ─────────────────────────────────────────

    #[test]
    fn provisioning_recipe_has_expected_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "fcp.datadog.setup");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 6);

        let step_ids: Vec<&str> = recipe.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            step_ids,
            vec![
                "prompt_auth_mode",
                "prompt_api_key",
                "prompt_app_key",
                "store_api_key",
                "store_app_key",
                "prompt_region",
            ]
        );
    }

    #[test]
    fn provisioning_recipe_dual_secret_steps() {
        let recipe = provisioning_recipe();
        let secret_steps: Vec<&ProvisioningStep> = recipe
            .steps
            .iter()
            .filter(|s| matches!(s.kind, ProvisioningStepType::PromptSecret { .. }))
            .collect();
        assert_eq!(secret_steps.len(), 2);
        assert_eq!(secret_steps[0].id.as_str(), "prompt_api_key");
        assert_eq!(secret_steps[1].id.as_str(), "prompt_app_key");
    }

    #[test]
    fn provisioning_recipe_store_secret_scope() {
        let recipe = provisioning_recipe();
        let store_steps: Vec<&ProvisioningStep> = recipe
            .steps
            .iter()
            .filter(|s| matches!(s.kind, ProvisioningStepType::StoreSecret { .. }))
            .collect();
        assert_eq!(store_steps.len(), 2);
        for step in &store_steps {
            if let ProvisioningStepType::StoreSecret { scope, .. } = &step.kind {
                assert_eq!(scope, "connector:fcp.datadog");
            }
        }
    }

    #[test]
    fn provisioning_recipe_store_secret_value_from() {
        let recipe = provisioning_recipe();
        for step in &recipe.steps {
            if let ProvisioningStepType::StoreSecret {
                key, value_from, ..
            } = &step.kind
            {
                match key.as_str() {
                    "api_key" => assert_eq!(value_from.as_str(), "prompt_api_key"),
                    "app_key" => assert_eq!(value_from.as_str(), "prompt_app_key"),
                    other => panic!("unexpected store key: {other}"),
                }
            }
        }
    }

    #[test]
    fn provisioning_recipe_dependencies() {
        let recipe = provisioning_recipe();
        let find_step = |id: &str| recipe.steps.iter().find(|s| s.id.as_str() == id).unwrap();

        assert!(find_step("prompt_auth_mode").depends_on.is_empty());
        assert_eq!(
            find_step("prompt_api_key").depends_on[0].as_str(),
            "prompt_auth_mode"
        );
        assert_eq!(
            find_step("prompt_app_key").depends_on[0].as_str(),
            "prompt_auth_mode"
        );
        assert_eq!(
            find_step("store_api_key").depends_on[0].as_str(),
            "prompt_api_key"
        );
        assert_eq!(
            find_step("store_app_key").depends_on[0].as_str(),
            "prompt_app_key"
        );
        assert!(find_step("prompt_region").depends_on.is_empty());
    }

    #[test]
    fn provisioning_recipe_prompt_user_steps() {
        let recipe = provisioning_recipe();
        let prompt_user_steps: Vec<&ProvisioningStep> = recipe
            .steps
            .iter()
            .filter(|s| matches!(s.kind, ProvisioningStepType::PromptUser { .. }))
            .collect();
        assert_eq!(prompt_user_steps.len(), 2);
        assert_eq!(prompt_user_steps[0].id.as_str(), "prompt_auth_mode");
        assert_eq!(prompt_user_steps[1].id.as_str(), "prompt_region");
    }

    #[test]
    fn provisioning_recipe_no_approval_required() {
        let recipe = provisioning_recipe();
        for step in &recipe.steps {
            assert!(
                !step.requires_approval,
                "step {} should not require approval",
                step.id.as_str()
            );
        }
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "fcp.datadog.setup");
        assert_eq!(v["version"], "1");
        assert!(v["steps"].as_array().unwrap().len() == 6);
    }

    // ── Provisioning readiness ──────────────────────────────────────

    #[test]
    fn provisioning_readiness_unconfigured() {
        let c = DatadogConnector::new();
        let r = c.provisioning_readiness();
        assert_eq!(r["auth_mode"], "unconfigured");
        assert_eq!(r["api_key_configured"], false);
        assert_eq!(r["app_key_configured"], false);
        assert_eq!(r["credential_id_configured"], false);
        assert_eq!(r["network_ok"], true); // default URL is datadoghq.com
        assert_eq!(r["region"], "us1");
    }

    #[test]
    fn provisioning_readiness_api_keys() {
        let mut c = DatadogConnector::new();
        c.config = Some(DatadogConfig {
            auth: DatadogAuth::ApiKeys {
                api_key: "test-key".into(),
                app_key: "test-app".into(),
            },
            base_url: DEFAULT_BASE_URL.into(),
        });
        let r = c.provisioning_readiness();
        assert_eq!(r["auth_mode"], "api_keys");
        assert_eq!(r["api_key_configured"], true);
        assert_eq!(r["app_key_configured"], true);
        assert_eq!(r["credential_id_configured"], false);
        assert_eq!(r["network_ok"], true);
        assert_eq!(r["region"], "us1");
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let mut c = DatadogConnector::new();
        c.config = Some(DatadogConfig {
            auth: DatadogAuth::CredentialId(CredentialId::new()),
            base_url: DEFAULT_BASE_URL.into(),
        });
        let r = c.provisioning_readiness();
        assert_eq!(r["auth_mode"], "credential_id");
        assert_eq!(r["api_key_configured"], false);
        assert_eq!(r["app_key_configured"], false);
        assert_eq!(r["credential_id_configured"], true);
        assert_eq!(r["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_network_check() {
        let mut c = DatadogConnector::new();

        // Valid datadoghq.com URL
        c.config = Some(DatadogConfig {
            auth: DatadogAuth::ApiKeys {
                api_key: "k".into(),
                app_key: "a".into(),
            },
            base_url: "https://api.datadoghq.com/api/v1".into(),
        });
        assert_eq!(c.provisioning_readiness()["network_ok"], true);

        // Valid datadoghq.eu URL
        c.config = Some(DatadogConfig {
            auth: DatadogAuth::ApiKeys {
                api_key: "k".into(),
                app_key: "a".into(),
            },
            base_url: "https://api.datadoghq.eu/api/v1".into(),
        });
        assert_eq!(c.provisioning_readiness()["network_ok"], true);

        // Invalid URL
        c.config = Some(DatadogConfig {
            auth: DatadogAuth::ApiKeys {
                api_key: "k".into(),
                app_key: "a".into(),
            },
            base_url: "https://custom.example.com/api/v1".into(),
        });
        assert_eq!(c.provisioning_readiness()["network_ok"], false);
    }

    #[test]
    fn provisioning_readiness_region_detection() {
        let mut c = DatadogConnector::new();

        let cases = vec![
            ("https://api.datadoghq.com/api/v1", "us1"),
            ("https://api.us3.datadoghq.com/api/v1", "us3"),
            ("https://api.us5.datadoghq.com/api/v1", "us5"),
            ("https://api.datadoghq.eu/api/v1", "eu1"),
            ("https://api.ap1.datadoghq.com/api/v1", "ap1"),
            ("https://custom.example.com/api/v1", "unknown"),
        ];

        for (url, expected_region) in cases {
            c.config = Some(DatadogConfig {
                auth: DatadogAuth::ApiKeys {
                    api_key: "k".into(),
                    app_key: "a".into(),
                },
                base_url: url.into(),
            });
            assert_eq!(
                c.provisioning_readiness()["region"],
                expected_region,
                "URL {url} should map to region {expected_region}"
            );
        }
    }

    #[test]
    fn provisioning_readiness_includes_base_url() {
        let mut c = DatadogConnector::new();
        c.config = Some(DatadogConfig {
            auth: DatadogAuth::ApiKeys {
                api_key: "k".into(),
                app_key: "a".into(),
            },
            base_url: "https://api.us3.datadoghq.com/api/v1".into(),
        });
        let r = c.provisioning_readiness();
        assert_eq!(r["base_url"], "https://api.us3.datadoghq.com/api/v1");
    }

    // ── Self-check includes provisioning ────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn self_check_includes_provisioning() {
        let c = DatadogConnector::new();
        let result = c.handle_self_check().await.unwrap();
        assert_eq!(result["connector_id"], "fcp.datadog");
        assert_eq!(result["status"], "unconfigured");
        let prov = &result["provisioning"];
        assert_eq!(prov["auth_mode"], "unconfigured");
        assert_eq!(prov["api_key_configured"], false);
        assert_eq!(prov["app_key_configured"], false);
        assert_eq!(prov["network_ok"], true);
        assert_eq!(prov["region"], "us1");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_configured_includes_provisioning() {
        let mut c = DatadogConnector::new();
        c.config = Some(DatadogConfig {
            auth: DatadogAuth::ApiKeys {
                api_key: "k".into(),
                app_key: "a".into(),
            },
            base_url: "https://api.datadoghq.eu/api/v1".into(),
        });
        let result = c.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "ready");
        let prov = &result["provisioning"];
        assert_eq!(prov["auth_mode"], "api_keys");
        assert_eq!(prov["region"], "eu1");
        assert_eq!(prov["api_key_configured"], true);
        assert_eq!(prov["app_key_configured"], true);
    }
}
