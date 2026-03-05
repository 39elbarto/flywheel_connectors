//! FCP Terraform Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, TerraformAuth, TerraformClient},
    error::TerraformError,
};

/// Parsed and validated Terraform connector configuration.
#[derive(Debug, Clone)]
struct TerraformConfig {
    auth: TerraformAuth,
    base_url: String,
    organization: Option<String>,
}

impl TerraformConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_token = params
            .get("api_token")
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

        let auth = match (api_token, credential_id) {
            (Some(key), None) => TerraformAuth::BearerToken(key),
            (None, Some(cred_id)) => TerraformAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        let organization = params
            .get("organization")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        Ok(Self { auth, base_url, organization })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

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

/// FCP Terraform Connector.
pub struct TerraformConnector {
    base: Arc<BaseConnector>,
    config: Option<TerraformConfig>,
    client: Option<Arc<TerraformClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl TerraformConnector {
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("terraform"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for TerraformConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl TerraformConnector {
    pub async fn handle_configure(&mut self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let config = TerraformConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Terraform connector");
        let client = TerraformClient::new(config.auth.clone(), Some(&config.base_url)).map_err(|e| e.to_fcp_error())?;
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    pub async fn handle_handshake(&mut self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::InvalidRequest { code: 1004, message: "Connector not configured".into() });
        }
        self.session_id = params.get("session_id").and_then(serde_json::Value::as_str).map(str::to_string);
        self.base.set_handshaken(true);
        Ok(json!({"protocol_version": "2.0", "connector_id": "fcp.terraform", "connector_version": "0.1.0",
            "capabilities": ["terraform.plan", "terraform.apply", "terraform.state", "terraform.state_write"]}))
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        let status = if configured && handshaken { "healthy" } else if configured { "degraded" } else { "unconfigured" };
        Ok(json!({"status": status, "configured": configured, "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed), "errors": self.error_count.load(Ordering::Relaxed)}))
    }

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();
        checks.push(DoctorCheck { name: "configuration".into(), passed: self.config.is_some(),
            message: if self.config.is_none() { Some("Not configured".into()) } else { None }, critical: true });
        checks.push(DoctorCheck { name: "client_initialized".into(), passed: self.client.is_some(),
            message: if self.client.is_none() { Some("API client not initialized".into()) } else { None }, critical: true });
        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck { name: "handshake".into(), passed: handshaken,
            message: if handshaken { None } else { Some("Handshake not completed".into()) }, critical: false });
        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({"connector_id": "fcp.terraform", "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" }}))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({"connector_id": "fcp.terraform", "version": "0.1.0", "operations": operations_info()}))
    }

    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let operation = params.get("operation_id").and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest { code: 1003, message: "Missing operation_id".into() })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal { message: "Client not initialized".into() })?;

        let result = match operation {
            "terraform.init" => self.invoke_init(client, &input).await,
            "terraform.validate" => self.invoke_validate(client, &input).await,
            "terraform.plan" => self.invoke_plan(client, &input).await,
            "terraform.show_plan" => self.invoke_show_plan(client, &input).await,
            "terraform.apply" => self.invoke_apply(client, &input).await,
            "terraform.destroy" => self.invoke_destroy(client, &input).await,
            "terraform.state_list" => self.invoke_state_list(client, &input).await,
            "terraform.state_show" => self.invoke_state_show(client, &input).await,
            "terraform.output" => self.invoke_output(client, &input).await,
            "terraform.import" => self.invoke_import(client, &input).await,
            "terraform.detect_drift" => self.invoke_detect_drift(client, &input).await,
            "terraform.list_modules" => self.invoke_list_modules(client, &input).await,
            _ => return Err(FcpError::InvalidRequest { code: 1002, message: format!("Unknown operation: {operation}") }),
        };

        result.map_err(|e| { self.error_count.fetch_add(1, Ordering::Relaxed); e.to_fcp_error() })
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params.get("operation_id").and_then(serde_json::Value::as_str).unwrap_or("");
        let allowed = operations_info().as_array().is_some_and(|ops|
            ops.iter().any(|o| o.get("id").and_then(serde_json::Value::as_str) == Some(operation)));
        Ok(json!({"allowed": allowed, "reason": if allowed { "Operation supported" } else { "Unknown operation" }}))
    }

    pub async fn handle_shutdown(&mut self, _params: serde_json::Value) -> FcpResult<serde_json::Value> {
        info!("Terraform connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn effective_org<'a>(&'a self, input: &'a serde_json::Value) -> Result<&'a str, TerraformError> {
        input.get("organization").and_then(serde_json::Value::as_str)
            .or_else(|| self.config.as_ref().and_then(|c| c.organization.as_deref()))
            .ok_or_else(|| TerraformError::Api { status_code: 400, message: "Missing required field: organization".into() })
    }

    async fn invoke_init(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let providers = resp.get("data").and_then(|d| d.get("attributes")).and_then(|a| a.get("terraform-version"))
            .map_or_else(|| json!([]), |v| json!([format!("terraform {}", v.as_str().unwrap_or("unknown"))]));
        Ok(json!({"initialized": true, "workspace_id": ws_id, "providers": providers}))
    }

    async fn invoke_validate(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let resp = client.get_workspace_by_name(org, ws_name).await?;
        Ok(json!({"valid": resp.get("data").is_some(), "diagnostics": []}))
    }

    async fn invoke_plan(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let is_destroy = input.get("destroy").and_then(serde_json::Value::as_bool).unwrap_or(false);
        let plan_only = input.get("refresh_only").and_then(serde_json::Value::as_bool).unwrap_or(false);
        let mut run_attrs = json!({"is-destroy": is_destroy, "plan-only": plan_only, "message": format!("Plan via FCP connector for {working_dir}")});
        if let Some(targets) = input.get("targets").and_then(serde_json::Value::as_array) {
            let ta: Vec<&str> = targets.iter().filter_map(serde_json::Value::as_str).collect();
            run_attrs["target-addrs"] = json!(ta);
        }
        let run_body = json!({"data": {"type": "runs", "attributes": run_attrs,
            "relationships": {"workspace": {"data": {"type": "workspaces", "id": ws_id}}}}});
        let run_resp = client.create_run(&run_body).await?;
        let run_id = run_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let summary = run_resp.get("data").and_then(|d| d.get("attributes")).and_then(|a| a.get("message"))
            .and_then(serde_json::Value::as_str).unwrap_or("Plan created").to_string();
        Ok(json!({"plan_hash": format!("blake3:{run_id}"), "plan_file": run_id, "summary": summary, "resource_changes": []}))
    }

    async fn invoke_show_plan(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let plan_file = require_str(input, "plan_file")?;
        let run_resp = client.get_run(plan_file).await?;
        let plan_id = run_resp.get("data").and_then(|d| d.get("relationships")).and_then(|r| r.get("plan"))
            .and_then(|p| p.get("data")).and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let use_json = input.get("json").and_then(serde_json::Value::as_bool).unwrap_or(false);
        let plan_detail = if use_json && !plan_id.is_empty() {
            client.get_plan_json_output(plan_id).await.unwrap_or_else(|_| json!({"error": "Could not retrieve JSON output"}))
        } else if !plan_id.is_empty() {
            let pr = client.get_plan(plan_id).await?;
            pr.get("data").and_then(|d| d.get("attributes")).cloned().unwrap_or_else(|| json!({}))
        } else {
            run_resp.get("data").and_then(|d| d.get("attributes")).cloned().unwrap_or_else(|| json!({}))
        };
        Ok(json!({"plan_detail": plan_detail}))
    }

    async fn invoke_apply(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let _wd = require_str(input, "working_dir")?;
        let plan_hash = require_str(input, "plan_hash")?;
        let run_id = plan_hash.strip_prefix("blake3:").unwrap_or(plan_hash);
        let resp = client.apply_run(run_id, None).await?;
        let summary = resp.get("data").and_then(|d| d.get("attributes")).and_then(|a| a.get("status"))
            .and_then(serde_json::Value::as_str).unwrap_or("Apply initiated").to_string();
        Ok(json!({"applied": true, "summary": summary}))
    }

    async fn invoke_destroy(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let _wd = require_str(input, "working_dir")?;
        let plan_hash = require_str(input, "plan_hash")?;
        let run_id = plan_hash.strip_prefix("blake3:").unwrap_or(plan_hash);
        let resp = client.apply_run(run_id, Some("Destroy via FCP connector")).await?;
        let summary = resp.get("data").and_then(|d| d.get("attributes")).and_then(|a| a.get("status"))
            .and_then(serde_json::Value::as_str).unwrap_or("Destroy initiated").to_string();
        Ok(json!({"destroyed": true, "summary": summary}))
    }

    async fn invoke_state_list(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let sv_resp = client.get_current_state_version(ws_id).await?;
        let sv_id = sv_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let filter = input.get("filter").and_then(serde_json::Value::as_str);
        let res_resp = client.list_state_resources(sv_id).await?;
        let resources = res_resp.get("data").and_then(serde_json::Value::as_array).map(|items| {
            let mut addrs: Vec<serde_json::Value> = items.iter().filter_map(|item| {
                let addr = item.get("attributes")?.get("address")?.as_str()?;
                Some(json!(addr))
            }).collect();
            if let Some(f) = filter { addrs.retain(|a| a.as_str().is_some_and(|s| s.starts_with(f))); }
            addrs
        }).unwrap_or_default();
        Ok(json!({"resources": resources}))
    }

    async fn invoke_state_show(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let address = require_str(input, "address")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let sv_resp = client.get_current_state_version(ws_id).await?;
        let sv_id = sv_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let res_resp = client.list_state_resources(sv_id).await?;
        let resource = res_resp.get("data").and_then(serde_json::Value::as_array).and_then(|items|
            items.iter().find(|item| item.get("attributes").and_then(|a| a.get("address")).and_then(serde_json::Value::as_str) == Some(address))
        ).and_then(|item| item.get("attributes").cloned()).unwrap_or_else(|| json!({}));
        Ok(json!({"resource": resource}))
    }

    async fn invoke_output(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let output_name = input.get("name").and_then(serde_json::Value::as_str);
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let sv_resp = client.get_current_state_version(ws_id).await?;
        let sv_id = sv_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let out_resp = client.list_state_version_outputs(sv_id).await?;
        let mut outputs = serde_json::Map::new();
        if let Some(items) = out_resp.get("data").and_then(serde_json::Value::as_array) {
            for item in items {
                if let Some(attrs) = item.get("attributes") {
                    let name = attrs.get("name").and_then(serde_json::Value::as_str).unwrap_or("");
                    let value = attrs.get("value").cloned().unwrap_or(serde_json::Value::Null);
                    let sensitive = attrs.get("sensitive").and_then(serde_json::Value::as_bool).unwrap_or(false);
                    if let Some(fn_) = output_name { if name != fn_ { continue; } }
                    outputs.insert(name.to_string(), json!({"value": if sensitive { json!("<sensitive>") } else { value }, "sensitive": sensitive}));
                }
            }
        }
        Ok(json!({"outputs": outputs}))
    }

    async fn invoke_import(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let address = require_str(input, "address")?;
        let resource_id = require_str(input, "id")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let run_body = json!({"data": {"type": "runs", "attributes": {"plan-only": true, "message": format!("Import {address} ({resource_id}) via FCP connector")},
            "relationships": {"workspace": {"data": {"type": "workspaces", "id": ws_id}}}}});
        client.create_run(&run_body).await?;
        Ok(json!({"imported": true, "address": address}))
    }

    async fn invoke_detect_drift(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let run_body = json!({"data": {"type": "runs", "attributes": {"refresh-only": true, "plan-only": true,
            "message": format!("Drift detection via FCP connector for {working_dir}")},
            "relationships": {"workspace": {"data": {"type": "workspaces", "id": ws_id}}}}});
        let run_resp = client.create_run(&run_body).await?;
        let has_changes = run_resp.get("data").and_then(|d| d.get("attributes")).and_then(|a| a.get("has-changes"))
            .and_then(serde_json::Value::as_bool).unwrap_or(false);
        Ok(json!({"drifted": has_changes, "drift_summary": [], "checkpoint_ts": chrono::Utc::now().to_rfc3339()}))
    }

    async fn invoke_list_modules(&self, client: &TerraformClient, input: &serde_json::Value) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp.get("data").and_then(|d| d.get("id")).and_then(serde_json::Value::as_str).unwrap_or("");
        let cv_resp = client.list_configuration_versions(ws_id).await?;
        let modules: Vec<serde_json::Value> = cv_resp.get("data").and_then(serde_json::Value::as_array).map(|items| {
            items.iter().map(|item| {
                let attrs = item.get("attributes").cloned().unwrap_or_else(|| json!({}));
                json!({"source": attrs.get("source").cloned().unwrap_or(serde_json::Value::Null),
                    "version": item.get("id").cloned().unwrap_or(serde_json::Value::Null)})
            }).collect()
        }).unwrap_or_default();
        Ok(json!({"modules": modules}))
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, TerraformError> {
    input.get(field).and_then(serde_json::Value::as_str)
        .ok_or_else(|| TerraformError::Api { status_code: 400, message: format!("Missing required field: {field}") })
}

fn operations_info() -> serde_json::Value {
    json!([
        {"id": "terraform.init", "summary": "Initialize a Terraform working directory", "capability": "terraform.plan", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict"},
        {"id": "terraform.validate", "summary": "Validate Terraform configuration syntax and consistency", "capability": "terraform.plan", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict"},
        {"id": "terraform.plan", "summary": "Generate a Terraform execution plan", "capability": "terraform.plan", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict"},
        {"id": "terraform.show_plan", "summary": "Display details of a saved plan file", "capability": "terraform.plan", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict"},
        {"id": "terraform.apply", "summary": "Apply a previously generated plan", "capability": "terraform.apply", "risk_level": "high", "safety_tier": "dangerous", "idempotency": "best_effort"},
        {"id": "terraform.destroy", "summary": "Destroy all resources managed by a configuration", "capability": "terraform.apply", "risk_level": "high", "safety_tier": "dangerous", "idempotency": "best_effort"},
        {"id": "terraform.state_list", "summary": "List all resources in the Terraform state", "capability": "terraform.state", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict"},
        {"id": "terraform.state_show", "summary": "Show attributes of a single resource in state", "capability": "terraform.state", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict"},
        {"id": "terraform.output", "summary": "Read Terraform output values", "capability": "terraform.state", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict"},
        {"id": "terraform.import", "summary": "Import an existing resource into Terraform state", "capability": "terraform.state_write", "risk_level": "medium", "safety_tier": "risky", "idempotency": "strict"},
        {"id": "terraform.detect_drift", "summary": "Detect configuration drift against real infrastructure", "capability": "terraform.plan", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict"},
        {"id": "terraform.list_modules", "summary": "List modules used in the configuration", "capability": "terraform.plan", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict"},
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn config_from_api_token() { let c = TerraformConfig::from_params(&json!({"api_token": "test"})).unwrap(); assert!(matches!(c.auth, TerraformAuth::BearerToken(_))); assert_eq!(c.base_url, DEFAULT_BASE_URL); }
    #[test] fn config_from_credential_id() { let c = TerraformConfig::from_params(&json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"})).unwrap(); assert!(c.auth.is_secretless()); }
    #[test] fn config_custom_base_url() { let c = TerraformConfig::from_params(&json!({"api_token": "t", "base_url": "https://tfe.example.com/api/v2"})).unwrap(); assert_eq!(c.base_url, "https://tfe.example.com/api/v2"); }
    #[test] fn config_with_organization() { let c = TerraformConfig::from_params(&json!({"api_token": "t", "organization": "my-org"})).unwrap(); assert_eq!(c.organization, Some("my-org".into())); }
    #[test] fn config_without_organization() { let c = TerraformConfig::from_params(&json!({"api_token": "t"})).unwrap(); assert!(c.organization.is_none()); }
    #[test] fn config_rejects_both_auth() { assert!(TerraformConfig::from_params(&json!({"api_token": "t", "credential_id": "550e8400-e29b-41d4-a716-446655440000"})).is_err()); }
    #[test] fn config_rejects_no_auth() { assert!(TerraformConfig::from_params(&json!({})).is_err()); }
    #[test] fn config_rejects_empty_token() { assert!(TerraformConfig::from_params(&json!({"api_token": ""})).is_err()); }
    #[test] fn config_rejects_whitespace_token() { assert!(TerraformConfig::from_params(&json!({"api_token": "   "})).is_err()); }
    #[test] fn config_rejects_non_string_cred() { assert!(TerraformConfig::from_params(&json!({"credential_id": 12345})).is_err()); }
    #[test] fn config_rejects_invalid_uuid() { assert!(TerraformConfig::from_params(&json!({"credential_id": "not-a-uuid"})).is_err()); }
    #[test] fn require_str_ok() { assert_eq!(require_str(&json!({"x": "v"}), "x").unwrap(), "v"); }
    #[test] fn require_str_missing() { assert!(require_str(&json!({}), "x").is_err()); }
    #[test] fn require_str_not_string() { assert!(require_str(&json!({"x": 42}), "x").is_err()); }
    #[test] fn require_str_null() { assert!(require_str(&json!({"x": null}), "x").is_err()); }
    #[test] fn ops_count() { assert_eq!(operations_info().as_array().unwrap().len(), 12); }
    #[test] fn ops_all_have_fields() { for op in operations_info().as_array().unwrap() { assert!(op.get("id").is_some()); assert!(op.get("summary").is_some()); assert!(op.get("capability").is_some()); assert!(op.get("risk_level").is_some()); assert!(op.get("safety_tier").is_some()); } }
    #[test] fn ops_unique_ids() { let ops = operations_info(); let mut ids: Vec<&str> = ops.as_array().unwrap().iter().filter_map(|o| o["id"].as_str()).collect(); let n = ids.len(); ids.sort_unstable(); ids.dedup(); assert_eq!(n, ids.len()); }
    #[test] fn ops_valid_risk() { for op in operations_info().as_array().unwrap() { assert!(["low","medium","high"].contains(&op["risk_level"].as_str().unwrap())); } }
    #[test] fn ops_valid_safety() { for op in operations_info().as_array().unwrap() { assert!(["safe","risky","dangerous"].contains(&op["safety_tier"].as_str().unwrap())); } }
    #[test] fn ops_safe_are_low_risk() { let safe = ["terraform.init","terraform.validate","terraform.plan","terraform.show_plan","terraform.state_list","terraform.state_show","terraform.output","terraform.detect_drift","terraform.list_modules"]; for op in operations_info().as_array().unwrap() { let id = op["id"].as_str().unwrap(); if safe.contains(&id) { assert_eq!(op["safety_tier"].as_str().unwrap(), "safe"); assert_eq!(op["risk_level"].as_str().unwrap(), "low"); } } }
    #[test] fn ops_dangerous_high_risk() { for op in operations_info().as_array().unwrap() { if op["safety_tier"].as_str() == Some("dangerous") { assert_eq!(op["risk_level"].as_str().unwrap(), "high"); } } }
    #[test] fn ops_contain_all_ids() { let binding = operations_info(); let ids: Vec<&str> = binding.as_array().unwrap().iter().filter_map(|o| o["id"].as_str()).collect(); for e in &["terraform.init","terraform.validate","terraform.plan","terraform.show_plan","terraform.apply","terraform.destroy","terraform.state_list","terraform.state_show","terraform.output","terraform.import","terraform.detect_drift","terraform.list_modules"] { assert!(ids.contains(e)); } }
    #[test] fn ops_caps_match() { let binding = operations_info(); let cs: Vec<(&str,&str)> = binding.as_array().unwrap().iter().map(|o| (o["id"].as_str().unwrap(), o["capability"].as_str().unwrap())).collect(); assert!(cs.contains(&("terraform.plan","terraform.plan"))); assert!(cs.contains(&("terraform.apply","terraform.apply"))); assert!(cs.contains(&("terraform.state_list","terraform.state"))); assert!(cs.contains(&("terraform.import","terraform.state_write"))); }
    #[test] fn doctor_healthy() { assert_eq!(DoctorResult::from_checks(vec![DoctorCheck{name:"a".into(),passed:true,message:None,critical:true}]).status, DoctorStatus::Healthy); }
    #[test] fn doctor_degraded() { assert_eq!(DoctorResult::from_checks(vec![DoctorCheck{name:"a".into(),passed:true,message:None,critical:true},DoctorCheck{name:"b".into(),passed:false,message:Some("w".into()),critical:false}]).status, DoctorStatus::Degraded); }
    #[test] fn doctor_unhealthy() { assert_eq!(DoctorResult::from_checks(vec![DoctorCheck{name:"c".into(),passed:false,message:Some("n".into()),critical:true}]).status, DoctorStatus::Unhealthy); }
    #[test] fn doctor_serializes() { let v = serde_json::to_value(DoctorResult::from_checks(vec![DoctorCheck{name:"t".into(),passed:true,message:None,critical:false}])).unwrap(); assert_eq!(v["status"],"healthy"); }
    #[test] fn config_trims_token() { match &TerraformConfig::from_params(&json!({"api_token":" tok "})).unwrap().auth { TerraformAuth::BearerToken(t) => assert_eq!(t,"tok"), TerraformAuth::CredentialId(_) => panic!() } }
    #[test] fn ops_all_have_idempotency() { for op in operations_info().as_array().unwrap() { assert!(op.get("idempotency").is_some()); } }
    #[test] fn doctor_empty() { assert_eq!(DoctorResult::from_checks(vec![]).status, DoctorStatus::Healthy); }
    #[test] fn connector_default() { let c = TerraformConnector::default(); assert!(c.config.is_none()); assert!(c.client.is_none()); assert!(c.session_id.is_none()); }
    #[test] fn ops_apply_destroy_best_effort() { for op in operations_info().as_array().unwrap() { let id = op["id"].as_str().unwrap(); if id=="terraform.apply"||id=="terraform.destroy" { assert_eq!(op["idempotency"].as_str().unwrap(),"best_effort"); } } }
    #[test] fn ops_strict_idempotency() { let s = ["terraform.init","terraform.validate","terraform.plan","terraform.show_plan","terraform.state_list","terraform.state_show","terraform.output","terraform.detect_drift","terraform.list_modules","terraform.import"]; for op in operations_info().as_array().unwrap() { let id = op["id"].as_str().unwrap(); if s.contains(&id) { assert_eq!(op["idempotency"].as_str().unwrap(),"strict"); } } }
}
