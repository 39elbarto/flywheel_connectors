//! FCP Sentry Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, SentryAuth, SentryClient},
    error::SentryError,
};

/// Parsed and validated Sentry connector configuration.
#[derive(Debug, Clone)]
struct SentryConfig {
    auth: SentryAuth,
    base_url: String,
}

impl SentryConfig {
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
            (Some(token), None) => SentryAuth::BearerToken(token),
            (None, Some(cred_id)) => SentryAuth::CredentialId(cred_id),
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

/// FCP Sentry Connector.
pub struct SentryConnector {
    base: Arc<BaseConnector>,
    config: Option<SentryConfig>,
    client: Option<Arc<SentryClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SentryConnector {
    /// Create a new Sentry connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("sentry"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for SentryConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SentryConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SentryConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Sentry connector");

        let client = SentryClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.sentry",
            "connector_version": "0.1.0",
            "capabilities": [
                "sentry.read",
                "sentry.write",
                "sentry.alerts",
                "sentry.admin"
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

        // Check: configuration present
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

        // Check: client initialized
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

        // Check: handshake completed
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
            "connector_id": "fcp.sentry",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.sentry",
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
            "sentry.list_projects" => self.invoke_list_projects(client, &input).await,
            "sentry.list_issues" => self.invoke_list_issues(client, &input).await,
            "sentry.get_issue" => self.invoke_get_issue(client, &input).await,
            "sentry.update_issue" => self.invoke_update_issue(client, &input).await,
            "sentry.delete_issue" => self.invoke_delete_issue(client, &input).await,
            "sentry.list_issue_events" => self.invoke_list_issue_events(client, &input).await,
            "sentry.get_event" => self.invoke_get_event(client, &input).await,
            "sentry.get_transaction" => self.invoke_get_transaction(client, &input).await,
            "sentry.list_releases" => self.invoke_list_releases(client, &input).await,
            "sentry.get_release" => self.invoke_get_release(client, &input).await,
            "sentry.list_release_deploys" => self.invoke_list_release_deploys(client, &input).await,
            "sentry.discover_query" => self.invoke_discover_query(client, &input).await,
            "sentry.list_alert_rules" => self.invoke_list_alert_rules(client, &input).await,
            "sentry.create_alert_rule" => self.invoke_create_alert_rule(client, &input).await,
            "sentry.update_alert_rule" => self.invoke_update_alert_rule(client, &input).await,
            "sentry.delete_alert_rule" => self.invoke_delete_alert_rule(client, &input).await,
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
        info!("Sentry connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // ── Operation implementations ─────────────────────────────────────

    async fn invoke_list_projects(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let cursor = input.get("cursor").and_then(|v| v.as_str());
        let data = client.list_projects(org, cursor).await?;
        Ok(json!({ "projects": data }))
    }

    async fn invoke_list_issues(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let query = input.get("query").and_then(|v| v.as_str());
        let sort = input.get("sort").and_then(|v| v.as_str());
        let cursor = input.get("cursor").and_then(|v| v.as_str());
        let data = client
            .list_issues(org, project, query, sort, cursor)
            .await?;
        Ok(json!({ "issues": data }))
    }

    async fn invoke_get_issue(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let issue_id = require_str(input, "issue_id")?;
        let data = client.get_issue(issue_id).await?;
        Ok(json!({ "issue": data }))
    }

    async fn invoke_update_issue(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let issue_id = require_str(input, "issue_id")?;
        let mut update = input.clone();
        // Remove issue_id from the update body
        if let Some(obj) = update.as_object_mut() {
            obj.remove("issue_id");
        }
        let data = client.update_issue(issue_id, &update).await?;
        Ok(json!({ "issue": data }))
    }

    async fn invoke_delete_issue(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let issue_id = require_str(input, "issue_id")?;
        client.delete_issue(issue_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_list_issue_events(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let issue_id = require_str(input, "issue_id")?;
        let full = input.get("full").and_then(|v| v.as_bool()).unwrap_or(false);
        let cursor = input.get("cursor").and_then(|v| v.as_str());
        let data = client.list_issue_events(issue_id, full, cursor).await?;
        Ok(json!({ "events": data }))
    }

    async fn invoke_get_event(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let event_id = require_str(input, "event_id")?;
        let data = client.get_event(org, project, event_id).await?;
        Ok(json!({ "event": data }))
    }

    async fn invoke_get_transaction(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let event_id = require_str(input, "event_id")?;
        let data = client.get_transaction(org, project, event_id).await?;
        Ok(json!({ "event": data }))
    }

    async fn invoke_list_releases(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = input.get("project_slug").and_then(|v| v.as_str());
        let query = input.get("query").and_then(|v| v.as_str());
        let cursor = input.get("cursor").and_then(|v| v.as_str());
        let data = client.list_releases(org, project, query, cursor).await?;
        Ok(json!({ "releases": data }))
    }

    async fn invoke_get_release(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let version = require_str(input, "version")?;
        let data = client.get_release(org, version).await?;
        Ok(json!({ "release": data }))
    }

    async fn invoke_list_release_deploys(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let version = require_str(input, "version")?;
        let data = client.list_release_deploys(org, version).await?;
        Ok(json!({ "deploys": data }))
    }

    async fn invoke_discover_query(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let query = require_str(input, "query")?;
        let fields: Vec<String> = input
            .get("fields")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let stats_period = input.get("statsPeriod").and_then(|v| v.as_str());
        let start = input.get("start").and_then(|v| v.as_str());
        let end = input.get("end").and_then(|v| v.as_str());
        let sort = input.get("sort").and_then(|v| v.as_str());
        let per_page = input
            .get("per_page")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let data = client
            .discover_query(
                org,
                query,
                &fields,
                stats_period,
                start,
                end,
                sort,
                per_page,
            )
            .await?;
        Ok(data)
    }

    async fn invoke_list_alert_rules(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let data = client.list_alert_rules(org, project).await?;
        Ok(json!({ "rules": data }))
    }

    async fn invoke_create_alert_rule(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let mut rule = input.clone();
        if let Some(obj) = rule.as_object_mut() {
            obj.remove("organization_slug");
            obj.remove("project_slug");
        }
        let data = client.create_alert_rule(org, project, &rule).await?;
        Ok(json!({ "rule": data }))
    }

    async fn invoke_update_alert_rule(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let rule_id = require_str(input, "rule_id")?;
        let mut rule = input.clone();
        if let Some(obj) = rule.as_object_mut() {
            obj.remove("organization_slug");
            obj.remove("project_slug");
            obj.remove("rule_id");
        }
        let data = client
            .update_alert_rule(org, project, rule_id, &rule)
            .await?;
        Ok(json!({ "rule": data }))
    }

    async fn invoke_delete_alert_rule(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let rule_id = require_str(input, "rule_id")?;
        client.delete_alert_rule(org, project, rule_id).await?;
        Ok(json!({ "deleted": true }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, SentryError> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| SentryError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "sentry.list_projects",
            "summary": "List projects in an organization",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.list_issues",
            "summary": "List/search issues in a project",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.get_issue",
            "summary": "Get a single issue by ID",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.update_issue",
            "summary": "Update issue status/assignment",
            "capability": "sentry.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "sentry.delete_issue",
            "summary": "Permanently delete an issue",
            "capability": "sentry.admin",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
        {
            "id": "sentry.list_issue_events",
            "summary": "List events for an issue",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.get_event",
            "summary": "Get full event with stacktrace",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.get_transaction",
            "summary": "Get a performance transaction event",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.list_releases",
            "summary": "List releases for an organization",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.get_release",
            "summary": "Get release details",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.list_release_deploys",
            "summary": "List deploys for a release",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.discover_query",
            "summary": "Run a Discover analytics query",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.list_alert_rules",
            "summary": "List alert rules for a project",
            "capability": "sentry.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sentry.create_alert_rule",
            "summary": "Create an alert rule",
            "capability": "sentry.alerts",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "sentry.update_alert_rule",
            "summary": "Update an alert rule",
            "capability": "sentry.alerts",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "sentry.delete_alert_rule",
            "summary": "Delete an alert rule",
            "capability": "sentry.admin",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SentryConfig::from_params ────────────────────────────────────

    #[test]
    fn config_from_auth_token() {
        let config = SentryConfig::from_params(&json!({
            "auth_token": "sntrys_test_token",
        }))
        .unwrap();
        assert!(matches!(config.auth, SentryAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = SentryConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = SentryConfig::from_params(&json!({
            "auth_token": "tok",
            "base_url": "https://sentry.example.com/api/0",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://sentry.example.com/api/0");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = SentryConfig::from_params(&json!({
            "auth_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = SentryConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_auth_token() {
        let result = SentryConfig::from_params(&json!({
            "auth_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_auth_token() {
        let result = SentryConfig::from_params(&json!({
            "auth_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = SentryConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = SentryConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    // ── require_str ──────────────────────────────────────────────────

    #[test]
    fn require_str_extracts_value() {
        let input = json!({"org": "my-org", "project": "backend"});
        assert_eq!(require_str(&input, "org").unwrap(), "my-org");
        assert_eq!(require_str(&input, "project").unwrap(), "backend");
    }

    #[test]
    fn require_str_missing_field() {
        let input = json!({"org": "my-org"});
        let err = require_str(&input, "project").unwrap_err();
        assert!(err.to_string().contains("project"));
    }

    #[test]
    fn require_str_non_string_field() {
        let input = json!({"count": 42});
        assert!(require_str(&input, "count").is_err());
    }

    #[test]
    fn require_str_null_field() {
        let input = json!({"field": null});
        assert!(require_str(&input, "field").is_err());
    }

    // ── operations_info ──────────────────────────────────────────────

    #[test]
    fn operations_info_has_16_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 16);
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
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap == "sentry.read" {
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

    // ── DoctorResult ─────────────────────────────────────────────────

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
                message: Some("warning".into()),
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
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                valid.contains(&tier),
                "invalid safety_tier: {tier} for op {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn config_trims_auth_token() {
        let config =
            SentryConfig::from_params(&json!({ "auth_token": "  sntrys_test  " })).unwrap();
        match &config.auth {
            SentryAuth::BearerToken(t) => assert_eq!(t, "sntrys_test"),
            SentryAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    // ── DoctorResult edge cases ─────────────────────────────────────

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
                message: Some("fail".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    // ── SentryConnector ──────────────────────────────────────────────

    #[test]
    fn connector_default() {
        let c = SentryConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_counters_zero() {
        let c = SentryConnector::new();
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

    // ── DoctorStatus serde ────────────────────────────────────────

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
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ── DoctorResult serialization roundtrip ──────────────────────

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

    // ── operations_info additional checks ─────────────────────────

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"sentry.list_projects"));
        assert!(ids.contains(&"sentry.list_issues"));
        assert!(ids.contains(&"sentry.get_issue"));
        assert!(ids.contains(&"sentry.update_issue"));
        assert!(ids.contains(&"sentry.delete_issue"));
        assert!(ids.contains(&"sentry.discover_query"));
        assert!(ids.contains(&"sentry.list_alert_rules"));
        assert!(ids.contains(&"sentry.create_alert_rule"));
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

    #[test]
    fn operations_admin_capability_for_dangerous_ops() {
        for op in operations_info().as_array().unwrap() {
            if op["safety_tier"] == "dangerous" {
                assert_eq!(
                    op["capability"], "sentry.admin",
                    "{} should require admin",
                    op["id"]
                );
            }
        }
    }

    // ── require_str edge cases ────────────────────────────────────

    #[test]
    fn require_str_empty_string() {
        let input = json!({"f": ""});
        assert_eq!(require_str(&input, "f").unwrap(), "");
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"f": true});
        assert!(require_str(&input, "f").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"f": [1, 2, 3]});
        assert!(require_str(&input, "f").is_err());
    }

    // ── Config edge cases ─────────────────────────────────────────

    #[test]
    fn config_default_base_url_when_none() {
        let config = SentryConfig::from_params(&json!({"auth_token": "tok"})).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_auth_token_debug_safe() {
        let config = SentryConfig::from_params(&json!({"auth_token": "secret_tok"})).unwrap();
        let dbg = format!("{config:?}");
        assert!(!dbg.contains("secret_tok"));
    }
}
