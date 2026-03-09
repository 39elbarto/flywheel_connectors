//! FCP Sentry Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError,
    FcpResult, IdempotencyClass, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
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
            "sentry.issue.search" => self.invoke_issue_search(client, &input).await,
            "sentry.issue.get_summary" => self.invoke_issue_get_summary(client, &input).await,
            "sentry.issue.assign" => self.invoke_issue_assign(client, &input).await,
            "sentry.issue.set_status" => self.invoke_issue_set_status(client, &input).await,
            "sentry.issue.set_priority" => self.invoke_issue_set_priority(client, &input).await,
            "sentry.performance.transactions" => {
                self.invoke_performance_transactions(client, &input).await
            }
            "sentry.performance.transaction.summary" => {
                self.invoke_performance_transaction_summary(client, &input).await
            }
            "sentry.performance.trace.summary" => {
                self.invoke_performance_trace_summary(client, &input).await
            }
            "sentry.release.health" => self.invoke_release_health(client, &input).await,
            "sentry.release.create" => self.invoke_release_create(client, &input).await,
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

    async fn invoke_issue_search(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let query = input.get("query").and_then(|v| v.as_str());
        let status = input.get("status").and_then(|v| v.as_str());
        let assigned_to = input.get("assigned_to").and_then(|v| v.as_str());
        let level = input.get("level").and_then(|v| v.as_str());
        let first_seen_start = input.get("first_seen_start").and_then(|v| v.as_str());
        let first_seen_end = input.get("first_seen_end").and_then(|v| v.as_str());
        let sort = input.get("sort").and_then(|v| v.as_str());
        let cursor = input.get("cursor").and_then(|v| v.as_str());
        let per_page = input.get("per_page").and_then(|v| v.as_u64()).map(|v| v as u32);
        let data = client
            .search_issues(
                org, project, query, status, assigned_to, level,
                first_seen_start, first_seen_end, sort, cursor, per_page,
            )
            .await?;
        Ok(json!({ "issues": data }))
    }

    async fn invoke_issue_get_summary(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let issue_id = require_str(input, "issue_id")?;
        let data = client.get_issue_summary(issue_id).await?;
        // Extract only summary fields from the full issue response
        Ok(json!({
            "summary": {
                "id": data.get("id"),
                "title": data.get("title"),
                "shortId": data.get("shortId"),
                "status": data.get("status"),
                "level": data.get("level"),
                "count": data.get("count"),
                "userCount": data.get("userCount"),
                "firstSeen": data.get("firstSeen"),
                "lastSeen": data.get("lastSeen"),
                "assignedTo": data.get("assignedTo"),
                "metadata": data.get("metadata"),
                "type": data.get("type"),
                "platform": data.get("platform")
            }
        }))
    }

    async fn invoke_issue_assign(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let issue_id = require_str(input, "issue_id")?;
        let assignee = input.get("assignee").and_then(|v| v.as_str());
        let body = match assignee {
            Some(a) => json!({ "assignedTo": a }),
            None => json!({ "assignedTo": "" }),
        };
        let data = client.update_issue(issue_id, &body).await?;
        Ok(json!({ "issue": data }))
    }

    async fn invoke_issue_set_status(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let issue_id = require_str(input, "issue_id")?;
        let status = require_str(input, "status")?;
        let mut body = json!({ "status": status });
        if let Some(substatus) = input.get("substatus").and_then(|v| v.as_str()) {
            body["substatus"] = json!(substatus);
        }
        let data = client.update_issue(issue_id, &body).await?;
        Ok(json!({ "issue": data }))
    }

    async fn invoke_issue_set_priority(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let issue_id = require_str(input, "issue_id")?;
        let priority = require_str(input, "priority")?;
        let body = json!({ "priority": priority });
        let data = client.update_issue(issue_id, &body).await?;
        Ok(json!({ "issue": data }))
    }

    async fn invoke_performance_transactions(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let transaction = input.get("transaction").and_then(|v| v.as_str());
        let environment = input.get("environment").and_then(|v| v.as_str());
        let start = input.get("start").and_then(|v| v.as_str());
        let end = input.get("end").and_then(|v| v.as_str());
        let sort = input.get("sort").and_then(|v| v.as_str());
        let per_page = input.get("per_page").and_then(|v| v.as_u64()).map(|v| v as u32);
        let cursor = input.get("cursor").and_then(|v| v.as_str());
        let data = client
            .query_transactions(
                org, project, transaction, environment, start, end, sort, per_page, cursor,
            )
            .await?;
        Ok(data)
    }

    async fn invoke_performance_transaction_summary(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let transaction = require_str(input, "transaction")?;
        let environment = input.get("environment").and_then(|v| v.as_str());
        let start = input.get("start").and_then(|v| v.as_str());
        let end = input.get("end").and_then(|v| v.as_str());
        let data = client
            .get_transaction_summary(org, project, transaction, environment, start, end)
            .await?;
        Ok(data)
    }

    async fn invoke_performance_trace_summary(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let trace_id = require_str(input, "trace_id")?;
        let data = client.get_trace_summary(org, trace_id).await?;
        Ok(json!({ "trace": data }))
    }

    async fn invoke_release_health(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let project = require_str(input, "project_slug")?;
        let version = require_str(input, "version")?;
        let data = client.get_release_health(org, project, version).await?;
        Ok(json!({ "health": data }))
    }

    async fn invoke_release_create(
        &self,
        client: &SentryClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SentryError> {
        let org = require_str(input, "organization_slug")?;
        let mut body = input.clone();
        if let Some(obj) = body.as_object_mut() {
            obj.remove("organization_slug");
        }
        let data = client.create_release(org, &body).await?;
        Ok(json!({ "release": data }))
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
            "sentry.list_projects",
            "List projects in an organization",
            json!({
                "type": "object",
                "required": ["organization_slug"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "cursor": { "type": "string", "description": "Pagination cursor" }
                }
            }),
            json!({
                "type": "object",
                "required": ["projects"],
                "properties": {
                    "projects": { "type": "array", "items": { "type": "object" } }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all projects in an organization. Useful for discovery before querying issues or events.".into(),
                common_mistakes: vec![
                    "Using project name instead of project slug for subsequent API calls.".into(),
                    "Not paginating when the organization has many projects.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.list_issues"),
                    CapabilityId::from_static("sentry.discover_query"),
                ],
            },
        ),
        op_info(
            "sentry.list_issues",
            "List/search issues in a project",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" },
                    "query": { "type": "string", "description": "Search query (Sentry search syntax)" },
                    "sort": { "type": "string", "enum": ["date", "new", "priority", "freq", "user"] },
                    "cursor": { "type": "string", "description": "Pagination cursor from Link header" }
                }
            }),
            json!({
                "type": "object",
                "required": ["issues"],
                "properties": {
                    "issues": { "type": "array", "description": "List of issue objects", "items": { "type": "object" } }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List or search issues in a Sentry project. Supports Sentry search syntax for filtering.".into(),
                common_mistakes: vec![
                    "Using Jira/GitHub search syntax instead of Sentry search syntax.".into(),
                    "Not using cursor-based pagination for large result sets.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend", "query": "is:unresolved level:error", "sort": "priority"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.get_issue"),
                    CapabilityId::from_static("sentry.list_issue_events"),
                ],
            },
        ),
        op_info(
            "sentry.get_issue",
            "Get a single issue by ID",
            json!({
                "type": "object",
                "required": ["issue_id"],
                "properties": {
                    "issue_id": { "type": "string", "description": "Sentry issue ID (numeric)" }
                }
            }),
            json!({
                "type": "object",
                "required": ["issue"],
                "properties": {
                    "issue": { "type": "object", "description": "Full issue object with stats, tags, assignee, status" }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve full details for a specific Sentry issue.".into(),
                common_mistakes: vec![
                    "Confusing issue ID (numeric) with short ID (e.g., PROJECT-123).".into(),
                ],
                examples: vec![
                    r#"{"issue_id": "1234567890"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.list_issues"),
                    CapabilityId::from_static("sentry.list_issue_events"),
                    CapabilityId::from_static("sentry.update_issue"),
                ],
            },
        ),
        op_info(
            "sentry.update_issue",
            "Update issue status/assignment",
            json!({
                "type": "object",
                "required": ["issue_id"],
                "properties": {
                    "issue_id": { "type": "string", "description": "Sentry issue ID" },
                    "status": { "type": "string", "enum": ["resolved", "unresolved", "ignored"] },
                    "substatus": { "type": "string", "description": "Issue substatus" },
                    "assignedTo": { "type": "string", "description": "Assign to user (email or 'team:slug')" },
                    "hasSeen": { "type": "boolean" },
                    "isBookmarked": { "type": "boolean" },
                    "isSubscribed": { "type": "boolean" }
                }
            }),
            json!({
                "type": "object",
                "required": ["issue"],
                "properties": {
                    "issue": { "type": "object", "description": "Updated issue object" }
                }
            }),
            "sentry.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Update issue status (resolve, ignore), assignment, or bookmark state.".into(),
                common_mistakes: vec![
                    "Using user display name instead of email or 'team:slug' for assignedTo.".into(),
                    "Setting status=resolved without specifying substatus for conditional resolution.".into(),
                ],
                examples: vec![
                    r#"{"issue_id": "1234567890", "status": "resolved"}"#.into(),
                    r#"{"issue_id": "1234567890", "assignedTo": "alice@example.com"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.get_issue"),
                    CapabilityId::from_static("sentry.list_issues"),
                ],
            },
        ),
        op_info(
            "sentry.delete_issue",
            "Permanently delete an issue",
            json!({
                "type": "object",
                "required": ["issue_id"],
                "properties": {
                    "issue_id": { "type": "string", "description": "Sentry issue ID" }
                }
            }),
            json!({ "type": "object" }),
            "sentry.admin",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Permanently delete an issue and all its events. This cannot be undone.".into(),
                common_mistakes: vec![
                    "Deleting issues that should be resolved or ignored instead.".into(),
                    "Not confirming with the user before permanent deletion.".into(),
                ],
                examples: vec![
                    r#"{"issue_id": "1234567890"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.update_issue"),
                    CapabilityId::from_static("sentry.get_issue"),
                ],
            },
        ),
        op_info(
            "sentry.list_issue_events",
            "List events for an issue",
            json!({
                "type": "object",
                "required": ["issue_id"],
                "properties": {
                    "issue_id": { "type": "string", "description": "Sentry issue ID" },
                    "cursor": { "type": "string", "description": "Pagination cursor" },
                    "full": { "type": "boolean", "description": "Include full event payloads (default: false)" }
                }
            }),
            json!({
                "type": "object",
                "required": ["events"],
                "properties": {
                    "events": { "type": "array", "items": { "type": "object" } }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List individual error events for a grouped issue.".into(),
                common_mistakes: vec![
                    "Setting full=true for large event lists (slow and large responses).".into(),
                ],
                examples: vec![
                    r#"{"issue_id": "1234567890", "full": false}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.get_event"),
                    CapabilityId::from_static("sentry.get_issue"),
                ],
            },
        ),
        op_info(
            "sentry.get_event",
            "Get full event with stacktrace",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug", "event_id"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" },
                    "event_id": { "type": "string", "description": "Event ID (UUID)" }
                }
            }),
            json!({
                "type": "object",
                "required": ["event"],
                "properties": {
                    "event": { "type": "object", "description": "Full event with stacktrace, contexts, tags, breadcrumbs, and user info" }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve full event details including stacktrace, breadcrumbs, and context for debugging.".into(),
                common_mistakes: vec![
                    "Using issue ID instead of event ID (UUID).".into(),
                    "Not specifying both organization_slug and project_slug.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend", "event_id": "a1b2c3d4e5f6"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.list_issue_events"),
                    CapabilityId::from_static("sentry.get_issue"),
                ],
            },
        ),
        op_info(
            "sentry.get_transaction",
            "Get a performance transaction event",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug", "event_id"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" },
                    "event_id": { "type": "string", "description": "Transaction event ID (UUID)" }
                }
            }),
            json!({
                "type": "object",
                "required": ["event"],
                "properties": {
                    "event": { "type": "object", "description": "Transaction event with spans, measurements, and trace context" }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve a specific performance transaction with span waterfall and measurements.".into(),
                common_mistakes: vec![
                    "Confusing error event IDs with transaction event IDs.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend", "event_id": "a1b2c3d4e5f6"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.discover_query"),
                    CapabilityId::from_static("sentry.get_event"),
                ],
            },
        ),
        op_info(
            "sentry.list_releases",
            "List releases for an organization",
            json!({
                "type": "object",
                "required": ["organization_slug"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Filter to a specific project" },
                    "query": { "type": "string", "description": "Search releases by version string" },
                    "cursor": { "type": "string", "description": "Pagination cursor" }
                }
            }),
            json!({
                "type": "object",
                "required": ["releases"],
                "properties": {
                    "releases": { "type": "array", "items": { "type": "object" } }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List releases to correlate errors with deploys.".into(),
                common_mistakes: vec![
                    "Not filtering by project when the organization has many projects.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.get_release"),
                    CapabilityId::from_static("sentry.list_release_deploys"),
                ],
            },
        ),
        op_info(
            "sentry.get_release",
            "Get release details",
            json!({
                "type": "object",
                "required": ["organization_slug", "version"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "version": { "type": "string", "description": "Release version identifier" }
                }
            }),
            json!({
                "type": "object",
                "required": ["release"],
                "properties": {
                    "release": { "type": "object", "description": "Release with commits, authors, new/resolved issue counts, and deploy info" }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get full release details to inspect commits, authors, and issue regression data.".into(),
                common_mistakes: vec![
                    "URL-encoding issues with version strings containing special characters (e.g., '+').".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "version": "backend@1.2.3"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.list_releases"),
                    CapabilityId::from_static("sentry.list_release_deploys"),
                ],
            },
        ),
        op_info(
            "sentry.list_release_deploys",
            "List deploys for a release",
            json!({
                "type": "object",
                "required": ["organization_slug", "version"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "version": { "type": "string", "description": "Release version identifier" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deploys"],
                "properties": {
                    "deploys": { "type": "array", "items": { "type": "object" } }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List deployment environments and timestamps for a release to correlate with error spikes.".into(),
                common_mistakes: vec![
                    "Not URL-encoding the version string when it contains '+' or '@' characters.".into(),
                    "Confusing deploy timestamps with release creation time — deploys track per-environment rollouts.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "version": "backend@1.2.3"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.get_release"),
                    CapabilityId::from_static("sentry.list_releases"),
                ],
            },
        ),
        op_info(
            "sentry.discover_query",
            "Run a Discover analytics query",
            json!({
                "type": "object",
                "required": ["organization_slug", "query", "fields"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "query": { "type": "string", "description": "Discover search query" },
                    "fields": { "type": "array", "items": { "type": "string" }, "description": "Fields to return" },
                    "statsPeriod": { "type": "string", "description": "Relative time period (e.g., '24h', '7d')" },
                    "start": { "type": "string", "description": "ISO 8601 start time" },
                    "end": { "type": "string", "description": "ISO 8601 end time" },
                    "sort": { "type": "string", "description": "Sort field with optional - prefix for descending" },
                    "per_page": { "type": "integer", "minimum": 1, "maximum": 100 }
                }
            }),
            json!({
                "type": "object",
                "required": ["data"],
                "properties": {
                    "data": { "type": "array", "description": "Query result rows", "items": { "type": "object" } },
                    "meta": { "type": "object", "description": "Field type metadata" }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Run Discover (Snuba) queries for performance data, transaction aggregations, or custom event analytics.".into(),
                common_mistakes: vec![
                    "Not specifying statsPeriod or start/end for time-bounded queries.".into(),
                    "Using SQL syntax instead of Sentry Discover query syntax.".into(),
                    "Requesting too many fields with high-cardinality groupings.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "query": "event.type:transaction transaction:/api/users", "fields": ["transaction", "p95()", "count()", "failure_rate()"], "statsPeriod": "24h", "sort": "-p95()"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.get_transaction"),
                    CapabilityId::from_static("sentry.list_issues"),
                ],
            },
        ),
        op_info(
            "sentry.list_alert_rules",
            "List alert rules for a project",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" }
                }
            }),
            json!({
                "type": "object",
                "required": ["rules"],
                "properties": {
                    "rules": { "type": "array", "items": { "type": "object" } }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List configured alert rules for a project.".into(),
                common_mistakes: vec![
                    "Not distinguishing between issue alert rules and metric alert rules in the response.".into(),
                    "Assuming all rules are returned in one page — use cursor pagination for projects with many rules.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.create_alert_rule"),
                    CapabilityId::from_static("sentry.update_alert_rule"),
                ],
            },
        ),
        op_info(
            "sentry.create_alert_rule",
            "Create an alert rule",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug", "name", "conditions", "actions"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" },
                    "name": { "type": "string", "description": "Alert rule name" },
                    "conditions": { "type": "array", "items": { "type": "object" } },
                    "actions": { "type": "array", "items": { "type": "object" } },
                    "filters": { "type": "array", "items": { "type": "object" } },
                    "action_match": { "type": "string", "enum": ["all", "any", "none"] },
                    "frequency": { "type": "integer", "minimum": 5, "description": "Rate limit in minutes" }
                }
            }),
            json!({
                "type": "object",
                "required": ["rule"],
                "properties": {
                    "rule": { "type": "object" }
                }
            }),
            "sentry.alerts",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new alert rule to be notified about specific error conditions.".into(),
                common_mistakes: vec![
                    "Mixing up issue alert conditions with metric alert trigger syntax.".into(),
                    "Not specifying frequency, resulting in alert storms.".into(),
                    "Using incorrect condition IDs (they differ between SaaS and self-hosted).".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend", "name": "High error rate", "conditions": [{"id": "sentry.rules.conditions.first_seen_event.FirstSeenEventCondition"}], "actions": [{"id": "sentry.mail.actions.NotifyEmailAction", "targetType": "IssueOwners"}], "action_match": "any", "frequency": 30}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.list_alert_rules"),
                    CapabilityId::from_static("sentry.update_alert_rule"),
                    CapabilityId::from_static("sentry.delete_alert_rule"),
                ],
            },
        ),
        op_info(
            "sentry.update_alert_rule",
            "Update an alert rule",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug", "rule_id"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" },
                    "rule_id": { "type": "string", "description": "Alert rule ID" },
                    "name": { "type": "string", "description": "Updated rule name" },
                    "conditions": { "type": "array", "items": { "type": "object" } },
                    "actions": { "type": "array", "items": { "type": "object" } },
                    "frequency": { "type": "integer", "minimum": 5 }
                }
            }),
            json!({
                "type": "object",
                "required": ["rule"],
                "properties": {
                    "rule": { "type": "object" }
                }
            }),
            "sentry.alerts",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Modify an existing alert rule. Sends the full rule definition (not a partial patch).".into(),
                common_mistakes: vec![
                    "Sending partial updates — the API replaces the full rule definition.".into(),
                    "Not fetching the current rule first before modifying.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend", "rule_id": "12345", "name": "Updated rule name", "frequency": 60}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.list_alert_rules"),
                    CapabilityId::from_static("sentry.create_alert_rule"),
                ],
            },
        ),
        op_info(
            "sentry.delete_alert_rule",
            "Delete an alert rule",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug", "rule_id"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" },
                    "rule_id": { "type": "string", "description": "Alert rule ID to delete" }
                }
            }),
            json!({ "type": "object" }),
            "sentry.admin",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Permanently delete an alert rule. Cannot be undone.".into(),
                common_mistakes: vec![
                    "Deleting rules that should be disabled instead (no disable API — consider updating conditions).".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend", "rule_id": "12345"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.list_alert_rules"),
                    CapabilityId::from_static("sentry.create_alert_rule"),
                ],
            },
        ),
        op_info(
            "sentry.issue.search",
            "Search issues with structured filters",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" },
                    "query": { "type": "string", "description": "Free-text search query" },
                    "status": { "type": "string", "enum": ["unresolved", "resolved", "ignored"], "description": "Filter by issue status" },
                    "assigned_to": { "type": "string", "description": "Filter by assignee (email or 'team:slug')" },
                    "level": { "type": "string", "enum": ["error", "warning", "info", "fatal"], "description": "Filter by error level" },
                    "first_seen_start": { "type": "string", "description": "ISO 8601 date — issues first seen after this date" },
                    "first_seen_end": { "type": "string", "description": "ISO 8601 date — issues first seen before this date" },
                    "sort": { "type": "string", "description": "Sort order (date, new, priority, freq, user)" },
                    "cursor": { "type": "string", "description": "Pagination cursor" },
                    "per_page": { "type": "integer", "minimum": 1, "maximum": 100, "description": "Results per page (max 100)" }
                }
            }),
            json!({
                "type": "object",
                "required": ["issues"],
                "properties": {
                    "issues": { "type": "array", "description": "Matching issue objects", "items": { "type": "object" } }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Search Sentry issues with structured filters. More ergonomic than list_issues for filtered searches.".into(),
                common_mistakes: vec![
                    "Using raw Sentry search syntax instead of the structured filter parameters.".into(),
                    "Not using cursor-based pagination for large result sets.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend", "status": "unresolved", "level": "error", "sort": "priority"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.list_issues"),
                    CapabilityId::from_static("sentry.get_issue"),
                    CapabilityId::from_static("sentry.issue.get_summary"),
                ],
            },
        ),
        op_info(
            "sentry.issue.get_summary",
            "Get a concise summary of a Sentry issue",
            json!({
                "type": "object",
                "required": ["issue_id"],
                "properties": {
                    "issue_id": { "type": "string", "description": "Sentry issue ID" }
                }
            }),
            json!({
                "type": "object",
                "required": ["summary"],
                "properties": {
                    "summary": { "type": "object", "description": "Concise issue summary (id, title, status, level, count, userCount, firstSeen, lastSeen, assignedTo, shortId)" }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get a concise summary of a Sentry issue without full event data. Useful for dashboards and quick triage.".into(),
                common_mistakes: vec![
                    "Using get_issue when only summary metadata is needed (get_issue returns much more data).".into(),
                ],
                examples: vec![
                    r#"{"issue_id": "1234567890"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.get_issue"),
                    CapabilityId::from_static("sentry.issue.search"),
                    CapabilityId::from_static("sentry.list_issues"),
                ],
            },
        ),
        op_info(
            "sentry.issue.assign",
            "Assign or unassign a Sentry issue",
            json!({
                "type": "object",
                "required": ["issue_id"],
                "properties": {
                    "issue_id": { "type": "string", "description": "Sentry issue ID" },
                    "assignee": { "type": "string", "description": "User email or team slug to assign; null/omitted to unassign" }
                }
            }),
            json!({
                "type": "object",
                "required": ["issue"],
                "properties": {
                    "issue": { "type": "object", "description": "Updated issue object" }
                }
            }),
            "sentry.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Assign a Sentry issue to a user or team. Pass null assignee to unassign.".into(),
                common_mistakes: vec![
                    "Using display name instead of email or 'team:slug' for assignee.".into(),
                ],
                examples: vec![
                    r#"{"issue_id": "1234567890", "assignee": "alice@example.com"}"#.into(),
                    r#"{"issue_id": "1234567890"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.update_issue"),
                    CapabilityId::from_static("sentry.get_issue"),
                ],
            },
        ),
        op_info(
            "sentry.issue.set_status",
            "Set issue status (resolved/unresolved/ignored)",
            json!({
                "type": "object",
                "required": ["issue_id", "status"],
                "properties": {
                    "issue_id": { "type": "string", "description": "Sentry issue ID" },
                    "status": { "type": "string", "enum": ["resolved", "unresolved", "ignored"], "description": "Issue status" },
                    "substatus": { "type": "string", "description": "Issue substatus (e.g., 'ongoing', 'escalating', 'new', 'archived_until_escalating', 'archived_forever', 'archived_until_condition_met')" }
                }
            }),
            json!({
                "type": "object",
                "required": ["issue"],
                "properties": {
                    "issue": { "type": "object", "description": "Updated issue object" }
                }
            }),
            "sentry.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Set issue status. Use 'resolved' to close, 'ignored' to suppress, 'unresolved' to reopen.".into(),
                common_mistakes: vec![
                    "Not specifying substatus when using 'ignored' status (defaults may not match intent).".into(),
                ],
                examples: vec![
                    r#"{"issue_id": "1234567890", "status": "resolved"}"#.into(),
                    r#"{"issue_id": "1234567890", "status": "ignored", "substatus": "archived_until_escalating"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.update_issue"),
                    CapabilityId::from_static("sentry.get_issue"),
                ],
            },
        ),
        op_info(
            "sentry.issue.set_priority",
            "Set issue priority level",
            json!({
                "type": "object",
                "required": ["issue_id", "priority"],
                "properties": {
                    "issue_id": { "type": "string", "description": "Sentry issue ID" },
                    "priority": { "type": "string", "enum": ["critical", "high", "medium", "low"], "description": "Issue priority level" }
                }
            }),
            json!({
                "type": "object",
                "required": ["issue"],
                "properties": {
                    "issue": { "type": "object", "description": "Updated issue object" }
                }
            }),
            "sentry.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Set issue priority level for triage. Affects alerting and SLA tracking.".into(),
                common_mistakes: vec![
                    "Using numeric priority values instead of string names (critical/high/medium/low).".into(),
                ],
                examples: vec![
                    r#"{"issue_id": "1234567890", "priority": "high"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.update_issue"),
                    CapabilityId::from_static("sentry.get_issue"),
                ],
            },
        ),
        op_info(
            "sentry.performance.transactions",
            "Query performance transactions with filters",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" },
                    "transaction": { "type": "string", "description": "Filter by transaction name" },
                    "environment": { "type": "string", "description": "Filter by environment" },
                    "start": { "type": "string", "description": "ISO 8601 start time" },
                    "end": { "type": "string", "description": "ISO 8601 end time" },
                    "sort": { "type": "string", "description": "Sort field with optional - prefix for descending" },
                    "per_page": { "type": "integer", "minimum": 1, "maximum": 100, "description": "Results per page" },
                    "cursor": { "type": "string", "description": "Pagination cursor" }
                }
            }),
            json!({
                "type": "object",
                "required": ["data"],
                "properties": {
                    "data": { "type": "array", "description": "Transaction result rows", "items": { "type": "object" } },
                    "meta": { "type": "object", "description": "Field type metadata" }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Query performance transactions with project, environment, time range, and transaction name filters.".into(),
                common_mistakes: vec![
                    "Not specifying start/end time range — queries without bounds may time out or return too much data.".into(),
                    "Confusing this with get_transaction which fetches a single event by ID.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend", "transaction": "/api/users", "start": "2026-03-01T00:00:00Z", "end": "2026-03-09T00:00:00Z"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.performance.transaction.summary"),
                    CapabilityId::from_static("sentry.discover_query"),
                    CapabilityId::from_static("sentry.get_transaction"),
                ],
            },
        ),
        op_info(
            "sentry.performance.transaction.summary",
            "Get performance summary for a transaction name",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug", "transaction"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" },
                    "transaction": { "type": "string", "description": "Transaction name (e.g., /api/users)" },
                    "environment": { "type": "string", "description": "Filter by environment" },
                    "start": { "type": "string", "description": "ISO 8601 start time" },
                    "end": { "type": "string", "description": "ISO 8601 end time" }
                }
            }),
            json!({
                "type": "object",
                "required": ["data"],
                "properties": {
                    "data": { "type": "array", "description": "Summary rows with percentiles and rates", "items": { "type": "object" } },
                    "meta": { "type": "object", "description": "Field type metadata" }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get aggregated performance summary (p50, p75, p95, p99, throughput, failure rate) for a specific transaction.".into(),
                common_mistakes: vec![
                    "Using a partial transaction name — the name must match exactly as reported by Sentry SDKs.".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend", "transaction": "/api/users"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.performance.transactions"),
                    CapabilityId::from_static("sentry.discover_query"),
                ],
            },
        ),
        op_info(
            "sentry.performance.trace.summary",
            "Get trace summary by trace ID",
            json!({
                "type": "object",
                "required": ["organization_slug", "trace_id"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "trace_id": { "type": "string", "description": "Trace ID (32-character hex string)" }
                }
            }),
            json!({
                "type": "object",
                "required": ["trace"],
                "properties": {
                    "trace": { "type": "object", "description": "Trace summary with span tree" }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve the full trace tree for a distributed trace by trace ID.".into(),
                common_mistakes: vec![
                    "Using a span ID or event ID instead of the trace ID (32-character hex).".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "trace_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.performance.transactions"),
                    CapabilityId::from_static("sentry.get_transaction"),
                ],
            },
        ),
        op_info(
            "sentry.release.health",
            "Get release health summary",
            json!({
                "type": "object",
                "required": ["organization_slug", "project_slug", "version"],
                "properties": {
                    "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                    "project_slug": { "type": "string", "description": "Sentry project slug" },
                    "version": { "type": "string", "description": "Release version identifier" }
                }
            }),
            json!({
                "type": "object",
                "required": ["health"],
                "properties": {
                    "health": { "type": "object", "description": "Release health with sessions, crash-free rate, and adoption metrics" }
                }
            }),
            "sentry.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get release health metrics including session counts, crash-free rate, and adoption percentage.".into(),
                common_mistakes: vec![
                    "Not URL-encoding version strings that contain '@' or '+' characters.".into(),
                    "Querying health for a release with no session data (returns empty metrics).".into(),
                ],
                examples: vec![
                    r#"{"organization_slug": "my-org", "project_slug": "backend", "version": "backend@1.2.3"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("sentry.get_release"),
                    CapabilityId::from_static("sentry.list_releases"),
                ],
            },
        ),
        {
            let mut info = op_info(
                "sentry.release.create",
                "Create a release marker",
                json!({
                    "type": "object",
                    "required": ["organization_slug", "version"],
                    "properties": {
                        "organization_slug": { "type": "string", "description": "Sentry organization slug" },
                        "version": { "type": "string", "description": "Release version identifier (e.g., 'backend@1.2.3')" },
                        "projects": { "type": "array", "items": { "type": "string" }, "description": "Project slugs to associate with this release" },
                        "ref": { "type": "string", "description": "Git ref (commit SHA or tag)" },
                        "url": { "type": "string", "description": "URL for the release (e.g., CI build link)" }
                    }
                }),
                json!({
                    "type": "object",
                    "required": ["release"],
                    "properties": {
                        "release": { "type": "object", "description": "Created release object" }
                    }
                }),
                "sentry.write",
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                AgentHint {
                    when_to_use: "Create a new release marker in Sentry to track deployments and correlate errors.".into(),
                    common_mistakes: vec![
                        "Not associating the release with projects — the release won't appear in project views.".into(),
                        "Using duplicate version strings — Sentry treats version as a unique identifier per org.".into(),
                    ],
                    examples: vec![
                        r#"{"organization_slug": "my-org", "version": "backend@1.3.0", "projects": ["backend"], "ref": "abc123def"}"#.into(),
                    ],
                    related: vec![
                        CapabilityId::from_static("sentry.list_releases"),
                        CapabilityId::from_static("sentry.get_release"),
                        CapabilityId::from_static("sentry.release.health"),
                    ],
                },
            );
            info.requires_approval = Some(ApprovalMode::Policy);
            info
        },
    ]
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

    /// Helper: serialize `operations_info` to JSON for test assertions.
    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn operations_info_has_26_operations() {
        let ops = ops_json();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 26);
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
    fn read_operations_are_safe() {
        let ops = ops_json();
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
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = ops_json();
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
        let ops = ops_json();
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

    #[test]
    fn operations_admin_capability_for_dangerous_ops() {
        for op in ops_json().as_array().unwrap() {
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

    #[test]
    fn require_str_nested_object() {
        let input = json!({"org": {"nested": true}});
        assert!(require_str(&input, "org").is_err());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_check_clone_and_debug() {
        let check = DoctorCheck {
            name: "config".into(),
            passed: true,
            message: Some("good".into()),
            critical: true,
        };
        let cloned = check.clone();
        assert_eq!(check.name, "config");
        assert_eq!(cloned.message, Some("good".into()));
        assert!(cloned.critical);
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn operations_create_alert_rule_not_idempotent() {
        let ops = ops_json();
        let create_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "sentry.create_alert_rule")
            .unwrap();
        assert_eq!(create_op["idempotency"].as_str().unwrap(), "none");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "c1".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn doctor_status_debug_format() {
        let dbg = format!("{:?}", DoctorStatus::Unhealthy);
        assert!(dbg.contains("Unhealthy"));
        let dbg2 = format!("{:?}", DoctorStatus::Degraded);
        assert!(dbg2.contains("Degraded"));
    }
}
