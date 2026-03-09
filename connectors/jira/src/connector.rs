//! FCP Jira Connector implementation.

use std::sync::Arc;

use base64::Engine;
use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::client::{JiraAuth, JiraClient};
use crate::error::JiraError;

/// Parsed configuration for the Jira connector.
struct JiraConfig {
    auth: JiraAuth,
    base_url: Option<String>,
    agile_url: Option<String>,
    automation_url: Option<String>,
}

impl JiraConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let domain =
            params
                .get("domain")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing domain in configuration".into(),
                })?;

        let email = params.get("email").and_then(|v| v.as_str());
        let api_token = params.get("api_token").and_then(|v| v.as_str());
        let credential_id = params.get("credential_id").and_then(|v| v.as_str());
        let base_url = params.get("base_url").and_then(|v| v.as_str());
        let agile_url = params.get("agile_url").and_then(|v| v.as_str());
        let automation_url = params.get("automation_url").and_then(|v| v.as_str());

        let auth = match (email, api_token, credential_id) {
            (Some(_), Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide either email+api_token or credential_id, not both".into(),
                });
            }
            (_, Some(_), Some(_)) | (Some(_), None, Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide either email+api_token or credential_id, not both".into(),
                });
            }
            (Some(e), Some(t), None) => JiraAuth::Token {
                domain: domain.to_string(),
                email: e.to_string(),
                api_token: t.to_string(),
            },
            (None, None, Some(raw)) => {
                let cid = CredentialId::parse(raw).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid credential_id: {e}"),
                })?;
                JiraAuth::CredentialId {
                    domain: domain.to_string(),
                    credential_id: cid,
                }
            }
            (Some(_), None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "email provided without api_token".into(),
                });
            }
            (None, Some(_), None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "api_token provided without email".into(),
                });
            }
            (None, None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing email+api_token or credential_id in configuration".into(),
                });
            }
        };

        Ok(Self {
            auth,
            base_url: base_url.map(String::from),
            agile_url: agile_url.map(String::from),
            automation_url: automation_url.map(String::from),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: String,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Pass,
    Fail,
    Warn,
}

/// FCP Jira Connector.
pub struct JiraConnector {
    base: Arc<BaseConnector>,
    pub(crate) client: Option<JiraClient>,
    config: Option<JiraConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl JiraConnector {
    /// Create a new Jira connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("jira"))),
            client: None,
            config: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let cfg = JiraConfig::from_params(&params)?;

        let mut client =
            JiraClient::new_with_auth(cfg.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        if let Some(url) = &cfg.base_url {
            client = client.with_base_url(url);
        }
        if let Some(url) = &cfg.agile_url {
            client = client.with_agile_url(url);
        }
        if let Some(url) = &cfg.automation_url {
            client = client.with_automation_url(url);
        }

        self.client = Some(client);
        self.config = Some(cfg);
        self.base.set_configured(true);
        info!("Jira connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:jira-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 50,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let auth_mode = self
            .config
            .as_ref()
            .map_or("none", |c| c.auth.redacted_label());
        let api_domain = self
            .config
            .as_ref()
            .map_or("not_configured", |c| c.auth.domain());
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "auth_mode": auth_mode,
            "api_domain": api_domain,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle doctor readiness diagnostics.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. configuration
        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            status: if configured {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if configured {
                "Connector configured".into()
            } else {
                "Not configured — call configure first".into()
            },
        });

        // 2. client_initialized
        let has_client = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            status: if has_client {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if has_client {
                "HTTP client ready".into()
            } else {
                "HTTP client not initialized".into()
            },
        });

        // 3. base_url
        let domain = self
            .config
            .as_ref()
            .map_or("not_configured", |c| c.auth.domain());
        checks.push(DoctorCheck {
            name: "base_url".into(),
            status: DoctorStatus::Pass,
            message: format!("Domain: {domain}.atlassian.net"),
        });

        // 4. auth_mode
        if let Some(cfg) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Pass,
                message: format!("Auth: {}", cfg.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Fail,
                message: "No auth configured".into(),
            });
        }

        // 5. network_constraints
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Pass,
            message: format!("Egress target: {domain}.atlassian.net"),
        });

        // 6. credential_injection
        let is_secretless = self.config.as_ref().is_some_and(|c| c.auth.is_secretless());
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            status: if is_secretless {
                DoctorStatus::Warn
            } else {
                DoctorStatus::Pass
            },
            message: if is_secretless {
                "Using credential_id — requires egress proxy for injection".into()
            } else {
                "Direct Basic auth — no proxy required".into()
            },
        });

        let all_pass = checks
            .iter()
            .all(|c| matches!(c.status, DoctorStatus::Pass));
        let any_fail = checks
            .iter()
            .any(|c| matches!(c.status, DoctorStatus::Fail));

        let overall = if any_fail {
            "unhealthy"
        } else if all_pass {
            "healthy"
        } else {
            "degraded"
        };

        let result = DoctorResult {
            status: overall.into(),
            checks,
        };
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(cfg) = &self.config else {
            let report = SelfCheckReport::failed("not_configured", "Call configure first");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        };

        if cfg.auth.is_secretless() {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Secretless mode — cannot verify connectivity without egress proxy",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        }

        let Some(client) = &self.client else {
            let report = SelfCheckReport::failed("client_missing", "HTTP client not initialized");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        };

        match client.health_check().await {
            Ok(_) => {
                let report = SelfCheckReport::ok();
                serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check: {e}"),
                })
            }
            Err(e) => {
                let report =
                    SelfCheckReport::failed("connectivity_failed", format!("API call failed: {e}"));
                serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check: {e}"),
                })
            }
        }
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                // ── Issue CRUD ───────────────────────────────────────
                op_info(
                    "jira.create_issue",
                    "Create a new Jira issue",
                    json!({
                        "type": "object",
                        "required": ["project_key", "issue_type", "summary"],
                        "properties": {
                            "project_key": { "type": "string" },
                            "issue_type": { "type": "string" },
                            "summary": { "type": "string" },
                            "description": { "type": "string" },
                            "priority": { "type": "string" },
                            "assignee": { "type": "string" },
                            "labels": { "type": "array", "items": { "type": "string" } },
                            "components": { "type": "array", "items": { "type": "string" } },
                            "custom_fields": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "key": { "type": "string" },
                            "self": { "type": "string" }
                        }
                    }),
                    "jira.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new issue in a Jira project.".into(),
                        common_mistakes: vec![
                            "Using project name instead of project key.".into(),
                        ],
                        examples: vec![
                            r#"{"project_key": "PROJ", "issue_type": "Story", "summary": "Implement login flow"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.get_issue"),
                            CapabilityId::from_static("jira.search_jql"),
                        ],
                    },
                ),
                op_info(
                    "jira.get_issue",
                    "Get a Jira issue by key or ID",
                    json!({
                        "type": "object",
                        "required": ["issue_key"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "fields": { "type": "string" },
                            "expand": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "key": { "type": "string" },
                            "fields": { "type": "object" },
                            "changelog": { "type": "object" }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a specific Jira issue by its key (e.g., PROJ-123).".into(),
                        common_mistakes: vec![
                            "Using issue summary instead of issue key.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "fields": "summary,status,assignee"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.update_issue"),
                            CapabilityId::from_static("jira.search_jql"),
                        ],
                    },
                ),
                op_info(
                    "jira.update_issue",
                    "Update fields on an existing Jira issue",
                    json!({
                        "type": "object",
                        "required": ["issue_key", "fields"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "fields": { "type": "object" },
                            "notify_users": { "type": "boolean" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "jira.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Modify specific fields on an existing issue.".into(),
                        common_mistakes: vec![
                            "Using field names instead of field IDs for custom fields.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "fields": {"summary": "Updated title"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.get_issue"),
                            CapabilityId::from_static("jira.transition_issue"),
                        ],
                    },
                ),
                op_info(
                    "jira.delete_issue",
                    "Delete a Jira issue (irreversible)",
                    json!({
                        "type": "object",
                        "required": ["issue_key"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "delete_subtasks": { "type": "boolean" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "jira.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Permanently delete a Jira issue. This cannot be undone.".into(),
                        common_mistakes: vec![
                            "Deleting issues with subtasks without setting delete_subtasks=true.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "delete_subtasks": true}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("jira.get_issue")],
                    },
                ),
                // ── Search ───────────────────────────────────────────
                op_info(
                    "jira.search_jql",
                    "Search issues via JQL",
                    json!({
                        "type": "object",
                        "required": ["jql"],
                        "properties": {
                            "jql": { "type": "string" },
                            "fields": { "type": "string" },
                            "max_results": { "type": "integer" },
                            "start_at": { "type": "integer" },
                            "expand": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "issues": { "type": "array" },
                            "total": { "type": "integer" },
                            "max_results": { "type": "integer" },
                            "start_at": { "type": "integer" }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for issues using JQL.".into(),
                        common_mistakes: vec![
                            "Using SQL syntax instead of JQL syntax.".into(),
                        ],
                        examples: vec![
                            r#"{"jql": "project = PROJ AND status = Open ORDER BY created DESC", "max_results": 25}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.get_issue"),
                            CapabilityId::from_static("jira.create_issue"),
                        ],
                    },
                ),
                // ── Transitions ──────────────────────────────────────
                op_info(
                    "jira.list_transitions",
                    "List available workflow transitions for an issue",
                    json!({
                        "type": "object",
                        "required": ["issue_key"],
                        "properties": {
                            "issue_key": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "transitions": { "type": "array" }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Check which status transitions are available before transitioning.".into(),
                        common_mistakes: vec![
                            "Assuming transition IDs are stable across projects.".into(),
                        ],
                        examples: vec![r#"{"issue_key": "PROJ-123"}"#.into()],
                        related: vec![CapabilityId::from_static("jira.transition_issue")],
                    },
                ),
                op_info(
                    "jira.transition_issue",
                    "Execute a workflow transition on an issue",
                    json!({
                        "type": "object",
                        "required": ["issue_key", "transition_id"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "transition_id": { "type": "string" },
                            "fields": { "type": "object" },
                            "comment": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "jira.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Change an issue's workflow status. Call list_transitions first.".into(),
                        common_mistakes: vec![
                            "Using a transition ID without checking list_transitions first.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "transition_id": "31"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.list_transitions"),
                            CapabilityId::from_static("jira.get_issue"),
                        ],
                    },
                ),
                // ── Sprint ───────────────────────────────────────────
                op_info(
                    "jira.list_sprints",
                    "List sprints for a Scrum board",
                    json!({
                        "type": "object",
                        "required": ["board_id"],
                        "properties": {
                            "board_id": { "type": "integer" },
                            "state": { "type": "string" },
                            "start_at": { "type": "integer" },
                            "max_results": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "values": { "type": "array" },
                            "is_last": { "type": "boolean" }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List sprints for a Scrum board. Filter by state.".into(),
                        common_mistakes: vec![
                            "Using project key instead of board ID.".into(),
                        ],
                        examples: vec![r#"{"board_id": 42, "state": "active"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("jira.move_to_sprint"),
                            CapabilityId::from_static("jira.search_jql"),
                        ],
                    },
                ),
                op_info(
                    "jira.move_to_sprint",
                    "Move issues into a sprint",
                    json!({
                        "type": "object",
                        "required": ["sprint_id", "issues"],
                        "properties": {
                            "sprint_id": { "type": "integer" },
                            "issues": { "type": "array", "items": { "type": "string" } }
                        }
                    }),
                    json!({ "type": "object" }),
                    "jira.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Add issues to a sprint. Use list_sprints first.".into(),
                        common_mistakes: vec![
                            "Trying to move issues to a closed sprint.".into(),
                        ],
                        examples: vec![
                            r#"{"sprint_id": 42, "issues": ["PROJ-100", "PROJ-101"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.list_sprints"),
                            CapabilityId::from_static("jira.search_jql"),
                        ],
                    },
                ),
                // ── Comments ─────────────────────────────────────────
                op_info(
                    "jira.add_comment",
                    "Add a comment to an issue",
                    json!({
                        "type": "object",
                        "required": ["issue_key", "body"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "body": { "type": "string" },
                            "visibility": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "body": { "type": "object" },
                            "created": { "type": "string" },
                            "author": { "type": "object" }
                        }
                    }),
                    "jira.write",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Add a comment to an existing issue.".into(),
                        common_mistakes: vec![
                            "Passing raw Markdown — Jira Cloud API v3 expects ADF.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "body": "Build passed, merging now."}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.list_comments"),
                            CapabilityId::from_static("jira.get_issue"),
                        ],
                    },
                ),
                op_info(
                    "jira.list_comments",
                    "List comments on an issue",
                    json!({
                        "type": "object",
                        "required": ["issue_key"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "start_at": { "type": "integer" },
                            "max_results": { "type": "integer" },
                            "order_by": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "comments": { "type": "array" },
                            "total": { "type": "integer" },
                            "start_at": { "type": "integer" },
                            "max_results": { "type": "integer" }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve comments on an issue.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "max_results": 20, "order_by": "-created"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.add_comment"),
                            CapabilityId::from_static("jira.get_issue"),
                        ],
                    },
                ),
                // ── Worklogs ────────────────────────────────────────
                op_info(
                    "jira.worklog.list",
                    "List worklogs for an issue",
                    json!({
                        "type": "object",
                        "required": ["issue_key"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "start_at": { "type": "integer" },
                            "max_results": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "worklogs": { "type": "array" },
                            "total": { "type": "integer" },
                            "start_at": { "type": "integer" },
                            "max_results": { "type": "integer" }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List time tracking worklogs on a Jira issue.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "max_results": 50}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.worklog.add"),
                            CapabilityId::from_static("jira.get_issue"),
                        ],
                    },
                ),
                op_info(
                    "jira.worklog.add",
                    "Add a worklog entry to an issue",
                    json!({
                        "type": "object",
                        "required": ["issue_key", "time_spent_seconds"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "time_spent_seconds": { "type": "integer" },
                            "started": { "type": "string" },
                            "comment": { "type": "string" },
                            "visibility": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "timeSpent": { "type": "string" },
                            "timeSpentSeconds": { "type": "integer" },
                            "started": { "type": "string" }
                        }
                    }),
                    "jira.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Log time spent working on a Jira issue.".into(),
                        common_mistakes: vec![
                            "Providing time_spent string instead of time_spent_seconds integer.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "time_spent_seconds": 7200, "started": "2026-03-01T09:00:00.000+0000"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.worklog.list"),
                            CapabilityId::from_static("jira.worklog.update"),
                        ],
                    },
                ),
                op_info(
                    "jira.worklog.update",
                    "Update an existing worklog entry",
                    json!({
                        "type": "object",
                        "required": ["issue_key", "worklog_id"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "worklog_id": { "type": "string" },
                            "time_spent_seconds": { "type": "integer" },
                            "started": { "type": "string" },
                            "comment": { "type": "string" },
                            "visibility": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "timeSpent": { "type": "string" },
                            "timeSpentSeconds": { "type": "integer" }
                        }
                    }),
                    "jira.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Modify an existing worklog entry (e.g. correct logged time).".into(),
                        common_mistakes: vec![
                            "Using issue key as worklog_id. worklog_id is a separate numeric ID.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "worklog_id": "100028", "time_spent_seconds": 10800}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.worklog.list"),
                            CapabilityId::from_static("jira.worklog.add"),
                        ],
                    },
                ),
                op_info(
                    "jira.worklog.delete",
                    "Delete a worklog entry (irreversible)",
                    json!({
                        "type": "object",
                        "required": ["issue_key", "worklog_id"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "worklog_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "jira.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Permanently delete a worklog entry. Cannot be undone.".into(),
                        common_mistakes: vec![
                            "Deleting worklogs without checking worklog.list first.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "worklog_id": "100028"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.worklog.list"),
                        ],
                    },
                ),
                // ── Attachments ──────────────────────────────────────
                op_info(
                    "jira.add_attachment",
                    "Upload a file attachment to an issue",
                    json!({
                        "type": "object",
                        "required": ["issue_key", "filename", "data"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "filename": { "type": "string" },
                            "data": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "attachments": { "type": "array" }
                        }
                    }),
                    "jira.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Attach a file to a Jira issue. Files must be base64-encoded.".into(),
                        common_mistakes: vec![
                            "Not base64-encoding the file data.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "filename": "screenshot.png", "data": "<base64>"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.get_issue"),
                            CapabilityId::from_static("jira.add_comment"),
                        ],
                    },
                ),
                // ── Automation Rules ────────────────────────────────────
                op_info(
                    "jira.automation.rule.list",
                    "List automation rules for a project",
                    json!({
                        "type": "object",
                        "required": ["project_id"],
                        "properties": {
                            "project_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "rules": { "type": "array" },
                            "total": { "type": "integer" }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all automation rules configured for a Jira project.".into(),
                        common_mistakes: vec![
                            "Using project key instead of numeric project ID.".into(),
                        ],
                        examples: vec![
                            r#"{"project_id": "10001"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.automation.rule.get"),
                            CapabilityId::from_static("jira.automation.rule.create"),
                        ],
                    },
                ),
                op_info(
                    "jira.automation.rule.get",
                    "Get an automation rule definition and status",
                    json!({
                        "type": "object",
                        "required": ["rule_id"],
                        "properties": {
                            "rule_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "integer" },
                            "name": { "type": "string" },
                            "state": { "type": "string" },
                            "enabled": { "type": "boolean" },
                            "trigger": { "type": "object" },
                            "conditions": { "type": "array" },
                            "actions": { "type": "array" }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve the definition, trigger, conditions, and actions of a specific automation rule.".into(),
                        common_mistakes: vec![
                            "Using rule name instead of numeric rule ID.".into(),
                        ],
                        examples: vec![
                            r#"{"rule_id": "42"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.automation.rule.list"),
                            CapabilityId::from_static("jira.automation.rule.update"),
                        ],
                    },
                ),
                op_info(
                    "jira.automation.rule.create",
                    "Create a new automation rule (requires approval)",
                    json!({
                        "type": "object",
                        "required": ["project_id", "name", "trigger", "actions"],
                        "properties": {
                            "project_id": { "type": "string" },
                            "name": { "type": "string" },
                            "description": { "type": "string" },
                            "trigger": { "type": "object" },
                            "conditions": { "type": "array" },
                            "actions": { "type": "array" },
                            "tags": { "type": "array", "items": { "type": "string" } },
                            "enabled": { "type": "boolean" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "integer" },
                            "name": { "type": "string" },
                            "state": { "type": "string" },
                            "enabled": { "type": "boolean" }
                        }
                    }),
                    "jira.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new automation rule. Rules can auto-transition issues, send notifications, and mutate data.".into(),
                        common_mistakes: vec![
                            "Creating rules without proper conditions, which may trigger on every issue.".into(),
                            "Using project key instead of numeric project ID.".into(),
                        ],
                        examples: vec![
                            r#"{"project_id": "10001", "name": "Auto-assign on create", "trigger": {"type": "jira.issue.created"}, "actions": [{"type": "jira.issue.assign", "value": {"accountId": "abc123"}}]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.automation.rule.list"),
                            CapabilityId::from_static("jira.automation.rule.update"),
                        ],
                    },
                ),
                op_info(
                    "jira.automation.rule.update",
                    "Update an existing automation rule",
                    json!({
                        "type": "object",
                        "required": ["rule_id"],
                        "properties": {
                            "rule_id": { "type": "string" },
                            "name": { "type": "string" },
                            "description": { "type": "string" },
                            "trigger": { "type": "object" },
                            "conditions": { "type": "array" },
                            "actions": { "type": "array" },
                            "tags": { "type": "array", "items": { "type": "string" } }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "integer" },
                            "name": { "type": "string" },
                            "state": { "type": "string" },
                            "enabled": { "type": "boolean" }
                        }
                    }),
                    "jira.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Modify an existing automation rule's trigger, conditions, or actions.".into(),
                        common_mistakes: vec![
                            "Removing conditions from an existing rule, causing unintended mass triggers.".into(),
                        ],
                        examples: vec![
                            r#"{"rule_id": "42", "name": "Updated rule name", "actions": [{"type": "jira.issue.transition", "value": {"transitionId": "5"}}]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.automation.rule.get"),
                            CapabilityId::from_static("jira.automation.rule.list"),
                        ],
                    },
                ),
                op_info(
                    "jira.automation.rule.enable",
                    "Enable a disabled automation rule",
                    json!({
                        "type": "object",
                        "required": ["rule_id"],
                        "properties": {
                            "rule_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "jira.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Re-enable a previously disabled automation rule. The rule will start firing on its trigger.".into(),
                        common_mistakes: vec![
                            "Enabling rules without reviewing their conditions first.".into(),
                        ],
                        examples: vec![
                            r#"{"rule_id": "42"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.automation.rule.get"),
                            CapabilityId::from_static("jira.automation.rule.disable"),
                        ],
                    },
                ),
                op_info(
                    "jira.automation.rule.disable",
                    "Disable an enabled automation rule",
                    json!({
                        "type": "object",
                        "required": ["rule_id"],
                        "properties": {
                            "rule_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "jira.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Disable an automation rule so it stops firing. Use before modifying rules in production.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"rule_id": "42"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.automation.rule.get"),
                            CapabilityId::from_static("jira.automation.rule.enable"),
                        ],
                    },
                ),
                op_info(
                    "jira.automation.rule.delete",
                    "Delete an automation rule (irreversible)",
                    json!({
                        "type": "object",
                        "required": ["rule_id"],
                        "properties": {
                            "rule_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "jira.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Permanently delete an automation rule. Cannot be undone.".into(),
                        common_mistakes: vec![
                            "Deleting rules without disabling them first.".into(),
                        ],
                        examples: vec![
                            r#"{"rule_id": "42"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.automation.rule.list"),
                            CapabilityId::from_static("jira.automation.rule.disable"),
                        ],
                    },
                ),
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

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "jira.create_issue" => self.invoke_create_issue(input).await,
            "jira.get_issue" => self.invoke_get_issue(input).await,
            "jira.update_issue" => self.invoke_update_issue(input).await,
            "jira.delete_issue" => self.invoke_delete_issue(input).await,
            "jira.search_jql" => self.invoke_search_jql(input).await,
            "jira.list_transitions" => self.invoke_list_transitions(input).await,
            "jira.transition_issue" => self.invoke_transition_issue(input).await,
            "jira.list_sprints" => self.invoke_list_sprints(input).await,
            "jira.move_to_sprint" => self.invoke_move_to_sprint(input).await,
            "jira.add_comment" => self.invoke_add_comment(input).await,
            "jira.list_comments" => self.invoke_list_comments(input).await,
            "jira.worklog.list" => self.invoke_list_worklogs(input).await,
            "jira.worklog.add" => self.invoke_add_worklog(input).await,
            "jira.worklog.update" => self.invoke_update_worklog(input).await,
            "jira.worklog.delete" => self.invoke_delete_worklog(input).await,
            "jira.add_attachment" => self.invoke_add_attachment(input).await,
            "jira.automation.rule.list" => self.invoke_list_automation_rules(input).await,
            "jira.automation.rule.get" => self.invoke_get_automation_rule(input).await,
            "jira.automation.rule.create" => self.invoke_create_automation_rule(input).await,
            "jira.automation.rule.update" => self.invoke_update_automation_rule(input).await,
            "jira.automation.rule.enable" => self.invoke_enable_automation_rule(input).await,
            "jira.automation.rule.disable" => self.invoke_disable_automation_rule(input).await,
            "jira.automation.rule.delete" => self.invoke_delete_automation_rule(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let project_key = require_str(&input, "project_key")?;
        let issue_type = require_str(&input, "issue_type")?;
        let summary = require_str(&input, "summary")?;

        let mut fields = json!({
            "project": { "key": project_key },
            "issuetype": { "name": issue_type },
            "summary": summary,
        });

        if let Some(desc) = input.get("description").and_then(|v| v.as_str()) {
            fields["description"] = json!(desc);
        }
        if let Some(priority) = input.get("priority").and_then(|v| v.as_str()) {
            fields["priority"] = json!({ "name": priority });
        }
        if let Some(assignee) = input.get("assignee").and_then(|v| v.as_str()) {
            fields["assignee"] = json!({ "accountId": assignee });
        }
        if let Some(labels) = input.get("labels").and_then(|v| v.as_array()) {
            fields["labels"] = json!(labels);
        }
        if let Some(components) = input.get("components").and_then(|v| v.as_array()) {
            let comp_objs: Vec<serde_json::Value> = components
                .iter()
                .filter_map(|c| c.as_str().map(|s| json!({ "name": s })))
                .collect();
            fields["components"] = json!(comp_objs);
        }
        if let Some(custom) = input.get("custom_fields").and_then(|v| v.as_object()) {
            for (k, v) in custom {
                fields[k] = v.clone();
            }
        }

        let body = json!({ "fields": fields });
        let resp = client
            .create_issue(&body)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        Ok(json!({
            "id": resp.id,
            "key": resp.key,
            "self": resp.self_url,
        }))
    }

    async fn invoke_get_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let fields = input.get("fields").and_then(|v| v.as_str());
        let expand = input.get("expand").and_then(|v| v.as_str());

        let resp = client
            .get_issue(issue_key, fields, expand)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_update_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let fields = input.get("fields").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: fields".into(),
        })?;
        let notify_users = input
            .get("notify_users")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let body = json!({ "fields": fields });
        client
            .update_issue(issue_key, &body, notify_users)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        Ok(json!({ "updated": true }))
    }

    async fn invoke_delete_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let delete_subtasks = input
            .get("delete_subtasks")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        client
            .delete_issue(issue_key, delete_subtasks)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_search_jql(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let jql = require_str(&input, "jql")?;

        let mut body = json!({ "jql": jql });
        if let Some(fields) = input.get("fields").and_then(|v| v.as_str()) {
            body["fields"] = json!(fields.split(',').collect::<Vec<_>>());
        }
        if let Some(max_results) = input.get("max_results").and_then(|v| v.as_u64()) {
            body["maxResults"] = json!(max_results);
        }
        if let Some(start_at) = input.get("start_at").and_then(|v| v.as_u64()) {
            body["startAt"] = json!(start_at);
        }
        if let Some(expand) = input.get("expand").and_then(|v| v.as_str()) {
            body["expand"] = json!(expand.split(',').collect::<Vec<_>>());
        }

        let resp = client
            .search_jql(&body)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_transitions(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;

        let resp = client
            .list_transitions(issue_key)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_transition_issue(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let transition_id = require_str(&input, "transition_id")?;

        let mut body = json!({
            "transition": { "id": transition_id }
        });
        if let Some(fields) = input.get("fields") {
            body["fields"] = fields.clone();
        }
        if let Some(comment) = input.get("comment").and_then(|v| v.as_str()) {
            body["update"] = json!({
                "comment": [{
                    "add": { "body": comment }
                }]
            });
        }

        client
            .transition_issue(issue_key, &body)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        Ok(json!({ "transitioned": true }))
    }

    async fn invoke_list_sprints(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let board_id =
            input
                .get("board_id")
                .and_then(|v| v.as_u64())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: board_id".into(),
                })?;
        let state = input.get("state").and_then(|v| v.as_str());
        let start_at = input.get("start_at").and_then(|v| v.as_u64());
        let max_results = input.get("max_results").and_then(|v| v.as_u64());

        let resp = client
            .list_sprints(board_id, state, start_at, max_results)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_move_to_sprint(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let sprint_id =
            input
                .get("sprint_id")
                .and_then(|v| v.as_u64())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: sprint_id".into(),
                })?;
        let issues =
            input
                .get("issues")
                .and_then(|v| v.as_array())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: issues".into(),
                })?;

        let body = json!({ "issues": issues });
        client
            .move_to_sprint(sprint_id, &body)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        Ok(json!({ "moved": true }))
    }

    async fn invoke_add_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let body_text = require_str(&input, "body")?;

        let mut comment_body = json!({ "body": body_text });
        if let Some(visibility) = input.get("visibility") {
            comment_body["visibility"] = visibility.clone();
        }

        let resp = client
            .add_comment(issue_key, &comment_body)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_comments(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let start_at = input.get("start_at").and_then(|v| v.as_u64());
        let max_results = input.get("max_results").and_then(|v| v.as_u64());
        let order_by = input.get("order_by").and_then(|v| v.as_str());

        let resp = client
            .list_comments(issue_key, start_at, max_results, order_by)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_worklogs(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let start_at = input.get("start_at").and_then(|v| v.as_u64());
        let max_results = input.get("max_results").and_then(|v| v.as_u64());

        let resp = client
            .list_worklogs(issue_key, start_at, max_results)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_add_worklog(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let time_spent_seconds =
            input
                .get("time_spent_seconds")
                .and_then(|v| v.as_u64())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: time_spent_seconds".into(),
                })?;

        let mut body = json!({ "timeSpentSeconds": time_spent_seconds });
        if let Some(started) = input.get("started").and_then(|v| v.as_str()) {
            body["started"] = json!(started);
        }
        if let Some(comment) = input.get("comment").and_then(|v| v.as_str()) {
            body["comment"] = json!(comment);
        }
        if let Some(visibility) = input.get("visibility") {
            body["visibility"] = visibility.clone();
        }

        let resp = client
            .add_worklog(issue_key, &body)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_update_worklog(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let worklog_id = require_str(&input, "worklog_id")?;

        let mut body = json!({});
        if let Some(seconds) = input.get("time_spent_seconds").and_then(|v| v.as_u64()) {
            body["timeSpentSeconds"] = json!(seconds);
        }
        if let Some(started) = input.get("started").and_then(|v| v.as_str()) {
            body["started"] = json!(started);
        }
        if let Some(comment) = input.get("comment").and_then(|v| v.as_str()) {
            body["comment"] = json!(comment);
        }
        if let Some(visibility) = input.get("visibility") {
            body["visibility"] = visibility.clone();
        }

        let resp = client
            .update_worklog(issue_key, worklog_id, &body)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_delete_worklog(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let worklog_id = require_str(&input, "worklog_id")?;

        client
            .delete_worklog(issue_key, worklog_id)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_add_attachment(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_key = require_str(&input, "issue_key")?;
        let filename = require_str(&input, "filename")?;
        let data_b64 = require_str(&input, "data")?;

        let data = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid base64 data: {e}"),
            })?;

        let resp = client
            .add_attachment(issue_key, filename, &data)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(json!({ "attachments": resp })).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    // ── Automation Rule operation implementations ─────────────────

    async fn invoke_list_automation_rules(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let project_id = require_str(&input, "project_id")?;

        let resp = client
            .list_automation_rules(project_id)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_get_automation_rule(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let rule_id = require_str(&input, "rule_id")?;

        let resp = client
            .get_automation_rule(rule_id)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_create_automation_rule(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let project_id = require_str(&input, "project_id")?;
        let name = require_str(&input, "name")?;

        let trigger = input.get("trigger").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: trigger".into(),
        })?;
        let actions = input.get("actions").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: actions".into(),
        })?;

        let mut body = json!({
            "name": name,
            "trigger": trigger,
            "actions": actions,
        });
        if let Some(desc) = input.get("description").and_then(|v| v.as_str()) {
            body["description"] = json!(desc);
        }
        if let Some(conditions) = input.get("conditions") {
            body["conditions"] = conditions.clone();
        }
        if let Some(tags) = input.get("tags") {
            body["tags"] = tags.clone();
        }
        if let Some(enabled) = input.get("enabled").and_then(|v| v.as_bool()) {
            body["enabled"] = json!(enabled);
        }

        let resp = client
            .create_automation_rule(project_id, &body)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_update_automation_rule(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let rule_id = require_str(&input, "rule_id")?;

        let mut body = json!({});
        if let Some(name) = input.get("name").and_then(|v| v.as_str()) {
            body["name"] = json!(name);
        }
        if let Some(desc) = input.get("description").and_then(|v| v.as_str()) {
            body["description"] = json!(desc);
        }
        if let Some(trigger) = input.get("trigger") {
            body["trigger"] = trigger.clone();
        }
        if let Some(conditions) = input.get("conditions") {
            body["conditions"] = conditions.clone();
        }
        if let Some(actions) = input.get("actions") {
            body["actions"] = actions.clone();
        }
        if let Some(tags) = input.get("tags") {
            body["tags"] = tags.clone();
        }

        let resp = client
            .update_automation_rule(rule_id, &body)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_enable_automation_rule(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let rule_id = require_str(&input, "rule_id")?;

        client
            .enable_automation_rule(rule_id)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        Ok(json!({ "enabled": true }))
    }

    async fn invoke_disable_automation_rule(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let rule_id = require_str(&input, "rule_id")?;

        client
            .disable_automation_rule(rule_id)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        Ok(json!({ "disabled": true }))
    }

    async fn invoke_delete_automation_rule(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let rule_id = require_str(&input, "rule_id")?;

        client
            .delete_automation_rule(rule_id)
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        Ok(json!({ "deleted": true }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Jira connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for JiraConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

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
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints,
        rate_limit: None,
        requires_approval: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = JiraConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["jira.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = JiraConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = JiraConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["jira.get_issue"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "jira.get_issue");
        let result = connector
            .handle_invoke(json!({
                "operation": "jira.get_issue",
                "input": { "issue_key": "PROJ-1" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = JiraConnector::new();
        connector
            .handle_configure(json!({
                "domain": "test",
                "email": "user@example.com",
                "api_token": "token",
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["jira.create_issue"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "jira.create_issue");
        let result = connector
            .handle_invoke(json!({
                "operation": "jira.create_issue",
                "input": { "project_key": "PROJ", "issue_type": "Task" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("summary")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = JiraConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"jira.create_issue"));
        assert!(op_ids.contains(&"jira.get_issue"));
        assert!(op_ids.contains(&"jira.update_issue"));
        assert!(op_ids.contains(&"jira.delete_issue"));
        assert!(op_ids.contains(&"jira.search_jql"));
        assert!(op_ids.contains(&"jira.list_transitions"));
        assert!(op_ids.contains(&"jira.transition_issue"));
        assert!(op_ids.contains(&"jira.list_sprints"));
        assert!(op_ids.contains(&"jira.move_to_sprint"));
        assert!(op_ids.contains(&"jira.add_comment"));
        assert!(op_ids.contains(&"jira.list_comments"));
        assert!(op_ids.contains(&"jira.worklog.list"));
        assert!(op_ids.contains(&"jira.worklog.add"));
        assert!(op_ids.contains(&"jira.worklog.update"));
        assert!(op_ids.contains(&"jira.worklog.delete"));
        assert!(op_ids.contains(&"jira.add_attachment"));
        assert!(op_ids.contains(&"jira.automation.rule.list"));
        assert!(op_ids.contains(&"jira.automation.rule.get"));
        assert!(op_ids.contains(&"jira.automation.rule.create"));
        assert!(op_ids.contains(&"jira.automation.rule.update"));
        assert!(op_ids.contains(&"jira.automation.rule.enable"));
        assert!(op_ids.contains(&"jira.automation.rule.disable"));
        assert!(op_ids.contains(&"jira.automation.rule.delete"));
        assert_eq!(ops.len(), 23);
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }

    // ── Provisioning automation tests ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_token_auth() {
        let mut connector = JiraConnector::new();
        let result = connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "user@example.com",
                "api_token": "secret-token"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.client.is_some());
        assert!(connector.config.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = JiraConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "domain": "mycompany",
                "credential_id": cid
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_token_and_credential_id() {
        let mut connector = JiraConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "user@example.com",
                "api_token": "secret",
                "credential_id": cid
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_auth() {
        let mut connector = JiraConnector::new();
        let result = connector
            .handle_configure(json!({ "domain": "mycompany" }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_domain() {
        let mut connector = JiraConnector::new();
        let result = connector
            .handle_configure(json!({
                "email": "user@example.com",
                "api_token": "token"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_email_without_api_token() {
        let mut connector = JiraConnector::new();
        let result = connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "user@example.com"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_mode() {
        let mut connector = JiraConnector::new();
        connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "user@example.com",
                "api_token": "token"
            }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
        assert_eq!(result["auth_mode"], "token");
        assert_eq!(result["api_domain"], "mycompany");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured() {
        let mut connector = JiraConnector::new();
        connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "user@example.com",
                "api_token": "token"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert!(checks.iter().all(|c| c["status"] == "pass"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = JiraConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert!(checks.iter().any(|c| c["status"] == "fail"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_warns() {
        let mut connector = JiraConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({
                "domain": "mycompany",
                "credential_id": cid
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "degraded");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "warn");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = JiraConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let mut connector = JiraConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({
                "domain": "mycompany",
                "credential_id": cid
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    // ── Sync unit tests: config, helpers, operations ─────────────────

    #[test]
    fn config_from_email_and_token() {
        let cfg = JiraConfig::from_params(&json!({
            "domain": "mycompany",
            "email": "user@example.com",
            "api_token": "secret"
        }))
        .unwrap();
        assert!(!cfg.auth.is_secretless());
        assert!(cfg.base_url.is_none());
    }

    #[test]
    fn config_from_credential_id() {
        let cfg = JiraConfig::from_params(&json!({
            "domain": "mycompany",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .unwrap();
        assert!(cfg.auth.is_secretless());
    }

    #[test]
    fn config_custom_urls() {
        let cfg = JiraConfig::from_params(&json!({
            "domain": "corp",
            "email": "u@e.com",
            "api_token": "t",
            "base_url": "https://jira.example.com",
            "agile_url": "https://jira.example.com/agile"
        }))
        .unwrap();
        assert_eq!(cfg.base_url.as_deref(), Some("https://jira.example.com"));
        assert_eq!(
            cfg.agile_url.as_deref(),
            Some("https://jira.example.com/agile")
        );
    }

    #[test]
    fn config_rejects_no_domain() {
        let result = JiraConfig::from_params(&json!({
            "email": "u@e.com", "api_token": "t"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_email_without_token() {
        let result = JiraConfig::from_params(&json!({
            "domain": "x", "email": "u@e.com"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_token_without_email() {
        let result = JiraConfig::from_params(&json!({
            "domain": "x", "api_token": "t"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_all_three_auth_methods() {
        let result = JiraConfig::from_params(&json!({
            "domain": "x",
            "email": "u@e.com",
            "api_token": "t",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_credential_id() {
        let result = JiraConfig::from_params(&json!({
            "domain": "x", "credential_id": "not-a-uuid"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = JiraConfig::from_params(&json!({ "domain": "x" }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_extracts_value() {
        let input = json!({"issue_key": "PROJ-1"});
        assert_eq!(require_str(&input, "issue_key").unwrap(), "PROJ-1");
    }

    #[test]
    fn require_str_missing_field() {
        let input = json!({});
        assert!(require_str(&input, "issue_key").is_err());
    }

    #[test]
    fn require_str_non_string() {
        let input = json!({"field": 42});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_null() {
        let input = json!({"field": null});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn connector_default() {
        let c = JiraConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }
}
