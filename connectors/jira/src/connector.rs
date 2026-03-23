//! FCP Jira Connector implementation.

use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use chrono::{DateTime, FixedOffset};
use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::client::{JiraAuth, JiraClient};
use crate::error::JiraError;
use crate::types::{
    JiraBeadRecord, JiraDeployment, JiraIssue, JiraSyncAction, JiraSyncConflict,
    JiraSyncConflictPolicy, JiraSyncOrigin, JiraSyncState,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

/// Parsed configuration for the Jira connector.
struct JiraConfig {
    auth: JiraAuth,
    deployment: JiraDeployment,
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
        let deployment_str = params
            .get("deployment")
            .and_then(|v| v.as_str())
            .unwrap_or("cloud");
        let deployment: JiraDeployment =
            deployment_str
                .parse()
                .map_err(|e: String| FcpError::InvalidRequest {
                    code: 1003,
                    message: e,
                })?;

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
            deployment,
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
    zone_dir: Option<PathBuf>,
}

impl JiraConnector {
    /// Create a new Jira connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.jira"))),
            client: None,
            config: None,
            verifier: None,
            session_id: None,
            zone_dir: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let cfg = JiraConfig::from_params(&params)?;

        let mut client = JiraClient::new_with_auth_and_deployment(cfg.auth.clone(), cfg.deployment)
            .map_err(|e| FcpError::Internal {
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
        self.verifier = None;
        self.session_id = None;
        self.zone_dir = None;
        self.base.set_handshaken(false);
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

        if self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }

        self.zone_dir = req.zone_dir.clone().map(PathBuf::from);
        if let Some(zone_dir) = self.zone_dir.as_ref() {
            fs::create_dir_all(zone_dir).map_err(|err| FcpError::Internal {
                message: format!(
                    "Failed to prepare Jira zone_dir '{}': {err}",
                    zone_dir.display()
                ),
            })?;
        }

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
            manifest_hash: Self::manifest_hash(),
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
                // ── Beads Sync ─────────────────────────────────────────
                op_info(
                    "jira.sync.pull_issue",
                    "Project a Jira issue into the canonical Beads sync record",
                    json!({
                        "type": "object",
                        "required": ["issue_key"],
                        "properties": {
                            "issue_key": { "type": "string" },
                            "bead_id": { "type": "string" },
                            "custom_field_id": { "type": "string" },
                            "correlation_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "action": { "type": "string" },
                            "bead": { "type": "object" },
                            "state": { "type": "object" },
                            "correlation_id": { "type": "string" },
                            "reason_codes": { "type": "array", "items": { "type": "string" } }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read a Jira issue and convert it into the connector's canonical Beads sync projection.".into(),
                        common_mistakes: vec![
                            "Calling the sync operations before handshake provides zone_dir; persisted sync state and singleton-writer fencing require it.".into(),
                            "Forgetting to pass custom_field_id when bead linkage is stored in a Jira custom field.".into(),
                            "Assuming Jira labels are returned unchanged; the reserved bead:<id> sync label is stripped from the public label set.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "custom_field_id": "customfield_10123"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.sync.reconcile"),
                            CapabilityId::from_static("jira.sync.push_bead"),
                            CapabilityId::from_static("jira.get_issue"),
                        ],
                    },
                ),
                op_info(
                    "jira.sync.push_bead",
                    "Create or safely update a Jira issue from a canonical Beads record",
                    json!({
                        "type": "object",
                        "required": ["bead"],
                        "properties": {
                            "bead": { "type": "object" },
                            "issue_key": { "type": "string" },
                            "project_key": { "type": "string" },
                            "issue_type": { "type": "string" },
                            "custom_field_id": { "type": "string" },
                            "notify_users": { "type": "boolean" },
                            "conflict_policy": { "type": "string", "enum": ["fail_closed", "last_write_wins"] },
                            "transition_comment": { "type": "string" },
                            "correlation_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "action": { "type": "string" },
                            "created": { "type": "boolean" },
                            "updated": { "type": "boolean" },
                            "bead": { "type": "object" },
                            "jira": { "type": "object" },
                            "state": { "type": "object" },
                            "conflict": { "type": "object" },
                            "correlation_id": { "type": "string" },
                            "reason_codes": { "type": "array", "items": { "type": "string" } }
                        }
                    }),
                    "jira.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Create a new Jira issue from a Beads record or update an existing mapped issue after reconciliation.".into(),
                        common_mistakes: vec![
                            "Calling the sync operations before handshake provides zone_dir; persisted sync state and singleton-writer fencing require it.".into(),
                            "Omitting project_key and issue_type when there is no existing issue mapping.".into(),
                            "Treating last_write_wins as a force flag; if Jira is newer the connector will return a pull recommendation instead of overwriting silently.".into(),
                        ],
                        examples: vec![
                            r#"{"project_key": "PROJ", "issue_type": "Task", "bead": {"beadId": "br-123", "title": "Sync Jira work"}, "conflict_policy": "fail_closed"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.sync.reconcile"),
                            CapabilityId::from_static("jira.sync.pull_issue"),
                            CapabilityId::from_static("jira.create_issue"),
                            CapabilityId::from_static("jira.update_issue"),
                        ],
                    },
                ),
                op_info(
                    "jira.sync.reconcile",
                    "Compare a canonical Beads record with the current Jira issue and choose a deterministic next action",
                    json!({
                        "type": "object",
                        "required": ["bead"],
                        "properties": {
                            "bead": { "type": "object" },
                            "issue_key": { "type": "string" },
                            "custom_field_id": { "type": "string" },
                            "conflict_policy": { "type": "string", "enum": ["fail_closed", "last_write_wins"] },
                            "correlation_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "action": { "type": "string" },
                            "bead": { "type": "object" },
                            "jira": { "type": "object" },
                            "state": { "type": "object" },
                            "conflict": { "type": "object" },
                            "correlation_id": { "type": "string" },
                            "reason_codes": { "type": "array", "items": { "type": "string" } }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Preview sync behavior without mutating Jira. Useful before push_bead or when deciding whether Jira or Beads should win.".into(),
                        common_mistakes: vec![
                            "Calling reconcile before handshake provides zone_dir; persisted sync state and singleton-writer fencing require it.".into(),
                            "Calling reconcile without issue_key, bead.issue_key, or persisted state.issue_key, which leaves the connector unable to fetch the Jira side.".into(),
                        ],
                        examples: vec![
                            r#"{"issue_key": "PROJ-123", "bead": {"beadId": "br-123", "title": "Sync Jira work"}, "conflict_policy": "last_write_wins"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("jira.sync.pull_issue"),
                            CapabilityId::from_static("jira.sync.push_bead"),
                            CapabilityId::from_static("jira.get_issue"),
                        ],
                    },
                ),
                // ── Server Info / Deployment ──────────────────────────────
                op_info(
                    "jira.server.info",
                    "Get Jira server information and detect deployment type",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "base_url": { "type": "string" },
                            "version": { "type": "string" },
                            "deployment_type": { "type": "string" },
                            "build_number": { "type": "integer" },
                            "server_title": { "type": "string" }
                        }
                    }),
                    "jira.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve Jira server information including version and deployment type (Cloud vs Server/DC).".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![
                            CapabilityId::from_static("jira.get_issue"),
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
        let intro = self.handle_introspect().await?;
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;

        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else if self.client.is_some() {
            return Err(FcpError::NotHandshaken);
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
            "jira.sync.pull_issue" => self.invoke_sync_pull_issue(input).await,
            "jira.sync.push_bead" => self.invoke_sync_push_bead(input).await,
            "jira.sync.reconcile" => self.invoke_sync_reconcile(input).await,
            "jira.server.info" => self.invoke_server_info().await,
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
        let time_spent_seconds = input
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

    async fn invoke_sync_pull_issue(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let custom_field_id = input
            .get("custom_field_id")
            .and_then(|value| value.as_str());
        let issue_key = require_str(&input, "issue_key")?;
        let correlation_id = parse_or_generate_correlation_id(&input);
        let state_path = self.sync_state_path()?;
        let sync_lease = self.acquire_sync_lease()?;
        let result = async {
            let mut store = Self::load_sync_store(&state_path)?;
            let previous = resolve_persisted_sync_state(
                &store,
                input.get("bead_id").and_then(|value| value.as_str()),
                Some(issue_key),
            );
            let issue = self.load_sync_issue(issue_key, custom_field_id).await?;
            let bead_id_hint = input
                .get("bead_id")
                .and_then(|value| value.as_str())
                .or_else(|| {
                    previous
                        .as_ref()
                        .and_then(|snapshot| snapshot.bead_id.as_deref())
                });
            let bead = issue_to_bead_record(&issue, bead_id_hint, custom_field_id)?;
            let current_fingerprint = bead_fingerprint(&bead)?;
            let action = previous
                .as_ref()
                .and_then(|snapshot| snapshot.jira_fingerprint.as_deref())
                .map_or(JiraSyncAction::PullIssue, |previous_fingerprint| {
                    if previous_fingerprint == current_fingerprint {
                        JiraSyncAction::Noop
                    } else {
                        JiraSyncAction::PullIssue
                    }
                });
            let sync_state = build_sync_state(
                &bead,
                &bead,
                extract_issue_revision(&issue),
                previous.as_ref(),
                recommended_sync_origin(action, previous.as_ref(), JiraSyncOrigin::Jira),
            )?;
            store.upsert(&bead.bead_id, sync_state.clone());
            Self::persist_sync_store(&state_path, &store)?;

            info!(
                correlation_id = %correlation_id,
                issue_key = %issue.key,
                bead_id = %bead.bead_id,
                action = ?action,
                "Jira sync pull completed"
            );

            Ok(json!({
                "action": action,
                "bead": bead,
                "state": sync_state,
                "correlation_id": correlation_id,
                "reason_codes": reason_codes_for_sync_action(action),
            }))
        }
        .await;
        if let Err(err) = sync_lease.release() {
            warn!(error = %err, "Failed to release Jira sync lease after pull_issue");
        }
        result
    }

    async fn invoke_sync_push_bead(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let bead = parse_sync_bead(&input)?;
        let policy = parse_sync_conflict_policy(&input)?;
        let custom_field_id = input
            .get("custom_field_id")
            .and_then(|value| value.as_str());
        let notify_users = input
            .get("notify_users")
            .and_then(|value| value.as_bool())
            .unwrap_or(true);
        let transition_comment = input
            .get("transition_comment")
            .and_then(|value| value.as_str());
        let correlation_id = parse_or_generate_correlation_id(&input);
        let state_path = self.sync_state_path()?;
        let sync_lease = self.acquire_sync_lease()?;
        let result = async {
            let mut store = Self::load_sync_store(&state_path)?;
            let issue_key_hint = input.get("issue_key").and_then(|value| value.as_str());
            let mut previous =
                resolve_persisted_sync_state(&store, Some(&bead.bead_id), issue_key_hint);
            let mut resolved_issue_key =
                resolve_sync_issue_key(&input, &bead, previous.as_ref()).map(str::to_owned);

            if resolved_issue_key.is_none() {
                if let Some(project_key) = input.get("project_key").and_then(|value| value.as_str())
                {
                    resolved_issue_key = self
                        .lookup_sync_issue_key_by_bead_label(
                            project_key,
                            &bead.bead_id,
                            custom_field_id,
                        )
                        .await?;
                    if resolved_issue_key.is_some() {
                        previous = resolve_persisted_sync_state(
                            &store,
                            Some(&bead.bead_id),
                            resolved_issue_key.as_deref(),
                        );
                    }
                }
            }

            if let Some(issue_key) = resolved_issue_key.as_deref() {
                let issue = self.load_sync_issue(issue_key, custom_field_id).await?;
                let jira = issue_to_bead_record(&issue, Some(&bead.bead_id), custom_field_id)?;
                let jira_revision = extract_issue_revision(&issue);
                let (action, conflict) = decide_sync_action(
                    &bead,
                    &jira,
                    previous.as_ref(),
                    jira_revision.as_deref(),
                    policy,
                    JiraSyncOrigin::Beads,
                )?;
                let sync_state = build_sync_state(
                    &bead,
                    &jira,
                    jira_revision,
                    previous.as_ref(),
                    recommended_sync_origin(action, previous.as_ref(), JiraSyncOrigin::Jira),
                )?;

                if action != JiraSyncAction::PushBead {
                    store.upsert(&bead.bead_id, sync_state.clone());
                    Self::persist_sync_store(&state_path, &store)?;
                    if conflict.is_some() {
                        warn!(
                            correlation_id = %correlation_id,
                            issue_key,
                            bead_id = %bead.bead_id,
                            action = ?action,
                            "Jira sync push detected a conflict"
                        );
                    } else {
                        info!(
                            correlation_id = %correlation_id,
                            issue_key,
                            bead_id = %bead.bead_id,
                            action = ?action,
                            "Jira sync push skipped mutation"
                        );
                    }
                    return Ok(json!({
                        "action": action,
                        "created": false,
                        "updated": false,
                        "bead": bead,
                        "jira": jira,
                        "state": sync_state,
                        "conflict": conflict,
                        "correlation_id": correlation_id,
                        "reason_codes": reason_codes_for_sync_action(action),
                    }));
                }

                let fields =
                    build_issue_fields_from_bead(&bead, config.deployment, custom_field_id, true);
                client
                    .update_issue(issue_key, &json!({ "fields": fields }), notify_users)
                    .await
                    .map_err(|error: JiraError| error.to_fcp_error())?;

                if status_transition_required(bead.status.as_deref(), jira.status.as_deref()) {
                    self.sync_transition_issue_status(
                        issue_key,
                        bead.status.as_deref().unwrap(),
                        transition_comment,
                    )
                    .await?;
                }

                let refreshed = self.load_sync_issue(issue_key, custom_field_id).await?;
                let jira = issue_to_bead_record(&refreshed, Some(&bead.bead_id), custom_field_id)?;
                let sync_state = build_sync_state(
                    &bead,
                    &jira,
                    extract_issue_revision(&refreshed),
                    previous.as_ref(),
                    JiraSyncOrigin::Beads,
                )?;
                store.upsert(&bead.bead_id, sync_state.clone());
                Self::persist_sync_store(&state_path, &store)?;

                info!(
                    correlation_id = %correlation_id,
                    issue_key,
                    bead_id = %bead.bead_id,
                    action = ?JiraSyncAction::PushBead,
                    "Jira sync push updated an existing issue"
                );

                return Ok(json!({
                    "action": JiraSyncAction::PushBead,
                    "created": false,
                    "updated": true,
                    "bead": bead,
                    "jira": jira,
                    "state": sync_state,
                    "correlation_id": correlation_id,
                    "reason_codes": ["updated_issue"],
                }));
            }

            let project_key = require_str(&input, "project_key")?;
            let issue_type = require_str(&input, "issue_type")?;
            let mut fields =
                build_issue_fields_from_bead(&bead, config.deployment, custom_field_id, false);
            fields.insert("project".into(), json!({ "key": project_key }));
            fields.insert("issuetype".into(), json!({ "name": issue_type }));

            let created = client
                .create_issue(&json!({ "fields": fields }))
                .await
                .map_err(|error: JiraError| error.to_fcp_error())?;

            let mut issue = self.load_sync_issue(&created.key, custom_field_id).await?;
            let mut jira = issue_to_bead_record(&issue, Some(&bead.bead_id), custom_field_id)?;

            if status_transition_required(bead.status.as_deref(), jira.status.as_deref()) {
                self.sync_transition_issue_status(
                    &created.key,
                    bead.status.as_deref().unwrap(),
                    transition_comment,
                )
                .await?;
                issue = self.load_sync_issue(&created.key, custom_field_id).await?;
                jira = issue_to_bead_record(&issue, Some(&bead.bead_id), custom_field_id)?;
            }

            let sync_state = build_sync_state(
                &bead,
                &jira,
                extract_issue_revision(&issue),
                previous.as_ref(),
                JiraSyncOrigin::Beads,
            )?;
            store.upsert(&bead.bead_id, sync_state.clone());
            Self::persist_sync_store(&state_path, &store)?;

            info!(
                correlation_id = %correlation_id,
                issue_key = %created.key,
                bead_id = %bead.bead_id,
                action = ?JiraSyncAction::PushBead,
                "Jira sync push created a new issue"
            );

            Ok(json!({
                "action": JiraSyncAction::PushBead,
                "created": true,
                "updated": false,
                "bead": bead,
                "jira": jira,
                "state": sync_state,
                "correlation_id": correlation_id,
                "reason_codes": ["created_issue"],
            }))
        }
        .await;
        if let Err(err) = sync_lease.release() {
            warn!(error = %err, "Failed to release Jira sync lease after push_bead");
        }
        result
    }

    async fn invoke_sync_reconcile(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let bead = parse_sync_bead(&input)?;
        let policy = parse_sync_conflict_policy(&input)?;
        let custom_field_id = input
            .get("custom_field_id")
            .and_then(|value| value.as_str());
        let correlation_id = parse_or_generate_correlation_id(&input);
        let state_path = self.sync_state_path()?;
        let sync_lease = self.acquire_sync_lease()?;
        let result = async {
            let mut store = Self::load_sync_store(&state_path)?;
            let previous = resolve_persisted_sync_state(
                &store,
                Some(&bead.bead_id),
                input.get("issue_key").and_then(|value| value.as_str()),
            );
            let issue_key = resolve_sync_issue_key(&input, &bead, previous.as_ref()).ok_or(
                FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing issue_key, bead.issue_key, or persisted state.issue_key"
                        .into(),
                },
            )?;
            let issue = self.load_sync_issue(issue_key, custom_field_id).await?;
            let jira = issue_to_bead_record(&issue, Some(&bead.bead_id), custom_field_id)?;
            let jira_revision = extract_issue_revision(&issue);
            let default_origin = previous
                .as_ref()
                .map_or(JiraSyncOrigin::Beads, |snapshot| snapshot.last_sync_origin);
            let (action, conflict) = decide_sync_action(
                &bead,
                &jira,
                previous.as_ref(),
                jira_revision.as_deref(),
                policy,
                default_origin,
            )?;
            let sync_state = build_sync_state(
                &bead,
                &jira,
                jira_revision,
                previous.as_ref(),
                recommended_sync_origin(action, previous.as_ref(), default_origin),
            )?;
            store.upsert(&bead.bead_id, sync_state.clone());
            Self::persist_sync_store(&state_path, &store)?;

            if conflict.is_some() {
                warn!(
                    correlation_id = %correlation_id,
                    issue_key,
                    bead_id = %bead.bead_id,
                    action = ?action,
                    "Jira sync reconcile detected a conflict"
                );
            } else {
                info!(
                    correlation_id = %correlation_id,
                    issue_key,
                    bead_id = %bead.bead_id,
                    action = ?action,
                    "Jira sync reconcile completed"
                );
            }

            Ok(json!({
                "action": action,
                "bead": bead,
                "jira": jira,
                "state": sync_state,
                "conflict": conflict,
                "correlation_id": correlation_id,
                "reason_codes": reason_codes_for_sync_action(action),
            }))
        }
        .await;
        if let Err(err) = sync_lease.release() {
            warn!(error = %err, "Failed to release Jira sync lease after reconcile");
        }
        result
    }

    async fn load_sync_issue(
        &self,
        issue_key: &str,
        custom_field_id: Option<&str>,
    ) -> FcpResult<JiraIssue> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let fields = sync_issue_fields(custom_field_id);
        client
            .get_issue(issue_key, Some(&fields), None)
            .await
            .map_err(|error: JiraError| error.to_fcp_error())
    }

    fn sync_state_path(&self) -> FcpResult<PathBuf> {
        let zone_dir = self.zone_dir.as_ref().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Handshake zone_dir is required for Jira sync state persistence".into(),
        })?;
        Ok(zone_dir.join(JIRA_SYNC_STATE_FILE))
    }

    fn sync_lease_path(&self) -> FcpResult<PathBuf> {
        let zone_dir = self.zone_dir.as_ref().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Handshake zone_dir is required for Jira singleton-writer lease".into(),
        })?;
        Ok(zone_dir.join(JIRA_SYNC_LEASE_FILE))
    }

    fn sync_lease_holder_id(&self) -> FcpResult<String> {
        let session_id = self.session_id.as_ref().ok_or(FcpError::NotConfigured)?;
        Ok(session_id.to_string())
    }

    fn acquire_sync_lease(&self) -> FcpResult<JiraSyncLease> {
        let lease_path = self.sync_lease_path()?;
        let holder = self.sync_lease_holder_id()?;
        JiraSyncLease::acquire(lease_path, holder, JIRA_SYNC_LEASE_TTL_SECONDS)
    }

    fn load_sync_store(path: &Path) -> FcpResult<JiraSyncStore> {
        read_json_file_if_exists::<JiraSyncStore>(path)
            .map(|state| state.unwrap_or_default())
            .map_err(|err| FcpError::Internal {
                message: format!(
                    "Failed to read Jira sync state file '{}': {err}",
                    path.display()
                ),
            })
    }

    fn persist_sync_store(path: &Path, store: &JiraSyncStore) -> FcpResult<()> {
        write_json_file_atomic(path, store).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to write Jira sync state file '{}': {err}",
                path.display()
            ),
        })
    }

    async fn lookup_sync_issue_key_by_bead_label(
        &self,
        project_key: &str,
        bead_id: &str,
        custom_field_id: Option<&str>,
    ) -> FcpResult<Option<String>> {
        if custom_field_id.is_some() {
            return Ok(None);
        }

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let label = format!("{BEAD_LABEL_PREFIX}{bead_id}");
        let jql = format!(
            "project = \"{}\" AND labels = \"{}\" ORDER BY created DESC",
            escape_jql_literal(project_key),
            escape_jql_literal(&label),
        );
        let result = client
            .search_jql(&json!({
                "jql": jql,
                "fields": ["summary"],
                "maxResults": 2,
            }))
            .await
            .map_err(|error: JiraError| error.to_fcp_error())?;

        match result.issues.as_slice() {
            [] => Ok(None),
            [issue] => Ok(Some(issue.key.clone())),
            _ => Err(FcpError::Conflict {
                message: format!(
                    "Multiple Jira issues already carry bead label '{label}'; manual resolution required"
                ),
            }),
        }
    }

    async fn sync_transition_issue_status(
        &self,
        issue_key: &str,
        target_status: &str,
        comment: Option<&str>,
    ) -> FcpResult<()> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let desired =
            normalize_status_value(Some(target_status)).ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "status cannot be empty".into(),
            })?;
        let transitions = client
            .list_transitions(issue_key)
            .await
            .map_err(|error: JiraError| error.to_fcp_error())?;
        let transition = transitions
            .transitions
            .iter()
            .find(|candidate| {
                transition_matches_status(
                    candidate.name.as_str(),
                    candidate
                        .to
                        .as_ref()
                        .and_then(|status| status.name.as_deref()),
                    &desired,
                )
            })
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "No Jira transition available from current state to status '{target_status}'"
                ),
            })?;

        let mut body = json!({
            "transition": { "id": transition.id }
        });
        if let Some(comment) = comment.and_then(|value| normalize_optional_text(Some(value))) {
            body["update"] = json!({
                "comment": [{
                    "add": { "body": comment }
                }]
            });
        }

        client
            .transition_issue(issue_key, &body)
            .await
            .map_err(|error: JiraError| error.to_fcp_error())
    }

    async fn invoke_server_info(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let info = client
            .server_info()
            .await
            .map_err(|e: JiraError| e.to_fcp_error())?;
        serde_json::to_value(info).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.session_id = None;
        self.zone_dir = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        info!("Jira connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for JiraConnector {
    fn default() -> Self {
        Self::new()
    }
}

const JIRA_SYNC_STATE_FILE: &str = "jira_sync_state.json";
const JIRA_SYNC_LEASE_FILE: &str = "jira_sync_lease.json";
const JIRA_SYNC_LEASE_TTL_SECONDS: u64 = 120;
const BEAD_LABEL_PREFIX: &str = "bead:";
const SYNC_BASE_FIELDS: &str = "summary,description,status,priority,labels,assignee,duedate,updated,timeoriginalestimate,aggregatetimeoriginalestimate,timetracking";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct JiraSyncStore {
    #[serde(default)]
    mappings: BTreeMap<String, JiraSyncState>,
}

impl JiraSyncStore {
    fn get_by_issue_key(&self, issue_key: &str) -> Option<(&String, &JiraSyncState)> {
        self.mappings.iter().find(|(_, snapshot)| {
            !snapshot.tombstoned && snapshot.issue_key.as_deref() == Some(issue_key)
        })
    }

    fn upsert(&mut self, bead_id: &str, state: JiraSyncState) {
        let stale_keys = state
            .issue_key
            .as_deref()
            .map_or_else(Vec::new, |issue_key| {
                self.mappings
                    .iter()
                    .filter(|(existing_bead_id, snapshot)| {
                        existing_bead_id.as_str() != bead_id
                            && snapshot.issue_key.as_deref() == Some(issue_key)
                    })
                    .map(|(existing_bead_id, _)| existing_bead_id.clone())
                    .collect::<Vec<_>>()
            });

        for stale_key in stale_keys {
            self.mappings.remove(&stale_key);
        }

        self.mappings.insert(bead_id.to_string(), state);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JiraSyncLeaseRecord {
    holder_instance_id: String,
    lease_seq: u64,
    expires_at: u64,
}

#[derive(Debug, Clone)]
struct JiraSyncLease {
    path: PathBuf,
    holder_instance_id: String,
    lease_seq: u64,
}

impl JiraSyncLease {
    fn acquire(path: PathBuf, holder_instance_id: String, ttl_seconds: u64) -> FcpResult<Self> {
        let now = current_unix_timestamp_secs();
        let previous = read_json_file_if_exists::<JiraSyncLeaseRecord>(&path).map_err(|err| {
            FcpError::Internal {
                message: format!(
                    "Failed to read Jira sync lease file '{}': {err}",
                    path.display()
                ),
            }
        })?;

        if let Some(record) = previous.as_ref()
            && record.expires_at > now
            && record.holder_instance_id != holder_instance_id
        {
            return Err(FcpError::ResourceExhausted {
                resource: format!(
                    "jira sync lease held by '{}' (lease_seq={}) until {}",
                    record.holder_instance_id, record.lease_seq, record.expires_at
                ),
            });
        }

        let lease_seq = previous.map_or(1, |record| record.lease_seq.saturating_add(1));
        let record = JiraSyncLeaseRecord {
            holder_instance_id: holder_instance_id.clone(),
            lease_seq,
            expires_at: now.saturating_add(ttl_seconds),
        };
        write_json_file_atomic(&path, &record).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to persist Jira sync lease file '{}': {err}",
                path.display()
            ),
        })?;

        Ok(Self {
            path,
            holder_instance_id,
            lease_seq,
        })
    }

    fn release(&self) -> FcpResult<()> {
        let existing =
            read_json_file_if_exists::<JiraSyncLeaseRecord>(&self.path).map_err(|err| {
                FcpError::Internal {
                    message: format!(
                        "Failed to read Jira sync lease file '{}': {err}",
                        self.path.display()
                    ),
                }
            })?;

        if let Some(record) = existing
            && record.holder_instance_id == self.holder_instance_id
            && record.lease_seq == self.lease_seq
            && let Err(err) = fs::remove_file(&self.path)
            && err.kind() != io::ErrorKind::NotFound
        {
            return Err(FcpError::Internal {
                message: format!(
                    "Failed to release Jira sync lease file '{}': {err}",
                    self.path.display()
                ),
            });
        }

        Ok(())
    }
}

fn write_json_file_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    fs::write(&tmp_path, payload)?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn read_json_file_if_exists<T>(path: &Path) -> io::Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    match fs::read(path) {
        Ok(bytes) => {
            let parsed = serde_json::from_slice::<T>(&bytes)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            Ok(Some(parsed))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn sync_issue_fields(custom_field_id: Option<&str>) -> String {
    match custom_field_id.and_then(|value| normalize_optional_text(Some(value))) {
        Some(custom_field_id) => format!("{SYNC_BASE_FIELDS},{custom_field_id}"),
        None => SYNC_BASE_FIELDS.to_string(),
    }
}

fn parse_sync_bead(input: &serde_json::Value) -> FcpResult<JiraBeadRecord> {
    let bead_value = input.get("bead").cloned().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "Missing required field: bead".into(),
    })?;
    let mut bead: JiraBeadRecord =
        serde_json::from_value(bead_value).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid bead payload: {error}"),
        })?;

    bead = normalize_bead_record(bead);

    if bead.bead_id.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "bead.beadId must not be empty".into(),
        });
    }
    if bead.title.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "bead.title must not be empty".into(),
        });
    }

    Ok(bead)
}

fn parse_sync_state(input: &serde_json::Value) -> FcpResult<Option<JiraSyncState>> {
    input
        .get("state")
        .cloned()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid sync state: {error}"),
            })
        })
        .transpose()
}

fn parse_sync_conflict_policy(input: &serde_json::Value) -> FcpResult<JiraSyncConflictPolicy> {
    input
        .get("conflict_policy")
        .cloned()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid conflict_policy: {error}"),
            })
        })
        .transpose()
        .map(|policy| policy.unwrap_or_default())
}

fn parse_or_generate_correlation_id(input: &serde_json::Value) -> String {
    input
        .get("correlation_id")
        .and_then(|value| value.as_str())
        .and_then(|value| normalize_optional_text(Some(value)))
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn resolve_persisted_sync_state(
    store: &JiraSyncStore,
    bead_id: Option<&str>,
    issue_key: Option<&str>,
) -> Option<JiraSyncState> {
    bead_id
        .and_then(|bead_id| store.mappings.get(bead_id).cloned())
        .or_else(|| {
            issue_key.and_then(|issue_key| {
                store
                    .get_by_issue_key(issue_key)
                    .map(|(_, snapshot)| snapshot.clone())
            })
        })
}

fn reason_codes_for_sync_action(action: JiraSyncAction) -> &'static [&'static str] {
    match action {
        JiraSyncAction::Noop => &["noop_already_converged"],
        JiraSyncAction::PushBead => &["beads_authoritative"],
        JiraSyncAction::PullIssue => &["jira_authoritative"],
        JiraSyncAction::Conflict => &["sync_conflict"],
    }
}

fn resolve_sync_issue_key<'a>(
    input: &'a serde_json::Value,
    bead: &'a JiraBeadRecord,
    state: Option<&'a JiraSyncState>,
) -> Option<&'a str> {
    input
        .get("issue_key")
        .and_then(|value| value.as_str())
        .or(bead.issue_key.as_deref())
        .or_else(|| state.and_then(|snapshot| snapshot.issue_key.as_deref()))
}

fn normalize_bead_record(mut bead: JiraBeadRecord) -> JiraBeadRecord {
    bead.bead_id = normalize_optional_text(Some(&bead.bead_id)).unwrap_or_default();
    bead.title = normalize_optional_text(Some(&bead.title)).unwrap_or_default();
    bead.description = normalize_optional_text(bead.description.as_deref());
    bead.status = normalize_status_value(bead.status.as_deref());
    bead.priority = normalize_priority_value(bead.priority.as_deref());
    bead.labels = normalize_public_labels(&bead.labels);
    bead.assignee = normalize_optional_text(bead.assignee.as_deref());
    bead.due_date = normalize_optional_text(bead.due_date.as_deref());
    bead.issue_key = normalize_optional_text(bead.issue_key.as_deref());
    bead.issue_id = normalize_optional_text(bead.issue_id.as_deref());
    bead.revision = normalize_optional_text(bead.revision.as_deref());
    bead
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn normalize_status_value(value: Option<&str>) -> Option<String> {
    normalize_optional_text(value).map(|value| value.to_lowercase())
}

fn normalize_priority_value(value: Option<&str>) -> Option<String> {
    normalize_optional_text(value).map(|value| value.to_lowercase())
}

fn normalize_public_labels(labels: &[String]) -> Vec<String> {
    let mut normalized = labels
        .iter()
        .filter_map(|label| normalize_optional_text(Some(label)))
        .filter(|label| !label.starts_with(BEAD_LABEL_PREFIX))
        .map(|label| label.to_lowercase())
        .collect::<Vec<_>>();
    normalized.sort_unstable();
    normalized.dedup();
    normalized
}

fn build_jira_labels(
    labels: &[String],
    bead_id: &str,
    custom_field_id: Option<&str>,
) -> Vec<String> {
    let mut normalized = normalize_public_labels(labels);
    if custom_field_id.is_none() {
        normalized.push(format!("{BEAD_LABEL_PREFIX}{bead_id}"));
    }
    normalized.sort_unstable();
    normalized.dedup();
    normalized
}

fn extract_bead_id_from_labels(labels: &[String]) -> Option<String> {
    labels.iter().find_map(|label| {
        label
            .strip_prefix(BEAD_LABEL_PREFIX)
            .and_then(|value| normalize_optional_text(Some(value)))
    })
}

fn escape_jql_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn stringify_scalar(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => normalize_optional_text(Some(value)),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Object(object) => object
            .get("value")
            .and_then(stringify_scalar)
            .or_else(|| object.get("id").and_then(stringify_scalar))
            .or_else(|| object.get("name").and_then(stringify_scalar)),
        _ => None,
    }
}

fn append_adf_text(value: &serde_json::Value, buffer: &mut String) {
    match value {
        serde_json::Value::String(value) => buffer.push_str(value),
        serde_json::Value::Array(values) => {
            for value in values {
                append_adf_text(value, buffer);
            }
        }
        serde_json::Value::Object(object) => {
            if object.get("type").and_then(|value| value.as_str()) == Some("hardBreak") {
                buffer.push('\n');
            }

            if let Some(text) = object.get("text").and_then(|value| value.as_str()) {
                buffer.push_str(text);
            }

            if let Some(content) = object.get("content") {
                append_adf_text(content, buffer);
                if let Some("paragraph" | "heading" | "listItem" | "codeBlock") =
                    object.get("type").and_then(|value| value.as_str())
                {
                    if !buffer.ends_with('\n') {
                        buffer.push('\n');
                    }
                }
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn jira_value_to_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => normalize_optional_text(Some(value)),
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
            let mut buffer = String::new();
            append_adf_text(value, &mut buffer);
            let text = buffer
                .lines()
                .map(str::trim_end)
                .collect::<Vec<_>>()
                .join("\n");
            normalize_optional_text(Some(&text))
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => None,
    }
}

fn issue_fields_map(issue: &JiraIssue) -> FcpResult<&serde_json::Map<String, serde_json::Value>> {
    issue
        .fields
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .ok_or(FcpError::Internal {
            message: format!("Jira issue {} is missing a fields object", issue.key),
        })
}

fn extract_issue_revision(issue: &JiraIssue) -> Option<String> {
    issue
        .fields
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|fields| fields.get("updated"))
        .and_then(|value| value.as_str())
        .map(str::to_owned)
}

fn issue_to_bead_record(
    issue: &JiraIssue,
    bead_id_hint: Option<&str>,
    custom_field_id: Option<&str>,
) -> FcpResult<JiraBeadRecord> {
    let fields = issue_fields_map(issue)?;
    let raw_labels = fields
        .get("labels")
        .and_then(serde_json::Value::as_array)
        .map_or_else(Vec::new, |labels| {
            labels
                .iter()
                .filter_map(|label| label.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        });
    let bead_id = bead_id_hint
        .and_then(|value| normalize_optional_text(Some(value)))
        .or_else(|| {
            custom_field_id
                .and_then(|field_id| fields.get(field_id))
                .and_then(stringify_scalar)
        })
        .or_else(|| extract_bead_id_from_labels(&raw_labels))
        .unwrap_or_else(|| issue.key.clone());

    let title = fields
        .get("summary")
        .and_then(|value| value.as_str())
        .and_then(|value| normalize_optional_text(Some(value)))
        .unwrap_or_else(|| issue.key.clone());

    Ok(normalize_bead_record(JiraBeadRecord {
        bead_id,
        title,
        description: fields.get("description").and_then(jira_value_to_text),
        status: fields
            .get("status")
            .and_then(|value| value.get("name"))
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        priority: fields
            .get("priority")
            .and_then(|value| value.get("name").or_else(|| value.get("id")))
            .and_then(stringify_scalar),
        labels: normalize_public_labels(&raw_labels),
        assignee: fields
            .get("assignee")
            .and_then(|value| {
                value
                    .get("id")
                    .or_else(|| value.get("accountId"))
                    .or_else(|| value.get("name"))
                    .or_else(|| value.get("emailAddress"))
                    .or_else(|| value.get("displayName"))
            })
            .and_then(stringify_scalar),
        due_date: fields
            .get("duedate")
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        estimate_seconds: fields
            .get("timetracking")
            .and_then(|value| value.get("originalEstimateSeconds"))
            .and_then(|value| value.as_u64())
            .or_else(|| {
                fields
                    .get("timeoriginalestimate")
                    .and_then(|value| value.as_u64())
            })
            .or_else(|| {
                fields
                    .get("aggregatetimeoriginalestimate")
                    .and_then(|value| value.as_u64())
            }),
        issue_key: Some(issue.key.clone()),
        issue_id: Some(issue.id.clone()),
        revision: extract_issue_revision(issue),
    }))
}

fn bead_fingerprint(bead: &JiraBeadRecord) -> FcpResult<String> {
    serde_json::to_string(&json!({
        "beadId": normalize_optional_text(Some(&bead.bead_id)).unwrap_or_default(),
        "title": normalize_optional_text(Some(&bead.title)).unwrap_or_default(),
        "description": normalize_optional_text(bead.description.as_deref()),
        "status": normalize_status_value(bead.status.as_deref()),
        "priority": normalize_priority_value(bead.priority.as_deref()),
        "labels": normalize_public_labels(&bead.labels),
        "assignee": normalize_optional_text(bead.assignee.as_deref()),
        "dueDate": normalize_optional_text(bead.due_date.as_deref()),
        "estimateSeconds": bead.estimate_seconds,
    }))
    .map_err(|error| FcpError::Internal {
        message: format!("Failed to serialize sync fingerprint: {error}"),
    })
}

fn compare_revision_markers(left: Option<&str>, right: Option<&str>) -> Option<Ordering> {
    match (
        left.and_then(|value| normalize_optional_text(Some(value))),
        right.and_then(|value| normalize_optional_text(Some(value))),
    ) {
        (Some(left), Some(right)) => {
            match (parse_revision_marker(&left), parse_revision_marker(&right)) {
                (Ok(left), Ok(right)) => Some(left.cmp(&right)),
                _ => Some(left.cmp(&right)),
            }
        }
        (Some(_), None) => Some(Ordering::Greater),
        (None, Some(_)) => Some(Ordering::Less),
        (None, None) => None,
    }
}

fn parse_revision_marker(value: &str) -> Result<DateTime<FixedOffset>, chrono::ParseError> {
    DateTime::<FixedOffset>::parse_from_rfc3339(value)
        .or_else(|_| DateTime::<FixedOffset>::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f%z"))
}

fn choose_authoritative_origin(
    bead: &JiraBeadRecord,
    jira_revision: Option<&str>,
    default_origin: JiraSyncOrigin,
) -> JiraSyncOrigin {
    match compare_revision_markers(bead.revision.as_deref(), jira_revision) {
        Some(Ordering::Greater) => JiraSyncOrigin::Beads,
        Some(Ordering::Less) => JiraSyncOrigin::Jira,
        Some(Ordering::Equal) | None => default_origin,
    }
}

fn decide_sync_action(
    bead: &JiraBeadRecord,
    jira: &JiraBeadRecord,
    state: Option<&JiraSyncState>,
    jira_revision: Option<&str>,
    policy: JiraSyncConflictPolicy,
    default_origin: JiraSyncOrigin,
) -> FcpResult<(JiraSyncAction, Option<JiraSyncConflict>)> {
    let bead_fp = bead_fingerprint(bead)?;
    let jira_fp = bead_fingerprint(jira)?;

    if bead_fp == jira_fp {
        return Ok((JiraSyncAction::Noop, None));
    }

    let bead_changed = state
        .and_then(|snapshot| snapshot.bead_fingerprint.as_deref())
        .is_none_or(|previous| previous != bead_fp);
    let jira_changed = state
        .and_then(|snapshot| snapshot.jira_fingerprint.as_deref())
        .is_none_or(|previous| previous != jira_fp);

    let reason_code = match state {
        None => "missing_sync_baseline",
        Some(_) if !bead_changed && !jira_changed => "baseline_divergence",
        Some(_) if bead_changed && jira_changed => "concurrent_changes_detected",
        Some(_) if bead_changed => return Ok((JiraSyncAction::PushBead, None)),
        Some(_) => return Ok((JiraSyncAction::PullIssue, None)),
    };

    match policy {
        JiraSyncConflictPolicy::FailClosed => Ok((
            JiraSyncAction::Conflict,
            Some(JiraSyncConflict {
                reason_code: reason_code.into(),
                bead_fingerprint: bead_fp,
                jira_fingerprint: jira_fp,
                bead_revision: bead.revision.clone(),
                jira_revision: jira_revision.map(str::to_owned),
            }),
        )),
        JiraSyncConflictPolicy::LastWriteWins => Ok((
            match choose_authoritative_origin(bead, jira_revision, default_origin) {
                JiraSyncOrigin::Beads => JiraSyncAction::PushBead,
                JiraSyncOrigin::Jira => JiraSyncAction::PullIssue,
            },
            None,
        )),
    }
}

fn recommended_sync_origin(
    action: JiraSyncAction,
    state: Option<&JiraSyncState>,
    default_origin: JiraSyncOrigin,
) -> JiraSyncOrigin {
    match action {
        JiraSyncAction::PushBead => JiraSyncOrigin::Beads,
        JiraSyncAction::PullIssue => JiraSyncOrigin::Jira,
        JiraSyncAction::Noop | JiraSyncAction::Conflict => {
            state.map_or(default_origin, |snapshot| snapshot.last_sync_origin)
        }
    }
}

fn build_sync_state(
    bead: &JiraBeadRecord,
    jira: &JiraBeadRecord,
    jira_revision: Option<String>,
    previous: Option<&JiraSyncState>,
    origin: JiraSyncOrigin,
) -> FcpResult<JiraSyncState> {
    Ok(JiraSyncState {
        bead_id: Some(bead.bead_id.clone()),
        issue_key: jira.issue_key.clone().or_else(|| bead.issue_key.clone()),
        issue_id: jira.issue_id.clone().or_else(|| bead.issue_id.clone()),
        bead_fingerprint: Some(bead_fingerprint(bead)?),
        jira_fingerprint: Some(bead_fingerprint(jira)?),
        bead_revision: bead.revision.clone(),
        jira_revision: jira_revision.or_else(|| jira.revision.clone()),
        last_sync_origin: origin,
        tombstoned: previous.is_some_and(|snapshot| snapshot.tombstoned),
    })
}

fn status_transition_required(desired_status: Option<&str>, current_status: Option<&str>) -> bool {
    match (
        normalize_status_value(desired_status),
        normalize_status_value(current_status),
    ) {
        (Some(desired), Some(current)) => desired != current,
        (Some(_), None) => true,
        _ => false,
    }
}

fn transition_matches_status(
    transition_name: &str,
    transition_target: Option<&str>,
    desired: &str,
) -> bool {
    normalize_status_value(Some(transition_name)).as_deref() == Some(desired)
        || normalize_status_value(transition_target).as_deref() == Some(desired)
}

fn build_issue_fields_from_bead(
    bead: &JiraBeadRecord,
    deployment: JiraDeployment,
    custom_field_id: Option<&str>,
    include_nulls: bool,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert("summary".into(), json!(bead.title));
    fields.insert(
        "labels".into(),
        json!(build_jira_labels(
            &bead.labels,
            &bead.bead_id,
            custom_field_id
        )),
    );

    let description = jira_description_value(bead.description.as_deref(), deployment);
    if include_nulls || !description.is_null() {
        fields.insert("description".into(), description);
    }

    if let Some(priority) = bead.priority.as_deref() {
        fields.insert("priority".into(), json!({ "name": priority }));
    }

    match bead.assignee.as_deref() {
        Some(assignee) => {
            fields.insert("assignee".into(), jira_assignee_value(assignee, deployment));
        }
        None if include_nulls => {
            fields.insert("assignee".into(), serde_json::Value::Null);
        }
        None => {}
    }

    match bead.due_date.as_deref() {
        Some(due_date) => {
            fields.insert("duedate".into(), json!(due_date));
        }
        None if include_nulls => {
            fields.insert("duedate".into(), serde_json::Value::Null);
        }
        None => {}
    }

    if let Some(estimate_seconds) = bead.estimate_seconds {
        fields.insert(
            "timetracking".into(),
            json!({ "originalEstimate": format_jira_estimate(estimate_seconds) }),
        );
    }

    if let Some(custom_field_id) =
        custom_field_id.and_then(|value| normalize_optional_text(Some(value)))
    {
        fields.insert(custom_field_id, json!(bead.bead_id));
    }

    fields
}

fn jira_description_value(
    description: Option<&str>,
    deployment: JiraDeployment,
) -> serde_json::Value {
    let Some(description) = normalize_optional_text(description) else {
        return serde_json::Value::Null;
    };

    match deployment {
        JiraDeployment::Cloud => {
            let content = description
                .lines()
                .map(|line| {
                    if line.is_empty() {
                        json!({ "type": "paragraph", "content": [] })
                    } else {
                        json!({
                            "type": "paragraph",
                            "content": [{ "type": "text", "text": line }]
                        })
                    }
                })
                .collect::<Vec<_>>();
            json!({
                "type": "doc",
                "version": 1,
                "content": if content.is_empty() {
                    vec![json!({ "type": "paragraph", "content": [] })]
                } else {
                    content
                }
            })
        }
        JiraDeployment::ServerDc => json!(description),
    }
}

fn jira_assignee_value(assignee: &str, deployment: JiraDeployment) -> serde_json::Value {
    match deployment {
        JiraDeployment::Cloud => json!({ "accountId": assignee }),
        JiraDeployment::ServerDc => json!({ "name": assignee }),
    }
}

fn format_jira_estimate(seconds: u64) -> String {
    let total_minutes = (seconds / 60).max(1);
    let hours = total_minutes / 60;
    let minutes = total_minutes % 60;

    match (hours, minutes) {
        (0, minutes) => format!("{minutes}m"),
        (hours, 0) => format!("{hours}h"),
        (hours, minutes) => format!("{hours}h {minutes}m"),
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

    fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
        let cap = match op {
            "jira.delete_issue" | "jira.worklog.delete" | "jira.automation.rule.delete" => {
                "jira.delete"
            }
            "jira.create_issue"
            | "jira.update_issue"
            | "jira.transition_issue"
            | "jira.move_to_sprint"
            | "jira.add_comment"
            | "jira.worklog.add"
            | "jira.worklog.update"
            | "jira.add_attachment"
            | "jira.automation.rule.create"
            | "jira.automation.rule.update"
            | "jira.automation.rule.enable"
            | "jira.automation.rule.disable"
            | "jira.sync.push_bead" => "jira.write",
            _ => "jira.read",
        };
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
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
        assert_eq!(result["manifest_hash"], JiraConnector::manifest_hash());
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_requires_configure() {
        let mut connector = JiraConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["jira.read"]
            }))
            .await;
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = JiraConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let connector = JiraConnector::new();
        let signing_key = Ed25519SigningKey::generate();
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
    async fn test_invoke_without_handshake() {
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
        let token = generate_valid_token(&signing_key, "jira.get_issue");
        let result = connector
            .handle_invoke(json!({
                "operation": "jira.get_issue",
                "input": { "issue_key": "PROJ-1" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotHandshaken));
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
        assert!(op_ids.contains(&"jira.sync.pull_issue"));
        assert!(op_ids.contains(&"jira.sync.push_bead"));
        assert!(op_ids.contains(&"jira.sync.reconcile"));
        assert!(op_ids.contains(&"jira.server.info"));
        assert_eq!(ops.len(), 27);
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

    #[test]
    fn connector_base_id_matches_manifest() {
        let connector = JiraConnector::new();
        assert_eq!(connector.base.id.as_ref(), "fcp.jira");
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
    async fn test_shutdown_clears_state() {
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

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["jira.read"]
            }))
            .await
            .unwrap();

        connector.handle_shutdown(json!({})).await.unwrap();

        assert!(connector.client.is_none());
        assert!(connector.config.is_none());
        assert!(connector.verifier.is_none());
        assert!(connector.session_id.is_none());
        assert!(connector.zone_dir.is_none());

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "not_configured");
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

    fn unique_zone_dir(label: &str) -> PathBuf {
        let unique = format!("jira-sync-{label}-{}", Uuid::new_v4());
        std::env::temp_dir().join(unique)
    }

    fn sample_sync_issue() -> JiraIssue {
        JiraIssue {
            id: "10010".into(),
            key: "PROJ-10".into(),
            self_url: None,
            fields: Some(json!({
                "summary": "Ship Jira sync",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{ "type": "text", "text": "Normalize records" }]
                    }]
                },
                "status": { "name": "In Progress" },
                "priority": { "name": "High" },
                "labels": ["backend", "bead:br-123"],
                "assignee": { "id": "acct-1" },
                "duedate": "2026-03-31",
                "updated": "2026-03-09T10:00:00+00:00",
                "timetracking": { "originalEstimateSeconds": 5400 }
            })),
            changelog: None,
        }
    }

    fn sample_sync_bead() -> JiraBeadRecord {
        normalize_bead_record(JiraBeadRecord {
            bead_id: "br-123".into(),
            title: "Ship Jira sync".into(),
            description: Some("Normalize records".into()),
            status: Some("In Progress".into()),
            priority: Some("High".into()),
            labels: vec!["backend".into()],
            assignee: Some("acct-1".into()),
            due_date: Some("2026-03-31".into()),
            estimate_seconds: Some(5400),
            issue_key: Some("PROJ-10".into()),
            issue_id: Some("10010".into()),
            revision: Some("2026-03-09T10:00:00+00:00".into()),
        })
    }

    #[test]
    fn sync_issue_projection_extracts_bead_label_and_adf_text() {
        let bead = issue_to_bead_record(&sample_sync_issue(), None, None).unwrap();

        assert_eq!(bead.bead_id, "br-123");
        assert_eq!(bead.title, "Ship Jira sync");
        assert_eq!(bead.description.as_deref(), Some("Normalize records"));
        assert_eq!(bead.status.as_deref(), Some("in progress"));
        assert_eq!(bead.priority.as_deref(), Some("high"));
        assert_eq!(bead.labels, vec!["backend"]);
        assert_eq!(bead.assignee.as_deref(), Some("acct-1"));
        assert_eq!(bead.due_date.as_deref(), Some("2026-03-31"));
        assert_eq!(bead.estimate_seconds, Some(5400));
        assert_eq!(bead.revision.as_deref(), Some("2026-03-09T10:00:00+00:00"));
    }

    #[test]
    fn sync_issue_projection_prefers_custom_field_bead_id() {
        let mut issue = sample_sync_issue();
        issue.fields = Some(json!({
            "summary": "Ship Jira sync",
            "status": { "name": "Open" },
            "labels": ["backend", "bead:wrong"],
            "customfield_10123": "br-999",
            "updated": "2026-03-09T10:00:00+00:00"
        }));

        let bead = issue_to_bead_record(&issue, None, Some("customfield_10123")).unwrap();
        assert_eq!(bead.bead_id, "br-999");
        assert_eq!(bead.labels, vec!["backend"]);
    }

    #[test]
    fn sync_build_issue_fields_includes_control_label_for_label_mode() {
        let fields =
            build_issue_fields_from_bead(&sample_sync_bead(), JiraDeployment::Cloud, None, false);

        assert_eq!(fields.get("summary"), Some(&json!("Ship Jira sync")));
        assert_eq!(
            fields.get("labels"),
            Some(&json!(vec!["backend", "bead:br-123"]))
        );
        assert_eq!(
            fields.get("assignee"),
            Some(&json!({ "accountId": "acct-1" }))
        );
        assert!(fields.get("description").unwrap().is_object());
    }

    #[test]
    fn sync_reconcile_detects_concurrent_changes() {
        let baseline = sample_sync_bead();
        let state = build_sync_state(
            &baseline,
            &baseline,
            Some("2026-03-09T10:00:00+00:00".into()),
            None,
            JiraSyncOrigin::Jira,
        )
        .unwrap();

        let mut local_bead = baseline.clone();
        local_bead.title = "Local title".into();
        local_bead.revision = Some("2026-03-09T11:00:00+00:00".into());

        let mut remote_jira = baseline;
        remote_jira.title = "Remote title".into();
        remote_jira.revision = Some("2026-03-09T10:30:00+00:00".into());

        let (action, conflict) = decide_sync_action(
            &local_bead,
            &remote_jira,
            Some(&state),
            remote_jira.revision.as_deref(),
            JiraSyncConflictPolicy::FailClosed,
            JiraSyncOrigin::Beads,
        )
        .unwrap();

        assert_eq!(action, JiraSyncAction::Conflict);
        assert_eq!(conflict.unwrap().reason_code, "concurrent_changes_detected");
    }

    #[test]
    fn sync_reconcile_last_write_wins_prefers_newer_bead_revision() {
        let baseline = sample_sync_bead();
        let state = build_sync_state(
            &baseline,
            &baseline,
            Some("2026-03-09T10:00:00+00:00".into()),
            None,
            JiraSyncOrigin::Jira,
        )
        .unwrap();

        let mut local_bead = baseline.clone();
        local_bead.title = "Local title".into();
        local_bead.revision = Some("2026-03-09T11:00:00+00:00".into());

        let mut remote_jira = baseline;
        remote_jira.title = "Remote title".into();
        remote_jira.revision = Some("2026-03-09T10:30:00+00:00".into());

        let (action, conflict) = decide_sync_action(
            &local_bead,
            &remote_jira,
            Some(&state),
            remote_jira.revision.as_deref(),
            JiraSyncConflictPolicy::LastWriteWins,
            JiraSyncOrigin::Jira,
        )
        .unwrap();

        assert_eq!(action, JiraSyncAction::PushBead);
        assert!(conflict.is_none());
    }

    #[test]
    fn sync_lease_fences_second_holder() {
        let lease_root = unique_zone_dir("lease-fence");
        std::fs::create_dir_all(&lease_root).unwrap();
        let lease_path = lease_root.join(JIRA_SYNC_LEASE_FILE);

        let first = JiraSyncLease::acquire(
            lease_path.clone(),
            "holder-a".into(),
            JIRA_SYNC_LEASE_TTL_SECONDS,
        )
        .unwrap();
        let second =
            JiraSyncLease::acquire(lease_path, "holder-b".into(), JIRA_SYNC_LEASE_TTL_SECONDS);

        match second.unwrap_err() {
            FcpError::ResourceExhausted { resource } => {
                assert!(resource.contains("holder-a"));
            }
            other => panic!("expected ResourceExhausted, got {other:?}"),
        }

        first.release().unwrap();
    }

    #[test]
    fn compare_revision_markers_accepts_jira_timezone_offsets_without_colon() {
        let ordering = compare_revision_markers(
            Some("2026-03-09T10:30:00.000+0000"),
            Some("2026-03-09T10:00:00.000+0000"),
        );
        assert_eq!(ordering, Some(Ordering::Greater));
    }

    // ════════════════════════════════════════════════════════════════
    // Deployment configuration
    // ════════════════════════════════════════════════════════════════

    #[fcp_async_core::runtime::test]
    async fn test_configure_default_deployment_is_cloud() {
        let mut connector = JiraConnector::new();
        connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "user@example.com",
                "api_token": "secret-token"
            }))
            .await
            .unwrap();
        assert!(connector.config.is_some());
        let cfg = connector.config.as_ref().unwrap();
        assert_eq!(cfg.deployment, JiraDeployment::Cloud);
        let client = connector.client.as_ref().unwrap();
        assert_eq!(client.deployment(), JiraDeployment::Cloud);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_cloud_explicit() {
        let mut connector = JiraConnector::new();
        connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "user@example.com",
                "api_token": "secret-token",
                "deployment": "cloud"
            }))
            .await
            .unwrap();
        let cfg = connector.config.as_ref().unwrap();
        assert_eq!(cfg.deployment, JiraDeployment::Cloud);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_server_dc() {
        let mut connector = JiraConnector::new();
        connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "admin",
                "api_token": "password",
                "deployment": "server_dc"
            }))
            .await
            .unwrap();
        let cfg = connector.config.as_ref().unwrap();
        assert_eq!(cfg.deployment, JiraDeployment::ServerDc);
        let client = connector.client.as_ref().unwrap();
        assert_eq!(client.deployment(), JiraDeployment::ServerDc);
        assert_eq!(client.api_path(), "/rest/api/2");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_server_shorthand() {
        let mut connector = JiraConnector::new();
        connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "admin",
                "api_token": "password",
                "deployment": "server"
            }))
            .await
            .unwrap();
        let cfg = connector.config.as_ref().unwrap();
        assert_eq!(cfg.deployment, JiraDeployment::ServerDc);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_dc_shorthand() {
        let mut connector = JiraConnector::new();
        connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "admin",
                "api_token": "password",
                "deployment": "dc"
            }))
            .await
            .unwrap();
        let cfg = connector.config.as_ref().unwrap();
        assert_eq!(cfg.deployment, JiraDeployment::ServerDc);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_invalid_deployment() {
        let mut connector = JiraConnector::new();
        let result = connector
            .handle_configure(json!({
                "domain": "mycompany",
                "email": "admin",
                "api_token": "password",
                "deployment": "invalid_type"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_server_info_op() {
        let connector = JiraConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        // Find the server.info op and verify its properties
        let server_info_op = ops
            .iter()
            .find(|o| o["id"].as_str() == Some("jira.server.info"))
            .expect("jira.server.info operation should be present");
        assert_eq!(server_info_op["capability"], "jira.read");
        assert_eq!(server_info_op["risk_level"], "low");
        assert_eq!(server_info_op["safety_tier"], "safe");
    }
}
