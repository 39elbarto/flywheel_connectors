//! FCP Jira Connector implementation.

use std::sync::Arc;

use base64::Engine;
use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::JiraClient, error::JiraError};

/// FCP Jira Connector.
pub struct JiraConnector {
    base: Arc<BaseConnector>,
    pub(crate) client: Option<JiraClient>,
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
        let domain =
            params
                .get("domain")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing domain in configuration".into(),
                })?;

        let email =
            params
                .get("email")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing email in configuration".into(),
                })?;

        let api_token =
            params
                .get("api_token")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_token in configuration".into(),
                })?;

        let base_url = params.get("base_url").and_then(|v| v.as_str());
        let agile_url = params.get("agile_url").and_then(|v| v.as_str());

        let mut client = JiraClient::new(domain, email, api_token).map_err(|e| {
            FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            }
        })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }
        if let Some(url) = agile_url {
            client = client.with_agile_url(url);
        }

        self.client = Some(client);
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
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
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
    pub async fn handle_simulate(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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
            "jira.add_attachment" => self.invoke_add_attachment(input).await,
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
        let fields = input
            .get("fields")
            .ok_or(FcpError::InvalidRequest {
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

    async fn invoke_list_sprints(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let board_id = input
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
        let sprint_id = input
            .get("sprint_id")
            .and_then(|v| v.as_u64())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: sprint_id".into(),
            })?;
        let issues = input
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

    async fn invoke_list_comments(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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
        connector.client = Some(
            JiraClient::new("test", "user@example.com", "token")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );

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
        assert!(op_ids.contains(&"jira.add_attachment"));
        assert_eq!(ops.len(), 12);
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
        let computed = manifest.compute_interface_hash().expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2.compute_interface_hash().expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
