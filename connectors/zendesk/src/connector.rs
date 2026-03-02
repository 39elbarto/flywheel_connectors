//! FCP Zendesk Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::ZendeskClient, error::ZendeskError};

/// FCP Zendesk Connector.
pub struct ZendeskConnector {
    base: Arc<BaseConnector>,
    client: Option<ZendeskClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl ZendeskConnector {
    /// Create a new Zendesk connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("zendesk"))),
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
        let subdomain =
            params
                .get("subdomain")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing subdomain in configuration".into(),
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

        let mut client =
            ZendeskClient::new(subdomain, email, api_token).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Zendesk connector configured");

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
            manifest_hash: "sha256:zendesk-connector-v1".into(),
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
                op_info(
                    "zendesk.create_ticket",
                    "Create a new support ticket",
                    json!({
                        "type": "object",
                        "required": ["subject"],
                        "properties": {
                            "subject": { "type": "string", "maxLength": 255 },
                            "description": { "type": "string" },
                            "priority": { "type": "string", "enum": ["urgent", "high", "normal", "low"] },
                            "status": { "type": "string", "enum": ["new", "open", "pending", "hold", "solved", "closed"] },
                            "type": { "type": "string", "enum": ["problem", "incident", "question", "task"] },
                            "requester_id": { "type": "integer" },
                            "assignee_id": { "type": "integer" },
                            "group_id": { "type": "integer" },
                            "tags": { "type": "array", "items": { "type": "string" } },
                            "custom_fields": { "type": "array", "items": { "type": "object" } }
                        }
                    }),
                    json!({ "type": "object", "required": ["ticket"], "properties": { "ticket": { "type": "object" } } }),
                    "zendesk.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new support ticket. At minimum requires a subject.".into(),
                        common_mistakes: vec![
                            "Not providing a description (creates an empty ticket).".into(),
                            "Using group name instead of group_id.".into(),
                        ],
                        examples: vec![
                            r#"{"subject": "Login issue", "description": "Cannot log in since update", "priority": "high", "type": "problem"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("zendesk.get_ticket"),
                            CapabilityId::from_static("zendesk.update_ticket"),
                            CapabilityId::from_static("zendesk.search_tickets"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.get_ticket",
                    "Get a single ticket by ID",
                    json!({
                        "type": "object",
                        "required": ["ticket_id"],
                        "properties": { "ticket_id": { "type": "integer" } }
                    }),
                    json!({ "type": "object", "required": ["ticket"], "properties": { "ticket": { "type": "object" } } }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a specific ticket by its numeric ID.".into(),
                        common_mistakes: vec!["Using ticket subject instead of ticket ID.".into()],
                        examples: vec![r#"{"ticket_id": 12345}"#.into()],
                        related: vec![
                            CapabilityId::from_static("zendesk.update_ticket"),
                            CapabilityId::from_static("zendesk.list_ticket_comments"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.update_ticket",
                    "Update fields on an existing ticket",
                    json!({
                        "type": "object",
                        "required": ["ticket_id"],
                        "properties": {
                            "ticket_id": { "type": "integer" },
                            "status": { "type": "string", "enum": ["new", "open", "pending", "hold", "solved", "closed"] },
                            "priority": { "type": "string", "enum": ["urgent", "high", "normal", "low"] },
                            "assignee_id": { "type": "integer" },
                            "tags": { "type": "array", "items": { "type": "string" } },
                            "comment": { "type": "object" },
                            "custom_fields": { "type": "array", "items": { "type": "object" } }
                        }
                    }),
                    json!({ "type": "object", "required": ["ticket"], "properties": { "ticket": { "type": "object" } } }),
                    "zendesk.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Modify ticket fields (status, priority, assignee, tags). Can also add a comment in the same call.".into(),
                        common_mistakes: vec![
                            "Setting status to 'closed' directly (must go through 'solved' first in most workflows).".into(),
                            "Not including a comment body when adding a public comment.".into(),
                        ],
                        examples: vec![
                            r#"{"ticket_id": 12345, "status": "solved", "comment": {"body": "Issue resolved.", "public": true}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("zendesk.get_ticket"),
                            CapabilityId::from_static("zendesk.list_ticket_comments"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.delete_ticket",
                    "Permanently delete a ticket (irreversible)",
                    json!({
                        "type": "object",
                        "required": ["ticket_id"],
                        "properties": { "ticket_id": { "type": "integer" } }
                    }),
                    json!({ "type": "object" }),
                    "zendesk.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Permanently delete a ticket. Cannot be undone.".into(),
                        common_mistakes: vec!["Deleting tickets that should be 'closed' instead.".into()],
                        examples: vec![r#"{"ticket_id": 12345}"#.into()],
                        related: vec![CapabilityId::from_static("zendesk.get_ticket")],
                    },
                ),
                op_info(
                    "zendesk.search_tickets",
                    "Search tickets using Zendesk search syntax with pagination",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" },
                            "sort_by": { "type": "string", "enum": ["created_at", "updated_at", "priority", "status", "ticket_type"] },
                            "sort_order": { "type": "string", "enum": ["asc", "desc"] },
                            "page": { "type": "integer", "minimum": 1 },
                            "per_page": { "type": "integer", "minimum": 1, "maximum": 100 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["results", "count"],
                        "properties": {
                            "results": { "type": "array", "items": { "type": "object" } },
                            "count": { "type": "integer" },
                            "next_page": { "type": "string" }
                        }
                    }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search tickets using Zendesk query syntax. Supports filtering by status, priority, assignee, tags, and more.".into(),
                        common_mistakes: vec![
                            "Using JQL or SQL syntax instead of Zendesk search syntax.".into(),
                            "Not handling pagination for large result sets.".into(),
                            "Search results are eventually consistent -- may not include very recent tickets.".into(),
                        ],
                        examples: vec![
                            r#"{"query": "status:open priority:urgent", "sort_by": "created_at", "sort_order": "desc"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("zendesk.get_ticket"),
                            CapabilityId::from_static("zendesk.create_ticket"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.list_ticket_comments",
                    "List comments on a ticket",
                    json!({
                        "type": "object",
                        "required": ["ticket_id"],
                        "properties": {
                            "ticket_id": { "type": "integer" },
                            "sort_order": { "type": "string", "enum": ["asc", "desc"] }
                        }
                    }),
                    json!({ "type": "object", "required": ["comments"], "properties": { "comments": { "type": "array", "items": { "type": "object" } } } }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve the comment thread on a ticket.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"ticket_id": 12345, "sort_order": "asc"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("zendesk.get_ticket"),
                            CapabilityId::from_static("zendesk.update_ticket"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.search_articles",
                    "Search Help Center knowledge base articles",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" },
                            "locale": { "type": "string" },
                            "category_id": { "type": "integer" },
                            "per_page": { "type": "integer", "minimum": 1, "maximum": 100 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["results", "count"],
                        "properties": {
                            "results": { "type": "array", "items": { "type": "object" } },
                            "count": { "type": "integer" }
                        }
                    }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search the Help Center knowledge base for articles matching a query.".into(),
                        common_mistakes: vec!["Not specifying locale for multi-language Help Centers.".into()],
                        examples: vec![r#"{"query": "password reset", "locale": "en-us"}"#.into()],
                        related: vec![CapabilityId::from_static("zendesk.get_article")],
                    },
                ),
                op_info(
                    "zendesk.get_article",
                    "Get a single Help Center article by ID",
                    json!({
                        "type": "object",
                        "required": ["article_id"],
                        "properties": {
                            "article_id": { "type": "integer" },
                            "locale": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "required": ["article"], "properties": { "article": { "type": "object" } } }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a specific Help Center article by its ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"article_id": 360001234567}"#.into()],
                        related: vec![CapabilityId::from_static("zendesk.search_articles")],
                    },
                ),
                op_info(
                    "zendesk.search_users",
                    "Search Zendesk users (customers and agents)",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["users", "count"],
                        "properties": {
                            "users": { "type": "array", "items": { "type": "object" } },
                            "count": { "type": "integer" }
                        }
                    }),
                    "zendesk.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for customers or agents by name, email, or other criteria.".into(),
                        common_mistakes: vec!["Not using quotes for exact email matches.".into()],
                        examples: vec![r#"{"query": "email:customer@example.com"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("zendesk.create_ticket"),
                            CapabilityId::from_static("zendesk.get_ticket"),
                        ],
                    },
                ),
                op_info(
                    "zendesk.apply_macro",
                    "Apply a macro to a ticket (predefined set of actions)",
                    json!({
                        "type": "object",
                        "required": ["ticket_id", "macro_id"],
                        "properties": {
                            "ticket_id": { "type": "integer" },
                            "macro_id": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "required": ["result"], "properties": { "result": { "type": "object" } } }),
                    "zendesk.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Apply a predefined macro to a ticket. Macros can change status, add comments, set fields, etc.".into(),
                        common_mistakes: vec!["Using macro name instead of macro_id.".into()],
                        examples: vec![r#"{"ticket_id": 12345, "macro_id": 67890}"#.into()],
                        related: vec![CapabilityId::from_static("zendesk.update_ticket")],
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
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
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
            "zendesk.create_ticket" => self.invoke_create_ticket(input).await,
            "zendesk.get_ticket" => self.invoke_get_ticket(input).await,
            "zendesk.update_ticket" => self.invoke_update_ticket(input).await,
            "zendesk.delete_ticket" => self.invoke_delete_ticket(input).await,
            "zendesk.search_tickets" => self.invoke_search_tickets(input).await,
            "zendesk.list_ticket_comments" => self.invoke_list_ticket_comments(input).await,
            "zendesk.search_articles" => self.invoke_search_articles(input).await,
            "zendesk.get_article" => self.invoke_get_article(input).await,
            "zendesk.search_users" => self.invoke_search_users(input).await,
            "zendesk.apply_macro" => self.invoke_apply_macro(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_ticket(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        require_str(&input, "subject")?;
        let result = client
            .create_ticket(&input)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_get_ticket(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let ticket_id = require_i64(&input, "ticket_id")?;
        let result = client
            .get_ticket(ticket_id)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_update_ticket(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let ticket_id = require_i64(&input, "ticket_id")?;
        // Build the update payload excluding ticket_id
        let mut update_data = input.clone();
        if let Some(obj) = update_data.as_object_mut() {
            obj.remove("ticket_id");
        }
        let result = client
            .update_ticket(ticket_id, &update_data)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_delete_ticket(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let ticket_id = require_i64(&input, "ticket_id")?;
        let result = client
            .delete_ticket(ticket_id)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_search_tickets(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let sort_by = input.get("sort_by").and_then(|v| v.as_str());
        let sort_order = input.get("sort_order").and_then(|v| v.as_str());
        let page = input.get("page").and_then(|v| v.as_i64());
        let per_page = input.get("per_page").and_then(|v| v.as_i64());
        let result = client
            .search_tickets(query, sort_by, sort_order, page, per_page)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_list_ticket_comments(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let ticket_id = require_i64(&input, "ticket_id")?;
        let sort_order = input.get("sort_order").and_then(|v| v.as_str());
        let result = client
            .list_ticket_comments(ticket_id, sort_order)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_search_articles(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let locale = input.get("locale").and_then(|v| v.as_str());
        let category_id = input.get("category_id").and_then(|v| v.as_i64());
        let per_page = input.get("per_page").and_then(|v| v.as_i64());
        let result = client
            .search_articles(query, locale, category_id, per_page)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_get_article(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let article_id = require_i64(&input, "article_id")?;
        let locale = input.get("locale").and_then(|v| v.as_str());
        let result = client
            .get_article(article_id, locale)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_search_users(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let result = client
            .search_users(query)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_apply_macro(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let ticket_id = require_i64(&input, "ticket_id")?;
        let macro_id = require_i64(&input, "macro_id")?;
        let result = client
            .apply_macro(ticket_id, macro_id)
            .await
            .map_err(|e: ZendeskError| e.to_fcp_error())?;
        Ok(result)
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(&self, _params: serde_json::Value) -> FcpResult<serde_json::Value> {
        info!("Zendesk connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for ZendeskConnector {
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

fn require_i64(input: &serde_json::Value, field: &str) -> FcpResult<i64> {
    input
        .get(field)
        .and_then(|v| v.as_i64())
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
        let mut connector = ZendeskConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["zendesk.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = ZendeskConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["zendesk.get_ticket"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "zendesk.get_ticket");
        let result = connector
            .handle_invoke(json!({
                "operation": "zendesk.get_ticket",
                "input": { "ticket_id": 123 },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = ZendeskConnector::new();
        connector.client = Some(
            ZendeskClient::new("test", "user@test.com", "token123")
                .unwrap()
                .with_base_url("http://localhost:9999/api/v2"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["zendesk.get_ticket"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "zendesk.get_ticket");
        let result = connector
            .handle_invoke(json!({
                "operation": "zendesk.get_ticket",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("ticket_id")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = ZendeskConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"zendesk.create_ticket"));
        assert!(op_ids.contains(&"zendesk.get_ticket"));
        assert!(op_ids.contains(&"zendesk.update_ticket"));
        assert!(op_ids.contains(&"zendesk.delete_ticket"));
        assert!(op_ids.contains(&"zendesk.search_tickets"));
        assert!(op_ids.contains(&"zendesk.list_ticket_comments"));
        assert!(op_ids.contains(&"zendesk.search_articles"));
        assert!(op_ids.contains(&"zendesk.get_article"));
        assert!(op_ids.contains(&"zendesk.search_users"));
        assert!(op_ids.contains(&"zendesk.apply_macro"));
        assert_eq!(ops.len(), 10);
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
