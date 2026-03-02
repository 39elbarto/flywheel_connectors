//! FCP Notion Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::NotionClient, error::NotionError};

/// FCP Notion Connector.
pub struct NotionConnector {
    base: Arc<BaseConnector>,
    client: Option<NotionClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl NotionConnector {
    /// Create a new Notion connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("notion"))),
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
        let token =
            params
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing token in configuration".into(),
                })?;

        let api_url = params.get("api_url").and_then(|v| v.as_str());

        let mut client = NotionClient::new(token).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = api_url {
            client = client.with_api_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Notion connector configured");

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
            manifest_hash: "sha256:notion-connector-v1".into(),
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
                    "notion.create_page",
                    "Create a new page in a database or as a child page",
                    json!({
                        "type": "object",
                        "required": ["parent", "properties"],
                        "properties": {
                            "parent": { "type": "object" },
                            "properties": { "type": "object" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new page or database entry in Notion.".into(),
                        common_mistakes: vec!["Not specifying the parent database or page ID".into()],
                        examples: vec![
                            r#"{"parent": {"database_id": "abc123"}, "properties": {"Name": {"title": [{"text": {"content": "New page"}}]}}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("notion.get_page"),
                            CapabilityId::from_static("notion.query_database"),
                        ],
                    },
                ),
                op_info(
                    "notion.get_page",
                    "Retrieve a Notion page by ID",
                    json!({
                        "type": "object",
                        "required": ["page_id"],
                        "properties": {
                            "page_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve details of a specific Notion page.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"page_id": "abc123-def456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("notion.create_page"),
                            CapabilityId::from_static("notion.update_page"),
                        ],
                    },
                ),
                op_info(
                    "notion.update_page",
                    "Update properties of a Notion page",
                    json!({
                        "type": "object",
                        "required": ["page_id", "properties"],
                        "properties": {
                            "page_id": { "type": "string" },
                            "properties": { "type": "object" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Update properties on an existing Notion page.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"page_id": "abc123", "properties": {"Status": {"select": {"name": "Done"}}}}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("notion.get_page")],
                    },
                ),
                op_info(
                    "notion.delete_page",
                    "Archive (soft-delete) a Notion page",
                    json!({
                        "type": "object",
                        "required": ["page_id"],
                        "properties": {
                            "page_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
                    "notion.delete",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Archive a Notion page (soft delete).".into(),
                        common_mistakes: vec!["Expecting permanent deletion — Notion only archives".into()],
                        examples: vec![r#"{"page_id": "abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("notion.get_page")],
                    },
                ),
                op_info(
                    "notion.query_database",
                    "Query a Notion database with filters and sorts",
                    json!({
                        "type": "object",
                        "required": ["database_id"],
                        "properties": {
                            "database_id": { "type": "string" },
                            "filter": { "type": "object" },
                            "start_cursor": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "results": { "type": "array" },
                            "has_more": { "type": "boolean" }
                        }
                    }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Query a database with optional filters.".into(),
                        common_mistakes: vec!["Not handling pagination with start_cursor".into()],
                        examples: vec![r#"{"database_id": "abc123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("notion.get_page"),
                            CapabilityId::from_static("notion.search"),
                        ],
                    },
                ),
                op_info(
                    "notion.search",
                    "Search pages and databases across the workspace",
                    json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "string" },
                            "filter": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "results": { "type": "array" },
                            "has_more": { "type": "boolean" }
                        }
                    }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search across all pages and databases.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"query": "meeting notes"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("notion.query_database"),
                            CapabilityId::from_static("notion.get_page"),
                        ],
                    },
                ),
                op_info(
                    "notion.get_block_children",
                    "Get child blocks of a block or page",
                    json!({
                        "type": "object",
                        "required": ["block_id"],
                        "properties": {
                            "block_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "results": { "type": "array" },
                            "has_more": { "type": "boolean" }
                        }
                    }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read the content blocks of a page.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"block_id": "abc123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("notion.get_page"),
                            CapabilityId::from_static("notion.append_blocks"),
                        ],
                    },
                ),
                op_info(
                    "notion.append_blocks",
                    "Append child blocks to a page or block",
                    json!({
                        "type": "object",
                        "required": ["block_id", "children"],
                        "properties": {
                            "block_id": { "type": "string" },
                            "children": { "type": "array" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "results": { "type": "array" }
                        }
                    }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Add content blocks to a page.".into(),
                        common_mistakes: vec!["Exceeding 100 blocks per request".into()],
                        examples: vec![
                            r#"{"block_id": "abc123", "children": [{"object": "block", "type": "paragraph", "paragraph": {"rich_text": [{"text": {"content": "Hello"}}]}}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("notion.get_block_children")],
                    },
                ),
                op_info(
                    "notion.add_comment",
                    "Add a comment to a page or discussion",
                    json!({
                        "type": "object",
                        "required": ["parent", "rich_text"],
                        "properties": {
                            "parent": { "type": "object" },
                            "rich_text": { "type": "array" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "comment": { "type": "object" } } }),
                    "notion.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Add a comment to a Notion page.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"parent": {"page_id": "abc123"}, "rich_text": [{"text": {"content": "Looks good!"}}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("notion.list_comments")],
                    },
                ),
                op_info(
                    "notion.list_comments",
                    "List comments on a page or block",
                    json!({
                        "type": "object",
                        "required": ["block_id"],
                        "properties": {
                            "block_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "results": { "type": "array" },
                            "has_more": { "type": "boolean" }
                        }
                    }),
                    "notion.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read comments on a page.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"block_id": "abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("notion.add_comment")],
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
            "notion.create_page" => self.invoke_create_page(input).await,
            "notion.get_page" => self.invoke_get_page(input).await,
            "notion.update_page" => self.invoke_update_page(input).await,
            "notion.delete_page" => self.invoke_delete_page(input).await,
            "notion.query_database" => self.invoke_query_database(input).await,
            "notion.search" => self.invoke_search(input).await,
            "notion.get_block_children" => self.invoke_get_block_children(input).await,
            "notion.append_blocks" => self.invoke_append_blocks(input).await,
            "notion.add_comment" => self.invoke_add_comment(input).await,
            "notion.list_comments" => self.invoke_list_comments(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_page(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        if input.get("parent").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: parent".into(),
            });
        }

        let page = client
            .create_page(input)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_get_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_id = require_str(&input, "page_id")?;

        let page = client
            .get_page(page_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_update_page(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_id = require_str(&input, "page_id")?;
        let properties = input.get("properties").cloned().unwrap_or(json!({}));

        let body = json!({ "properties": properties });
        let page = client
            .update_page(page_id, body)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_delete_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_id = require_str(&input, "page_id")?;

        let page = client
            .delete_page(page_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "page": page }))
    }

    async fn invoke_query_database(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let database_id = require_str(&input, "database_id")?;
        let filter = input.get("filter").cloned();
        let start_cursor = input.get("start_cursor").and_then(|v| v.as_str());

        let result = client
            .query_database(database_id, filter, start_cursor)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({
            "results": result.results,
            "has_more": result.has_more,
            "next_cursor": result.next_cursor
        }))
    }

    async fn invoke_search(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = input.get("query").and_then(|v| v.as_str());
        let filter = input.get("filter").cloned();

        let result = client
            .search(query, filter)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({
            "results": result.results,
            "has_more": result.has_more,
            "next_cursor": result.next_cursor
        }))
    }

    async fn invoke_get_block_children(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let result = client
            .get_block_children(block_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({
            "results": result.results,
            "has_more": result.has_more
        }))
    }

    async fn invoke_append_blocks(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let children = input.get("children").cloned().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: children".into(),
        })?;

        let result = client
            .append_blocks(block_id, children)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "results": result.results }))
    }

    async fn invoke_add_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        if input.get("parent").is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: parent".into(),
            });
        }

        let comment = client
            .add_comment(input)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({ "comment": comment }))
    }

    async fn invoke_list_comments(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let block_id = require_str(&input, "block_id")?;

        let result = client
            .list_comments(block_id)
            .await
            .map_err(|e: NotionError| e.to_fcp_error())?;

        Ok(json!({
            "results": result.results,
            "has_more": result.has_more
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Notion connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for NotionConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

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
        let mut connector = NotionConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["notion.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = NotionConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = NotionConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["notion.get_page"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "notion.get_page");

        let result = connector
            .handle_invoke(json!({
                "operation": "notion.get_page",
                "input": { "page_id": "page-123" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = NotionConnector::new();
        connector.client = Some(
            NotionClient::new("fake_key")
                .unwrap()
                .with_api_url("http://localhost:9999/v1"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["notion.get_page"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "notion.get_page");

        let result = connector
            .handle_invoke(json!({
                "operation": "notion.get_page",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("page_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = NotionConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"notion.create_page"));
        assert!(op_ids.contains(&"notion.get_page"));
        assert!(op_ids.contains(&"notion.update_page"));
        assert!(op_ids.contains(&"notion.delete_page"));
        assert!(op_ids.contains(&"notion.query_database"));
        assert!(op_ids.contains(&"notion.search"));
        assert!(op_ids.contains(&"notion.get_block_children"));
        assert!(op_ids.contains(&"notion.append_blocks"));
        assert!(op_ids.contains(&"notion.add_comment"));
        assert!(op_ids.contains(&"notion.list_comments"));
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
}
