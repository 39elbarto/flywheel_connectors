//! FCP Figma Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::FigmaClient, error::FigmaError};

/// FCP Figma Connector.
pub struct FigmaConnector {
    base: Arc<BaseConnector>,
    client: Option<FigmaClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl FigmaConnector {
    /// Create a new Figma connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("figma"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
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

        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let mut client = FigmaClient::new(token).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Figma connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
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
            manifest_hash: "sha256:figma-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 25,
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                // ── Design Knowledge ──────────────────────────────────
                op_info(
                    "figma.get_file",
                    "Get a Figma file's document tree",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "ids": { "type": "string", "description": "Comma-separated node IDs" },
                            "depth": { "type": "integer", "description": "Traversal depth", "minimum": 1 },
                            "geometry": { "type": "string", "description": "Include vector path data", "enum": ["paths"] },
                            "plugin_data": { "type": "string", "description": "Plugin IDs for data inclusion" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["name", "document", "lastModified", "version"],
                        "properties": {
                            "name": { "type": "string" },
                            "document": { "type": "object" },
                            "lastModified": { "type": "string" },
                            "version": { "type": "string" },
                            "components": { "type": "object" },
                            "styles": { "type": "object" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a Figma file's full or partial document tree.".into(),
                        common_mistakes: vec![
                            "Not using ids parameter for large files.".into(),
                            "Confusing file_key with node IDs.".into(),
                        ],
                        examples: vec![
                            r#"{"file_key": "abc123DEF456"}"#.into(),
                            r#"{"file_key": "abc123DEF456", "ids": "1:2,3:4", "depth": 2}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("figma.get_file_nodes"),
                            CapabilityId::from_static("figma.list_file_versions"),
                        ],
                    },
                ),
                op_info(
                    "figma.get_file_nodes",
                    "Get specific nodes from a Figma file by ID",
                    json!({
                        "type": "object",
                        "required": ["file_key", "ids"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "ids": { "type": "string", "description": "Comma-separated node IDs (e.g., '1:2,3:4')" },
                            "depth": { "type": "integer", "description": "Traversal depth per node", "minimum": 1 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["nodes"],
                        "properties": { "nodes": { "type": "object" } }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve specific nodes by ID. More efficient than get_file for targeted access.".into(),
                        common_mistakes: vec!["Using wrong node ID format (should be 'X:Y').".into()],
                        examples: vec![r#"{"file_key": "abc123DEF456", "ids": "1:2,3:4"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.get_file"),
                            CapabilityId::from_static("figma.export_images"),
                        ],
                    },
                ),
                op_info(
                    "figma.get_file_components",
                    "Get all components published in a file",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["meta"],
                        "properties": { "meta": { "type": "object" } }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all published components in a file's library.".into(),
                        common_mistakes: vec!["Confusing file components with team library components.".into()],
                        examples: vec![r#"{"file_key": "abc123DEF456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.get_file"),
                            CapabilityId::from_static("figma.get_file_styles"),
                        ],
                    },
                ),
                op_info(
                    "figma.get_file_styles",
                    "Get all published styles in a file",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["meta"],
                        "properties": { "meta": { "type": "object" } }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all published styles (colors, text, effects, grids) in a file.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"file_key": "abc123DEF456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.get_file"),
                            CapabilityId::from_static("figma.get_file_components"),
                        ],
                    },
                ),
                // ── Image Export ──────────────────────────────────────
                op_info(
                    "figma.export_images",
                    "Export node(s) as PNG, SVG, JPG, or PDF",
                    json!({
                        "type": "object",
                        "required": ["file_key", "ids", "format"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "ids": { "type": "string", "description": "Comma-separated node IDs" },
                            "format": { "type": "string", "description": "Export format", "enum": ["png", "svg", "jpg", "pdf"] },
                            "scale": { "type": "number", "description": "Export scale (0.01 - 4.0)", "minimum": 0.01, "maximum": 4.0 },
                            "svg_include_id": { "type": "boolean" },
                            "svg_simplify_stroke": { "type": "boolean" },
                            "use_absolute_bounds": { "type": "boolean" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["images"],
                        "properties": {
                            "images": { "type": "object" },
                            "err": { "type": "string" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Export design nodes as images. Returns time-limited download URLs.".into(),
                        common_mistakes: vec![
                            "Not downloading images before URL expires.".into(),
                            "Exporting at high scale for very large frames.".into(),
                        ],
                        examples: vec![r#"{"file_key": "abc123DEF456", "ids": "1:2", "format": "png", "scale": 2.0}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.get_file_nodes"),
                            CapabilityId::from_static("figma.get_file"),
                        ],
                    },
                ),
                // ── Version History ──────────────────────────────────
                op_info(
                    "figma.list_file_versions",
                    "List version history for a file",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["versions"],
                        "properties": {
                            "versions": { "type": "array", "items": { "type": "object" } },
                            "pagination": { "type": "object" }
                        }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve version history for a Figma file.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"file_key": "abc123DEF456"}"#.into()],
                        related: vec![CapabilityId::from_static("figma.get_file")],
                    },
                ),
                // ── Comments ─────────────────────────────────────────
                op_info(
                    "figma.list_comments",
                    "List comments on a Figma file",
                    json!({
                        "type": "object",
                        "required": ["file_key"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "as_md": { "type": "boolean", "description": "Return as Markdown" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["comments"],
                        "properties": { "comments": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve all comments and replies on a Figma file.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"file_key": "abc123DEF456"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.post_comment"),
                            CapabilityId::from_static("figma.get_file"),
                        ],
                    },
                ),
                op_info(
                    "figma.post_comment",
                    "Post a comment on a Figma file",
                    json!({
                        "type": "object",
                        "required": ["file_key", "message"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "message": { "type": "string", "description": "Comment body text" },
                            "comment_id": { "type": "string", "description": "Reply to comment by ID" },
                            "client_meta": { "type": "object", "description": "Anchor position" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "message", "created_at"],
                        "properties": {
                            "id": { "type": "string" },
                            "message": { "type": "string" },
                            "created_at": { "type": "string" },
                            "user": { "type": "object" }
                        }
                    }),
                    "figma.write",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Add a comment to a Figma file. Can be top-level or reply.".into(),
                        common_mistakes: vec![
                            "Not providing client_meta when anchoring to a specific element.".into(),
                        ],
                        examples: vec![
                            r#"{"file_key": "abc123DEF456", "message": "Looks great!"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("figma.list_comments"),
                            CapabilityId::from_static("figma.delete_comment"),
                        ],
                    },
                ),
                op_info(
                    "figma.delete_comment",
                    "Delete a comment from a Figma file",
                    json!({
                        "type": "object",
                        "required": ["file_key", "comment_id"],
                        "properties": {
                            "file_key": { "type": "string", "description": "Figma file key" },
                            "comment_id": { "type": "string", "description": "Comment ID to delete" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "figma.delete",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Delete a comment. Only the author or file owner can delete.".into(),
                        common_mistakes: vec!["Trying to delete comments authored by other users.".into()],
                        examples: vec![r#"{"file_key": "abc123DEF456", "comment_id": "12345"}"#.into()],
                        related: vec![CapabilityId::from_static("figma.list_comments")],
                    },
                ),
                // ── Webhooks ─────────────────────────────────────────
                op_info(
                    "figma.list_webhooks",
                    "List all webhooks registered for a team",
                    json!({
                        "type": "object",
                        "required": ["team_id"],
                        "properties": {
                            "team_id": { "type": "string", "description": "Team ID" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["webhooks"],
                        "properties": { "webhooks": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "figma.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all registered webhooks for a team.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"team_id": "12345"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("figma.create_webhook"),
                            CapabilityId::from_static("figma.delete_webhook"),
                        ],
                    },
                ),
                op_info(
                    "figma.create_webhook",
                    "Register a webhook for file change events",
                    json!({
                        "type": "object",
                        "required": ["team_id", "event_type", "endpoint", "passcode"],
                        "properties": {
                            "team_id": { "type": "string", "description": "Team ID" },
                            "event_type": { "type": "string", "description": "Event type", "enum": ["FILE_UPDATE", "FILE_DELETE", "FILE_VERSION_UPDATE", "LIBRARY_PUBLISH", "FILE_COMMENT"] },
                            "endpoint": { "type": "string", "description": "HTTPS URL for webhook POST" },
                            "passcode": { "type": "string", "description": "Secret for signature verification" },
                            "description": { "type": "string", "description": "Webhook description" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "team_id", "event_type", "endpoint", "status"],
                        "properties": {
                            "id": { "type": "string" },
                            "team_id": { "type": "string" },
                            "event_type": { "type": "string" },
                            "endpoint": { "type": "string" },
                            "status": { "type": "string" }
                        }
                    }),
                    "figma.webhook",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Register a webhook to receive events for file updates, deletions, comments.".into(),
                        common_mistakes: vec![
                            "Not providing a valid HTTPS endpoint URL.".into(),
                            "Forgetting the passcode for signature verification.".into(),
                        ],
                        examples: vec![
                            r#"{"team_id": "12345", "event_type": "FILE_UPDATE", "endpoint": "https://example.com/webhook", "passcode": "secret123"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("figma.list_webhooks"),
                            CapabilityId::from_static("figma.delete_webhook"),
                        ],
                    },
                ),
                op_info(
                    "figma.delete_webhook",
                    "Delete a webhook subscription",
                    json!({
                        "type": "object",
                        "required": ["webhook_id"],
                        "properties": {
                            "webhook_id": { "type": "string", "description": "Webhook ID to delete" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "figma.delete",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Remove a webhook subscription.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"webhook_id": "67890"}"#.into()],
                        related: vec![CapabilityId::from_static("figma.list_webhooks")],
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
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
            "figma.get_file" => self.invoke_get_file(input).await,
            "figma.get_file_nodes" => self.invoke_get_file_nodes(input).await,
            "figma.get_file_components" => self.invoke_get_file_components(input).await,
            "figma.get_file_styles" => self.invoke_get_file_styles(input).await,
            "figma.export_images" => self.invoke_export_images(input).await,
            "figma.list_file_versions" => self.invoke_list_file_versions(input).await,
            "figma.list_comments" => self.invoke_list_comments(input).await,
            "figma.post_comment" => self.invoke_post_comment(input).await,
            "figma.delete_comment" => self.invoke_delete_comment(input).await,
            "figma.list_webhooks" => self.invoke_list_webhooks(input).await,
            "figma.create_webhook" => self.invoke_create_webhook(input).await,
            "figma.delete_webhook" => self.invoke_delete_webhook(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_get_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let ids = input.get("ids").and_then(|v| v.as_str());
        let depth = input
            .get("depth")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let geometry = input.get("geometry").and_then(|v| v.as_str());
        let plugin_data = input.get("plugin_data").and_then(|v| v.as_str());

        let file = client
            .get_file(file_key, ids, depth, geometry, plugin_data)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(file).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_get_file_nodes(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let ids = require_str(&input, "ids")?;
        let depth = input
            .get("depth")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let nodes = client
            .get_file_nodes(file_key, ids, depth)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(nodes).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_get_file_components(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;

        let components = client
            .get_file_components(file_key)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(components).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_get_file_styles(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;

        let styles = client
            .get_file_styles(file_key)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(styles).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_export_images(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let ids = require_str(&input, "ids")?;
        let format = require_str(&input, "format")?;
        let scale = input.get("scale").and_then(|v| v.as_f64());
        let svg_include_id = input.get("svg_include_id").and_then(|v| v.as_bool());
        let svg_simplify_stroke = input.get("svg_simplify_stroke").and_then(|v| v.as_bool());
        let use_absolute_bounds = input.get("use_absolute_bounds").and_then(|v| v.as_bool());

        let result = client
            .export_images(
                file_key,
                ids,
                format,
                scale,
                svg_include_id,
                svg_simplify_stroke,
                use_absolute_bounds,
            )
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_list_file_versions(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;

        let versions = client
            .list_file_versions(file_key)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(versions).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_list_comments(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let as_md = input.get("as_md").and_then(|v| v.as_bool());

        let comments = client
            .list_comments(file_key, as_md)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(comments).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_post_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let message = require_str(&input, "message")?;
        let comment_id = input.get("comment_id").and_then(|v| v.as_str());
        let client_meta = input.get("client_meta").cloned();

        let comment = client
            .post_comment(file_key, message, comment_id, client_meta)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(comment).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_delete_comment(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_key = require_str(&input, "file_key")?;
        let comment_id = require_str(&input, "comment_id")?;

        client
            .delete_comment(file_key, comment_id)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        Ok(json!({}))
    }

    async fn invoke_list_webhooks(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let team_id = require_str(&input, "team_id")?;

        let webhooks = client
            .list_webhooks(team_id)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(webhooks).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_create_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let team_id = require_str(&input, "team_id")?;
        let event_type = require_str(&input, "event_type")?;
        let endpoint = require_str(&input, "endpoint")?;
        let passcode = require_str(&input, "passcode")?;
        let description = input.get("description").and_then(|v| v.as_str());

        let webhook = client
            .create_webhook(team_id, event_type, endpoint, passcode, description)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        serde_json::to_value(webhook).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_delete_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let webhook_id = require_str(&input, "webhook_id")?;

        client
            .delete_webhook(webhook_id)
            .await
            .map_err(|e: FigmaError| e.to_fcp_error())?;

        Ok(json!({}))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Figma connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for FigmaConnector {
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
        let mut connector = FigmaConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["figma.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = FigmaConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_configured() {
        let mut connector = FigmaConnector::new();
        connector
            .handle_configure(json!({
                "token": "fake-token",
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = FigmaConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["figma.get_file"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "figma.get_file");

        let result = connector
            .handle_invoke(json!({
                "operation": "figma.get_file",
                "input": { "file_key": "abc123" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = FigmaConnector::new();
        connector.client = Some(
            FigmaClient::new("fake_key")
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
                "capabilities_requested": ["figma.get_file_nodes"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "figma.get_file_nodes");

        let result = connector
            .handle_invoke(json!({
                "operation": "figma.get_file_nodes",
                "input": { "file_key": "abc123" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("ids"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = FigmaConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"figma.get_file"));
        assert!(op_ids.contains(&"figma.get_file_nodes"));
        assert!(op_ids.contains(&"figma.get_file_components"));
        assert!(op_ids.contains(&"figma.get_file_styles"));
        assert!(op_ids.contains(&"figma.export_images"));
        assert!(op_ids.contains(&"figma.list_file_versions"));
        assert!(op_ids.contains(&"figma.list_comments"));
        assert!(op_ids.contains(&"figma.post_comment"));
        assert!(op_ids.contains(&"figma.delete_comment"));
        assert!(op_ids.contains(&"figma.list_webhooks"));
        assert!(op_ids.contains(&"figma.create_webhook"));
        assert!(op_ids.contains(&"figma.delete_webhook"));
        assert_eq!(ops.len(), 12);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unknown_operation_rejected() {
        let mut connector = FigmaConnector::new();
        connector.client = Some(
            FigmaClient::new("fake_key")
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
                "capabilities_requested": ["figma.nonexistent"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "figma.nonexistent");

        let result = connector
            .handle_invoke(json!({
                "operation": "figma.nonexistent",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FcpError::OperationNotGranted { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_token() {
        let mut connector = FigmaConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("token"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_returns_allowed() {
        let connector = FigmaConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let token = generate_valid_token(&signing_key, "figma.get_file");

        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-1",
                "connector_id": "figma",
                "operation": "figma.get_file",
                "zone_id": "z:work",
                "input": { "file_key": "abc123" },
                "capability_token": token
            }))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let connector = FigmaConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }
}
