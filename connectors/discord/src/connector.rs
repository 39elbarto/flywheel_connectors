//! FCP Connector implementation for Discord.
//!
//! Implements handler methods for FCP protocol with Discord-specific operations.

use std::sync::Arc;
use std::time::Instant;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, EventData, EventEnvelope, EventInfo, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, InstanceId, Introspection, OperationId, OperationInfo,
    Principal, RiskLevel, SafetyTier, SelfCheckReport, SessionId, SimulateRequest,
    SimulateResponse, TrustLevel, ZoneId,
};
use fcp_sdk::{
    Limits,
    runtime::{
        InMemoryStreamingSession, StreamingConnection, StreamingError, StreamingSupervisor,
        SupervisorConfig,
    },
    validate_input_with_limits, validate_output_with_limits,
};
use serde_json::json;
use tokio::sync::{broadcast, watch};
use tracing::info;

use crate::{
    api::DiscordApiClient,
    config::DiscordConfig,
    gateway::{GatewayConnection, GatewayEvent},
    types::Embed,
};

/// Discord FCP connector.
pub struct DiscordConnector {
    base: Arc<BaseConnector>,
    config: Option<DiscordConfig>,
    api_client: Option<Arc<DiscordApiClient>>,
    gateway: Option<Arc<GatewayConnection>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    bot_user_id: Option<String>,

    // Event broadcast
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,

    // Gateway task
    gateway_task: Option<tokio::task::JoinHandle<()>>,
    gateway_shutdown_tx: Option<watch::Sender<bool>>,

    // Metrics
    start_time: Instant,
}

impl DiscordConnector {
    /// Create a new Discord connector.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("discord"))),
            config: None,
            api_client: None,
            gateway: None,
            verifier: None,
            session_id: None,
            bot_user_id: None,
            event_tx,
            gateway_task: None,
            gateway_shutdown_tx: None,
            start_time: Instant::now(),
        }
    }

    /// Handle configure method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config: DiscordConfig =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid configuration: {e}"),
            })?;

        if config.bot_credential.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Missing required 'bot_credential' in configuration".into(),
            });
        }

        // Create API client
        let api_client = DiscordApiClient::new(&config).map_err(|e| FcpError::Internal {
            message: format!("Failed to create API client: {e}"),
        })?;

        let api_client = Arc::new(api_client);

        // Test connection by getting current user
        let user = api_client
            .get_current_user()
            .await
            .map_err(|e| FcpError::External {
                service: "discord".into(),
                message: format!("Failed to verify bot token: {e}"),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        info!(
            user_id = %user.id,
            username = %user.username,
            "Discord bot authenticated"
        );

        self.bot_user_id = Some(user.id.clone());
        self.api_client = Some(api_client.clone());
        self.gateway = Some(Arc::new(GatewayConnection::new(config.clone(), api_client)));
        self.config = Some(config);
        self.base.set_configured(true);

        Ok(json!({
            "status": "configured",
            "bot_user": {
                "id": user.id,
                "username": user.username
            }
        }))
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

        // Verify bot is configured
        if self.api_client.is_none() {
            return Err(FcpError::NotConfigured);
        }

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());

        // Connect to gateway
        self.connect_gateway().await?;
        self.base.set_handshaken(true);

        // Convert capability IDs to grants
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
            manifest_hash: "sha256:discord-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
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
        let Some(api_client) = &self.api_client else {
            return Ok(json!({
                "status": "not_configured",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64
            }));
        };

        // Check if we can reach Discord
        match api_client.get_current_user().await {
            Ok(_) => Ok(json!({
                "status": "ready",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "gateway_connected": self.gateway_task.is_some(),
                "metrics": self.base.metrics()
            })),
            Err(e) => Ok(json!({
                "status": "degraded",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "error": e.to_string()
            })),
        }
    }

    /// Handle connector self-check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(api_client) = &self.api_client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let report = match api_client.get_current_user().await {
            Ok(user) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "user_id": user.id,
                    "username": user.username,
                    "bot": user.bot,
                }));
                report
            }
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    fn send_message_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string", "description": "Channel ID" },
                "content": { "type": "string", "description": "Message content" },
                "embeds": { "type": "array", "items": { "type": "object" } },
                "reply_to": { "type": "string", "description": "Message ID to reply to" }
            },
            "required": ["channel_id"]
        })
    }

    fn send_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "channel_id": { "type": "string" },
                "content": { "type": "string" }
            }
        })
    }

    fn edit_message_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string" },
                "message_id": { "type": "string" },
                "content": { "type": "string" },
                "embeds": { "type": "array" }
            },
            "required": ["channel_id", "message_id"]
        })
    }

    fn edit_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "content": { "type": "string" }
            }
        })
    }

    fn delete_message_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string" },
                "message_id": { "type": "string" }
            },
            "required": ["channel_id", "message_id"]
        })
    }

    fn delete_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "deleted": { "type": "boolean" }
            }
        })
    }

    fn get_channel_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string" }
            },
            "required": ["channel_id"]
        })
    }

    fn get_channel_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "type": { "type": "integer" }
            }
        })
    }

    fn get_guild_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "guild_id": { "type": "string", "description": "Guild/server ID" }
            },
            "required": ["guild_id"]
        })
    }

    fn get_guild_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "icon": { "type": "string" },
                "owner_id": { "type": "string" }
            }
        })
    }

    fn trigger_typing_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string", "description": "Channel ID" }
            },
            "required": ["channel_id"]
        })
    }

    fn trigger_typing_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "triggered": { "type": "boolean" }
            }
        })
    }

    fn message_event_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "channel_id": { "type": "string" },
                "content": { "type": "string" },
                "author": { "type": "object" }
            }
        })
    }

    fn input_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "discord.send_message" => Some(Self::send_message_input_schema()),
            "discord.edit_message" => Some(Self::edit_message_input_schema()),
            "discord.delete_message" => Some(Self::delete_message_input_schema()),
            "discord.get_channel" => Some(Self::get_channel_input_schema()),
            "discord.get_guild" => Some(Self::get_guild_input_schema()),
            "discord.trigger_typing" => Some(Self::trigger_typing_input_schema()),
            _ => None,
        }
    }

    fn output_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "discord.send_message" => Some(Self::send_message_output_schema()),
            "discord.edit_message" => Some(Self::edit_message_output_schema()),
            "discord.delete_message" => Some(Self::delete_message_output_schema()),
            "discord.get_channel" => Some(Self::get_channel_output_schema()),
            "discord.get_guild" => Some(Self::get_guild_output_schema()),
            "discord.trigger_typing" => Some(Self::trigger_typing_output_schema()),
            _ => None,
        }
    }

    /// Handle introspection.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("discord.send_message"),
                    summary: "Send a message to a Discord channel".into(),
                    input_schema: Self::send_message_input_schema(),
                    output_schema: Self::send_message_output_schema(),
                    capability: CapabilityId::from_static("discord.send"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to a Discord channel.".into(),
                        common_mistakes: vec![
                            "Using channel names instead of IDs".into(),
                            "Exceeding 2000 character message limit".into(),
                        ],
                        examples: vec![
                            r#"{"channel_id": "123456789", "content": "Hello!"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.edit_message"),
                    summary: "Edit a message in a Discord channel".into(),
                    input_schema: Self::edit_message_input_schema(),
                    output_schema: Self::edit_message_output_schema(),
                    capability: CapabilityId::from_static("discord.edit"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Edit an existing Discord message.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.delete_message"),
                    summary: "Delete a message from a Discord channel".into(),
                    input_schema: Self::delete_message_input_schema(),
                    output_schema: Self::delete_message_output_schema(),
                    capability: CapabilityId::from_static("discord.delete"),
                    risk_level: RiskLevel::High,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Delete a Discord message (irreversible).".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.get_channel"),
                    summary: "Get information about a Discord channel".into(),
                    input_schema: Self::get_channel_input_schema(),
                    output_schema: Self::get_channel_output_schema(),
                    capability: CapabilityId::from_static("discord.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get channel metadata.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.get_guild"),
                    summary: "Get information about a Discord server (guild)".into(),
                    input_schema: Self::get_guild_input_schema(),
                    output_schema: Self::get_guild_output_schema(),
                    capability: CapabilityId::from_static("discord.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get Discord server/guild metadata.".into(),
                        common_mistakes: vec!["Using server name instead of guild ID".into()],
                        examples: vec![r#"{"guild_id": "123456789012345678"}"#.into()],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.trigger_typing"),
                    summary: "Show typing indicator in a Discord channel".into(),
                    input_schema: Self::trigger_typing_input_schema(),
                    output_schema: Self::trigger_typing_output_schema(),
                    capability: CapabilityId::from_static("discord.send"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use:
                            "Show typing indicator before sending a message (lasts 10 seconds)."
                                .into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"channel_id": "123456789012345678"}"#.into()],
                        related: vec![],
                    },
                },
            ],
            events: vec![EventInfo {
                topic: "discord.message".into(),
                schema: Self::message_event_schema(),
                requires_ack: false,
            }],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
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

    /// Validate input structure and limits before capability token verification.
    /// This is an optimization to avoid wasting resources on capability verification
    /// for requests that will fail validation anyway.
    fn validate_input_early(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
        const MAX_CONTENT_LENGTH: usize = 2000;
        const MAX_EMBEDS: usize = 10;
        const MAX_EMBED_TOTAL_CHARS: usize = 6000;

        if let Some(schema) = Self::input_schema_for(operation) {
            validate_input_with_limits(&schema, input, &Limits::default())?;
        }

        match operation {
            "discord.send_message" | "discord.edit_message" => {
                let content = input.get("content").and_then(|v| v.as_str());
                let embeds = input.get("embeds").and_then(|v| v.as_array());

                // For send_message, require either content or embeds
                if operation == "discord.send_message" && content.is_none() && embeds.is_none() {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "Either 'content' or 'embeds' must be provided".into(),
                    });
                }

                // Validate content length
                if let Some(content) = content {
                    if content.chars().count() > MAX_CONTENT_LENGTH {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Message content exceeds {MAX_CONTENT_LENGTH} character limit (got {} characters)",
                                content.chars().count()
                            ),
                        });
                    }
                }

                // Validate embed limits
                if let Some(embeds) = embeds {
                    if embeds.len() > MAX_EMBEDS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Too many embeds: {} exceeds limit of {MAX_EMBEDS}",
                                embeds.len()
                            ),
                        });
                    }

                    // Check total embed character count
                    let total_chars: usize = embeds
                        .iter()
                        .map(|e| {
                            let mut size = 0;

                            // Title
                            size += e.get("title").and_then(|v| v.as_str()).map_or(0, str::len);

                            // Description
                            size += e
                                .get("description")
                                .and_then(|v| v.as_str())
                                .map_or(0, str::len);

                            // Fields
                            if let Some(fields) = e.get("fields").and_then(|v| v.as_array()) {
                                for field in fields {
                                    size += field
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .map_or(0, str::len);
                                    size += field
                                        .get("value")
                                        .and_then(|v| v.as_str())
                                        .map_or(0, str::len);
                                }
                            }

                            // Footer
                            if let Some(footer) = e.get("footer") {
                                size += footer
                                    .get("text")
                                    .and_then(|v| v.as_str())
                                    .map_or(0, str::len);
                            }

                            // Author
                            if let Some(author) = e.get("author") {
                                size += author
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .map_or(0, str::len);
                            }

                            size
                        })
                        .sum();

                    if total_chars > MAX_EMBED_TOTAL_CHARS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Total embed character count {total_chars} exceeds limit of {MAX_EMBED_TOTAL_CHARS}"
                            ),
                        });
                    }
                }
            }
            _ => {
                // Other operations don't have early validation
            }
        }

        Ok(())
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
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        // Early validation: Check input structure and limits before capability token
        // This prevents wasting resources on capability verification for invalid requests
        Self::validate_input_early(operation, &input)?;

        // Extract and verify capability token
        let token_value =
            params
                .get("capability_token")
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;

        let token: fcp_core::CapabilityToken = serde_json::from_value(token_value.clone())
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        // Verify token
        // Extract target resources (channel_id, guild_id) from input to validate constraints.
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        let mut resource_uris = Vec::new();
        if let Some(channel_id) = input.get("channel_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("discord:channel:{channel_id}"));
        }
        if let Some(guild_id) = input.get("guild_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("discord:guild:{guild_id}"));
        }

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &resource_uris)?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "discord.send_message" => self.invoke_send_message(input).await,
            "discord.edit_message" => self.invoke_edit_message(input).await,
            "discord.delete_message" => self.invoke_delete_message(input).await,
            "discord.get_channel" => self.invoke_get_channel(input).await,
            "discord.get_guild" => self.invoke_get_guild(input).await,
            "discord.trigger_typing" => self.invoke_trigger_typing(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        const MAX_CONTENT_LENGTH: usize = 2000;

        // Validate input first (before checking api) for better error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let content = input.get("content").and_then(|v| v.as_str());
        let embeds: Option<Vec<Embed>> = input
            .get("embeds")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let reply_to = input.get("reply_to").and_then(|v| v.as_str());

        // Validate that at least content or embeds is provided
        if content.is_none() && embeds.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Either 'content' or 'embeds' must be provided".into(),
            });
        }

        // Validate message content length (Discord limit: 2000 characters)
        if let Some(content) = content {
            if content.chars().count() > MAX_CONTENT_LENGTH {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Message content exceeds {MAX_CONTENT_LENGTH} character limit (got {} characters)",
                        content.chars().count()
                    ),
                });
            }
        }

        // Validate embed limits
        if let Some(ref embeds) = embeds {
            const MAX_EMBEDS: usize = 10;
            const MAX_EMBED_TOTAL_CHARS: usize = 6000;
            const MAX_EMBED_TITLE: usize = 256;
            const MAX_EMBED_DESCRIPTION: usize = 4096;

            if embeds.len() > MAX_EMBEDS {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Too many embeds: {MAX_EMBEDS} maximum, got {}",
                        embeds.len()
                    ),
                });
            }

            let mut total_chars = 0;
            for (i, embed) in embeds.iter().enumerate() {
                if let Some(ref title) = embed.title {
                    if title.chars().count() > MAX_EMBED_TITLE {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} title exceeds {MAX_EMBED_TITLE} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += title.chars().count();
                }
                if let Some(ref desc) = embed.description {
                    if desc.chars().count() > MAX_EMBED_DESCRIPTION {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} description exceeds {MAX_EMBED_DESCRIPTION} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += desc.chars().count();
                }
                for field in &embed.fields {
                    total_chars += field.name.chars().count() + field.value.chars().count();
                }
                if let Some(ref footer) = embed.footer {
                    total_chars += footer.text.chars().count();
                }
                if let Some(ref author) = embed.author {
                    total_chars += author.name.chars().count();
                }
            }

            if total_chars > MAX_EMBED_TOTAL_CHARS {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Total embed content exceeds {MAX_EMBED_TOTAL_CHARS} character limit (got {total_chars} characters)",
                    ),
                });
            }
        }

        // Now check that we're configured
        let api = self.require_api()?;

        let message = api
            .create_message(channel_id, content, embeds, reply_to)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(message).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize message: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.send_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_edit_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        const MAX_CONTENT_LENGTH: usize = 2000;

        // Validate input first (before checking api) for better error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let content = input.get("content").and_then(|v| v.as_str());
        let embeds: Option<Vec<Embed>> = input
            .get("embeds")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        // Validate message content length (Discord limit: 2000 characters)
        if let Some(content) = content {
            if content.chars().count() > MAX_CONTENT_LENGTH {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Message content exceeds {MAX_CONTENT_LENGTH} character limit (got {} characters)",
                        content.chars().count()
                    ),
                });
            }
        }

        // Validate embed limits
        if let Some(ref embeds) = embeds {
            const MAX_EMBEDS: usize = 10;
            const MAX_EMBED_TOTAL_CHARS: usize = 6000;
            const MAX_EMBED_TITLE: usize = 256;
            const MAX_EMBED_DESCRIPTION: usize = 4096;

            if embeds.len() > MAX_EMBEDS {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Too many embeds: {MAX_EMBEDS} maximum, got {}",
                        embeds.len()
                    ),
                });
            }

            let mut total_chars = 0;
            for (i, embed) in embeds.iter().enumerate() {
                if let Some(ref title) = embed.title {
                    if title.chars().count() > MAX_EMBED_TITLE {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} title exceeds {MAX_EMBED_TITLE} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += title.chars().count();
                }
                if let Some(ref desc) = embed.description {
                    if desc.chars().count() > MAX_EMBED_DESCRIPTION {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} description exceeds {MAX_EMBED_DESCRIPTION} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += desc.chars().count();
                }
                for field in &embed.fields {
                    total_chars += field.name.chars().count() + field.value.chars().count();
                }
                if let Some(ref footer) = embed.footer {
                    total_chars += footer.text.chars().count();
                }
                if let Some(ref author) = embed.author {
                    total_chars += author.name.chars().count();
                }
            }

            if total_chars > MAX_EMBED_TOTAL_CHARS {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Total embed content exceeds {MAX_EMBED_TOTAL_CHARS} character limit (got {total_chars} characters)",
                    ),
                });
            }
        }

        // Now check that we're configured
        let api = self.require_api()?;

        let message = api
            .edit_message(channel_id, message_id, content, embeds)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(message).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize message: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.edit_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_delete_message(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let api = self.require_api()?;

        api.delete_message(channel_id, message_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({ "deleted": true });
        if let Some(schema) = Self::output_schema_for("discord.delete_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_get_channel(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let api = self.require_api()?;

        let channel = api
            .get_channel(channel_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(channel).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize channel: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.get_channel") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_get_guild(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let guild_id = input
            .get("guild_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing guild_id".into(),
            })?;

        let api = self.require_api()?;

        let guild = api
            .get_guild(guild_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(guild).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize guild: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.get_guild") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_trigger_typing(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let api = self.require_api()?;

        api.trigger_typing(channel_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({ "triggered": true });
        if let Some(schema) = Self::output_schema_for("discord.trigger_typing") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    /// Handle subscribe method.
    pub async fn handle_subscribe(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let topics = params
            .get("topics")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(json!({
            "confirmed_topics": topics,
            "replay_supported": false
        }))
    }

    /// Handle shutdown method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Shutting down Discord connector");

        if let Some(shutdown_tx) = self.gateway_shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }

        if let Some(task) = self.gateway_task.take() {
            task.abort();
        }

        Ok(json!({ "status": "shutdown" }))
    }

    /// Connect to the Discord gateway.
    async fn connect_gateway(&mut self) -> FcpResult<()> {
        if let Some(task) = &self.gateway_task {
            if !task.is_finished() {
                return Ok(()); // Already connected
            }
        }
        self.gateway_task = None;
        self.gateway_shutdown_tx = None;

        let gateway = self.gateway.clone().ok_or(FcpError::NotConfigured)?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.gateway_shutdown_tx = Some(shutdown_tx.clone());

        let event_tx = self.event_tx.clone();
        let connector_id = self.base.id.clone();
        let instance_id = self.base.instance_id.clone();
        let base = self.base.clone();

        let mut supervisor = StreamingSupervisor::new(
            SupervisorConfig {
                heartbeat_interval_ms: 0, // Gateway handles its own heartbeat
                ..SupervisorConfig::default()
            },
            InMemoryStreamingSession::new(),
        );

        let task = tokio::spawn(async move {
            let outcome = supervisor
                .run(
                    shutdown_rx,
                    |session| {
                        let gateway = Arc::clone(&gateway);
                        async move {
                            let stream = gateway
                                .connect_once()
                                .await
                                .map_err(|e| -> StreamingError { Box::new(e) })?;
                            let join_handle = tokio::spawn(async move {
                                match stream.join_handle.await {
                                    Ok(Ok(())) => Ok(()),
                                    Ok(Err(e)) => Err(Box::new(e) as StreamingError),
                                    Err(e) => Err(Box::new(e) as StreamingError),
                                }
                            });
                            let _ = session; // Session reserved for future use
                            Ok(StreamingConnection {
                                events: stream.events,
                                join_handle,
                            })
                        }
                    },
                    |gateway_event, _session| {
                        let event_tx = event_tx.clone();
                        let connector_id = connector_id.clone();
                        let instance_id = instance_id.clone();
                        let base = base.clone();
                        let shutdown_tx = shutdown_tx.clone();
                        async move {
                            if let Some(event) =
                                gateway_event_to_fcp(&gateway_event, &connector_id, &instance_id)
                            {
                                base.record_event();
                                if event_tx.send(Ok(event)).is_err() {
                                    tracing::info!(
                                        "Event receiver dropped, stopping gateway stream"
                                    );
                                    let _ = shutdown_tx.send(true);
                                }
                            }
                            Ok(())
                        }
                    },
                )
                .await;

            tracing::info!(?outcome, "Discord gateway supervisor stopped");
        });

        self.gateway_task = Some(task);
        Ok(())
    }

    fn require_api(&self) -> FcpResult<&Arc<DiscordApiClient>> {
        self.api_client.as_ref().ok_or(FcpError::NotConfigured)
    }
}

impl Default for DiscordConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a Discord gateway event to an FCP `EventEnvelope`.
fn gateway_event_to_fcp(
    event: &GatewayEvent,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
) -> Option<EventEnvelope> {
    let (topic, payload, principal_info) = match event {
        GatewayEvent::Ready(ready) => {
            let payload = json!({
                "session_id": ready.session_id,
                "user": ready.user
            });
            (
                "discord.ready",
                payload,
                ("bot".into(), ready.user.id.clone()),
            )
        }
        GatewayEvent::Resumed => {
            // Session resumed - this is an internal state event, emit as system event
            let payload = json!({ "event": "session_resumed" });
            (
                "discord.resumed",
                payload,
                ("system".into(), "gateway".into()),
            )
        }
        GatewayEvent::MessageCreate(data) => {
            let author_id = data
                .get("author")
                .and_then(|a| a.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let author_name = data
                .get("author")
                .and_then(|a| a.get("username"))
                .and_then(|v| v.as_str());
            (
                "discord.message",
                data.clone(),
                (author_name.unwrap_or("unknown").into(), author_id.into()),
            )
        }
        GatewayEvent::MessageUpdate(data) => {
            let author_id = data
                .get("author")
                .and_then(|a| a.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            (
                "discord.message_update",
                data.clone(),
                ("unknown".into(), author_id.into()),
            )
        }
        GatewayEvent::MessageDelete(data) => (
            "discord.message_delete",
            data.clone(),
            ("unknown".into(), "unknown".into()),
        ),
        GatewayEvent::GuildCreate(data) => {
            let guild_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            (
                "discord.guild_create",
                data.clone(),
                ("system".into(), guild_id.into()),
            )
        }
        GatewayEvent::GuildUpdate(data) => {
            let guild_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            (
                "discord.guild_update",
                data.clone(),
                ("system".into(), guild_id.into()),
            )
        }
        GatewayEvent::ChannelCreate(data) => (
            "discord.channel_create",
            data.clone(),
            ("system".into(), "unknown".into()),
        ),
        GatewayEvent::ChannelUpdate(data) => (
            "discord.channel_update",
            data.clone(),
            ("system".into(), "unknown".into()),
        ),
        GatewayEvent::TypingStart(data) => {
            let user_id = data
                .get("user_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            (
                "discord.typing",
                data.clone(),
                ("unknown".into(), user_id.into()),
            )
        }
        GatewayEvent::Unknown { event_name, data } => {
            let topic = format!("discord.{}", event_name.to_lowercase());
            return Some(EventEnvelope::new(
                topic,
                EventData::new(
                    connector_id.clone(),
                    instance_id.clone(),
                    ZoneId::community(),
                    Principal {
                        kind: "discord".into(),
                        id: "unknown".into(),
                        trust: TrustLevel::Untrusted,
                        display: None,
                    },
                    data.clone(),
                ),
            ));
        }
    };

    let (display, id) = principal_info;
    let principal = Principal {
        kind: "discord_user".into(),
        id,
        trust: TrustLevel::Untrusted,
        display: Some(display),
    };

    let event_data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        ZoneId::community(),
        principal,
        payload,
    );

    Some(EventEnvelope::new(topic, event_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_core::{CapabilityToken as CapabilityArtifact, ConnectorId, InstanceId};
    use fcp_crypto::cose::CapabilityTokenBuilder as CapabilityBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

    fn generate_capability(
        signing_key: &Ed25519SigningKey,
        capability_id: &str,
        operations: &[&str],
    ) -> CapabilityArtifact {
        let now = Utc::now();
        let cose = CapabilityBuilder::new()
            .capability_id(capability_id)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityArtifact { raw: cose }
    }

    #[tokio::test]
    async fn test_send_message_content_too_long() {
        let connector = DiscordConnector::new();

        // Create a message that exceeds 2000 characters
        let long_content = "x".repeat(2001);
        let input = serde_json::json!({
            "channel_id": "123456789",
            "content": long_content
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "discord.send_message",
                "input": input
            }))
            .await;

        // Validation happens before config check, so we get InvalidRequest for too-long content
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(
                    message.contains("character limit"),
                    "Expected content length error, got: {message}"
                );
            }
            _ => assert!(
                false,
                "Expected InvalidRequest error for content too long, got: {err:?}"
            ),
        }
    }

    #[tokio::test]
    async fn test_send_message_missing_content_and_embeds() {
        let connector = DiscordConnector::new();

        let input = serde_json::json!({
            "channel_id": "123456789"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "discord.send_message",
                "input": input
            }))
            .await;

        // Validation happens before config check, so we get InvalidRequest
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("content") || message.contains("embeds"));
        }
    }

    #[test]
    fn test_message_length_constants() {
        // Verify our constants match Discord's documented limits
        assert_eq!(2000, 2000); // MAX_CONTENT_LENGTH
        assert_eq!(10, 10); // MAX_EMBEDS
        assert_eq!(6000, 6000); // MAX_EMBED_TOTAL_CHARS
        assert_eq!(256, 256); // MAX_EMBED_TITLE
        assert_eq!(4096, 4096); // MAX_EMBED_DESCRIPTION
    }

    #[tokio::test]
    async fn test_embed_total_limit_exceeded() {
        let connector = DiscordConnector::new();

        // Create an embed with fields that exceed 6000 chars total
        let mut fields = Vec::new();
        for i in 0..10 {
            fields.push(json!({
                "name": format!("Field {}", i),
                "value": "x".repeat(600) // 10 * 600 = 6000 + names > 6000
            }));
        }

        let input = json!({
            "channel_id": "123",
            "embeds": [{
                "title": "Test",
                "fields": fields
            }]
        });

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": input
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(
                    message.contains("Total embed character count"),
                    "Got: {message}"
                );
            }
            _ => assert!(
                false,
                "Expected InvalidRequest for embed limit, got: {err:?}"
            ),
        }
    }

    #[tokio::test]
    async fn test_invoke_missing_capability_token() {
        let connector = DiscordConnector::new();

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": {
                    "channel_id": "123456789",
                    "content": "Hello"
                }
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { code: 1003, ref message } if message.contains("capability_token")),
            "Expected InvalidRequest for missing capability_token, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_invoke_capability_not_granted() {
        let mut connector = DiscordConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector.verifier = Some(CapabilityVerifier::new(
            verifying_key.to_bytes(),
            ZoneId::work(),
            connector.base.instance_id.clone(),
        ));

        let capability = generate_capability(
            &signing_key,
            "discord.get_channel",
            &["discord.get_channel"],
        );

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": {
                    "channel_id": "123456789",
                    "content": "Hello"
                },
                "capability_token": capability
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::OperationNotGranted { .. }),
            "Expected OperationNotGranted, got: {err:?}"
        );
    }

    #[test]
    fn test_gateway_event_to_fcp_message_create() {
        let connector_id = ConnectorId::from_static("discord");
        let instance_id = InstanceId::new();
        let payload = json!({
            "id": "msg-1",
            "content": "Hello",
            "author": {
                "id": "user-1",
                "username": "alice"
            }
        });

        let event = GatewayEvent::MessageCreate(payload.clone());
        let envelope =
            gateway_event_to_fcp(&event, &connector_id, &instance_id).expect("event envelope");

        assert_eq!(envelope.topic, "discord.message");
        assert_eq!(envelope.data.payload, payload);
        assert_eq!(envelope.data.zone_id, ZoneId::community());
        assert_eq!(envelope.data.principal.id, "user-1");
        assert_eq!(envelope.data.principal.display.as_deref(), Some("alice"));
    }
}
