//! FCP Slack Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::SlackClient,
    error::SlackError,
    types::{DoctorCheck, DoctorReport, OperationReceipt},
};

/// FCP Slack Connector.
pub struct SlackConnector {
    base: Arc<BaseConnector>,
    client: Option<SlackClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl SlackConnector {
    /// Create a new Slack connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("slack"))),
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

        let mut client = SlackClient::new(token).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Slack connector configured");

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
            manifest_hash: "sha256:slack-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 100,
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
                op_info(
                    "slack.post_message",
                    "Post a message to a Slack channel",
                    json!({
                        "type": "object",
                        "required": ["channel", "text"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "text": { "type": "string", "description": "Message text" },
                            "thread_ts": { "type": "string", "description": "Thread timestamp for replies" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a message to a Slack channel.".into(),
                        common_mistakes: vec!["Using channel name instead of channel ID".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "text": "Hello from FCP!"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slack.get_channel_history"),
                            CapabilityId::from_static("slack.reply_thread"),
                        ],
                    },
                ),
                op_info(
                    "slack.reply_thread",
                    "Reply to a thread in a Slack channel",
                    json!({
                        "type": "object",
                        "required": ["channel", "text", "thread_ts"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "text": { "type": "string", "description": "Reply text" },
                            "thread_ts": { "type": "string", "description": "Thread timestamp" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Reply to an existing thread in a Slack channel.".into(),
                        common_mistakes: vec!["Using message ts instead of thread_ts".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "text": "Replying!", "thread_ts": "1234567890.123456"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slack.post_message"),
                            CapabilityId::from_static("slack.get_channel_history"),
                        ],
                    },
                ),
                op_info(
                    "slack.get_channel_history",
                    "Get conversation history for a channel",
                    json!({
                        "type": "object",
                        "required": ["channel"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "limit": { "type": "integer", "description": "Max messages to return" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "messages": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve recent messages from a Slack channel.".into(),
                        common_mistakes: vec!["Not specifying a limit, which defaults to Slack's default".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "limit": 10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slack.post_message"),
                            CapabilityId::from_static("slack.search_messages"),
                        ],
                    },
                ),
                op_info(
                    "slack.search_messages",
                    "Search messages across the workspace",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": { "query": { "type": "string", "description": "Search query" } }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "object" },
                            "total": { "type": "integer" }
                        }
                    }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for messages matching a query across Slack.".into(),
                        common_mistakes: vec!["Using non-Slack search syntax".into()],
                        examples: vec![
                            r#"{"query": "deployment in:#general"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.get_channel_history")],
                    },
                ),
                op_info(
                    "slack.list_channels",
                    "List channels in the workspace",
                    json!({
                        "type": "object",
                        "properties": {
                            "types": { "type": "string", "description": "Comma-separated channel types (public_channel, private_channel, mpim, im)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "channels": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List available channels in a Slack workspace.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"types": "public_channel"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.get_channel_history")],
                    },
                ),
                op_info(
                    "slack.get_user_info",
                    "Get information about a Slack user",
                    json!({
                        "type": "object",
                        "required": ["user"],
                        "properties": {
                            "user": { "type": "string", "description": "User ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "user": { "type": "object" } } }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Look up details about a Slack user by ID.".into(),
                        common_mistakes: vec!["Using display name instead of user ID".into()],
                        examples: vec![
                            r#"{"user": "U01234567"}"#.into(),
                        ],
                        related: vec![],
                    },
                ),
                op_info(
                    "slack.upload_file",
                    "Upload a file to Slack channels",
                    json!({
                        "type": "object",
                        "required": ["channels", "content"],
                        "properties": {
                            "channels": { "type": "string", "description": "Comma-separated channel IDs" },
                            "content": { "type": "string", "description": "File content" },
                            "filename": { "type": "string", "description": "Filename to display" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "file": { "type": "object" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Upload file content to one or more Slack channels.".into(),
                        common_mistakes: vec!["Forgetting to specify channels".into()],
                        examples: vec![
                            r#"{"channels": "C01234567", "content": "log data here", "filename": "output.log"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.download_file")],
                    },
                ),
                op_info(
                    "slack.download_file",
                    "Get file info and download URL",
                    json!({
                        "type": "object",
                        "required": ["file_id"],
                        "properties": {
                            "file_id": { "type": "string", "description": "Slack file ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "file": { "type": "object" } } }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve info about a file including its download URL.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"file_id": "F01234567"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.upload_file")],
                    },
                ),
                op_info(
                    "slack.add_reaction",
                    "Add an emoji reaction to a message",
                    json!({
                        "type": "object",
                        "required": ["channel", "timestamp", "name"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "timestamp": { "type": "string", "description": "Message timestamp" },
                            "name": { "type": "string", "description": "Emoji name without colons" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "ok": { "type": "boolean" } } }),
                    "slack.write",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "React to a Slack message with an emoji.".into(),
                        common_mistakes: vec!["Including colons around the emoji name".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "timestamp": "1234567890.123456", "name": "thumbsup"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.post_message")],
                    },
                ),
                op_info(
                    "slack.set_channel_topic",
                    "Set the topic for a Slack channel",
                    json!({
                        "type": "object",
                        "required": ["channel", "topic"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "topic": { "type": "string", "description": "New channel topic" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "topic": { "type": "string" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Update the topic of a Slack channel.".into(),
                        common_mistakes: vec!["Using channel name instead of ID".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "topic": "Sprint 42 - Deployment day"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.list_channels")],
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
            "slack.post_message" => self.invoke_post_message(input).await,
            "slack.reply_thread" => self.invoke_reply_thread(input).await,
            "slack.get_channel_history" => self.invoke_get_channel_history(input).await,
            "slack.search_messages" => self.invoke_search_messages(input).await,
            "slack.list_channels" => self.invoke_list_channels(input).await,
            "slack.get_user_info" => self.invoke_get_user_info(input).await,
            "slack.upload_file" => self.invoke_upload_file(input).await,
            "slack.download_file" => self.invoke_download_file(input).await,
            "slack.add_reaction" => self.invoke_add_reaction(input).await,
            "slack.set_channel_topic" => self.invoke_set_channel_topic(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_post_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let text = require_str(&input, "text")?;
        let thread_ts = input.get("thread_ts").and_then(|v| v.as_str());

        let message = client
            .post_message(channel, text, thread_ts)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.post_message".into(),
            effect: "message_created".into(),
            resource: format!("channel:{channel}"),
            timestamp: message.ts.clone(),
        };

        Ok(json!({ "message": message, "receipt": receipt }))
    }

    async fn invoke_reply_thread(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let text = require_str(&input, "text")?;
        let thread_ts = require_str(&input, "thread_ts")?;

        let message = client
            .post_message(channel, text, Some(thread_ts))
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.reply_thread".into(),
            effect: "thread_reply_created".into(),
            resource: format!("channel:{channel}:thread:{thread_ts}"),
            timestamp: message.ts.clone(),
        };

        Ok(json!({ "message": message, "receipt": receipt }))
    }

    async fn invoke_get_channel_history(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let messages = client
            .get_channel_history(channel, limit)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "messages": messages }))
    }

    async fn invoke_search_messages(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;

        let results = client
            .search_messages(query)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let total = results.messages.total;
        Ok(json!({
            "messages": results.messages,
            "total": total
        }))
    }

    async fn invoke_list_channels(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let types = input.get("types").and_then(|v| v.as_str());

        let channels = client
            .list_channels(types)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "channels": channels }))
    }

    async fn invoke_get_user_info(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user = require_str(&input, "user")?;

        let user_info = client
            .get_user_info(user)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "user": user_info }))
    }

    async fn invoke_upload_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channels = require_str(&input, "channels")?;
        let content = require_str(&input, "content")?;
        let filename = input.get("filename").and_then(|v| v.as_str());

        let file = client
            .upload_file(channels, content, filename)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.upload_file".into(),
            effect: "file_uploaded".into(),
            resource: format!("file:{id}", id = file.id),
            timestamp: String::new(),
        };

        Ok(json!({ "file": file, "receipt": receipt }))
    }

    async fn invoke_download_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;

        let file = client
            .get_file_info(file_id)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "file": file }))
    }

    async fn invoke_add_reaction(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let timestamp = require_str(&input, "timestamp")?;
        let name = require_str(&input, "name")?;

        client
            .add_reaction(channel, timestamp, name)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.add_reaction".into(),
            effect: "reaction_added".into(),
            resource: format!("channel:{channel}:message:{timestamp}"),
            timestamp: timestamp.to_string(),
        };

        Ok(json!({ "ok": true, "receipt": receipt }))
    }

    async fn invoke_set_channel_topic(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let topic = require_str(&input, "topic")?;

        let result = client
            .set_channel_topic(channel, topic)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.set_channel_topic".into(),
            effect: "topic_updated".into(),
            resource: format!("channel:{channel}"),
            timestamp: String::new(),
        };

        Ok(json!({ "topic": result, "receipt": receipt }))
    }

    /// Required OAuth scopes for core connector functionality.
    ///
    /// Read scopes allow channel/user/message listing.
    /// Write scopes allow posting messages and reactions.
    const REQUIRED_SCOPES: &'static [&'static str] = &[
        "channels:read",
        "channels:history",
        "chat:write",
        "users:read",
    ];

    /// Handle doctor readiness check.
    ///
    /// Validates:
    /// 1. Token is present (client configured)
    /// 2. Token is valid (auth.test succeeds)
    /// 3. Required OAuth scopes are granted
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the doctor report fails.
    #[instrument(skip(self))]
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // Check 1: Client configured (token present)
        let client_present = self.client.is_some();
        checks.push(DoctorCheck {
            name: "token_present".into(),
            passed: client_present,
            message: if client_present {
                "Bot token is configured".into()
            } else {
                "No token configured — call configure with a valid bot token".into()
            },
        });

        // If no client, remaining checks cannot proceed.
        if !client_present {
            let report = DoctorReport {
                ready: false,
                checks,
            };
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize doctor report: {e}"),
            });
        }

        let client = self.client.as_ref().expect("checked above");

        // Check 2: Token validity via auth.test (also proves network reachability)
        match client.auth_test().await {
            Ok((auth_info, scopes)) => {
                checks.push(DoctorCheck {
                    name: "token_valid".into(),
                    passed: true,
                    message: format!(
                        "Token valid — team: {} ({}), user: {} ({})",
                        auth_info.team, auth_info.team_id, auth_info.user, auth_info.user_id
                    ),
                });

                // Check 3: Required scopes
                let missing = SlackClient::validate_scopes(&scopes, Self::REQUIRED_SCOPES);
                if missing.is_empty() {
                    checks.push(DoctorCheck {
                        name: "scopes_valid".into(),
                        passed: true,
                        message: format!("All required scopes granted ({})", scopes.join(", ")),
                    });
                } else {
                    checks.push(DoctorCheck {
                        name: "scopes_valid".into(),
                        passed: false,
                        message: format!(
                            "Missing required scopes: {}. Granted: {}",
                            missing.join(", "),
                            scopes.join(", ")
                        ),
                    });
                }
            }
            Err(e) => {
                let is_auth = matches!(
                    &e,
                    SlackError::Api { error, .. }
                        if error == "not_authed" || error == "invalid_auth" || error == "token_revoked"
                );
                checks.push(DoctorCheck {
                    name: "token_valid".into(),
                    passed: false,
                    message: if is_auth {
                        format!("Token invalid or revoked: {e}")
                    } else {
                        format!("auth.test failed (network or server issue): {e}")
                    },
                });
                // Skip scope check since auth failed
                checks.push(DoctorCheck {
                    name: "scopes_valid".into(),
                    passed: false,
                    message: "Cannot validate scopes — auth.test failed".into(),
                });
            }
        }

        let all_passed = checks.iter().all(|c| c.passed);
        let report = DoctorReport {
            ready: all_passed,
            checks,
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor report: {e}"),
        })
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Slack connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for SlackConnector {
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let mut connector = SlackConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = SlackConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = SlackConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.list_channels"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "slack.list_channels");

        let result = connector
            .handle_invoke(json!({
                "operation": "slack.list_channels",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
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
                "capabilities_requested": ["slack.post_message"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "slack.post_message");

        let result = connector
            .handle_invoke(json!({
                "operation": "slack.post_message",
                "input": { "channel": "C01234567" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("text"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"slack.post_message"));
        assert!(op_ids.contains(&"slack.reply_thread"));
        assert!(op_ids.contains(&"slack.get_channel_history"));
        assert!(op_ids.contains(&"slack.search_messages"));
        assert!(op_ids.contains(&"slack.list_channels"));
        assert!(op_ids.contains(&"slack.get_user_info"));
        assert!(op_ids.contains(&"slack.upload_file"));
        assert!(op_ids.contains(&"slack.download_file"));
        assert!(op_ids.contains(&"slack.add_reaction"));
        assert!(op_ids.contains(&"slack.set_channel_topic"));
        assert_eq!(ops.len(), 10);
    }

    // ── Doctor / Provisioning tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = SlackConnector::new();
        let result = connector.handle_doctor().await.unwrap();

        assert!(!result["ready"].as_bool().unwrap());
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0]["name"], "token_present");
        assert!(!checks[0]["passed"].as_bool().unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_valid_token_all_scopes() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth.test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "x-oauth-scopes",
                        "channels:read,channels:history,chat:write,users:read,reactions:write",
                    )
                    .set_body_json(json!({
                        "ok": true,
                        "url": "https://test-workspace.slack.com/",
                        "team": "Test Workspace",
                        "user": "testbot",
                        "team_id": "T00000001",
                        "user_id": "U00000001",
                        "bot_id": "B00000001",
                        "is_enterprise_install": false
                    })),
            )
            .mount(&mock_server)
            .await;

        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("xoxb-test-token")
                .unwrap()
                .with_base_url(mock_server.uri()),
        );

        let result = connector.handle_doctor().await.unwrap();

        assert!(result["ready"].as_bool().unwrap());
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 3);

        // All checks should pass
        for check in checks {
            assert!(
                check["passed"].as_bool().unwrap(),
                "Check {} failed: {}",
                check["name"],
                check["message"]
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_missing_scopes() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth.test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-oauth-scopes", "channels:read")
                    .set_body_json(json!({
                        "ok": true,
                        "url": "https://test.slack.com/",
                        "team": "Test",
                        "user": "bot",
                        "team_id": "T1",
                        "user_id": "U1"
                    })),
            )
            .mount(&mock_server)
            .await;

        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("xoxb-test")
                .unwrap()
                .with_base_url(mock_server.uri()),
        );

        let result = connector.handle_doctor().await.unwrap();

        assert!(!result["ready"].as_bool().unwrap());
        let checks = result["checks"].as_array().unwrap();

        let scope_check = checks.iter().find(|c| c["name"] == "scopes_valid").unwrap();
        assert!(!scope_check["passed"].as_bool().unwrap());
        let msg = scope_check["message"].as_str().unwrap();
        assert!(msg.contains("channels:history"));
        assert!(msg.contains("chat:write"));
        assert!(msg.contains("users:read"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_invalid_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth.test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": false,
                "error": "invalid_auth"
            })))
            .mount(&mock_server)
            .await;

        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("xoxb-bad-token")
                .unwrap()
                .with_base_url(mock_server.uri()),
        );

        let result = connector.handle_doctor().await.unwrap();

        assert!(!result["ready"].as_bool().unwrap());
        let checks = result["checks"].as_array().unwrap();

        let token_check = checks.iter().find(|c| c["name"] == "token_valid").unwrap();
        assert!(!token_check["passed"].as_bool().unwrap());
        assert!(token_check["message"].as_str().unwrap().contains("invalid"));
    }

    #[test]
    fn test_validate_scopes_all_present() {
        let granted: Vec<String> = vec![
            "channels:read".into(),
            "channels:history".into(),
            "chat:write".into(),
            "users:read".into(),
        ];
        let missing = SlackClient::validate_scopes(&granted, &["channels:read", "chat:write"]);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_validate_scopes_some_missing() {
        let granted: Vec<String> = vec!["channels:read".into()];
        let missing =
            SlackClient::validate_scopes(&granted, &["channels:read", "chat:write", "users:read"]);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"chat:write".to_string()));
        assert!(missing.contains(&"users:read".to_string()));
    }
}
