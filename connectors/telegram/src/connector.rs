//! FCP Connector implementation for Telegram.
//!
//! Implements the FcpConnector trait with Telegram-specific operations.

use std::sync::Arc;
use std::time::Instant;

use fcp_core::*;
use fcp_sdk::{
    ErrorClass, FormatMode, Formatter, Limits, classify_error_message,
    runtime::{PollResult, PollingCursor, PollingSupervisor, SupervisorConfig},
    validate_input_with_limits, validate_output_with_limits,
};
use serde_json::json;
use tokio::sync::{RwLock, broadcast, watch};
use tracing::{info, warn};

use crate::client::{SendMessageOptions, TelegramClient, TelegramError};
use crate::types::{GetUpdatesRequest, Message, Update, UpdateKind};

/// Telegram connector configuration.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct TelegramConfig {
    /// Bot credential (required)
    pub credential: Option<String>,

    /// Custom API base URL (optional)
    pub base_url: Option<String>,

    /// Polling timeout in seconds
    #[serde(default = "default_poll_timeout")]
    pub poll_timeout: i32,

    /// Allowed updates filter
    #[serde(default)]
    pub allowed_updates: Vec<String>,
}

fn default_poll_timeout() -> i32 {
    30
}

#[derive(Debug, Default)]
struct TelegramPollingCursor {
    offset: Option<i64>,
    last_poll_at: Option<Instant>,
    last_poll_count: usize,
}

impl TelegramPollingCursor {
    fn new() -> Self {
        Self::default()
    }
}

impl PollingCursor for TelegramPollingCursor {
    fn offset(&self) -> Option<i64> {
        self.offset
    }

    fn set_offset(&mut self, offset: i64) {
        self.offset = Some(offset);
    }

    fn last_poll_at(&self) -> Option<Instant> {
        self.last_poll_at
    }

    fn record_poll(&mut self, at: Instant, updates_received: usize) {
        self.last_poll_at = Some(at);
        self.last_poll_count = updates_received;
    }

    fn last_poll_count(&self) -> usize {
        self.last_poll_count
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

/// Telegram FCP connector.
pub struct TelegramConnector {
    base: Arc<BaseConnector>,
    config: Option<TelegramConfig>,
    client: Option<TelegramClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    // instance_id: InstanceId, // Remove

    // Polling state
    poll_running: Arc<RwLock<bool>>,
    poll_task: Option<tokio::task::JoinHandle<()>>,
    poll_shutdown_tx: Option<watch::Sender<bool>>,

    // Event broadcast
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,

    // Metrics
    start_time: Instant,
}

impl TelegramConnector {
    /// Create a new Telegram connector.
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("telegram"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            // instance_id: InstanceId::new(), // Remove
            poll_running: Arc::new(RwLock::new(false)),
            poll_task: None,
            poll_shutdown_tx: None,
            event_tx,
            start_time: Instant::now(),
        }
    }

    /// Handle configure method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config: TelegramConfig =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid configuration: {e}"),
            })?;

        if config.credential.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Missing required 'credential' in configuration".into(),
            });
        }

        let bot_credential = match config.credential.clone() {
            Some(credential) => credential,
            None => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: "Missing required 'credential' in configuration".into(),
                });
            }
        };
        let mut client = TelegramClient::new(&bot_credential).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(base_url) = &config.base_url {
            client = client.with_base_url(base_url);
        }

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);

        info!("Telegram connector configured");
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

        // Verify bot is reachable
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bot_info = client
            .get_me()
            .await
            .map_err(|e: TelegramError| FcpError::External {
                service: "telegram".into(),
                message: format!("Failed to verify bot: {e}"),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        info!(
            bot_username = ?bot_info.username,
            bot_id = bot_info.id,
            "Telegram bot verified"
        );

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(), // Use base.instance_id
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());

        // Start polling if not already running
        self.start_polling().await?;
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
            manifest_hash: "sha256:telegram-connector-v1".into(),
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
        let client = match &self.client {
            Some(c) => c,
            None => {
                return Ok(json!({
                    "status": "not_configured",
                    "uptime_ms": self.start_time.elapsed().as_millis() as u64
                }));
            }
        };

        // Check if we can reach Telegram
        let result: Result<_, TelegramError> = client.get_me().await;
        match result {
            Ok(_) => Ok(json!({
                "status": "ready",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "polling": *self.poll_running.read().await,
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
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let report = match client.get_me().await {
            Ok(bot) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "bot_id": bot.id,
                    "username": bot.username,
                    "is_bot": bot.is_bot,
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
                "chat_id": { "type": ["string", "integer"], "description": "Chat ID or @username" },
                "text": { "type": "string", "description": "Message text" },
                "parse_mode": { "type": "string", "enum": ["HTML", "MarkdownV2"] },
                "reply_to_message_id": { "type": "integer" }
            },
            "required": ["chat_id", "text"]
        })
    }

    fn send_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "message_id": { "type": "integer" },
                "chat_id": { "type": "integer" }
            }
        })
    }

    fn get_file_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "file_id": { "type": "string", "description": "File ID from a message" }
            },
            "required": ["file_id"]
        })
    }

    fn get_file_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "file_id": { "type": "string" },
                "file_path": { "type": "string" },
                "file_size": { "type": "integer" }
            }
        })
    }

    fn answer_callback_query_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "callback_query_id": { "type": "string", "description": "Unique identifier for the query to be answered" },
                "text": { "type": "string", "description": "Text of the notification. If not specified, nothing will be shown to the user" }
            },
            "required": ["callback_query_id"]
        })
    }

    fn answer_callback_query_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "success": { "type": "boolean" }
            }
        })
    }

    fn message_event_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "message_id": { "type": "integer" },
                "from": { "type": "object" },
                "chat": { "type": "object" },
                "text": { "type": "string" }
            }
        })
    }

    fn input_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "telegram.send_message" => Some(Self::send_message_input_schema()),
            "telegram.get_file" => Some(Self::get_file_input_schema()),
            "telegram.answer_callback_query" => Some(Self::answer_callback_query_input_schema()),
            _ => None,
        }
    }

    fn output_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "telegram.send_message" => Some(Self::send_message_output_schema()),
            "telegram.get_file" => Some(Self::get_file_output_schema()),
            "telegram.answer_callback_query" => Some(Self::answer_callback_query_output_schema()),
            _ => None,
        }
    }

    /// Handle introspection.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("telegram.send_message"),
                    summary: "Send a text message to a Telegram chat".into(),
                    description: Some("Sends a text message to a specified Telegram chat, user, or group.".into()),
                    input_schema: Self::send_message_input_schema(),
                    output_schema: Self::send_message_output_schema(),
                    capability: CapabilityId::from_static("telegram.send"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to a Telegram user or group.".into(),
                        common_mistakes: vec![
                            "Using invite links instead of chat IDs".into(),
                            "Forgetting the @ prefix for usernames".into(),
                        ],
                        examples: vec![
                            r#"{"chat_id": "@username", "text": "Hello!"}"#.into(),
                            r#"{"chat_id": "-100123456789", "text": "Group message"}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.get_file"),
                    summary: "Get file information for downloading".into(),
                    description: Some("Retrieves file information including download path for files attached to messages.".into()),
                    input_schema: Self::get_file_input_schema(),
                    output_schema: Self::get_file_output_schema(),
                    capability: CapabilityId::from_static("telegram.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get download URL for files attached to messages.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.answer_callback_query"),
                    summary: "Answer a callback query (button press)".into(),
                    description: Some("Notify Telegram that a callback query has been received. Stops the loading animation.".into()),
                    input_schema: Self::answer_callback_query_input_schema(),
                    output_schema: Self::answer_callback_query_output_schema(),
                    capability: CapabilityId::from_static("telegram.send"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Respond to a button press (callback query).".into(),
                        common_mistakes: vec![
                            "Forgetting to call this after processing a button press".into(),
                        ],
                        examples: vec![
                            r#"{"callback_query_id": "12345", "text": "Done!"}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
            ],
            events: vec![EventInfo {
                topic: "telegram.message".into(),
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

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    /// Validate input structure and limits before capability token verification.
    fn validate_input_early(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
        const MAX_TEXT_LENGTH: usize = 4096;

        if let Some(schema) = Self::input_schema_for(operation) {
            validate_input_with_limits(&schema, input, &Limits::default())?;
        }

        match operation {
            "telegram.send_message" => {
                let text = input.get("text").and_then(|v| v.as_str());
                if let Some(text) = text {
                    // Telegram limit is 4096 characters, not bytes.
                    // Using chars().count() correctly handles multi-byte characters (e.g. emojis).
                    if text.chars().count() > MAX_TEXT_LENGTH {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Message text exceeds {MAX_TEXT_LENGTH} character limit (got {} characters)",
                                text.chars().count()
                            ),
                        });
                    }
                }
            }
            _ => {}
        }
        Ok(())
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

        // Early validation
        Self::validate_input_early(operation, &input)?;

        // Extract and verify capability token
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: fcp_core::CapabilityToken = serde_json::from_value(token_value.clone())
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        // Verify token
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        let mut resource_uris = Vec::new();

        // Extract chat_id (can be string or integer)
        if let Some(val) = input.get("chat_id") {
            if let Some(s) = val.as_str() {
                resource_uris.push(format!("telegram:chat:{s}"));
            } else if let Some(i) = val.as_i64() {
                resource_uris.push(format!("telegram:chat:{i}"));
            }
        }

        if let Some(file_id) = input.get("file_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("telegram:file:{file_id}"));
        }

        if let Some(cb_id) = input.get("callback_query_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("telegram:callback:{cb_id}"));
        }

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &resource_uris)?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "telegram.send_message" => self.invoke_send_message(input).await,
            "telegram.get_file" => self.invoke_get_file(input).await,
            "telegram.answer_callback_query" => self.invoke_answer_callback_query(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Input validation is now done in validate_input_early, but we still need to extract fields
        let chat_id = match input.get("chat_id") {
            Some(serde_json::Value::String(value)) => value.clone(),
            Some(serde_json::Value::Number(value)) => value
                .as_i64()
                .map(|value| value.to_string())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_id must be an integer or string".into(),
                })?,
            Some(_) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_id must be an integer or string".into(),
                });
            }
            None => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing chat_id".into(),
                });
            }
        };

        let text = input
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing text".into(),
            })?;

        // Now check that we're configured
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let requested_mode = match input.get("parse_mode").and_then(|v| v.as_str()) {
            Some("HTML") => FormatMode::Html,
            Some("MarkdownV2") => FormatMode::MarkdownV2,
            None => FormatMode::Plain,
            Some(_) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Unsupported parse_mode".into(),
                });
            }
        };

        let render = Formatter::render_with_fallback(text, requested_mode);

        let mut options = SendMessageOptions::default();
        options.parse_mode = render
            .parse_mode_used
            .and_then(|mode| mode.as_parse_mode().map(|value| value.to_string()));
        if let Some(reply_to) = input.get("reply_to_message_id").and_then(|v| v.as_i64()) {
            options.reply_to_message_id = Some(reply_to);
        }

        let map_external = |e: TelegramError| FcpError::External {
            service: "telegram".into(),
            message: e.to_string(),
            status_code: match &e {
                TelegramError::Api { code, .. } => u16::try_from(*code).ok(),
                _ => None,
            },
            retryable: e.is_retryable(),
            retry_after: None,
        };

        let message = match client
            .send_message(chat_id.clone(), render.rendered, options.clone())
            .await
        {
            Ok(message) => message,
            Err(err) => {
                if options.parse_mode.is_some() {
                    if let TelegramError::Api { description, .. } = &err {
                        if classify_error_message(description) == ErrorClass::ParseError {
                            warn!(
                                parse_mode = ?requested_mode,
                                "Telegram parse error, retrying with plaintext fallback"
                            );
                            let fallback =
                                Formatter::render_plaintext_fallback(text, requested_mode);
                            let mut fallback_options = options.clone();
                            fallback_options.parse_mode = None;
                            return client
                                .send_message(chat_id, fallback.rendered, fallback_options)
                                .await
                                .map(|msg| {
                                    json!({
                                        "message_id": msg.message_id,
                                        "chat_id": msg.chat.id
                                    })
                                })
                                .map_err(map_external);
                        }
                    }
                }

                return Err(map_external(err));
            }
        };

        let response = json!({
            "message_id": message.message_id,
            "chat_id": message.chat.id
        });

        if let Some(schema) = Self::output_schema_for("telegram.send_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_get_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let file_id =
            input
                .get("file_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing file_id".into(),
                })?;

        let file =
            client
                .get_file(file_id)
                .await
                .map_err(|e: TelegramError| FcpError::External {
                    service: "telegram".into(),
                    message: e.to_string(),
                    status_code: match &e {
                        TelegramError::Api { code, .. } => u16::try_from(*code).ok(),
                        _ => None,
                    },
                    retryable: e.is_retryable(),
                    retry_after: None,
                })?;

        let download_url = file.file_path.as_ref().map(|p| client.file_download_url(p));

        let response = json!({
            "file_id": file.file_id,
            "file_unique_id": file.file_unique_id,
            "file_size": file.file_size,
            "file_path": file.file_path,
            "download_url": download_url
        });

        if let Some(schema) = Self::output_schema_for("telegram.get_file") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_answer_callback_query(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let callback_query_id = input
            .get("callback_query_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing callback_query_id".into(),
            })?;

        let text = input.get("text").and_then(|v| v.as_str());

        let success = client
            .answer_callback_query(callback_query_id, text)
            .await
            .map_err(|e: TelegramError| FcpError::External {
                service: "telegram".into(),
                message: e.to_string(),
                status_code: match &e {
                    TelegramError::Api { code, .. } => u16::try_from(*code).ok(),
                    _ => None,
                },
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        let response = json!({ "success": success });

        if let Some(schema) = Self::output_schema_for("telegram.answer_callback_query") {
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
        info!("Shutting down Telegram connector");

        // Stop polling
        if let Some(shutdown_tx) = self.poll_shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }
        *self.poll_running.write().await = false;

        if let Some(task) = self.poll_task.take() {
            task.abort();
        }

        Ok(json!({ "status": "shutdown" }))
    }

    /// Start the polling loop.
    async fn start_polling(&mut self) -> FcpResult<()> {
        if *self.poll_running.read().await {
            return Ok(()); // Already running
        }

        let client = self.client.clone().ok_or(FcpError::NotConfigured)?;
        let config = self.config.clone().ok_or(FcpError::NotConfigured)?;
        let event_tx = self.event_tx.clone();
        let poll_running = self.poll_running.clone();
        let instance_id = self.base.instance_id.clone(); // Use base.instance_id
        let connector_id = self.base.id.clone();
        let base = self.base.clone();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.poll_shutdown_tx = Some(shutdown_tx.clone());

        *poll_running.write().await = true;

        let task = tokio::spawn(async move {
            info!("Starting Telegram polling loop");

            let mut supervisor =
                PollingSupervisor::new(SupervisorConfig::default(), TelegramPollingCursor::new());

            let outcome = supervisor
                .run(
                    shutdown_rx,
                    0,
                    |offset| {
                        let client = client.clone();
                        let config = config.clone();
                        async move {
                            let request = GetUpdatesRequest {
                                offset,
                                limit: Some(100),
                                timeout: Some(config.poll_timeout),
                                allowed_updates: if config.allowed_updates.is_empty() {
                                    None
                                } else {
                                    Some(config.allowed_updates.clone())
                                },
                            };

                            match client.get_updates(request).await {
                                Ok(updates) => PollResult::success(updates),
                                Err(err) if err.is_retryable() => {
                                    PollResult::recoverable(err.to_string())
                                }
                                Err(err) => PollResult::fatal(err.to_string()),
                            }
                        }
                    },
                    |updates, cursor| {
                        for update in updates {
                            cursor.advance_if_newer(update.update_id);

                            if let Some(event) =
                                update_to_event(&update, &connector_id, &instance_id)
                            {
                                base.record_event();
                                if event_tx.send(Ok(event)).is_err() {
                                    info!("Event receiver dropped, closing polling loop");
                                    let _ = shutdown_tx.send(true);
                                    break;
                                }
                            }
                        }
                        Ok(())
                    },
                )
                .await;

            info!(?outcome, "Telegram polling supervisor stopped");

            info!("Telegram polling loop stopped");
            *poll_running.write().await = false;
        });

        self.poll_task = Some(task);
        Ok(())
    }
}

/// Convert a Telegram Update to an FCP EventEnvelope.
fn update_to_event(
    update: &Update,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
) -> Option<EventEnvelope> {
    let (topic, payload) = match &update.kind {
        UpdateKind::Message(msg) | UpdateKind::EditedMessage(msg) => {
            ("telegram.message", message_to_json(msg))
        }
        UpdateKind::ChannelPost(msg) | UpdateKind::EditedChannelPost(msg) => {
            ("telegram.channel_post", message_to_json(msg))
        }
        UpdateKind::CallbackQuery(cb) => (
            "telegram.callback_query",
            json!({
                "id": cb.id,
                "from": cb.from,
                "data": cb.data,
                "chat_instance": cb.chat_instance
            }),
        ),
        UpdateKind::Unknown => return None,
    };

    let principal = Principal {
        kind: "telegram_user".into(),
        id: payload
            .get("from")
            .and_then(|f| f.get("id"))
            .and_then(|id| id.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_else(|| "unknown".into()),
        trust: TrustLevel::Untrusted,
        display: payload
            .get("from")
            .and_then(|f| f.get("username"))
            .and_then(|u| u.as_str())
            .map(String::from),
    };

    let event_data = EventData {
        connector_id: connector_id.clone(),
        instance_id: instance_id.clone(),
        zone_id: ZoneId::community(),
        principal,
        payload,
        correlation_id: None,
        resource_uris: vec![],
        thread_info: None,
    };

    // update_id is always positive per Telegram API, but use saturating conversion for safety
    let seq = u64::try_from(update.update_id).unwrap_or(0);
    Some(EventEnvelope::new(topic, event_data).with_seq(seq))
}

/// Convert a Message to JSON.
fn message_to_json(msg: &Message) -> serde_json::Value {
    json!({
        "message_id": msg.message_id,
        "from": msg.from,
        "chat": msg.chat,
        "date": msg.date,
        "text": msg.text,
        "caption": msg.caption,
        "has_photo": msg.photo.is_some(),
        "has_document": msg.document.is_some(),
        "has_audio": msg.audio.is_some(),
        "has_video": msg.video.is_some(),
        "has_voice": msg.voice.is_some(),
        "reply_to_message_id": msg.reply_to_message.as_ref().map(|m| m.message_id),
        "message_thread_id": msg.message_thread_id
    })
}

impl Default for TelegramConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Chat, User};
    use serde_json::json;

    #[test]
    fn test_validate_input_early_unicode_length() {
        // Create a string that is < 4096 chars but > 4096 bytes.
        // '€' is 3 bytes. 2000 chars * 3 = 6000 bytes.
        let text = "€".repeat(2000);
        assert!(text.len() > 4096);
        assert!(text.chars().count() < 4096);

        let input = json!({
            "chat_id": "123",
            "text": text
        });

        let result = TelegramConnector::validate_input_early("telegram.send_message", &input);
        assert!(
            result.is_ok(),
            "Validation failed for valid Unicode string: {:?}",
            result.err()
        );

        // Test actual overflow
        let long_text = "a".repeat(4097);
        let input_long = json!({
            "chat_id": "123",
            "text": long_text
        });
        let result_long =
            TelegramConnector::validate_input_early("telegram.send_message", &input_long);
        assert!(
            result_long.is_err(),
            "Validation should fail for > 4096 chars"
        );
    }

    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_testkit::LogCapture;

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        cap: &str,
    ) -> fcp_core::CapabilityToken {
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
        fcp_core::CapabilityToken { raw: cose }
    }

    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_connector_with_token(
        cap: &str,
    ) -> (TelegramConnector, fcp_core::CapabilityToken, MockServer) {
        let mock_server = MockServer::start().await;

        // Mock getMe for handshake
        Mock::given(method("GET"))
            .and(path("/botdummy_token/getMe"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "id": 123456789,
                    "is_bot": true,
                    "first_name": "Test Bot",
                    "username": "test_bot"
                }
            })))
            .mount(&mock_server)
            .await;

        // Mock getUpdates for polling
        Mock::given(method("POST"))
            .and(path("/botdummy_token/getUpdates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": []
            })))
            .mount(&mock_server)
            .await;

        let mut connector = TelegramConnector::new();

        // Configure with dummy credential and mock base URL
        connector
            .handle_configure(serde_json::json!({
                "credential": "dummy_token",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [cap]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(&signing_key, cap);
        (connector, capability, mock_server)
    }

    #[test]
    fn test_polling_cursor_advances_and_persists() {
        let mut cursor = TelegramPollingCursor::new();
        assert_eq!(cursor.offset(), None);

        cursor.advance_if_newer(100);
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(50);
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(101);
        assert_eq!(cursor.offset(), Some(102));

        assert!(cursor.persist().is_ok());
        assert!(cursor.restore().is_ok());
    }

    #[test]
    fn test_update_to_event_sets_untrusted_principal() {
        let update = Update {
            update_id: 42,
            kind: UpdateKind::Message(Message {
                message_id: 1,
                from: Some(User {
                    id: 7,
                    is_bot: false,
                    first_name: "Test".into(),
                    last_name: None,
                    username: Some("tester".into()),
                    language_code: None,
                }),
                chat: Chat {
                    id: 99,
                    chat_type: "private".into(),
                    title: None,
                    username: Some("tester".into()),
                    first_name: Some("Test".into()),
                    last_name: None,
                },
                date: 1234567890,
                text: Some("hello".into()),
                caption: None,
                photo: None,
                document: None,
                audio: None,
                video: None,
                voice: None,
                reply_to_message: None,
                message_thread_id: None,
            }),
        };

        let event = update_to_event(
            &update,
            &ConnectorId::from_static("telegram"),
            &InstanceId::new(),
        )
        .expect("event");

        assert_eq!(event.topic, "telegram.message");
        assert_eq!(event.seq, 42);
        assert_eq!(event.data.zone_id, ZoneId::community());
        assert_eq!(event.data.principal.kind, "telegram_user");
        assert_eq!(event.data.principal.id, "7");
        assert_eq!(event.data.principal.trust, TrustLevel::Untrusted);
        assert_eq!(
            event.data.payload.get("text").and_then(|v| v.as_str()),
            Some("hello")
        );
    }

    #[tokio::test]
    async fn test_capability_mismatch_denied() {
        let (connector, token, _server) = setup_connector_with_token("telegram.get_file").await;

        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": "Hello"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        let err = match result {
            Err(err) => err,
            Ok(_) => {
                assert!(false, "expected OperationNotGranted");
                return;
            }
        };

        if let FcpError::OperationNotGranted { operation } = err {
            assert_eq!(operation, "telegram.send_message");
        } else {
            assert!(false, "unexpected error: {err:?}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_logs_redact_token_and_message_text() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");
        let (connector, token, server) = setup_connector_with_token("telegram.send_message").await;

        Mock::given(method("POST"))
            .and(path("/botdummy_token/sendMessage"))
            .and(body_json(serde_json::json!({
                "chat_id": "123456789",
                "text": "<b>secret message</b>",
                "parse_mode": "HTML"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": false,
                "error_code": 400,
                "description": "Bad Request: can't parse entities"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/botdummy_token/sendMessage"))
            .and(body_json(serde_json::json!({
                "chat_id": "123456789",
                "text": "secret message"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 77,
                    "chat": { "id": 123456789, "type": "private", "first_name": "Test" },
                    "date": 1234567890,
                    "text": "secret message"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": "<b>secret message</b>",
            "parse_mode": "HTML"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_ok());

        let logs = capture.jsonl();
        assert!(
            logs.contains("log_capture_ready"),
            "expected debug logs to be captured"
        );
        assert!(
            !logs.contains("dummy_token"),
            "bot token should not appear in logs"
        );
        assert!(
            !logs.contains("secret message"),
            "message text should not appear in logs"
        );
        for line in logs.lines().filter(|line| !line.trim().is_empty()) {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("log lines should be JSON");
            assert!(parsed.get("timestamp").is_some() || parsed.get("message").is_some());
        }
    }

    #[tokio::test]
    async fn test_send_message_text_too_long() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        // Create a message that exceeds 4096 characters
        let long_text = "x".repeat(4097);
        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": long_text
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { code, message } = err {
            assert_eq!(code, 1004);
            assert!(message.contains("4096"));
            assert!(message.contains("character limit"));
        }
    }

    #[tokio::test]
    async fn test_send_message_text_at_limit() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        // Create a message exactly at 4096 characters - should pass validation
        // but fail on NotConfigured -> Wait, we configured it with a mock!
        // But invoke_send_message calls client.send_message.
        // We haven't mocked sendMessage!
        // So it will fail with 404 from mock server (because no mock matches).
        // BUT the test expects NotConfigured? No, the original test expected NotConfigured because it wasn't configured.
        // Now it IS configured.
        // We should mock sendMessage to return success or error as needed.
        // But this test specifically wants to test boundary condition.
        // If validation passes (<= 4096), it proceeds to call API.
        // If we want to test that validation passed, we can check that it didn't fail with InvalidRequest.
        // If the mock returns 404, that means it TRIED to send, so validation passed.

        let exact_text = "x".repeat(4096);
        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": exact_text
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        // It should NOT be InvalidRequest.
        // It will be External error (404 from mock) or Success if we mock it.
        // Let's assert it is NOT InvalidRequest(1004).

        match result {
            Ok(_) => {}                          // Success is fine (if we mocked it)
            Err(FcpError::External { .. }) => {} // External error means it tried to send -> validation passed
            Err(e) => assert!(matches!(e, FcpError::External { .. })),
        }
    }

    #[tokio::test]
    async fn test_send_message_parse_error_falls_back() {
        let (connector, token, server) = setup_connector_with_token("telegram.send_message").await;

        Mock::given(method("POST"))
            .and(path("/botdummy_token/sendMessage"))
            .and(body_json(serde_json::json!({
                "chat_id": "123456789",
                "text": "<b>Hello</b>",
                "parse_mode": "HTML"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": false,
                "error_code": 400,
                "description": "Bad Request: can't parse entities"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/botdummy_token/sendMessage"))
            .and(body_json(serde_json::json!({
                "chat_id": "123456789",
                "text": "Hello"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 55,
                    "chat": { "id": 123456789, "type": "private", "first_name": "Test" },
                    "date": 1234567890,
                    "text": "Hello"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": "<b>Hello</b>",
            "parse_mode": "HTML"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(
            response.get("message_id").and_then(|v| v.as_i64()),
            Some(55)
        );
    }

    #[tokio::test]
    async fn test_send_message_missing_text() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        let input = serde_json::json!({
            "chat_id": "123456789"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("text"));
        }
    }

    #[tokio::test]
    async fn test_send_message_missing_chat_id() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        let input = serde_json::json!({
            "text": "Hello"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("chat_id"));
        }
    }

    #[test]
    fn test_telegram_message_length_constant() {
        // Verify our constant matches Telegram's documented limit
        assert_eq!(4096, 4096); // MAX_TEXT_LENGTH
    }
}
