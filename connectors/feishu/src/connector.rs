//! Feishu connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::FeishuClient;
use crate::types::{ReplyMessageRequest, SendMessageRequest};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_MESSAGES_SEND: &str = "feishu.messages.send";
const OP_MESSAGES_REPLY: &str = "feishu.messages.reply";
const OP_MESSAGES_GET: &str = "feishu.messages.get";
const OP_CHATS_LIST: &str = "feishu.chats.list";
const OP_CHATS_GET: &str = "feishu.chats.get";
const OP_USERS_GET: &str = "feishu.users.get";
const OP_DOCS_GET: &str = "feishu.docs.get";
const OP_SHEETS_GET: &str = "feishu.sheets.get";
const OP_CALENDAR_EVENTS: &str = "feishu.calendar.events";
const OP_HEALTH: &str = "feishu.health";

// Capability IDs
const CAP_MSG_WRITE: &str = "feishu.messages.write";
const CAP_MSG_READ: &str = "feishu.messages.read";
const CAP_CHATS_READ: &str = "feishu.chats.read";
const CAP_USERS_READ: &str = "feishu.users.read";
const CAP_DOCS_READ: &str = "feishu.docs.read";
const CAP_CALENDAR_READ: &str = "feishu.calendar.read";

/// Feishu connector configuration.
#[derive(Clone, Deserialize)]
struct FeishuConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    app_id: String,
    app_secret: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for FeishuConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeishuConfig")
            .field("base_url", &self.base_url)
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://open.feishu.cn".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

// Doctor types
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self { passed, checks }
    }
}

/// Feishu connector state.
#[derive(Debug)]
pub struct FeishuConnector {
    base: BaseConnector,
    config: Option<FeishuConfig>,
    client: Option<FeishuClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl FeishuConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.feishu")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.runtime.is_some();
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });

        if let Some(config) = &self.config {
            let allowed_hosts = ["open.feishu.cn", "open.larksuite.com"];
            let host_part = config
                .base_url
                .split("://")
                .nth(1)
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");
            let host_ok = host_part == "localhost"
                || host_part == "127.0.0.1"
                || allowed_hosts.contains(&host_part);
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(if host_ok {
                    "Base URL matches allowed hosts".into()
                } else {
                    format!("Base URL {} does not match allowed hosts", config.base_url)
                }),
                critical: true,
            });

            let creds_ok = self
                .client
                .as_ref()
                .is_some_and(|c| c.has_credentials());
            checks.push(DoctorCheck {
                name: "credentials".into(),
                passed: creds_ok,
                message: Some(if creds_ok {
                    "App credentials configured".into()
                } else {
                    "App ID or secret missing".into()
                }),
                critical: true,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for FeishuConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_SEND),
            summary: "Send a message via Feishu".into(),
            description: Some("Sends a message to a user or chat".into()),
            input_schema: json!({
                "type": "object",
                "required": ["receive_id", "msg_type", "content"],
                "properties": {
                    "receive_id": { "type": "string", "description": "Receiver ID (user open_id or chat_id)" },
                    "receive_id_type": { "type": "string", "description": "Type: open_id, user_id, union_id, email, chat_id", "default": "open_id" },
                    "msg_type": { "type": "string", "description": "Message type: text, post, image, interactive, etc." },
                    "content": { "type": "string", "description": "JSON-encoded message content" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a message to a Feishu user or group chat".into(),
                common_mistakes: vec![
                    "Content must be JSON-encoded string matching msg_type schema".into(),
                    "receive_id_type defaults to open_id if not specified".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_MESSAGES_REPLY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_REPLY),
            summary: "Reply to a Feishu message".into(),
            description: Some("Sends a reply to an existing message".into()),
            input_schema: json!({
                "type": "object",
                "required": ["message_id", "msg_type", "content"],
                "properties": {
                    "message_id": { "type": "string", "description": "Message ID to reply to" },
                    "msg_type": { "type": "string", "description": "Message type" },
                    "content": { "type": "string", "description": "JSON-encoded message content" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When replying to an existing message in a thread".into(),
                common_mistakes: vec![
                    "message_id must be valid and accessible".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_MESSAGES_SEND)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_GET),
            summary: "Get a Feishu message by ID".into(),
            description: Some("Retrieves a single message by its message ID".into()),
            input_schema: json!({
                "type": "object",
                "required": ["message_id"],
                "properties": {
                    "message_id": { "type": "string", "description": "Message ID to retrieve" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" },
                    "msg_type": { "type": "string" },
                    "body": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to read the content of a specific message".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHATS_LIST),
            summary: "List Feishu chats".into(),
            description: Some("Lists chats the bot is a member of, with pagination".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "page_token": { "type": "string", "description": "Pagination token" },
                    "page_size": { "type": "integer", "description": "Page size (max 200)", "default": 20 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "page_token": { "type": "string" },
                    "has_more": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CHATS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list all chats the bot has access to".into(),
                common_mistakes: vec![
                    "Use page_token from response for subsequent pages".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_CHATS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHATS_GET),
            summary: "Get Feishu chat details".into(),
            description: Some("Retrieves details of a specific chat".into()),
            input_schema: json!({
                "type": "object",
                "required": ["chat_id"],
                "properties": {
                    "chat_id": { "type": "string", "description": "Chat ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "chat_id": { "type": "string" },
                    "name": { "type": "string" },
                    "description": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CHATS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific chat".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_CHATS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_USERS_GET),
            summary: "Get Feishu user info".into(),
            description: Some("Retrieves user information by user ID".into()),
            input_schema: json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string", "description": "User ID" },
                    "user_id_type": { "type": "string", "description": "Type: open_id, user_id, union_id", "default": "open_id" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "user_id": { "type": "string" },
                    "name": { "type": "string" },
                    "email": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to look up user information".into(),
                common_mistakes: vec![
                    "user_id_type must match the format of user_id provided".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOCS_GET),
            summary: "Get Feishu document content".into(),
            description: Some("Retrieves the raw content of a Feishu document".into()),
            input_schema: json!({
                "type": "object",
                "required": ["document_id"],
                "properties": {
                    "document_id": { "type": "string", "description": "Document ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "document": { "type": "object" },
                    "body": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to read a Feishu document's content".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SHEETS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SHEETS_GET),
            summary: "Get Feishu spreadsheet info".into(),
            description: Some("Retrieves spreadsheet metadata and sheet list".into()),
            input_schema: json!({
                "type": "object",
                "required": ["spreadsheet_token"],
                "properties": {
                    "spreadsheet_token": { "type": "string", "description": "Spreadsheet token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "spreadsheet_token": { "type": "string" },
                    "title": { "type": "string" },
                    "sheets": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to read a Feishu spreadsheet's structure and data".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_DOCS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CALENDAR_EVENTS),
            summary: "List Feishu calendar events".into(),
            description: Some("Lists events from a specific calendar".into()),
            input_schema: json!({
                "type": "object",
                "required": ["calendar_id"],
                "properties": {
                    "calendar_id": { "type": "string", "description": "Calendar ID" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "page_token": { "type": "string" },
                    "has_more": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CALENDAR_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list events from a Feishu calendar".into(),
                common_mistakes: vec![
                    "calendar_id is required, not the same as user_id".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Feishu API health check".into(),
            description: Some("Verifies connectivity and authentication to Feishu API".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When checking if the Feishu API connection is healthy".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

#[async_trait]
impl FcpConnector for FeishuConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: FeishuConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Feishu config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let mut client = FeishuClient::new(
            &config.base_url,
            &config.app_id,
            &config.app_secret,
            config.retry.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Feishu client: {e}"),
        })?;

        // Attempt to obtain a tenant access token on configure
        if let Ok(token) = client.obtain_tenant_access_token().await {
            tracing::info!("Feishu tenant access token obtained (length={})", token.len());
        } else {
            tracing::warn!("Failed to obtain Feishu tenant access token; will retry on first request");
        }

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snapshot = if self.config.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        if !client.has_credentials() {
            return Ok(SelfCheckReport::degraded(
                "missing_credentials",
                "App ID or secret not configured",
            ));
        }

        match client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(err) => {
                if err.is_retryable() {
                    Ok(SelfCheckReport::degraded(
                        "self_check_retryable",
                        err.to_string(),
                    ))
                } else {
                    Ok(SelfCheckReport::failed(
                        "self_check_failed",
                        err.to_string(),
                    ))
                }
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl FeishuConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_MESSAGES_SEND | OP_MESSAGES_REPLY => CapabilityId::from_static(CAP_MSG_WRITE),
            OP_MESSAGES_GET => CapabilityId::from_static(CAP_MSG_READ),
            OP_CHATS_LIST | OP_CHATS_GET => CapabilityId::from_static(CAP_CHATS_READ),
            OP_USERS_GET | OP_HEALTH => CapabilityId::from_static(CAP_USERS_READ),
            OP_DOCS_GET | OP_SHEETS_GET => CapabilityId::from_static(CAP_DOCS_READ),
            OP_CALENDAR_EVENTS => CapabilityId::from_static(CAP_CALENDAR_READ),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Feishu client missing after configure".into(),
        })?;

        let output = match operation {
            OP_MESSAGES_SEND => {
                let receive_id = req
                    .input
                    .get("receive_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'receive_id' field".into(),
                    })?;
                let msg_type = req
                    .input
                    .get("msg_type")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'msg_type' field".into(),
                    })?;
                let content = req
                    .input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'content' field".into(),
                    })?;
                let receive_id_type = req
                    .input
                    .get("receive_id_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("open_id");

                let send_req = SendMessageRequest {
                    receive_id: receive_id.into(),
                    msg_type: msg_type.into(),
                    content: content.into(),
                };
                let resp = client
                    .send_message(runtime, receive_id_type, &send_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_MESSAGES_REPLY => {
                let message_id = req
                    .input
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message_id' field".into(),
                    })?;
                let msg_type = req
                    .input
                    .get("msg_type")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'msg_type' field".into(),
                    })?;
                let content = req
                    .input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'content' field".into(),
                    })?;

                let reply_req = ReplyMessageRequest {
                    msg_type: msg_type.into(),
                    content: content.into(),
                };
                let resp = client
                    .reply_message(runtime, message_id, &reply_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_MESSAGES_GET => {
                let message_id = req
                    .input
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message_id' field".into(),
                    })?;
                let resp = client
                    .get_message(runtime, message_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CHATS_LIST => {
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let page_size = req
                    .input
                    .get("page_size")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let resp = client
                    .list_chats(runtime, page_token, page_size)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CHATS_GET => {
                let chat_id = req
                    .input
                    .get("chat_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_id' field".into(),
                    })?;
                let resp = client
                    .get_chat(runtime, chat_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_USERS_GET => {
                let user_id = req
                    .input
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'user_id' field".into(),
                    })?;
                let user_id_type = req
                    .input
                    .get("user_id_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("open_id");
                let resp = client
                    .get_user(runtime, user_id, user_id_type)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_DOCS_GET => {
                let document_id = req
                    .input
                    .get("document_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'document_id' field".into(),
                    })?;
                let resp = client
                    .get_document(runtime, document_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_SHEETS_GET => {
                let spreadsheet_token = req
                    .input
                    .get("spreadsheet_token")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'spreadsheet_token' field".into(),
                    })?;
                let resp = client
                    .get_spreadsheet(runtime, spreadsheet_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CALENDAR_EVENTS => {
                let calendar_id = req
                    .input
                    .get("calendar_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'calendar_id' field".into(),
                    })?;
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_calendar_events(runtime, calendar_id, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_HEALTH => {
                client.health_check().await.map_err(|e| e.to_fcp_error())?;
                json!({ "status": "healthy" })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_MSG_WRITE),
                CapabilityId::from_static(CAP_MSG_READ),
                CapabilityId::from_static(CAP_CHATS_READ),
                CapabilityId::from_static(CAP_USERS_READ),
                CapabilityId::from_static(CAP_DOCS_READ),
                CapabilityId::from_static(CAP_CALENDAR_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(connector_id: &ConnectorId, operation: &'static str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = FeishuConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = FeishuConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = FeishuConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = FeishuConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = FeishuConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = FeishuConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_MESSAGES_SEND),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = FeishuConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 10);
        let op_ids: Vec<&str> = intro.operations.iter().map(|op| op.id.as_str()).collect();
        assert!(op_ids.contains(&OP_MESSAGES_SEND));
        assert!(op_ids.contains(&OP_MESSAGES_REPLY));
        assert!(op_ids.contains(&OP_MESSAGES_GET));
        assert!(op_ids.contains(&OP_CHATS_LIST));
        assert!(op_ids.contains(&OP_CHATS_GET));
        assert!(op_ids.contains(&OP_USERS_GET));
        assert!(op_ids.contains(&OP_DOCS_GET));
        assert!(op_ids.contains(&OP_SHEETS_GET));
        assert!(op_ids.contains(&OP_CALENDAR_EVENTS));
        assert!(op_ids.contains(&OP_HEALTH));
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 10);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_messages_send_is_risky() {
        let ops = operations_info();
        let send = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_SEND)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_messages_get_is_safe() {
        let ops = operations_info();
        let get = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_GET)
            .unwrap();
        assert_eq!(get.safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn test_health_op_is_safe_and_strict() {
        let ops = operations_info();
        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.safety_tier, SafetyTier::Safe);
        assert_eq!(health.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = FeishuConnector::manifest_hash();
        let hash2 = FeishuConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = FeishuConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let connector = FeishuConnector::new();
        // Can't test with full configure (needs network), just verify unconfigured case
        let req = base_invoke(connector.id(), "feishu.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err()); // Not configured
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = FeishuConnector::new();
        let req = base_invoke(connector.id(), OP_MESSAGES_SEND);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_default_impl() {
        let connector = FeishuConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.feishu");
    }

    #[test]
    fn test_config_debug_redacts_secret() {
        let config = FeishuConfig {
            base_url: "https://open.feishu.cn".into(),
            app_id: "cli_test".into(),
            app_secret: "secret_value_here".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("secret_value_here"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_chats_list_capability() {
        let ops = operations_info();
        let cl = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CHATS_LIST)
            .unwrap();
        assert_eq!(cl.capability, CapabilityId::from_static(CAP_CHATS_READ));
    }

    #[test]
    fn test_docs_get_capability() {
        let ops = operations_info();
        let dg = ops
            .iter()
            .find(|op| op.id.as_str() == OP_DOCS_GET)
            .unwrap();
        assert_eq!(dg.capability, CapabilityId::from_static(CAP_DOCS_READ));
    }

    #[test]
    fn test_sheets_get_capability() {
        let ops = operations_info();
        let sg = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SHEETS_GET)
            .unwrap();
        assert_eq!(sg.capability, CapabilityId::from_static(CAP_DOCS_READ));
    }

    #[test]
    fn test_calendar_events_capability() {
        let ops = operations_info();
        let ce = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CALENDAR_EVENTS)
            .unwrap();
        assert_eq!(ce.capability, CapabilityId::from_static(CAP_CALENDAR_READ));
    }

    #[test]
    fn test_users_get_capability() {
        let ops = operations_info();
        let ug = ops
            .iter()
            .find(|op| op.id.as_str() == OP_USERS_GET)
            .unwrap();
        assert_eq!(ug.capability, CapabilityId::from_static(CAP_USERS_READ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_capabilities() {
        let mut connector = FeishuConnector::new();
        let result = connector.handshake(base_handshake()).await.unwrap();
        assert_eq!(result.capabilities_granted.len(), 6);
    }

    #[test]
    fn test_messages_reply_is_risky() {
        let ops = operations_info();
        let reply = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_REPLY)
            .unwrap();
        assert_eq!(reply.safety_tier, SafetyTier::Risky);
        assert_eq!(reply.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_no_dangerous_operations() {
        // Feishu connector has no dangerous operations (no delete endpoints)
        let ops = operations_info();
        assert!(ops.iter().all(|op| op.safety_tier != SafetyTier::Dangerous));
    }

    #[test]
    fn test_all_safe_operations_are_low_risk() {
        let ops = operations_info();
        for op in &ops {
            if op.safety_tier == SafetyTier::Safe {
                assert_eq!(op.risk_level, RiskLevel::Low, "Op {} should be low risk", op.id.as_str());
            }
        }
    }

    #[test]
    fn test_all_risky_operations_are_medium_risk() {
        let ops = operations_info();
        for op in &ops {
            if op.safety_tier == SafetyTier::Risky {
                assert_eq!(op.risk_level, RiskLevel::Medium, "Op {} should be medium risk", op.id.as_str());
            }
        }
    }
}
