//! LINE connector implementation.

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

use crate::client::LineClient;
use crate::types::{Message, RichMenu};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_PUSH: &str = "line.messages.push";
const OP_REPLY: &str = "line.messages.reply";
const OP_MULTICAST: &str = "line.messages.multicast";
const OP_PROFILE_GET: &str = "line.profile.get";
const OP_GROUP_PROFILE: &str = "line.group.profile";
const OP_GROUP_MEMBERS: &str = "line.group.members";
const OP_RICH_MENU_LIST: &str = "line.rich_menu.list";
const OP_RICH_MENU_CREATE: &str = "line.rich_menu.create";
const OP_RICH_MENU_DELETE: &str = "line.rich_menu.delete";
const OP_HEALTH: &str = "line.health";

// Capability IDs
const CAP_MSG_WRITE: &str = "line.messages.write";
const CAP_PROFILE_READ: &str = "line.profile.read";
const CAP_MENU_READ: &str = "line.menu.read";
const CAP_MENU_WRITE: &str = "line.menu.write";

/// LINE connector configuration.
#[derive(Clone, Deserialize)]
struct LineConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    channel_access_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for LineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineConfig")
            .field("base_url", &self.base_url)
            .field("channel_access_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://api.line.me".into()
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

/// LINE connector state.
#[derive(Debug)]
pub struct LineConnector {
    base: BaseConnector,
    config: Option<LineConfig>,
    client: Option<LineClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl LineConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.line")),
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
            let allowed_hosts = ["api.line.me"];
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
                    "Base URL matches allowed host (api.line.me)".into()
                } else {
                    format!("Base URL {} does not match allowed hosts", config.base_url)
                }),
                critical: true,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for LineConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_PUSH),
            summary: "Push a message to a LINE user".into(),
            description: Some("Sends a push message to a specific user by user ID".into()),
            input_schema: json!({
                "type": "object",
                "required": ["to", "messages"],
                "properties": {
                    "to": { "type": "string", "description": "User ID to send to" },
                    "messages": {
                        "type": "array",
                        "description": "Array of message objects (max 5)",
                        "items": { "type": "object" }
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "sent_messages": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a message to a LINE user proactively".into(),
                common_mistakes: vec![
                    "User ID must start with 'U' (33 chars total)".into(),
                    "Maximum 5 messages per request".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_REPLY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_REPLY),
            summary: "Reply to a LINE message".into(),
            description: Some("Sends a reply using a reply token from a webhook event".into()),
            input_schema: json!({
                "type": "object",
                "required": ["reply_token", "messages"],
                "properties": {
                    "reply_token": { "type": "string", "description": "Reply token from webhook" },
                    "messages": {
                        "type": "array",
                        "description": "Array of message objects (max 5)",
                        "items": { "type": "object" }
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "sent_messages": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When replying to a user message received via webhook".into(),
                common_mistakes: vec![
                    "Reply tokens expire after 1 minute".into(),
                    "Reply tokens can only be used once".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PUSH)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MULTICAST),
            summary: "Send a message to multiple LINE users".into(),
            description: Some("Sends a message to up to 500 users at once".into()),
            input_schema: json!({
                "type": "object",
                "required": ["to", "messages"],
                "properties": {
                    "to": {
                        "type": "array",
                        "description": "Array of user IDs (max 500)",
                        "items": { "type": "string" }
                    },
                    "messages": {
                        "type": "array",
                        "description": "Array of message objects (max 5)",
                        "items": { "type": "object" }
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "sent_messages": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When broadcasting a message to multiple users at once".into(),
                common_mistakes: vec![
                    "Maximum 500 user IDs per request".into(),
                    "Maximum 5 messages per request".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PUSH)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PROFILE_GET),
            summary: "Get a LINE user's profile".into(),
            description: Some("Retrieves display name, picture URL, and status message".into()),
            input_schema: json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string", "description": "LINE user ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "displayName": { "type": "string" },
                    "userId": { "type": "string" },
                    "pictureUrl": { "type": "string" },
                    "statusMessage": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PROFILE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to look up a user's profile information".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GROUP_PROFILE),
            summary: "Get a LINE group's profile".into(),
            description: Some("Retrieves group name and picture URL".into()),
            input_schema: json!({
                "type": "object",
                "required": ["group_id"],
                "properties": {
                    "group_id": { "type": "string", "description": "LINE group ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "groupId": { "type": "string" },
                    "groupName": { "type": "string" },
                    "pictureUrl": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PROFILE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need group chat information".into(),
                common_mistakes: vec![
                    "Group ID starts with 'C'".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GROUP_MEMBERS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GROUP_MEMBERS),
            summary: "List members of a LINE group".into(),
            description: Some("Returns member IDs with pagination support".into()),
            input_schema: json!({
                "type": "object",
                "required": ["group_id"],
                "properties": {
                    "group_id": { "type": "string", "description": "LINE group ID" },
                    "start": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "memberIds": { "type": "array", "items": { "type": "string" } },
                    "next": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PROFILE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list all members of a group".into(),
                common_mistakes: vec![
                    "Use pagination token from 'next' field for subsequent pages".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GROUP_PROFILE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RICH_MENU_LIST),
            summary: "List LINE rich menus".into(),
            description: Some("Lists all rich menus for the bot".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "richmenus": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MENU_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to see existing rich menus".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_RICH_MENU_CREATE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RICH_MENU_CREATE),
            summary: "Create a LINE rich menu".into(),
            description: Some("Creates a new rich menu configuration".into()),
            input_schema: json!({
                "type": "object",
                "required": ["size", "selected", "name", "chatBarText", "areas"],
                "properties": {
                    "size": { "type": "object", "properties": { "width": { "type": "integer" }, "height": { "type": "integer" } } },
                    "selected": { "type": "boolean" },
                    "name": { "type": "string" },
                    "chatBarText": { "type": "string" },
                    "areas": { "type": "array" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "richMenuId": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MENU_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When creating a new rich menu for users to interact with".into(),
                common_mistakes: vec![
                    "Size must be 2500x1686 or 2500x843".into(),
                    "Upload the image separately after creating the menu".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_RICH_MENU_DELETE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RICH_MENU_DELETE),
            summary: "Delete a LINE rich menu".into(),
            description: Some("Permanently deletes a rich menu".into()),
            input_schema: json!({
                "type": "object",
                "required": ["rich_menu_id"],
                "properties": {
                    "rich_menu_id": { "type": "string", "description": "Rich menu ID to delete" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "deleted": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MENU_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When permanently removing a rich menu".into(),
                common_mistakes: vec![
                    "This action is irreversible".into(),
                    "Users linked to this menu will lose their menu".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_RICH_MENU_CREATE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "LINE API health check".into(),
            description: Some("Verifies connectivity and authentication to LINE API".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PROFILE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When checking if the LINE API connection is healthy".into(),
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
impl FcpConnector for LineConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: LineConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid LINE config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = LineClient::new(
            &config.base_url,
            &config.channel_access_token,
            config.retry.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create LINE client: {e}"),
        })?;

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

        if client.is_secretless() {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with empty token; egress proxy injection required",
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

impl LineConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_PUSH | OP_REPLY | OP_MULTICAST => CapabilityId::from_static(CAP_MSG_WRITE),
            OP_PROFILE_GET | OP_GROUP_PROFILE | OP_GROUP_MEMBERS | OP_HEALTH => {
                CapabilityId::from_static(CAP_PROFILE_READ)
            }
            OP_RICH_MENU_LIST => CapabilityId::from_static(CAP_MENU_READ),
            OP_RICH_MENU_CREATE | OP_RICH_MENU_DELETE => {
                CapabilityId::from_static(CAP_MENU_WRITE)
            }
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
            message: "LINE client missing after configure".into(),
        })?;

        let output = match operation {
            OP_PUSH => {
                let to = req.input.get("to").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'to' field".into(),
                    },
                )?;
                let messages: Vec<Message> = req
                    .input
                    .get("messages")
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'messages' field: {e}"),
                    })?
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'messages' field".into(),
                    })?;

                let resp = client
                    .push_message(runtime, to, messages)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_REPLY => {
                let reply_token = req
                    .input
                    .get("reply_token")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'reply_token' field".into(),
                    })?;
                let messages: Vec<Message> = req
                    .input
                    .get("messages")
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'messages' field: {e}"),
                    })?
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'messages' field".into(),
                    })?;

                let resp = client
                    .reply_message(runtime, reply_token, messages)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_MULTICAST => {
                let to: Vec<String> = req
                    .input
                    .get("to")
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'to' field: {e}"),
                    })?
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'to' field".into(),
                    })?;
                let messages: Vec<Message> = req
                    .input
                    .get("messages")
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'messages' field: {e}"),
                    })?
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'messages' field".into(),
                    })?;

                let resp = client
                    .multicast(runtime, &to, messages)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_PROFILE_GET => {
                let user_id = req
                    .input
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'user_id' field".into(),
                    })?;
                let profile = client
                    .get_profile(runtime, user_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(profile).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize profile: {e}"),
                })?
            }
            OP_GROUP_PROFILE => {
                let group_id = req
                    .input
                    .get("group_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'group_id' field".into(),
                    })?;
                let summary = client
                    .get_group_summary(runtime, group_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(summary).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize group summary: {e}"),
                })?
            }
            OP_GROUP_MEMBERS => {
                let group_id = req
                    .input
                    .get("group_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'group_id' field".into(),
                    })?;
                let start = req.input.get("start").and_then(|v| v.as_str());
                let members = client
                    .get_group_members(runtime, group_id, start)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(members).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize group members: {e}"),
                })?
            }
            OP_RICH_MENU_LIST => {
                let menus = client
                    .list_rich_menus(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(menus).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize rich menus: {e}"),
                })?
            }
            OP_RICH_MENU_CREATE => {
                let menu: RichMenu = serde_json::from_value(req.input.clone()).map_err(|e| {
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid rich menu input: {e}"),
                    }
                })?;
                let resp = client
                    .create_rich_menu(runtime, &menu)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "richMenuId": resp.rich_menu_id })
            }
            OP_RICH_MENU_DELETE => {
                let rich_menu_id = req
                    .input
                    .get("rich_menu_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'rich_menu_id' field".into(),
                    })?;
                client
                    .delete_rich_menu(runtime, rich_menu_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "deleted": true })
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
                CapabilityId::from_static(CAP_PROFILE_READ),
                CapabilityId::from_static(CAP_MENU_READ),
                CapabilityId::from_static(CAP_MENU_WRITE),
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
        let mut connector = LineConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = LineConnector::new();
        let config = json!({
            "channel_access_token": "test_token"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = LineConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = LineConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = LineConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = LineConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = LineConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_PUSH),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = LineConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 10);
        let op_ids: Vec<&str> = intro.operations.iter().map(|op| op.id.as_str()).collect();
        assert!(op_ids.contains(&OP_PUSH));
        assert!(op_ids.contains(&OP_REPLY));
        assert!(op_ids.contains(&OP_MULTICAST));
        assert!(op_ids.contains(&OP_PROFILE_GET));
        assert!(op_ids.contains(&OP_GROUP_PROFILE));
        assert!(op_ids.contains(&OP_GROUP_MEMBERS));
        assert!(op_ids.contains(&OP_RICH_MENU_LIST));
        assert!(op_ids.contains(&OP_RICH_MENU_CREATE));
        assert!(op_ids.contains(&OP_RICH_MENU_DELETE));
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
    fn test_push_is_risky() {
        let ops = operations_info();
        let push = ops.iter().find(|op| op.id.as_str() == OP_PUSH).unwrap();
        assert_eq!(push.safety_tier, SafetyTier::Risky);
        assert_eq!(push.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_profile_get_is_safe() {
        let ops = operations_info();
        let profile = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PROFILE_GET)
            .unwrap();
        assert_eq!(profile.safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn test_rich_menu_delete_is_dangerous() {
        let ops = operations_info();
        let del = ops
            .iter()
            .find(|op| op.id.as_str() == OP_RICH_MENU_DELETE)
            .unwrap();
        assert_eq!(del.safety_tier, SafetyTier::Dangerous);
        assert_eq!(del.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_rich_menu_create_is_strict_idempotency() {
        let ops = operations_info();
        let create = ops
            .iter()
            .find(|op| op.id.as_str() == OP_RICH_MENU_CREATE)
            .unwrap();
        assert_eq!(create.idempotency, IdempotencyClass::Strict);
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
        let hash1 = LineConnector::manifest_hash();
        let hash2 = LineConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = LineConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "line.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = LineConnector::new();
        let req = base_invoke(connector.id(), OP_PUSH);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_push_missing_to() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_PUSH);
        req.input = json!({ "messages": [{ "type": "text", "text": "hi" }] });
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_push_missing_messages() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_PUSH);
        req.input = json!({ "to": "U1234" });
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_reply_missing_token() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_REPLY);
        req.input = json!({ "messages": [{ "type": "text", "text": "hi" }] });
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_profile_missing_user_id() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PROFILE_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_group_profile_missing_group_id() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_GROUP_PROFILE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rich_menu_delete_missing_id() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_RICH_MENU_DELETE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_default_impl() {
        let connector = LineConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.line");
    }

    #[test]
    fn test_config_debug_redacts_token() {
        let config = LineConfig {
            base_url: "https://api.line.me".into(),
            channel_access_token: "secret_token_value".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("secret_token_value"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_multicast_capability() {
        let ops = operations_info();
        let mc = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MULTICAST)
            .unwrap();
        assert_eq!(mc.capability, CapabilityId::from_static(CAP_MSG_WRITE));
    }

    #[test]
    fn test_group_members_capability() {
        let ops = operations_info();
        let gm = ops
            .iter()
            .find(|op| op.id.as_str() == OP_GROUP_MEMBERS)
            .unwrap();
        assert_eq!(gm.capability, CapabilityId::from_static(CAP_PROFILE_READ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_capabilities() {
        let mut connector = LineConnector::new();
        let result = connector.handshake(base_handshake()).await.unwrap();
        assert_eq!(result.capabilities_granted.len(), 4);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_custom_timeout() {
        let mut connector = LineConnector::new();
        let config = json!({
            "channel_access_token": "tok",
            "request_timeout_ms": 60000
        });
        connector.configure(config).await.unwrap();
        assert!(connector.runtime.is_some());
    }
}
