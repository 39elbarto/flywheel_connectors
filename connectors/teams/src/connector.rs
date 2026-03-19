//! Teams connector implementation.

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
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::TeamsClient;
use crate::types::TeamsAuth;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_LIST_TEAMS: &str = "teams.list_teams";
const OP_GET_TEAM: &str = "teams.get_team";
const OP_LIST_CHANNELS: &str = "teams.list_channels";
const OP_GET_CHANNEL: &str = "teams.get_channel";
const OP_SEND_CHANNEL_MSG: &str = "teams.send_channel_message";
const OP_LIST_CHATS: &str = "teams.list_chats";
const OP_SEND_CHAT_MSG: &str = "teams.send_chat_message";
const OP_LIST_CHAT_MSGS: &str = "teams.list_chat_messages";

// Capability IDs
const CAP_READ: &str = "teams.read";
const CAP_WRITE: &str = "teams.write";

/// Doctor check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

/// Single doctor check.
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

/// Microsoft Teams connector.
#[derive(Debug)]
pub struct TeamsConnector {
    base: BaseConnector,
    config: Option<crate::types::TeamsConfig>,
    client: Option<TeamsClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl TeamsConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.teams")),
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
    #[must_use]
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
                "Graph API client initialized".into()
            } else {
                "Graph client missing; re-run configure".into()
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
            let allowed_hosts = ["graph.microsoft.com"];
            let host_part = config
                .graph_base_url
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
                    "Graph URL matches allowed host (graph.microsoft.com)".into()
                } else {
                    format!("Graph URL host {host_part} not in allowed list")
                }),
                critical: true,
            });

            let auth_mode = match &config.auth {
                TeamsAuth::AccessToken { .. } => "access_token",
                TeamsAuth::ClientCredentials { .. } => "client_credentials",
                TeamsAuth::CredentialId { .. } => "credential_id",
            };
            let secretless = self.client.as_ref().is_some_and(TeamsClient::is_secretless);
            checks.push(DoctorCheck {
                name: "credential_mode".into(),
                passed: !secretless,
                message: Some(if secretless {
                    "Credential injection required via egress proxy".into()
                } else {
                    format!("Auth mode: {auth_mode}")
                }),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for TeamsConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_LIST_TEAMS),
            summary: "List joined teams".into(),
            description: Some("Lists teams the authenticated user has joined".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "teams": { "type": "array", "items": { "type": "object" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to discover which Teams the user belongs to".into(),
                common_mistakes: vec![
                    "Requires delegated permissions (Team.ReadBasic.All or similar)".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_LIST_CHANNELS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_TEAM),
            summary: "Get team details".into(),
            description: Some("Retrieves details of a specific team by ID".into()),
            input_schema: json!({
                "type": "object",
                "required": ["team_id"],
                "properties": {
                    "team_id": { "type": "string", "description": "Team ID" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific team".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_LIST_CHANNELS),
            summary: "List channels in a team".into(),
            description: Some("Lists all channels in the specified team".into()),
            input_schema: json!({
                "type": "object",
                "required": ["team_id"],
                "properties": {
                    "team_id": { "type": "string", "description": "Team ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "channels": { "type": "array", "items": { "type": "object" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to list channels available in a team".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SEND_CHANNEL_MSG)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_CHANNEL),
            summary: "Get channel details".into(),
            description: Some("Retrieves details of a specific channel".into()),
            input_schema: json!({
                "type": "object",
                "required": ["team_id", "channel_id"],
                "properties": {
                    "team_id": { "type": "string" },
                    "channel_id": { "type": "string" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific channel".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEND_CHANNEL_MSG),
            summary: "Send a message to a channel".into(),
            description: Some("Posts a message to a Teams channel".into()),
            input_schema: json!({
                "type": "object",
                "required": ["team_id", "channel_id", "content"],
                "properties": {
                    "team_id": { "type": "string" },
                    "channel_id": { "type": "string" },
                    "content": { "type": "string", "description": "Message content" },
                    "content_type": { "type": "string", "default": "text", "description": "text or html" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": { "message_id": { "type": "string" } }
            }),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to post a message in a Teams channel".into(),
                common_mistakes: vec![
                    "Requires ChannelMessage.Send permission".into(),
                    "HTML content needs content_type set to 'html'".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_LIST_CHANNELS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_LIST_CHATS),
            summary: "List user's chats".into(),
            description: Some("Lists the authenticated user's 1:1 and group chats".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "chats": { "type": "array", "items": { "type": "object" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to list the user's chat conversations".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SEND_CHAT_MSG)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEND_CHAT_MSG),
            summary: "Send a chat message".into(),
            description: Some("Sends a message in a 1:1 or group chat".into()),
            input_schema: json!({
                "type": "object",
                "required": ["chat_id", "content"],
                "properties": {
                    "chat_id": { "type": "string" },
                    "content": { "type": "string" },
                    "content_type": { "type": "string", "default": "text" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": { "message_id": { "type": "string" } }
            }),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a direct or group chat message".into(),
                common_mistakes: vec!["Requires Chat.ReadWrite permission".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_LIST_CHATS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_LIST_CHAT_MSGS),
            summary: "List messages in a chat".into(),
            description: Some("Lists messages in a 1:1 or group chat".into()),
            input_schema: json!({
                "type": "object",
                "required": ["chat_id"],
                "properties": {
                    "chat_id": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "messages": { "type": "array", "items": { "type": "object" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read chat history".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{field}' field"),
        })
}

#[async_trait]
impl FcpConnector for TeamsConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: crate::types::TeamsConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Teams config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.timeout_ms)),
        ));

        let timeout = Duration::from_millis(config.timeout_ms);
        let client = match &config.auth {
            TeamsAuth::AccessToken { access_token } => {
                TeamsClient::new(&config.graph_base_url, access_token, timeout).map_err(|e| {
                    FcpError::Internal {
                        message: format!("Failed to create Teams client: {e}"),
                    }
                })?
            }
            TeamsAuth::CredentialId { credential_id } => {
                TeamsClient::new_secretless(&config.graph_base_url, credential_id, timeout)
                    .map_err(|e| FcpError::Internal {
                        message: format!("Failed to create Teams client: {e}"),
                    })?
            }
            TeamsAuth::ClientCredentials {
                client_id,
                client_secret,
                tenant_id,
            } => TeamsClient::from_client_credentials(
                &config.graph_base_url,
                client_id,
                client_secret,
                tenant_id,
                timeout,
            )
            .await
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create Teams client: {e}"),
            })?,
        };

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

impl TeamsConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;

        let operation = req.operation.as_str();
        let required_cap = match operation {
            OP_LIST_TEAMS | OP_GET_TEAM | OP_LIST_CHANNELS | OP_GET_CHANNEL | OP_LIST_CHATS
            | OP_LIST_CHAT_MSGS => CapabilityId::from_static(CAP_READ),
            OP_SEND_CHANNEL_MSG | OP_SEND_CHAT_MSG => CapabilityId::from_static(CAP_WRITE),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        let verifier = self.verifier.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing capability verifier".into(),
        })?;
        verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Teams client".into(),
        })?;

        let output = match operation {
            OP_LIST_TEAMS => {
                let teams = client.list_my_teams().await.map_err(|e| e.to_fcp_error())?;
                json!({ "teams": teams })
            }
            OP_GET_TEAM => {
                let team_id = require_str(&req.input, "team_id")?;
                let team = client
                    .get_team(team_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&team).map_err(|e| FcpError::Internal {
                    message: format!("Serialization error: {e}"),
                })?
            }
            OP_LIST_CHANNELS => {
                let team_id = require_str(&req.input, "team_id")?;
                let channels = client
                    .list_channels(team_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "channels": channels })
            }
            OP_GET_CHANNEL => {
                let team_id = require_str(&req.input, "team_id")?;
                let channel_id = require_str(&req.input, "channel_id")?;
                let channel = client
                    .get_channel(team_id, channel_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&channel).map_err(|e| FcpError::Internal {
                    message: format!("Serialization error: {e}"),
                })?
            }
            OP_SEND_CHANNEL_MSG => {
                let team_id = require_str(&req.input, "team_id")?;
                let channel_id = require_str(&req.input, "channel_id")?;
                let content = require_str(&req.input, "content")?;
                let content_type = req
                    .input
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("text");
                let msg = client
                    .send_channel_message(team_id, channel_id, content, content_type)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "message_id": msg.id.unwrap_or_default() })
            }
            OP_LIST_CHATS => {
                let chats = client.list_my_chats().await.map_err(|e| e.to_fcp_error())?;
                json!({ "chats": chats })
            }
            OP_SEND_CHAT_MSG => {
                let chat_id = require_str(&req.input, "chat_id")?;
                let content = require_str(&req.input, "content")?;
                let content_type = req
                    .input
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("text");
                let msg = client
                    .send_chat_message(chat_id, content, content_type)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "message_id": msg.id.unwrap_or_default() })
            }
            OP_LIST_CHAT_MSGS => {
                let chat_id = require_str(&req.input, "chat_id")?;
                let messages = client
                    .list_chat_messages(chat_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "messages": messages })
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

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 8);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        for op in &operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_send_operations_are_risky() {
        let ops = operations_info();
        let send_ch = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_CHANNEL_MSG)
            .unwrap();
        assert_eq!(send_ch.safety_tier, SafetyTier::Risky);
        assert_eq!(send_ch.idempotency, IdempotencyClass::None);

        let send_chat = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_CHAT_MSG)
            .unwrap();
        assert_eq!(send_chat.safety_tier, SafetyTier::Risky);
    }

    #[test]
    fn test_read_operations_are_safe() {
        let ops = operations_info();
        let list_teams = ops
            .iter()
            .find(|op| op.id.as_str() == OP_LIST_TEAMS)
            .unwrap();
        assert_eq!(list_teams.safety_tier, SafetyTier::Safe);
        assert_eq!(list_teams.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_introspection() {
        let connector = TeamsConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 8);
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_access_token() {
        let mut connector = TeamsConnector::new();
        let result = connector
            .configure(json!({
                "auth": { "mode": "access_token", "access_token": "tok_123" }
            }))
            .await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id() {
        let mut connector = TeamsConnector::new();
        let result = connector
            .configure(json!({
                "auth": { "mode": "credential_id", "credential_id": "cred_1" }
            }))
            .await;
        assert!(result.is_ok());
        assert!(connector.client.as_ref().unwrap().is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_invalid() {
        let mut connector = TeamsConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = TeamsConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = TeamsConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = TeamsConnector::new();
        let req = HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };
        let result = connector.handshake(req).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status, "accepted");
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let h1 = TeamsConnector::manifest_hash();
        let h2 = TeamsConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = TeamsConnector::new();
        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_LIST_TEAMS),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = TeamsConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_LIST_TEAMS),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = TeamsConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_requires_handshake_after_configure() {
        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await
            .unwrap();

        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_2"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_LIST_TEAMS),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let err = connector.invoke(req).await.unwrap_err();
        assert!(matches!(err, FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_unauthorized_is_failed() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me"))
            .respond_with(
                wiremock::ResponseTemplate::new(401).set_body_json(serde_json::json!({
                    "error": {
                        "code": "InvalidAuthenticationToken",
                        "message": "Access token has expired."
                    }
                })),
            )
            .mount(&mock_server)
            .await;

        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "graph_base_url": mock_server.uri(),
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await
            .unwrap();

        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert_eq!(report.reason_code.as_deref(), Some("self_check_failed"));
    }
}
