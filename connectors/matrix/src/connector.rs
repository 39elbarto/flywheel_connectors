//! Matrix connector implementation.

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

use crate::client::MatrixClient;
use crate::types::{CreateRoomRequest, MatrixAuth};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_JOINED_ROOMS: &str = "matrix.joined_rooms";
const OP_CREATE_ROOM: &str = "matrix.create_room";
const OP_JOIN_ROOM: &str = "matrix.join_room";
const OP_LEAVE_ROOM: &str = "matrix.leave_room";
const OP_SEND_MESSAGE: &str = "matrix.send_message";
const OP_GET_MESSAGES: &str = "matrix.get_messages";

const CAP_READ: &str = "matrix.read";
const CAP_WRITE: &str = "matrix.write";
const CAP_MANAGE: &str = "matrix.manage";

/// Matrix connector.
#[derive(Debug)]
pub struct MatrixConnector {
    base: BaseConnector,
    config: Option<crate::types::MatrixConfig>,
    client: Option<MatrixClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl MatrixConnector {
    /// Create a new connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.matrix")),
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

    /// Run diagnostics.
    #[must_use]
    pub fn doctor(&self) -> serde_json::Value {
        let configured = self.config.is_some();
        let client_ok = self.client.is_some();
        let runtime_ok = self.runtime.is_some();
        let passed = configured && client_ok && runtime_ok;
        json!({
            "passed": passed,
            "checks": [
                { "name": "configuration", "passed": configured, "critical": true },
                { "name": "client_initialized", "passed": client_ok, "critical": true },
                { "name": "runtime", "passed": runtime_ok, "critical": true },
            ]
        })
    }
}

impl Default for MatrixConnector {
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
            id: OperationId::from_static(OP_JOINED_ROOMS),
            summary: "List joined rooms".into(),
            description: Some("Lists all rooms the authenticated user has joined".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": { "rooms": { "type": "array", "items": { "type": "string" } } }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to discover which rooms the bot is in".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_JOIN_ROOM)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CREATE_ROOM),
            summary: "Create a room".into(),
            description: Some("Creates a new Matrix room".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "topic": { "type": "string" },
                    "invite": { "type": "array", "items": { "type": "string" } },
                    "visibility": { "type": "string", "enum": ["public", "private"] },
                    "preset": { "type": "string", "enum": ["private_chat", "public_chat", "trusted_private_chat"] }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": { "room_id": { "type": "string" } }
            }),
            capability: CapabilityId::from_static(CAP_MANAGE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to create a new conversation space".into(),
                common_mistakes: vec![
                    "Room names are optional; room IDs are auto-generated".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_JOIN_ROOM),
            summary: "Join a room".into(),
            description: Some("Joins a room by ID or alias".into()),
            input_schema: json!({
                "type": "object",
                "required": ["room_id_or_alias"],
                "properties": {
                    "room_id_or_alias": { "type": "string", "description": "Room ID (!...) or alias (#...)" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MANAGE),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to join a room before sending messages".into(),
                common_mistakes: vec!["Room IDs start with !, aliases start with #".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_LEAVE_ROOM)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_LEAVE_ROOM),
            summary: "Leave a room".into(),
            description: Some("Leaves a room".into()),
            input_schema: json!({
                "type": "object",
                "required": ["room_id"],
                "properties": {
                    "room_id": { "type": "string" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MANAGE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to leave a room you no longer need".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_JOIN_ROOM)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEND_MESSAGE),
            summary: "Send a message to a room".into(),
            description: Some("Sends a text message to a Matrix room".into()),
            input_schema: json!({
                "type": "object",
                "required": ["room_id", "body"],
                "properties": {
                    "room_id": { "type": "string" },
                    "body": { "type": "string" },
                    "msgtype": { "type": "string", "default": "m.text", "description": "m.text, m.notice, m.emote" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": { "event_id": { "type": "string" } }
            }),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a message in a Matrix room".into(),
                common_mistakes: vec![
                    "Must be joined to the room first".into(),
                    "Use m.notice for bot messages to avoid notification spam".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_MESSAGES)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_MESSAGES),
            summary: "Get messages from a room".into(),
            description: Some("Retrieves messages from a room with pagination".into()),
            input_schema: json!({
                "type": "object",
                "required": ["room_id"],
                "properties": {
                    "room_id": { "type": "string" },
                    "from": { "type": "string", "description": "Pagination token" },
                    "limit": { "type": "integer", "default": 20 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "messages": { "type": "array" },
                    "end": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read chat history from a room".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SEND_MESSAGE)],
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
impl FcpConnector for MatrixConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: crate::types::MatrixConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Matrix config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.timeout_ms)),
        ));

        let timeout = Duration::from_millis(config.timeout_ms);
        let token = match &config.auth {
            MatrixAuth::AccessToken { access_token } => access_token.as_str(),
            MatrixAuth::CredentialId { .. } => "",
        };

        let client = MatrixClient::new(&config.homeserver_url, token, timeout).map_err(|e| {
            FcpError::Internal {
                message: format!("Failed to create Matrix client: {e}"),
            }
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

impl MatrixConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let operation = req.operation.as_str();

        if let Some(verifier) = &self.verifier {
            let required_cap = match operation {
                OP_JOINED_ROOMS | OP_GET_MESSAGES => CapabilityId::from_static(CAP_READ),
                OP_SEND_MESSAGE => CapabilityId::from_static(CAP_WRITE),
                OP_CREATE_ROOM | OP_JOIN_ROOM | OP_LEAVE_ROOM => {
                    CapabilityId::from_static(CAP_MANAGE)
                }
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            };
            verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let output = match operation {
            OP_JOINED_ROOMS => {
                let rooms = client.joined_rooms().await.map_err(|e| e.to_fcp_error())?;
                json!({ "rooms": rooms })
            }
            OP_CREATE_ROOM => {
                let name = req
                    .input
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let topic = req
                    .input
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let invite: Vec<String> = req
                    .input
                    .get("invite")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let visibility = req
                    .input
                    .get("visibility")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let preset = req
                    .input
                    .get("preset")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let create_req = CreateRoomRequest {
                    name,
                    topic,
                    room_alias_name: None,
                    invite,
                    visibility,
                    preset,
                };
                let resp = client
                    .create_room(&create_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "room_id": resp.room_id })
            }
            OP_JOIN_ROOM => {
                let room = require_str(&req.input, "room_id_or_alias")?;
                client.join_room(room).await.map_err(|e| e.to_fcp_error())?;
                json!({ "status": "joined" })
            }
            OP_LEAVE_ROOM => {
                let room_id = require_str(&req.input, "room_id")?;
                client
                    .leave_room(room_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "status": "left" })
            }
            OP_SEND_MESSAGE => {
                let room_id = require_str(&req.input, "room_id")?;
                let body = require_str(&req.input, "body")?;
                let msgtype = req
                    .input
                    .get("msgtype")
                    .and_then(|v| v.as_str())
                    .unwrap_or("m.text");
                let resp = client
                    .send_message(room_id, body, msgtype)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "event_id": resp.event_id })
            }
            OP_GET_MESSAGES => {
                let room_id = require_str(&req.input, "room_id")?;
                let from = req.input.get("from").and_then(|v| v.as_str());
                let limit = u32::try_from(
                    req.input
                        .get("limit")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(20),
                )
                .unwrap_or(20);
                let resp = client
                    .get_messages(room_id, from, limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "messages": resp.chunk,
                    "end": resp.end,
                })
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
    fn operations_count() {
        assert_eq!(operations_info().len(), 6);
    }

    #[test]
    fn operations_have_hints() {
        for op in &operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn send_message_is_risky() {
        let ops = operations_info();
        let send = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
    }

    #[test]
    fn read_ops_are_safe() {
        let ops = operations_info();
        let rooms = ops
            .iter()
            .find(|op| op.id.as_str() == OP_JOINED_ROOMS)
            .unwrap();
        assert_eq!(rooms.safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn introspection() {
        let c = MatrixConnector::new();
        let intro = c.introspect();
        assert_eq!(intro.operations.len(), 6);
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn configure_access_token() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "access_token", "access_token": "syt_abc" }
            }))
            .await;
        assert!(result.is_ok());
        assert!(c.config.is_some());
        assert!(c.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_credential_id() {
        let mut c = MatrixConnector::new();
        let result = c
            .configure(json!({
                "homeserver_url": "https://matrix.org",
                "auth": { "mode": "credential_id", "credential_id": "cred_1" }
            }))
            .await;
        assert!(result.is_ok());
        assert!(c.client.as_ref().unwrap().is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_invalid() {
        let mut c = MatrixConnector::new();
        assert!(c.configure(json!({})).await.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_before_configure() {
        let c = MatrixConnector::new();
        let h = c.health().await;
        assert!(matches!(h.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn health_after_configure() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .unwrap();
        let h = c.health().await;
        assert!(matches!(h.status, HealthState::Ready));
    }

    #[test]
    fn doctor_before_configure() {
        let c = MatrixConnector::new();
        let d = c.doctor();
        assert!(!d["passed"].as_bool().unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_after_configure() {
        let mut c = MatrixConnector::new();
        c.configure(json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .await
        .unwrap();
        let d = c.doctor();
        assert!(d["passed"].as_bool().unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn handshake() {
        let mut c = MatrixConnector::new();
        let req = HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
                CapabilityId::from_static(CAP_MANAGE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };
        let result = c.handshake(req).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status, "accepted");
    }

    #[test]
    fn manifest_hash_deterministic() {
        let h1 = MatrixConnector::manifest_hash();
        let h2 = MatrixConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_before_configure() {
        let c = MatrixConnector::new();
        let r = c.self_check().await.unwrap();
        assert_eq!(r.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate() {
        let c = MatrixConnector::new();
        let req = SimulateRequest::new(
            c.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = c.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }
}
