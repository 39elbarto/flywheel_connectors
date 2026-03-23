//! `WeCom` enterprise messaging connector.

use std::collections::BTreeMap;
use std::time::Instant;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, EventData, EventEnvelope, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, OrderingPolicy,
    Principal, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, TrustLevel, UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::client::WeComClient;
use crate::types::{
    WeComCallbackEnvelope, WeComCallbackIngestRequest, WeComCallbackVerifyRequest, WeComConfig,
    WeComDepartmentListRequest, WeComMediaDownloadRequest, WeComMediaUploadRequest,
    WeComMessageKind, WeComMessageRequest, WeComStateModel, WeComUserLookupRequest,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_SEND_TEXT: &str = "wecom.messages.send_text";
const OP_SEND_MARKDOWN: &str = "wecom.messages.send_markdown";
const OP_SEND_IMAGE: &str = "wecom.messages.send_image";
const OP_SEND_FILE: &str = "wecom.messages.send_file";
const OP_UPLOAD_MEDIA: &str = "wecom.media.upload";
const OP_DOWNLOAD_MEDIA: &str = "wecom.media.download";
const OP_GET_USER: &str = "wecom.users.get";
const OP_LIST_DEPARTMENTS: &str = "wecom.departments.list";
const OP_VERIFY_CALLBACK_URL: &str = "wecom.callback.verify_url";
const OP_INGEST_CALLBACK_EVENT: &str = "wecom.callback.ingest_event";
const OP_HEALTH: &str = "wecom.health";

const CAP_MESSAGES_WRITE: &str = "wecom.messages.write";
const CAP_MEDIA_WRITE: &str = "wecom.media.write";
const CAP_MEDIA_READ: &str = "wecom.media.read";
const CAP_USERS_READ: &str = "wecom.users.read";
const CAP_DEPARTMENTS_READ: &str = "wecom.departments.read";
const CAP_EVENTS_READ: &str = "wecom.events.read";
const CAP_HEALTH_READ: &str = "wecom.health.read";

#[derive(Debug, Clone, PartialEq, Eq)]
struct WeComConversation {
    kind: &'static str,
    id: String,
    stream_key: String,
    resource_uri: String,
}

#[derive(Debug)]
struct WeComState {
    client: WeComClient,
}

#[derive(Debug)]
pub struct WeComConnector {
    base: BaseConnector,
    state: Option<WeComState>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
}

impl WeComConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.wecom")),
            state: None,
            verifier: None,
            started_at: Instant::now(),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    #[allow(clippy::too_many_lines)]
    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_SEND_TEXT,
                "Send a WeCom text message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["content"],
                    "properties": {
                        "content": { "type": "string" },
                        "touser": { "type": "string" },
                        "toparty": { "type": "string" },
                        "totag": { "type": "string" },
                        "safe": { "type": "boolean" },
                        "enable_duplicate_check": { "type": "boolean" },
                        "duplicate_check_interval": { "type": "integer", "minimum": 0 }
                    }
                }),
                "Use when a work-zone automation must proactively deliver plain text into WeCom.",
            ),
            operation(
                OP_SEND_MARKDOWN,
                "Send a WeCom markdown message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["content"],
                    "properties": {
                        "content": { "type": "string" },
                        "touser": { "type": "string" },
                        "toparty": { "type": "string" },
                        "totag": { "type": "string" },
                        "enable_duplicate_check": { "type": "boolean" },
                        "duplicate_check_interval": { "type": "integer", "minimum": 0 }
                    }
                }),
                "Use when the destination accepts WeCom markdown rendering and rich formatting matters.",
            ),
            operation(
                OP_SEND_IMAGE,
                "Send a WeCom image message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["media_id"],
                    "properties": {
                        "media_id": { "type": "string" },
                        "touser": { "type": "string" },
                        "toparty": { "type": "string" },
                        "totag": { "type": "string" },
                        "safe": { "type": "boolean" },
                        "enable_duplicate_check": { "type": "boolean" },
                        "duplicate_check_interval": { "type": "integer", "minimum": 0 }
                    }
                }),
                "Use after `wecom.media.upload` when you need to send one uploaded image by its temporary WeCom `media_id`.",
            ),
            operation(
                OP_SEND_FILE,
                "Send a WeCom file message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["media_id"],
                    "properties": {
                        "media_id": { "type": "string" },
                        "touser": { "type": "string" },
                        "toparty": { "type": "string" },
                        "totag": { "type": "string" },
                        "safe": { "type": "boolean" },
                        "enable_duplicate_check": { "type": "boolean" },
                        "duplicate_check_interval": { "type": "integer", "minimum": 0 }
                    }
                }),
                "Use after `wecom.media.upload` when you need to send one uploaded file by its temporary WeCom `media_id`.",
            ),
            operation(
                OP_UPLOAD_MEDIA,
                "Upload temporary media to WeCom",
                CAP_MEDIA_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::BestEffort,
                json!({
                    "type": "object",
                    "required": ["media_type", "file_name", "content_base64"],
                    "properties": {
                        "media_type": { "type": "string", "enum": ["image", "voice", "video", "file"] },
                        "file_name": { "type": "string" },
                        "mime_type": { "type": "string" },
                        "content_base64": { "type": "string" }
                    }
                }),
                "Use before sending media messages that require a temporary WeCom media_id.",
            ),
            operation(
                OP_DOWNLOAD_MEDIA,
                "Download media bytes for a WeCom media_id",
                CAP_MEDIA_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["media_id"],
                    "properties": {
                        "media_id": { "type": "string" }
                    }
                }),
                "Use after inbound callback normalization when a MediaId or ThumbMediaId must be resolved into bytes.",
            ),
            operation(
                OP_GET_USER,
                "Fetch a WeCom user profile",
                CAP_USERS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["userid"],
                    "properties": {
                        "userid": { "type": "string" }
                    }
                }),
                "Use for directory lookups when you already know the WeCom userid.",
            ),
            operation(
                OP_LIST_DEPARTMENTS,
                "List WeCom departments",
                CAP_DEPARTMENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "properties": {
                        "id": { "type": "integer" }
                    }
                }),
                "Use for read-only org hierarchy discovery inside the bound tenant.",
            ),
            operation(
                OP_VERIFY_CALLBACK_URL,
                "Verify a host-forwarded WeCom callback URL challenge",
                CAP_EVENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["msg_signature", "timestamp", "nonce", "echostr"],
                    "properties": {
                        "msg_signature": { "type": "string" },
                        "timestamp": { "type": "string" },
                        "nonce": { "type": "string" },
                        "echostr": { "type": "string" }
                    }
                }),
                "Use when the host receives WeCom's initial callback URL validation GET and needs the decrypted plaintext challenge.",
            ),
            operation(
                OP_INGEST_CALLBACK_EVENT,
                "Verify, decrypt, and normalize one host-forwarded WeCom callback event",
                CAP_EVENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["msg_signature", "timestamp", "nonce", "body"],
                    "properties": {
                        "msg_signature": { "type": "string" },
                        "timestamp": { "type": "string" },
                        "nonce": { "type": "string" },
                        "body": { "type": "string", "description": "Raw XML body from the WeCom HTTP POST callback" },
                        "body_xml": { "type": "string", "description": "Alias for body when the host already labels the payload as XML" }
                    }
                }),
                "Use when the host forwards a signed WeCom callback POST and needs a normalized EventEnvelope plus attachment references.",
            ),
            operation(
                OP_HEALTH,
                "Verify WeCom credentials and token issuance",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use before invoking mutations when you need a bounded credential and connectivity check.",
            ),
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        verifier.verify(&req.capability_token, &capability, &req.operation, &[])?;

        let (output, resource_uris) = match req.operation.as_str() {
            OP_SEND_TEXT => {
                let request = WeComMessageRequest::from_value(&req.input, WeComMessageKind::Text)?;
                let output = state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_SEND_MARKDOWN => {
                let request =
                    WeComMessageRequest::from_value(&req.input, WeComMessageKind::Markdown)?;
                let output = state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_SEND_IMAGE => {
                let request = WeComMessageRequest::from_value(&req.input, WeComMessageKind::Image)?;
                let output = state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_SEND_FILE => {
                let request = WeComMessageRequest::from_value(&req.input, WeComMessageKind::File)?;
                let output = state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_UPLOAD_MEDIA => {
                let request = WeComMediaUploadRequest::from_value(&req.input)?;
                let output = state
                    .client
                    .upload_media(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_DOWNLOAD_MEDIA => {
                let request = WeComMediaDownloadRequest::from_value(&req.input)?;
                let output = state
                    .client
                    .download_media(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let resource_uris = vec![format!("wecom:media:{}", output.media_id)];
                let output = serde_json::to_value(&output).map_err(|error| FcpError::Internal {
                    message: format!("failed to serialize WeCom media download response: {error}"),
                })?;
                (output, resource_uris)
            }
            OP_GET_USER => {
                let request = WeComUserLookupRequest::from_value(&req.input)?;
                let output = state
                    .client
                    .get_user(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_LIST_DEPARTMENTS => {
                let request = WeComDepartmentListRequest::from_value(&req.input)?;
                let output = state
                    .client
                    .list_departments(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_VERIFY_CALLBACK_URL => {
                let request = WeComCallbackVerifyRequest::from_value(&req.input)?;
                let challenge = state
                    .client
                    .verify_callback_url(&request)
                    .map_err(|error| error.to_fcp_error())?;
                (
                    json!({
                        "verified": true,
                        "transport": "callback_http_get",
                        "receive_id": state.client.config().callback_receive_id(),
                        "challenge": challenge.clone(),
                        "http_response": {
                            "status": 200,
                            "content_type": "text/plain; charset=utf-8",
                            "body": challenge,
                        }
                    }),
                    Vec::new(),
                )
            }
            OP_INGEST_CALLBACK_EVENT => {
                let request = WeComCallbackIngestRequest::from_value(&req.input)?;
                let callback = state
                    .client
                    .ingest_callback_event(&request)
                    .map_err(|error| error.to_fcp_error())?;
                let event = normalize_callback_event(
                    &callback,
                    verifier,
                    &self.base.id,
                    &self.base.instance_id,
                    state.client.config().agent_id(),
                );
                let resource_uris = event.data.resource_uris.clone();
                let output = json!({
                    "delivery": {
                        "id": callback_delivery_id(&callback),
                        "transport": "callback_http",
                        "verified": true,
                        "msg_signature": request.msg_signature(),
                        "timestamp": request.timestamp(),
                        "nonce": request.nonce(),
                        "receive_id": callback.receive_id.clone(),
                    },
                    "callback": {
                        "outer": &callback.wrapper,
                        "message": &callback.message,
                        "plaintext_xml": &callback.plaintext_xml,
                    },
                    "event": &event,
                });
                (output, resource_uris)
            }
            OP_HEALTH => {
                let _token = state
                    .client
                    .access_token()
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let model = state.client.state_model().await;
                let output = json!({
                    "status": "ok",
                    "base_url": model.base_url.clone(),
                    "agent_id": model.agent_id,
                    "token_cached": model.token_cached,
                    "callback_configured": model.callback_configured,
                    "state": &model,
                    "manifest_hash": Self::manifest_hash(),
                });
                (output, Vec::new())
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("unknown operation: {}", req.operation),
                });
            }
        };

        let mut response = InvokeResponse::ok(req.id, output);
        response.resource_uris = resource_uris;
        Ok(response)
    }
}

impl Default for WeComConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FcpConnector for WeComConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let config = WeComConfig::from_value(config)?;
        let client = WeComClient::new(config).map_err(|error| error.to_fcp_error())?;
        self.state = Some(WeComState { client });
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: granted_capabilities(req.capabilities_requested),
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
        let status = if self.state.is_some() {
            HealthState::Ready
        } else {
            HealthState::Starting
        };
        let details = if let Some(state) = self.state.as_ref() {
            let model = state.client.state_model().await;
            Some(health_details(&model))
        } else {
            None
        };
        HealthSnapshot {
            status,
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details,
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(state) = self.state.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before WeCom self_check",
            ));
        };
        match state.client.access_token().await {
            Ok(_) => {
                let model = state.client.state_model().await;
                let report = SelfCheckReport::ok();
                Ok(SelfCheckReport {
                    details: Some(health_details(&model)),
                    ..report
                })
            }
            Err(error) => Ok(SelfCheckReport::from_error(&error.to_fcp_error())),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.state = None;
        self.verifier = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations(),
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

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        if self.state.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) = verifier.verify(&req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

fn health_details(model: &WeComStateModel) -> Value {
    json!({
        "base_url": model.base_url.clone(),
        "agent_id": model.agent_id,
        "token_cached": model.token_cached,
        "callback_configured": model.callback_configured,
        "state": model,
    })
}

fn normalize_callback_event(
    callback: &WeComCallbackEnvelope,
    verifier: &CapabilityVerifier,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
    fallback_agent_id: u64,
) -> EventEnvelope {
    let agent_id = callback_agent_id(callback, fallback_agent_id);
    let conversation = callback_conversation(&callback.message, &agent_id);
    let attachments = callback_attachments(&callback.message);
    let delivery_id = callback_delivery_id(callback);
    let resource_uris = callback_resource_uris(
        callback,
        conversation.as_ref(),
        attachments.as_slice(),
        &agent_id,
    );
    let create_time = callback_create_time(&callback.message);
    let topic = callback_topic(&callback.message);
    let principal = callback_principal(&callback.message, &callback.receive_id);
    let cursor = delivery_id.clone();

    let payload = json!({
        "transport": "callback_http",
        "delivery_id": delivery_id.clone(),
        "receive_id": callback.receive_id,
        "agent_id": agent_id,
        "msg_type": xml_field(&callback.message, "MsgType"),
        "event_type": xml_field(&callback.message, "Event"),
        "change_type": xml_field(&callback.message, "ChangeType"),
        "conversation": conversation.as_ref().map(|conversation| {
            json!({
                "kind": conversation.kind,
                "id": conversation.id,
                "resource_uri": conversation.resource_uri,
            })
        }),
        "attachments": attachments,
        "outer": &callback.wrapper,
        "message": &callback.message,
        "plaintext_xml": &callback.plaintext_xml,
    });

    let event_data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        verifier.zone_id.clone(),
        principal,
        payload,
    )
    .with_resource_uris(resource_uris);

    let (seq, ordering) = callback_sequence(&delivery_id, create_time, conversation.is_some());
    let mut event = EventEnvelope::new(topic, event_data)
        .with_seq(seq)
        .with_cursor(cursor)
        .with_ordering(ordering);
    if let Some(conversation) = conversation {
        event = event.with_stream_key(conversation.stream_key);
    }
    if let Some(timestamp) = create_time {
        event.timestamp = timestamp;
    }
    event
}

fn callback_agent_id(callback: &WeComCallbackEnvelope, fallback_agent_id: u64) -> String {
    xml_field(&callback.message, "AgentID")
        .or_else(|| xml_field(&callback.wrapper, "AgentID"))
        .map(ToString::to_string)
        .unwrap_or_else(|| fallback_agent_id.to_string())
}

fn callback_topic(message: &BTreeMap<String, String>) -> String {
    let msg_type = xml_field(message, "MsgType")
        .map(topic_component)
        .unwrap_or_else(|| "unknown".to_string());
    if msg_type == "event" {
        let event_type = xml_field(message, "Event")
            .map(topic_component)
            .unwrap_or_else(|| "unknown".to_string());
        if let Some(change_type) = xml_field(message, "ChangeType").map(topic_component) {
            format!("wecom.event.{event_type}.{change_type}")
        } else {
            format!("wecom.event.{event_type}")
        }
    } else {
        format!("wecom.message.{msg_type}")
    }
}

fn callback_principal(message: &BTreeMap<String, String>, receive_id: &str) -> Principal {
    if let Some(external_user_id) = xml_field(message, "ExternalUserID") {
        return Principal {
            kind: "external_user".into(),
            id: external_user_id.to_string(),
            trust: TrustLevel::Paired,
            display: Some(external_user_id.to_string()),
        };
    }
    if let Some(user_id) =
        xml_field(message, "FromUserName").or_else(|| xml_field(message, "UserID"))
    {
        return Principal {
            kind: "user".into(),
            id: user_id.to_string(),
            trust: TrustLevel::Paired,
            display: Some(user_id.to_string()),
        };
    }

    Principal {
        kind: "service".into(),
        id: format!("wecom:{receive_id}"),
        trust: TrustLevel::Paired,
        display: Some("WeCom callback".into()),
    }
}

fn callback_conversation(
    message: &BTreeMap<String, String>,
    agent_id: &str,
) -> Option<WeComConversation> {
    if xml_field(message, "MsgType").is_some_and(|msg_type| msg_type.eq_ignore_ascii_case("event"))
    {
        return None;
    }

    if let Some(chat_id) = xml_field(message, "OpenChatId").or_else(|| xml_field(message, "ChatId"))
    {
        let chat_id = chat_id.to_string();
        return Some(WeComConversation {
            kind: "room",
            stream_key: format!("agent:{agent_id}:chat:{chat_id}"),
            resource_uri: format!("wecom:chat:{chat_id}"),
            id: chat_id,
        });
    }

    if let Some(external_user_id) = xml_field(message, "ExternalUserID") {
        let external_user_id = external_user_id.to_string();
        return Some(WeComConversation {
            kind: "dm",
            stream_key: format!("agent:{agent_id}:external:{external_user_id}"),
            resource_uri: format!("wecom:external_user:{external_user_id}"),
            id: external_user_id,
        });
    }

    xml_field(message, "FromUserName")
        .or_else(|| xml_field(message, "UserID"))
        .map(|user_id| {
            let user_id = user_id.to_string();
            WeComConversation {
                kind: "dm",
                stream_key: format!("agent:{agent_id}:dm:{user_id}"),
                resource_uri: format!("wecom:user:{user_id}"),
                id: user_id,
            }
        })
}

fn callback_attachments(message: &BTreeMap<String, String>) -> Vec<Value> {
    let mut attachments = Vec::new();

    if let Some(media_id) = xml_field(message, "MediaId") {
        let mut attachment = json!({
            "kind": "media_id",
            "field": "MediaId",
            "media_id": media_id,
            "media_type": inferred_media_type(message),
            "download_operation": OP_DOWNLOAD_MEDIA,
        });
        if let Some(file_name) = xml_field(message, "FileName") {
            attachment["file_name"] = json!(file_name);
        }
        attachments.push(attachment);
    }

    if let Some(thumb_media_id) = xml_field(message, "ThumbMediaId") {
        attachments.push(json!({
            "kind": "media_id",
            "field": "ThumbMediaId",
            "media_id": thumb_media_id,
            "media_type": "thumbnail",
            "download_operation": OP_DOWNLOAD_MEDIA,
        }));
    }

    if let Some(pic_url) = xml_field(message, "PicUrl") {
        attachments.push(json!({
            "kind": "url",
            "field": "PicUrl",
            "url": pic_url,
            "media_type": "image",
        }));
    }

    if let Some(url) = xml_field(message, "Url") {
        attachments.push(json!({
            "kind": "url",
            "field": "Url",
            "url": url,
        }));
    }

    attachments
}

fn inferred_media_type(message: &BTreeMap<String, String>) -> &'static str {
    match xml_field(message, "MsgType")
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("image") => "image",
        Some("voice") => "voice",
        Some("video") => "video",
        Some("file") => "file",
        _ => "binary",
    }
}

fn callback_resource_uris(
    callback: &WeComCallbackEnvelope,
    conversation: Option<&WeComConversation>,
    attachments: &[Value],
    agent_id: &str,
) -> Vec<String> {
    let mut resource_uris = Vec::new();
    push_unique(
        &mut resource_uris,
        format!("wecom:tenant:{}", callback.receive_id),
    );
    push_unique(&mut resource_uris, format!("wecom:agent:{agent_id}"));

    if let Some(message_id) = xml_field(&callback.message, "MsgId") {
        push_unique(&mut resource_uris, format!("wecom:message:{message_id}"));
    }
    if let Some(conversation) = conversation {
        push_unique(&mut resource_uris, conversation.resource_uri.clone());
    }
    if let Some(user_id) = xml_field(&callback.message, "FromUserName")
        .or_else(|| xml_field(&callback.message, "UserID"))
    {
        push_unique(&mut resource_uris, format!("wecom:user:{user_id}"));
    }
    if let Some(external_user_id) = xml_field(&callback.message, "ExternalUserID") {
        push_unique(
            &mut resource_uris,
            format!("wecom:external_user:{external_user_id}"),
        );
    }

    for attachment in attachments {
        if let Some(media_id) = attachment.get("media_id").and_then(Value::as_str) {
            push_unique(&mut resource_uris, format!("wecom:media:{media_id}"));
        }
    }

    resource_uris
}

fn callback_delivery_id(callback: &WeComCallbackEnvelope) -> String {
    let mut hasher = Sha256::new();
    hasher.update(callback.receive_id.as_bytes());
    hasher.update([0]);
    if let Some(encrypt) = callback.wrapper.get("Encrypt") {
        hasher.update(encrypt.as_bytes());
        hasher.update([0]);
    }
    hasher.update(callback.plaintext_xml.as_bytes());
    hex::encode(hasher.finalize())
}

fn callback_sequence(
    delivery_id: &str,
    create_time: Option<DateTime<Utc>>,
    has_stream_key: bool,
) -> (u64, OrderingPolicy) {
    let digest = Sha256::digest(delivery_id.as_bytes());
    let hash_u64 = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);

    if has_stream_key && let Some(create_time) = create_time {
        let suffix = hash_u64 % 10_000;
        let seq = create_time.timestamp().max(0) as u64 * 10_000 + suffix;
        return (seq, OrderingPolicy::PerKey);
    }

    (hash_u64, OrderingPolicy::Unordered)
}

fn callback_create_time(message: &BTreeMap<String, String>) -> Option<DateTime<Utc>> {
    xml_field(message, "CreateTime")
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
}

fn topic_component(raw: &str) -> String {
    let mut result = String::new();
    let mut last_was_separator = false;
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            result.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            result.push('_');
            last_was_separator = true;
        }
    }
    let normalized = result.trim_matches('_');
    if normalized.is_empty() {
        "unknown".to_string()
    } else {
        normalized.to_string()
    }
}

fn xml_field<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    fields
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn push_unique(values: &mut Vec<String>, candidate: String) {
    if !values.iter().any(|existing| existing == &candidate) {
        values.push(candidate);
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_SEND_TEXT | OP_SEND_MARKDOWN | OP_SEND_IMAGE | OP_SEND_FILE => CAP_MESSAGES_WRITE,
        OP_UPLOAD_MEDIA => CAP_MEDIA_WRITE,
        OP_DOWNLOAD_MEDIA => CAP_MEDIA_READ,
        OP_GET_USER => CAP_USERS_READ,
        OP_LIST_DEPARTMENTS => CAP_DEPARTMENTS_READ,
        OP_VERIFY_CALLBACK_URL | OP_INGEST_CALLBACK_EVENT => CAP_EVENTS_READ,
        OP_HEALTH => CAP_HEALTH_READ,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| {
            matches!(
                capability.as_str(),
                CAP_MESSAGES_WRITE
                    | CAP_MEDIA_WRITE
                    | CAP_MEDIA_READ
                    | CAP_USERS_READ
                    | CAP_DEPARTMENTS_READ
                    | CAP_EVENTS_READ
                    | CAP_HEALTH_READ
            )
        })
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn operation(
    id: &'static str,
    summary: &str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: Value,
    when_to_use: &str,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(summary.into()),
        input_schema,
        output_schema: json!({ "type": "object" }),
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: vec![
                "For send operations, WeCom requires at least one of touser, toparty, or totag."
                    .into(),
            ],
            examples: Vec::new(),
            related: vec![CapabilityId::from_static(CAP_HEALTH_READ)],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_core::{CapabilityToken, OrderingPolicy, RequestId, ZoneId};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use serde_json::Value;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::types::DEFAULT_TIMEOUT_MS;

    fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [19_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_HEALTH_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken { raw }
    }

    #[fcp_async_core::runtime::test]
    async fn health_reflects_whether_token_is_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cgi-bin/gettoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&server)
            .await;

        let mut connector = WeComConnector::new();
        connector
            .configure(json!({
                "base_url": server.uri(),
                "corp_id": "corp",
                "agent_id": 1_000_002_u64,
                "agent_secret": "secret",
                "request_timeout_ms": DEFAULT_TIMEOUT_MS
            }))
            .await
            .expect("configure should succeed");

        let health_before = connector.health().await;
        assert_eq!(
            health_before
                .details
                .as_ref()
                .and_then(|details| details.get("token_cached"))
                .and_then(Value::as_bool),
            Some(false)
        );

        let report = connector
            .self_check()
            .await
            .expect("self_check should return");
        assert_eq!(
            report.status,
            fcp_core::SelfCheckStatus::Ok,
            "self_check should populate the token cache"
        );

        let health_after = connector.health().await;
        assert_eq!(
            health_after
                .details
                .as_ref()
                .and_then(|details| details.get("token_cached"))
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_returns_status_and_state() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cgi-bin/gettoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&server)
            .await;

        let mut connector = WeComConnector::new();
        connector
            .configure(json!({
                "base_url": server.uri(),
                "corp_id": "corp",
                "agent_id": 1_000_002_u64,
                "agent_secret": "secret",
                "request_timeout_ms": DEFAULT_TIMEOUT_MS
            }))
            .await
            .expect("configure should succeed");
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");

        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("wecom-health"),
                connector_id: ConnectorId::from_static("fcp.wecom"),
                operation: OperationId::from_static(OP_HEALTH),
                zone_id: ZoneId::work(),
                input: json!({}),
                capability_token: capability_token(&signing_key, CAP_HEALTH_READ, OP_HEALTH),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("health invoke should succeed");

        assert_eq!(response.result.as_ref().expect("result")["status"], "ok");
        assert_eq!(
            response.result.as_ref().expect("result")["token_cached"],
            json!(true)
        );
    }

    #[test]
    fn operations_advertise_image_file_and_duplicate_check_inputs() {
        let operations = WeComConnector::operations();

        let send_text = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_SEND_TEXT)
            .expect("send_text operation should exist");
        assert!(
            send_text
                .input_schema
                .get("properties")
                .and_then(|value| value.get("enable_duplicate_check"))
                .is_some(),
            "send_text should advertise duplicate-check input"
        );

        let send_image = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_SEND_IMAGE)
            .expect("send_image operation should exist");
        assert_eq!(send_image.capability.as_str(), CAP_MESSAGES_WRITE);
        assert_eq!(send_image.idempotency, IdempotencyClass::None);
        assert_eq!(
            send_image
                .input_schema
                .get("required")
                .and_then(Value::as_array)
                .and_then(|required| required.first())
                .and_then(Value::as_str),
            Some("media_id")
        );

        let send_file = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_SEND_FILE)
            .expect("send_file operation should exist");
        assert_eq!(send_file.capability.as_str(), CAP_MESSAGES_WRITE);
        assert_eq!(send_file.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn normalize_callback_event_prefers_room_stream_and_attachment_refs() {
        let connector = WeComConnector::new();
        let verifier = CapabilityVerifier::new(
            [0_u8; 32],
            ZoneId::work(),
            connector.base.instance_id.clone(),
        );
        let callback = WeComCallbackEnvelope {
            receive_id: "corp".into(),
            wrapper: BTreeMap::from([
                ("ToUserName".into(), "corp".into()),
                ("AgentID".into(), "1000002".into()),
                ("Encrypt".into(), "ciphertext".into()),
            ]),
            message: BTreeMap::from([
                ("FromUserName".into(), "alice".into()),
                ("CreateTime".into(), "1710000000".into()),
                ("MsgType".into(), "image".into()),
                ("OpenChatId".into(), "room-1".into()),
                ("MediaId".into(), "MEDIA123".into()),
                ("ThumbMediaId".into(), "THUMB123".into()),
                ("PicUrl".into(), "https://example.test/pic.png".into()),
                ("MsgId".into(), "42".into()),
            ]),
            plaintext_xml: "<xml />".into(),
        };

        let event = normalize_callback_event(
            &callback,
            &verifier,
            &connector.base.id,
            &connector.base.instance_id,
            1_000_002,
        );

        assert_eq!(event.topic, "wecom.message.image");
        assert_eq!(
            event.stream_key.as_deref(),
            Some("agent:1000002:chat:room-1")
        );
        assert_eq!(event.ordering, Some(OrderingPolicy::PerKey));
        assert!(
            event
                .data
                .resource_uris
                .iter()
                .any(|uri| uri == "wecom:chat:room-1")
        );
        assert!(
            event
                .data
                .resource_uris
                .iter()
                .any(|uri| uri == "wecom:media:MEDIA123")
        );
        assert_eq!(
            event.data.payload["attachments"][0]["download_operation"],
            OP_DOWNLOAD_MEDIA
        );
    }

    #[test]
    fn normalize_callback_event_builds_change_event_topic() {
        let connector = WeComConnector::new();
        let verifier = CapabilityVerifier::new(
            [1_u8; 32],
            ZoneId::work(),
            connector.base.instance_id.clone(),
        );
        let callback = WeComCallbackEnvelope {
            receive_id: "corp".into(),
            wrapper: BTreeMap::from([("Encrypt".into(), "ciphertext".into())]),
            message: BTreeMap::from([
                ("MsgType".into(), "event".into()),
                ("Event".into(), "change_contact".into()),
                ("ChangeType".into(), "create_user".into()),
                ("UserID".into(), "bob".into()),
            ]),
            plaintext_xml: "<xml />".into(),
        };

        let event = normalize_callback_event(
            &callback,
            &verifier,
            &connector.base.id,
            &connector.base.instance_id,
            1_000_002,
        );

        assert_eq!(event.topic, "wecom.event.change_contact.create_user");
        assert!(event.stream_key.is_none());
        assert_eq!(event.ordering, Some(OrderingPolicy::Unordered));
        assert_eq!(event.data.principal.kind, "user");
        assert_eq!(event.data.principal.id, "bob");
        assert!(event.data.payload["conversation"].is_null());
        assert!(
            event
                .data
                .resource_uris
                .iter()
                .any(|uri| uri == "wecom:user:bob")
        );
    }
}
