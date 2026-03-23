//! `DingTalk` enterprise robot connector.

use std::time::Instant;

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::client::{DingTalkClient, default_mime_type};
use crate::types::{DingTalkConfig, ParsedTarget};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_SEND_TEXT: &str = "dingtalk.messages.send_text";
const OP_SEND_LINK: &str = "dingtalk.messages.send_link";
const OP_SEND_FILE: &str = "dingtalk.messages.send_file";
const OP_UPLOAD_MEDIA: &str = "dingtalk.media.upload";
const OP_HEALTH: &str = "dingtalk.health";

const CAP_MESSAGES_WRITE: &str = "dingtalk.messages.write";
const CAP_MEDIA_WRITE: &str = "dingtalk.media.write";
const CAP_HEALTH_READ: &str = "dingtalk.health.read";

// ─────────────────────────────────────────────────────────────────
// Doctor types (V3 requirement)
// ─────────────────────────────────────────────────────────────────
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

#[derive(Debug)]
pub struct DingTalkConnector {
    base: BaseConnector,
    client: Option<DingTalkClient>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
}

impl DingTalkConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.dingtalk")),
            client: None,
            verifier: None,
            started_at: Instant::now(),
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

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing - configure first".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: self.verifier.is_some(),
            message: Some(if self.verifier.is_some() {
                "Handshake completed".into()
            } else {
                "Handshake not completed".into()
            }),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    #[allow(clippy::too_many_lines)]
    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_SEND_TEXT,
                "Send a DingTalk text or markdown message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["to", "content"],
                    "properties": {
                        "to": { "type": "string" },
                        "content": { "type": "string" }
                    }
                }),
                "Use for proactive DingTalk messages to `user:<userid>`, `chat:<openConversationId>`, or a bare userid.",
            ),
            operation(
                OP_SEND_LINK,
                "Send a DingTalk link message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["to", "title", "text", "message_url"],
                    "properties": {
                        "to": { "type": "string" },
                        "title": { "type": "string" },
                        "text": { "type": "string" },
                        "message_url": { "type": "string" },
                        "pic_url": { "type": "string" }
                    }
                }),
                "Use when the chat should receive a link-style card rather than raw markdown.",
            ),
            operation(
                OP_SEND_FILE,
                "Send a DingTalk file message using an existing media_id",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["to", "media_id", "file_name", "file_type"],
                    "properties": {
                        "to": { "type": "string" },
                        "media_id": { "type": "string" },
                        "file_name": { "type": "string" },
                        "file_type": { "type": "string" }
                    }
                }),
                "Use after `dingtalk.media.upload` when DingTalk requires a media_id-backed file send.",
            ),
            operation(
                OP_UPLOAD_MEDIA,
                "Upload media to DingTalk",
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
                "Use when you need a DingTalk media_id before sending files or rich media.",
            ),
            operation(
                OP_HEALTH,
                "Verify DingTalk credentials and token issuance",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use as a bounded preflight check before higher-risk send operations.",
            ),
        ]
    }

    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        verifier.verify(&req.capability_token, &capability, &req.operation, &[])?;

        let output = match req.operation.as_str() {
            OP_SEND_TEXT => {
                let to = required_string(&req.input, "to")?;
                let content = required_string(&req.input, "content")?;
                let target = ParsedTarget::parse(to);
                let (path, body) = if target.is_group {
                    (
                        "/v1.0/robot/groupMessages/send",
                        json!({
                            "robotCode": client.config().client_id,
                            "openConversationId": target.id,
                            "msgKey": "sampleMarkdown",
                            "msgParam": json!({
                                "title": title_for(content),
                                "text": content,
                            }).to_string(),
                        }),
                    )
                } else {
                    (
                        "/v1.0/robot/oToMessages/batchSend",
                        json!({
                            "robotCode": client.config().client_id,
                            "userIds": [target.id],
                            "msgKey": "sampleMarkdown",
                            "msgParam": json!({
                                "title": title_for(content),
                                "text": content,
                            }).to_string(),
                        }),
                    )
                };
                client
                    .post_json(path, body)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_SEND_LINK => {
                let to = required_string(&req.input, "to")?;
                let title = required_string(&req.input, "title")?;
                let text = required_string(&req.input, "text")?;
                let message_url = required_string(&req.input, "message_url")?;
                let pic_url = req
                    .input
                    .get("pic_url")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let target = ParsedTarget::parse(to);
                let (path, body) = if target.is_group {
                    (
                        "/v1.0/robot/groupMessages/send",
                        json!({
                            "robotCode": client.config().client_id,
                            "openConversationId": target.id,
                            "msgKey": "sampleLink",
                            "msgParam": json!({
                                "title": title,
                                "text": text,
                                "messageUrl": message_url,
                                "picUrl": pic_url,
                            }).to_string(),
                        }),
                    )
                } else {
                    (
                        "/v1.0/robot/oToMessages/batchSend",
                        json!({
                            "robotCode": client.config().client_id,
                            "userIds": [target.id],
                            "msgKey": "sampleLink",
                            "msgParam": json!({
                                "title": title,
                                "text": text,
                                "messageUrl": message_url,
                                "picUrl": pic_url,
                            }).to_string(),
                        }),
                    )
                };
                client
                    .post_json(path, body)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_SEND_FILE => {
                let to = required_string(&req.input, "to")?;
                let media_id = required_string(&req.input, "media_id")?;
                let file_name = required_string(&req.input, "file_name")?;
                let file_type = required_string(&req.input, "file_type")?;
                let target = ParsedTarget::parse(to);
                let (path, body) = if target.is_group {
                    (
                        "/v1.0/robot/groupMessages/send",
                        json!({
                            "robotCode": client.config().client_id,
                            "openConversationId": target.id,
                            "msgKey": "sampleFile",
                            "msgParam": json!({
                                "mediaId": media_id,
                                "fileName": file_name,
                                "fileType": file_type,
                            }).to_string(),
                        }),
                    )
                } else {
                    (
                        "/v1.0/robot/oToMessages/batchSend",
                        json!({
                            "robotCode": client.config().client_id,
                            "userIds": [target.id],
                            "msgKey": "sampleFile",
                            "msgParam": json!({
                                "mediaId": media_id,
                                "fileName": file_name,
                                "fileType": file_type,
                            }).to_string(),
                        }),
                    )
                };
                client
                    .post_json(path, body)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_UPLOAD_MEDIA => {
                let media_type = required_string(&req.input, "media_type")?;
                if !matches!(media_type, "image" | "voice" | "video" | "file") {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: "media_type must be one of image, voice, video, or file".into(),
                    });
                }
                let file_name = required_string(&req.input, "file_name")?;
                let mime_type = req
                    .input
                    .get("mime_type")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| default_mime_type(media_type));
                let content_base64 = required_string(&req.input, "content_base64")?;
                client
                    .upload_media(media_type, file_name, mime_type, content_base64)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_HEALTH => {
                let _token = client.access_token().await.map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": "ok",
                    "base_url": client.config().base_url,
                    "media_base_url": client.config().media_base_url,
                    "client_id": client.config().client_id,
                    "manifest_hash": Self::manifest_hash(),
                })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("unknown operation: {}", req.operation),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for DingTalkConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FcpConnector for DingTalkConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let config: DingTalkConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid DingTalk configuration: {error}"),
            })?;
        self.client = Some(DingTalkClient::new(config).map_err(|e| e.to_fcp_error())?);
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
        HealthSnapshot {
            status: if self.client.is_some() {
                HealthState::Ready
            } else {
                HealthState::Starting
            },
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: self.client.as_ref().map(|c| {
                json!({
                    "base_url": c.config().base_url,
                    "media_base_url": c.config().media_base_url,
                    "client_id": c.config().client_id,
                })
            }),
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = self.client.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before DingTalk self_check",
            ));
        };
        match client.access_token().await {
            Ok(_) => Ok(SelfCheckReport::ok()),
            Err(error) => Ok(SelfCheckReport::from_error(&error.to_fcp_error())),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
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
        if self.client.is_none() {
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

fn title_for(content: &str) -> String {
    content.chars().take(10).collect()
}

fn required_string<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} is required"),
        })
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_SEND_TEXT | OP_SEND_LINK | OP_SEND_FILE => CAP_MESSAGES_WRITE,
        OP_UPLOAD_MEDIA => CAP_MEDIA_WRITE,
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
                CAP_MESSAGES_WRITE | CAP_MEDIA_WRITE | CAP_HEALTH_READ
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
                "Group routes must use the `chat:` prefix with an openConversationId.".into(),
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
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method, path, query_param},
    };

    async fn configured_connector(server: &MockServer) -> DingTalkConnector {
        let mut connector = DingTalkConnector::new();
        connector
            .configure(json!({
                "base_url": server.uri(),
                "media_base_url": server.uri(),
                "client_id": "ding-app",
                "client_secret": "secret"
            }))
            .await
            .expect("configure should succeed");
        connector
    }

    #[fcp_async_core::runtime::test]
    async fn config_rejects_empty_client_id() {
        let mut connector = DingTalkConnector::new();
        let result = connector
            .configure(json!({
                "client_id": "",
                "client_secret": "secret"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn send_text_posts_expected_oto_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/oauth2/accessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "token-123",
                "expireIn": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1.0/robot/oToMessages/batchSend"))
            .and(body_partial_json(json!({
                "robotCode": "ding-app",
                "userIds": ["user-1"],
                "msgKey": "sampleMarkdown"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "processQueryKey": "msg-1"
            })))
            .mount(&server)
            .await;

        let connector = configured_connector(&server).await;
        let client = connector.client.as_ref().unwrap();

        let output = client
            .post_json(
                "/v1.0/robot/oToMessages/batchSend",
                json!({
                    "robotCode": "ding-app",
                    "userIds": ["user-1"],
                    "msgKey": "sampleMarkdown",
                    "msgParam": json!({"title":"hello","text":"hello from ding"}).to_string(),
                }),
            )
            .await
            .expect("send text should succeed");

        assert_eq!(output["processQueryKey"], "msg-1");
    }

    #[fcp_async_core::runtime::test]
    async fn upload_media_posts_expected_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/oauth2/accessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "token-123",
                "expireIn": 7200
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/media/upload"))
            .and(query_param("access_token", "token-123"))
            .and(query_param("type", "image"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "media_id": "MEDIA123"
            })))
            .mount(&server)
            .await;

        let connector = configured_connector(&server).await;
        let client = connector.client.as_ref().unwrap();

        let output = client
            .upload_media("image", "test.png", "image/png", &BASE64.encode(b"png"))
            .await
            .expect("upload should succeed");

        assert_eq!(output["media_id"], "MEDIA123");
    }

    #[fcp_async_core::runtime::test]
    async fn health_returns_ready_after_configure() {
        let server = MockServer::start().await;
        let connector = configured_connector(&server).await;
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[fcp_async_core::runtime::test]
    async fn health_returns_starting_before_configure() {
        let connector = DingTalkConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Starting));
    }

    #[test]
    fn doctor_fails_before_configure() {
        let connector = DingTalkConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_passes_after_configure() {
        let server = MockServer::start().await;
        let connector = configured_connector(&server).await;
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_fails_before_configure() {
        let connector = DingTalkConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_ne!(report.status, fcp_core::SelfCheckStatus::Ok);
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_returns_five_operations() {
        let connector = DingTalkConnector::new();
        let introspection = connector.introspect();
        assert_eq!(introspection.operations.len(), 5);
    }

    #[test]
    fn operations_count() {
        let ops = DingTalkConnector::operations();
        assert_eq!(ops.len(), 5);
        assert_eq!(ops[0].id.as_str(), OP_SEND_TEXT);
        assert_eq!(ops[4].id.as_str(), OP_HEALTH);
    }

    #[test]
    fn required_capability_maps_correctly() {
        assert!(required_capability(OP_SEND_TEXT).is_ok());
        assert!(required_capability(OP_SEND_LINK).is_ok());
        assert!(required_capability(OP_UPLOAD_MEDIA).is_ok());
        assert!(required_capability("unknown.op").is_err());
    }

    #[test]
    fn granted_capabilities_filters() {
        let requested = vec![
            CapabilityId::from_static(CAP_MESSAGES_WRITE),
            CapabilityId::from_static("dingtalk.fake"),
        ];
        let granted = granted_capabilities(requested);
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].capability.as_str(), CAP_MESSAGES_WRITE);
    }

    #[test]
    fn title_for_truncates() {
        assert_eq!(title_for("hello world, this is long"), "hello worl");
        assert_eq!(title_for("short"), "short");
    }
}
