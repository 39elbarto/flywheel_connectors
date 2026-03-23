//! `DingTalk` enterprise robot connector.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use fcp_async_core::sync::Mutex;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
use reqwest::{Url, multipart};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const DEFAULT_BASE_URL: &str = "https://api.dingtalk.com";
const DEFAULT_MEDIA_BASE_URL: &str = "https://oapi.dingtalk.com";
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const TOKEN_REFRESH_SAFETY_MARGIN_SECS: u64 = 60;

const OP_SEND_TEXT: &str = "dingtalk.messages.send_text";
const OP_SEND_LINK: &str = "dingtalk.messages.send_link";
const OP_SEND_FILE: &str = "dingtalk.messages.send_file";
const OP_UPLOAD_MEDIA: &str = "dingtalk.media.upload";
const OP_HEALTH: &str = "dingtalk.health";

const CAP_MESSAGES_WRITE: &str = "dingtalk.messages.write";
const CAP_MEDIA_WRITE: &str = "dingtalk.media.write";
const CAP_HEALTH_READ: &str = "dingtalk.health.read";

#[derive(Debug, Clone, Deserialize)]
struct DingTalkConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    #[serde(default = "default_media_base_url")]
    media_base_url: String,
    client_id: String,
    client_secret: String,
    #[serde(default = "default_timeout_ms")]
    request_timeout_ms: u64,
}

#[derive(Debug, Clone)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

#[derive(Debug)]
struct DingTalkState {
    config: DingTalkConfig,
    client: reqwest::Client,
    token_cache: Arc<Mutex<Option<CachedAccessToken>>>,
}

#[derive(Debug)]
pub struct DingTalkConnector {
    base: BaseConnector,
    state: Option<DingTalkState>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessTokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    expire_in: u64,
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

fn default_media_base_url() -> String {
    DEFAULT_MEDIA_BASE_URL.to_string()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

impl DingTalkConfig {
    fn validate(&self) -> FcpResult<()> {
        if self.client_id.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "client_id must not be empty".into(),
            });
        }
        if self.client_secret.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "client_secret must not be empty".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        validate_host(
            &self.base_url,
            &["api.dingtalk.com", "localhost", "127.0.0.1"],
        )?;
        validate_host(
            &self.media_base_url,
            &["oapi.dingtalk.com", "localhost", "127.0.0.1"],
        )?;
        Ok(())
    }
}

impl DingTalkState {
    fn new(config: DingTalkConfig) -> FcpResult<Self> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("failed to build DingTalk HTTP client: {error}"),
            })?;
        Ok(Self {
            config,
            client,
            token_cache: Arc::new(Mutex::new(None)),
        })
    }

    fn api_url(&self, path: &str) -> FcpResult<Url> {
        let mut url =
            Url::parse(self.config.base_url.trim()).map_err(|error| FcpError::Internal {
                message: format!("stored DingTalk base_url is invalid: {error}"),
            })?;
        url.set_path(path);
        Ok(url)
    }

    fn media_url(&self, path: &str) -> FcpResult<Url> {
        let mut url =
            Url::parse(self.config.media_base_url.trim()).map_err(|error| FcpError::Internal {
                message: format!("stored DingTalk media_base_url is invalid: {error}"),
            })?;
        url.set_path(path);
        Ok(url)
    }

    async fn access_token(&self) -> FcpResult<String> {
        {
            let cache = self.token_cache.lock().await;
            if let Some(cached) = cache.as_ref() {
                if Instant::now() < cached.expires_at {
                    return Ok(cached.token.clone());
                }
            }
        }

        let url = self.api_url("/v1.0/oauth2/accessToken")?;
        let response = self
            .client
            .post(url)
            .json(&json!({
                "appKey": self.config.client_id,
                "appSecret": self.config.client_secret
            }))
            .send()
            .await
            .map_err(map_transport_error("dingtalk access token"))?;
        let body: Value = response.json().await.map_err(|error| FcpError::Internal {
            message: format!("failed to decode DingTalk access token response: {error}"),
        })?;
        let token: AccessTokenResponse =
            serde_json::from_value(body.clone()).map_err(|error| FcpError::Internal {
                message: format!("failed to parse DingTalk access token payload: {error}"),
            })?;
        if token.access_token.trim().is_empty() {
            return Err(FcpError::Internal {
                message: format!("DingTalk access token response missing access_token: {body}"),
            });
        }
        let ttl = token
            .expire_in
            .saturating_sub(TOKEN_REFRESH_SAFETY_MARGIN_SECS)
            .max(1);
        *self.token_cache.lock().await = Some(CachedAccessToken {
            token: token.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
        });
        Ok(token.access_token)
    }

    async fn post_json(&self, path: &str, body: Value) -> FcpResult<Value> {
        let token = self.access_token().await?;
        let url = self.api_url(path)?;
        let response = self
            .client
            .post(url)
            .header("x-acs-dingtalk-access-token", &token)
            .json(&body)
            .send()
            .await
            .map_err(map_transport_error("dingtalk post request"))?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(FcpError::External {
                service: "dingtalk".into(),
                message: format!("DingTalk API request failed [{status}]: {body}"),
                status_code: Some(status),
                retryable: false,
                retry_after: None,
            });
        }
        response.json().await.map_err(|error| FcpError::Internal {
            message: format!("failed to decode DingTalk JSON response: {error}"),
        })
    }

    async fn upload_media(
        &self,
        media_type: &str,
        file_name: &str,
        mime_type: &str,
        content_base64: &str,
    ) -> FcpResult<Value> {
        let token = self.access_token().await?;
        let bytes =
            BASE64
                .decode(content_base64.trim())
                .map_err(|error| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("content_base64 must be valid base64: {error}"),
                })?;
        let mut url = self.media_url("/media/upload")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("access_token", &token);
            query.append_pair("type", media_type);
        }
        let part = multipart::Part::bytes(bytes)
            .file_name(file_name.to_string())
            .mime_str(mime_type)
            .map_err(|error| FcpError::InvalidRequest {
                code: 1005,
                message: format!("invalid mime_type: {error}"),
            })?;
        let response = self
            .client
            .post(url)
            .multipart(multipart::Form::new().part("media", part))
            .send()
            .await
            .map_err(map_transport_error("dingtalk upload media"))?;
        let body: Value = response.json().await.map_err(|error| FcpError::Internal {
            message: format!("failed to decode DingTalk upload response: {error}"),
        })?;
        ensure_dingtalk_media_success(body)
    }
}

impl DingTalkConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.dingtalk")),
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
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
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
                        "robotCode": state.config.client_id,
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
                        "robotCode": state.config.client_id,
                        "userIds": [target.id],
                        "msgKey": "sampleMarkdown",
                        "msgParam": json!({
                            "title": title_for(content),
                            "text": content,
                        }).to_string(),
                        }),
                    )
                };
                state.post_json(path, body).await?
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
                        "robotCode": state.config.client_id,
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
                        "robotCode": state.config.client_id,
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
                state.post_json(path, body).await?
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
                        "robotCode": state.config.client_id,
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
                        "robotCode": state.config.client_id,
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
                state.post_json(path, body).await?
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
                state
                    .upload_media(media_type, file_name, mime_type, content_base64)
                    .await?
            }
            OP_HEALTH => {
                let _token = state.access_token().await?;
                json!({
                    "status": "ok",
                    "base_url": state.config.base_url,
                    "media_base_url": state.config.media_base_url,
                    "client_id": state.config.client_id,
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
        self.state = Some(DingTalkState::new(config)?);
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
            status: if self.state.is_some() {
                HealthState::Ready
            } else {
                HealthState::Starting
            },
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: self.state.as_ref().map(|state| {
                json!({
                    "base_url": state.config.base_url,
                    "media_base_url": state.config.media_base_url,
                    "client_id": state.config.client_id,
                })
            }),
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(state) = self.state.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before DingTalk self_check",
            ));
        };
        match state.access_token().await {
            Ok(_) => Ok(SelfCheckReport::ok()),
            Err(error) => Ok(SelfCheckReport::from_error(&error)),
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

#[derive(Debug, Clone, Copy)]
struct ParsedTarget<'a> {
    id: &'a str,
    is_group: bool,
}

impl<'a> ParsedTarget<'a> {
    #[allow(clippy::option_if_let_else)]
    fn parse(raw: &'a str) -> Self {
        if let Some(id) = raw.strip_prefix("chat:") {
            Self { id, is_group: true }
        } else if let Some(id) = raw.strip_prefix("user:") {
            Self {
                id,
                is_group: false,
            }
        } else {
            Self {
                id: raw,
                is_group: false,
            }
        }
    }
}

fn validate_host(raw: &str, allowed_hosts: &[&str]) -> FcpResult<()> {
    let url = Url::parse(raw.trim()).map_err(|error| FcpError::InvalidRequest {
        code: 1001,
        message: format!("invalid URL `{raw}`: {error}"),
    })?;
    let host = url.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1001,
        message: format!("URL `{raw}` must include a host"),
    })?;
    if !allowed_hosts.contains(&host) {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("URL host `{host}` is not allowed"),
        });
    }
    Ok(())
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

fn map_transport_error(context: &'static str) -> impl Fn(reqwest::Error) -> FcpError {
    move |error| FcpError::External {
        service: "dingtalk".into(),
        message: format!("{context} failed: {error}"),
        status_code: None,
        retryable: error.is_timeout() || error.is_connect(),
        retry_after: None,
    }
}

fn ensure_dingtalk_media_success(body: Value) -> FcpResult<Value> {
    let errcode = body.get("errcode").and_then(Value::as_i64).unwrap_or(0);
    if errcode == 0 {
        Ok(body)
    } else {
        let errmsg = body
            .get("errmsg")
            .and_then(Value::as_str)
            .unwrap_or("unknown DingTalk media upload error");
        Err(FcpError::External {
            service: "dingtalk".into(),
            message: format!("DingTalk media upload error {errcode}: {errmsg}"),
            status_code: None,
            retryable: false,
            retry_after: None,
        })
    }
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

fn default_mime_type(media_type: &str) -> &'static str {
    match media_type {
        "image" => "image/png",
        "voice" => "audio/amr",
        "video" => "video/mp4",
        _ => "application/octet-stream",
    }
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
            related: vec![CapabilityId::from_static(OP_HEALTH)],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method, path, query_param},
    };

    #[test]
    fn config_rejects_empty_client_id() {
        let error = serde_json::from_value::<DingTalkConfig>(json!({
            "client_id": "",
            "client_secret": "secret"
        }))
        .expect("config should deserialize")
        .validate()
        .expect_err("client_id must be required");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
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

        let state = DingTalkState::new(DingTalkConfig {
            base_url: server.uri(),
            media_base_url: server.uri(),
            client_id: "ding-app".into(),
            client_secret: "secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        })
        .expect("state should build");

        let output = state
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

        let state = DingTalkState::new(DingTalkConfig {
            base_url: server.uri(),
            media_base_url: server.uri(),
            client_id: "ding-app".into(),
            client_secret: "secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        })
        .expect("state should build");

        let output = state
            .upload_media("image", "test.png", "image/png", &BASE64.encode(b"png"))
            .await
            .expect("upload should succeed");

        assert_eq!(output["media_id"], "MEDIA123");
    }
}
