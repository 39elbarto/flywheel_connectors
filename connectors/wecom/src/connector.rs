//! `WeCom` enterprise messaging connector.

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
const DEFAULT_BASE_URL: &str = "https://qyapi.weixin.qq.com";
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const TOKEN_REFRESH_SAFETY_MARGIN_SECS: u64 = 60;

const OP_SEND_TEXT: &str = "wecom.messages.send_text";
const OP_SEND_MARKDOWN: &str = "wecom.messages.send_markdown";
const OP_UPLOAD_MEDIA: &str = "wecom.media.upload";
const OP_GET_USER: &str = "wecom.users.get";
const OP_LIST_DEPARTMENTS: &str = "wecom.departments.list";
const OP_HEALTH: &str = "wecom.health";

const CAP_MESSAGES_WRITE: &str = "wecom.messages.write";
const CAP_MEDIA_WRITE: &str = "wecom.media.write";
const CAP_USERS_READ: &str = "wecom.users.read";
const CAP_DEPARTMENTS_READ: &str = "wecom.departments.read";
const CAP_HEALTH_READ: &str = "wecom.health.read";

#[derive(Debug, Clone, Deserialize)]
struct WeComConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    corp_id: String,
    agent_id: u64,
    agent_secret: String,
    #[serde(default = "default_timeout_ms")]
    request_timeout_ms: u64,
}

#[derive(Debug, Clone)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

#[derive(Debug)]
struct WeComState {
    config: WeComConfig,
    client: reqwest::Client,
    token_cache: Arc<Mutex<Option<CachedAccessToken>>>,
}

#[derive(Debug)]
pub struct WeComConnector {
    base: BaseConnector,
    state: Option<WeComState>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

impl WeComConfig {
    fn validate(&self) -> FcpResult<()> {
        if self.corp_id.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "corp_id must not be empty".into(),
            });
        }
        if self.agent_secret.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "agent_secret must not be empty".into(),
            });
        }
        if self.agent_id == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "agent_id must be greater than zero".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }

        let base_url =
            Url::parse(self.base_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("invalid base_url: {error}"),
            })?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "base_url must use http or https".into(),
            });
        }
        let host = base_url
            .host_str()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: "base_url must include a host".into(),
            })?;
        if !matches!(host, "qyapi.weixin.qq.com" | "localhost" | "127.0.0.1") {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: format!(
                    "base_url host `{host}` is not allowed; use qyapi.weixin.qq.com or localhost for tests"
                ),
            });
        }
        Ok(())
    }
}

impl WeComState {
    fn new(config: WeComConfig) -> FcpResult<Self> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("failed to build WeCom HTTP client: {error}"),
            })?;
        Ok(Self {
            config,
            client,
            token_cache: Arc::new(Mutex::new(None)),
        })
    }

    fn url(&self, path: &str) -> FcpResult<Url> {
        let mut url =
            Url::parse(self.config.base_url.trim()).map_err(|error| FcpError::Internal {
                message: format!("stored base_url is invalid: {error}"),
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

        let mut url = self.url("/cgi-bin/gettoken")?;
        url.query_pairs_mut()
            .append_pair("corpid", self.config.corp_id.trim())
            .append_pair("corpsecret", self.config.agent_secret.trim());

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(map_transport_error("wecom access token"))?;
        let body: Value = response.json().await.map_err(|error| FcpError::Internal {
            message: format!("failed to decode WeCom access token response: {error}"),
        })?;
        let body = ensure_wecom_success(body)?;
        let token: AccessTokenResponse =
            serde_json::from_value(body).map_err(|error| FcpError::Internal {
                message: format!("failed to parse WeCom access token payload: {error}"),
            })?;
        if token.access_token.trim().is_empty() {
            return Err(FcpError::Internal {
                message: "WeCom access token response omitted access_token".into(),
            });
        }
        let ttl = token
            .expires_in
            .saturating_sub(TOKEN_REFRESH_SAFETY_MARGIN_SECS)
            .max(1);
        let cached = CachedAccessToken {
            token: token.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
        };
        *self.token_cache.lock().await = Some(cached);
        Ok(token.access_token)
    }

    async fn get_json(&self, path: &str, params: &[(&str, String)]) -> FcpResult<Value> {
        let token = self.access_token().await?;
        let mut url = self.url(path)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("access_token", &token);
            for (key, value) in params {
                query.append_pair(key, value);
            }
        }
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(map_transport_error("wecom get request"))?;
        let body: Value = response.json().await.map_err(|error| FcpError::Internal {
            message: format!("failed to decode WeCom JSON response: {error}"),
        })?;
        ensure_wecom_success(body)
    }

    async fn post_json(&self, path: &str, body: Value) -> FcpResult<Value> {
        let token = self.access_token().await?;
        let mut url = self.url(path)?;
        url.query_pairs_mut().append_pair("access_token", &token);
        let response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(map_transport_error("wecom post request"))?;
        let body: Value = response.json().await.map_err(|error| FcpError::Internal {
            message: format!("failed to decode WeCom JSON response: {error}"),
        })?;
        ensure_wecom_success(body)
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
        let mut url = self.url("/cgi-bin/media/upload")?;
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
        let form = multipart::Form::new().part("media", part);
        let response = self
            .client
            .post(url)
            .multipart(form)
            .send()
            .await
            .map_err(map_transport_error("wecom upload media"))?;
        let body: Value = response.json().await.map_err(|error| FcpError::Internal {
            message: format!("failed to decode WeCom upload response: {error}"),
        })?;
        ensure_wecom_success(body)
    }
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
                        "safe": { "type": "boolean" }
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
                        "totag": { "type": "string" }
                    }
                }),
                "Use when the destination accepts WeCom markdown rendering and rich formatting matters.",
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

        let output = match req.operation.as_str() {
            OP_SEND_TEXT => {
                let targets = extract_targets(&req.input)?;
                let content = required_string(&req.input, "content")?;
                let body = json!({
                    "touser": targets.touser,
                    "toparty": targets.toparty,
                    "totag": targets.totag,
                    "msgtype": "text",
                    "agentid": state.config.agent_id,
                    "text": { "content": content },
                    "safe": i32::from(req.input.get("safe").and_then(Value::as_bool).unwrap_or(false))
                });
                state.post_json("/cgi-bin/message/send", body).await?
            }
            OP_SEND_MARKDOWN => {
                let targets = extract_targets(&req.input)?;
                let content = required_string(&req.input, "content")?;
                let body = json!({
                    "touser": targets.touser,
                    "toparty": targets.toparty,
                    "totag": targets.totag,
                    "msgtype": "markdown",
                    "agentid": state.config.agent_id,
                    "markdown": { "content": content }
                });
                state.post_json("/cgi-bin/message/send", body).await?
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
                    .unwrap_or("application/octet-stream");
                let content_base64 = required_string(&req.input, "content_base64")?;
                state
                    .upload_media(media_type, file_name, mime_type, content_base64)
                    .await?
            }
            OP_GET_USER => {
                let userid = required_string(&req.input, "userid")?;
                state
                    .get_json("/cgi-bin/user/get", &[("userid", userid.to_string())])
                    .await?
            }
            OP_LIST_DEPARTMENTS => {
                let mut params = Vec::new();
                if let Some(id) = req.input.get("id").and_then(Value::as_i64) {
                    params.push(("id", id.to_string()));
                }
                state.get_json("/cgi-bin/department/list", &params).await?
            }
            OP_HEALTH => {
                let _token = state.access_token().await?;
                json!({
                    "status": "ok",
                    "base_url": state.config.base_url,
                    "agent_id": state.config.agent_id,
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
        let config: WeComConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid WeCom configuration: {error}"),
            })?;
        let state = WeComState::new(config)?;
        self.state = Some(state);
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
        let details = self.state.as_ref().map(|state| {
            json!({
                "base_url": state.config.base_url,
                "agent_id": state.config.agent_id,
                "token_cached": false,
            })
        });
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

#[derive(Debug)]
struct MessageTargets<'a> {
    touser: &'a str,
    toparty: &'a str,
    totag: &'a str,
}

fn extract_targets(input: &Value) -> FcpResult<MessageTargets<'_>> {
    let touser = input.get("touser").and_then(Value::as_str).unwrap_or("");
    let toparty = input.get("toparty").and_then(Value::as_str).unwrap_or("");
    let totag = input.get("totag").and_then(Value::as_str).unwrap_or("");
    if touser.is_empty() && toparty.is_empty() && totag.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "at least one target must be provided via touser, toparty, or totag".into(),
        });
    }
    Ok(MessageTargets {
        touser,
        toparty,
        totag,
    })
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
        service: "wecom".into(),
        message: format!("{context} failed: {error}"),
        status_code: None,
        retryable: error.is_timeout() || error.is_connect(),
        retry_after: None,
    }
}

fn ensure_wecom_success(body: Value) -> FcpResult<Value> {
    let errcode = body.get("errcode").and_then(Value::as_i64).unwrap_or(0);
    if errcode == 0 {
        Ok(body)
    } else {
        let errmsg = body
            .get("errmsg")
            .and_then(Value::as_str)
            .unwrap_or("unknown WeCom error");
        Err(FcpError::External {
            service: "wecom".into(),
            message: format!("WeCom API error {errcode}: {errmsg}"),
            status_code: None,
            retryable: false,
            retry_after: None,
        })
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_SEND_TEXT | OP_SEND_MARKDOWN => CAP_MESSAGES_WRITE,
        OP_UPLOAD_MEDIA => CAP_MEDIA_WRITE,
        OP_GET_USER => CAP_USERS_READ,
        OP_LIST_DEPARTMENTS => CAP_DEPARTMENTS_READ,
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
                    | CAP_USERS_READ
                    | CAP_DEPARTMENTS_READ
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
    fn config_rejects_empty_corp_id() {
        let error = serde_json::from_value::<WeComConfig>(json!({
            "corp_id": "",
            "agent_id": 1_000_002_u64,
            "agent_secret": "secret"
        }))
        .expect("config should deserialize")
        .validate()
        .expect_err("corp_id must be required");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn send_text_posts_expected_message_payload() {
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

        Mock::given(method("POST"))
            .and(path("/cgi-bin/message/send"))
            .and(query_param("access_token", "token-123"))
            .and(body_partial_json(json!({
                "touser": "zhangsan",
                "msgtype": "text",
                "agentid": 1_000_002_u64,
                "text": { "content": "hello from test" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "msgid": "mid-1"
            })))
            .mount(&server)
            .await;

        let state = WeComState::new(WeComConfig {
            base_url: server.uri(),
            corp_id: "corp".into(),
            agent_id: 1_000_002,
            agent_secret: "secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        })
        .expect("state should build");

        let output = state
            .post_json(
                "/cgi-bin/message/send",
                json!({
                    "touser": "zhangsan",
                    "msgtype": "text",
                    "agentid": 1_000_002_u64,
                    "text": { "content": "hello from test" }
                }),
            )
            .await
            .expect("send text should succeed");

        assert_eq!(output["msgid"], "mid-1");
    }

    #[fcp_async_core::runtime::test]
    async fn upload_media_posts_multipart_request() {
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

        Mock::given(method("POST"))
            .and(path("/cgi-bin/media/upload"))
            .and(query_param("access_token", "token-123"))
            .and(query_param("type", "image"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "type": "image",
                "media_id": "MEDIA123"
            })))
            .mount(&server)
            .await;

        let state = WeComState::new(WeComConfig {
            base_url: server.uri(),
            corp_id: "corp".into(),
            agent_id: 1_000_002,
            agent_secret: "secret".into(),
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
