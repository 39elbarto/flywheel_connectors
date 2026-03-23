//! Tencent `QQ` bot connector.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
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
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const DEFAULT_BASE_URL: &str = "https://api.sgroup.qq.com";
const DEFAULT_TOKEN_BASE_URL: &str = "https://bots.qq.com";
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const TOKEN_REFRESH_SAFETY_MARGIN_SECS: u64 = 60;

const OP_SEND_CHANNEL: &str = "qq.messages.send_channel";
const OP_SEND_GROUP: &str = "qq.messages.send_group";
const OP_SEND_C2C: &str = "qq.messages.send_c2c";
const OP_GET_GATEWAY: &str = "qq.gateway.get";
const OP_HEALTH: &str = "qq.health";

const CAP_MESSAGES_WRITE: &str = "qq.messages.write";
const CAP_GATEWAY_READ: &str = "qq.gateway.read";
const CAP_HEALTH_READ: &str = "qq.health.read";

#[derive(Debug, Clone, Deserialize)]
struct QqConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    #[serde(default = "default_token_base_url")]
    token_base_url: String,
    app_id: String,
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
struct QqState {
    config: QqConfig,
    client: reqwest::Client,
    token_cache: Arc<Mutex<Option<CachedAccessToken>>>,
}

#[derive(Debug)]
pub struct QqConnector {
    base: BaseConnector,
    state: Option<QqState>,
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

fn default_token_base_url() -> String {
    DEFAULT_TOKEN_BASE_URL.to_string()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

impl QqConfig {
    fn validate(&self) -> FcpResult<()> {
        if self.app_id.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "app_id must not be empty".into(),
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
            &["api.sgroup.qq.com", "localhost", "127.0.0.1"],
        )?;
        validate_host(
            &self.token_base_url,
            &["bots.qq.com", "localhost", "127.0.0.1"],
        )?;
        Ok(())
    }
}

impl QqState {
    fn new(config: QqConfig) -> FcpResult<Self> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("failed to build QQ HTTP client: {error}"),
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
                message: format!("stored QQ base_url is invalid: {error}"),
            })?;
        url.set_path(path);
        Ok(url)
    }

    fn token_url(&self, path: &str) -> FcpResult<Url> {
        let mut url =
            Url::parse(self.config.token_base_url.trim()).map_err(|error| FcpError::Internal {
                message: format!("stored QQ token_base_url is invalid: {error}"),
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

        let url = self.token_url("/app/getAppAccessToken")?;
        let response = self
            .client
            .post(url)
            .json(&json!({
                "appId": self.config.app_id,
                "clientSecret": self.config.client_secret
            }))
            .send()
            .await
            .map_err(map_transport_error("qq access token"))?;
        let body: Value = response.json().await.map_err(|error| FcpError::Internal {
            message: format!("failed to decode QQ access token response: {error}"),
        })?;
        let token: AccessTokenResponse =
            serde_json::from_value(body.clone()).map_err(|error| FcpError::Internal {
                message: format!("failed to parse QQ access token payload: {error}"),
            })?;
        if token.access_token.trim().is_empty() {
            return Err(FcpError::Internal {
                message: format!("QQ access token response missing access_token: {body}"),
            });
        }
        let ttl = token
            .expires_in
            .saturating_sub(TOKEN_REFRESH_SAFETY_MARGIN_SECS)
            .max(1);
        *self.token_cache.lock().await = Some(CachedAccessToken {
            token: token.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
        });
        Ok(token.access_token)
    }

    async fn api_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> FcpResult<Value> {
        let token = self.access_token().await?;
        let url = self.api_url(path)?;
        let request = self
            .client
            .request(method, url)
            .header("Authorization", format!("QQBot {token}"));
        let request = if let Some(body) = body.as_ref() {
            request.json(body)
        } else {
            request
        };
        let response = request
            .send()
            .await
            .map_err(map_transport_error("qq api request"))?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(FcpError::External {
                service: "qq".into(),
                message: format!("QQ API request failed [{status}]: {body}"),
                status_code: Some(status),
                retryable: false,
                retry_after: None,
            });
        }
        response.json().await.map_err(|error| FcpError::Internal {
            message: format!("failed to decode QQ JSON response: {error}"),
        })
    }
}

impl QqConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.qq")),
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
                OP_SEND_CHANNEL,
                "Send a QQ channel message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["channel_id", "content"],
                    "properties": {
                        "channel_id": { "type": "string" },
                        "content": { "type": "string" },
                        "msg_id": { "type": "string" }
                    }
                }),
                "Use for QQ channel deliveries when you already know the target channel_id.",
            ),
            operation(
                OP_SEND_GROUP,
                "Send a QQ group message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["group_openid", "content"],
                    "properties": {
                        "group_openid": { "type": "string" },
                        "content": { "type": "string" },
                        "msg_id": { "type": "string" }
                    }
                }),
                "Use for QQ group deliveries to a known group_openid target.",
            ),
            operation(
                OP_SEND_C2C,
                "Send a QQ C2C message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["openid", "content"],
                    "properties": {
                        "openid": { "type": "string" },
                        "content": { "type": "string" },
                        "msg_id": { "type": "string" }
                    }
                }),
                "Use for one-to-one QQ bot messages directed at a specific openid.",
            ),
            operation(
                OP_GET_GATEWAY,
                "Get the QQ gateway websocket URL",
                CAP_GATEWAY_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use when a higher-level runtime needs the official QQ gateway URL for event intake.",
            ),
            operation(
                OP_HEALTH,
                "Verify QQ credentials and gateway discovery",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use before higher-risk send operations when you need a bounded auth and connectivity check.",
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
            OP_SEND_CHANNEL => {
                let channel_id = required_string(&req.input, "channel_id")?;
                let content = required_string(&req.input, "content")?;
                let msg_id = req.input.get("msg_id").and_then(Value::as_str);
                state
                    .api_request(
                        reqwest::Method::POST,
                        &format!("/channels/{channel_id}/messages"),
                        Some(channel_message_body(content, msg_id)),
                    )
                    .await?
            }
            OP_SEND_GROUP => {
                let group_openid = required_string(&req.input, "group_openid")?;
                let content = required_string(&req.input, "content")?;
                let msg_id = req.input.get("msg_id").and_then(Value::as_str);
                state
                    .api_request(
                        reqwest::Method::POST,
                        &format!("/v2/groups/{group_openid}/messages"),
                        Some(direct_message_body(content, msg_id)),
                    )
                    .await?
            }
            OP_SEND_C2C => {
                let openid = required_string(&req.input, "openid")?;
                let content = required_string(&req.input, "content")?;
                let msg_id = req.input.get("msg_id").and_then(Value::as_str);
                state
                    .api_request(
                        reqwest::Method::POST,
                        &format!("/v2/users/{openid}/messages"),
                        Some(direct_message_body(content, msg_id)),
                    )
                    .await?
            }
            OP_GET_GATEWAY => {
                state
                    .api_request(reqwest::Method::GET, "/gateway", None)
                    .await?
            }
            OP_HEALTH => {
                let _token = state.access_token().await?;
                let gateway = state
                    .api_request(reqwest::Method::GET, "/gateway", None)
                    .await?;
                json!({
                    "status": "ok",
                    "base_url": state.config.base_url,
                    "gateway": gateway.get("url").cloned().unwrap_or(Value::Null),
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

impl Default for QqConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FcpConnector for QqConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let config: QqConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid QQ configuration: {error}"),
            })?;
        self.state = Some(QqState::new(config)?);
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
                    "token_base_url": state.config.token_base_url,
                    "app_id": state.config.app_id,
                })
            }),
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(state) = self.state.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before QQ self_check",
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

fn map_transport_error(context: &'static str) -> impl Fn(reqwest::Error) -> FcpError {
    move |error| FcpError::External {
        service: "qq".into(),
        message: format!("{context} failed: {error}"),
        status_code: None,
        retryable: error.is_timeout() || error.is_connect(),
        retry_after: None,
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_SEND_CHANNEL | OP_SEND_GROUP | OP_SEND_C2C => CAP_MESSAGES_WRITE,
        OP_GET_GATEWAY => CAP_GATEWAY_READ,
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
                CAP_MESSAGES_WRITE | CAP_GATEWAY_READ | CAP_HEALTH_READ
            )
        })
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
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

fn direct_message_body(content: &str, msg_id: Option<&str>) -> Value {
    let mut body = json!({
        "content": content,
        "msg_type": 0,
        "msg_seq": 1,
    });
    if let Some(msg_id) = msg_id {
        body["msg_id"] = json!(msg_id);
    }
    body
}

fn channel_message_body(content: &str, msg_id: Option<&str>) -> Value {
    let mut body = json!({
        "content": content,
    });
    if let Some(msg_id) = msg_id {
        body["msg_id"] = json!(msg_id);
    }
    body
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
                "QQ channel sends use channel_id, while group and C2C sends require group_openid or openid."
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
        matchers::{body_partial_json, header, method, path},
    };

    #[test]
    fn config_rejects_empty_app_id() {
        let error = serde_json::from_value::<QqConfig>(json!({
            "app_id": "",
            "client_secret": "secret"
        }))
        .expect("config should deserialize")
        .validate()
        .expect_err("app_id must be required");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn send_channel_posts_expected_payload() {
        let api_server = MockServer::start().await;
        let token_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/app/getAppAccessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&token_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/channels/channel-1/messages"))
            .and(header("authorization", "QQBot token-123"))
            .and(body_partial_json(json!({
                "content": "hello qq"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg-1",
                "timestamp": "123456"
            })))
            .mount(&api_server)
            .await;

        let state = QqState::new(QqConfig {
            base_url: api_server.uri(),
            token_base_url: token_server.uri(),
            app_id: "app-1".into(),
            client_secret: "secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        })
        .expect("state should build");

        let output = state
            .api_request(
                reqwest::Method::POST,
                "/channels/channel-1/messages",
                Some(channel_message_body("hello qq", None)),
            )
            .await
            .expect("channel send should succeed");

        assert_eq!(output["id"], "msg-1");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_request_uses_bearer_token() {
        let api_server = MockServer::start().await;
        let token_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/app/getAppAccessToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&token_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/gateway"))
            .and(header("authorization", "QQBot token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "url": "wss://gateway.qq.example/ws"
            })))
            .mount(&api_server)
            .await;

        let state = QqState::new(QqConfig {
            base_url: api_server.uri(),
            token_base_url: token_server.uri(),
            app_id: "app-1".into(),
            client_secret: "secret".into(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
        })
        .expect("state should build");

        let output = state
            .api_request(reqwest::Method::GET, "/gateway", None)
            .await
            .expect("gateway discovery should succeed");

        assert_eq!(output["url"], "wss://gateway.qq.example/ws");
    }
}
