//! `WeCom` enterprise messaging connector.

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

use crate::client::WeComClient;
use crate::types::{
    WeComConfig, WeComDepartmentListRequest, WeComMediaUploadRequest, WeComMessageKind,
    WeComMessageRequest, WeComStateModel, WeComUserLookupRequest,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

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
                let request = WeComMessageRequest::from_value(&req.input, WeComMessageKind::Text)?;
                state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_SEND_MARKDOWN => {
                let request =
                    WeComMessageRequest::from_value(&req.input, WeComMessageKind::Markdown)?;
                state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_UPLOAD_MEDIA => {
                let request = WeComMediaUploadRequest::from_value(&req.input)?;
                state
                    .client
                    .upload_media(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_GET_USER => {
                let request = WeComUserLookupRequest::from_value(&req.input)?;
                state
                    .client
                    .get_user(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_LIST_DEPARTMENTS => {
                let request = WeComDepartmentListRequest::from_value(&req.input)?;
                state
                    .client
                    .list_departments(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_HEALTH => {
                let _token = state
                    .client
                    .access_token()
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let model = state.client.state_model().await;
                json!({
                    "status": "ok",
                    "base_url": model.base_url.clone(),
                    "agent_id": model.agent_id,
                    "token_cached": model.token_cached,
                    "state": &model,
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
        "base_url": model.base_url,
        "agent_id": model.agent_id,
        "token_cached": model.token_cached,
        "state": model,
    })
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
    use serde_json::Value;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::types::DEFAULT_TIMEOUT_MS;

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
}
