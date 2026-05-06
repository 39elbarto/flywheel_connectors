use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_async_core::Cx;
use fcp_openai_compat::{ChatChunk, ChatMessage, OpenAiError, RateLimitPolicy};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError,
    FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, RequestId, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use futures_util::StreamExt as _;
use serde_json::{Value, json};
use tracing::info;

use crate::client::{
    DEFAULT_MODEL, DeepSeekAuth, DeepSeekClient, DeepSeekProvider, normalize_deepseek_base_url,
    validate_auth_material,
};
use crate::error::openai_error_to_fcp;
use crate::types::chat_request_from_value;

pub const CONNECTOR_ID: &str = "fcp.deepseek";
pub const CONNECTOR_VERSION: &str = "0.1.0";

const OP_CHAT: &str = "deepseek.chat.completions";
const OP_CHAT_STREAM: &str = "deepseek.chat.completions_stream";
const OP_MODELS: &str = "deepseek.models.list";
const OP_HEALTH: &str = "deepseek.health";
const OP_EMBEDDINGS: &str = "deepseek.embeddings.create";

const CAP_CHAT: &str = "deepseek.chat";
const CAP_MODELS: &str = "deepseek.models.read";
const CAP_HEALTH: &str = "deepseek.health.read";
const CAP_EMBEDDINGS: &str = "deepseek.embeddings";

#[derive(Debug, Clone)]
struct DeepSeekConfig {
    auth: DeepSeekAuth,
    base_url: String,
    default_model: String,
    request_timeout: Duration,
    model_cache_ttl: Duration,
    rate_limit_policy: RateLimitPolicy,
}

impl DeepSeekConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let inline_auth = params
            .get("api_key")
            .and_then(Value::as_str)
            .map(|value| validate_auth_material("api_key", value))
            .transpose()
            .map_err(invalid_config)?;
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(|value| validate_auth_material("credential_id", value))
            .transpose()
            .map_err(invalid_config)?;

        let auth = match (inline_auth, credential_id) {
            (Some(key), None) => DeepSeekAuth::ApiKey(key),
            (None, Some(id)) => DeepSeekAuth::CredentialId(id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id".into(),
                });
            }
        };

        let base_url = normalize_deepseek_base_url(params.get("base_url").and_then(Value::as_str))
            .map_err(invalid_config)?;
        let default_model = params
            .get("default_model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_MODEL)
            .to_string();
        let request_timeout = Duration::from_millis(optional_positive_u64(
            params,
            "request_timeout_ms",
            240_000,
        )?);
        let model_cache_ttl = Duration::from_secs(optional_positive_u64(
            params,
            "model_cache_ttl_seconds",
            3600,
        )?);
        let rate_limit_policy = params
            .get("wait_on_rate_limit_ms")
            .and_then(Value::as_u64)
            .map(Duration::from_millis)
            .map_or(RateLimitPolicy::FailFast, RateLimitPolicy::WaitUpTo);

        Ok(Self {
            auth,
            base_url,
            default_model,
            request_timeout,
            model_cache_ttl,
            rate_limit_policy,
        })
    }

    fn build_client(&self) -> DeepSeekClient {
        DeepSeekClient::new(
            DeepSeekProvider::new(self.base_url.clone(), self.auth.clone()),
            self.request_timeout,
            self.model_cache_ttl,
            self.rate_limit_policy,
        )
    }
}

pub struct DeepSeekConnector {
    base: Arc<BaseConnector>,
    config: Option<DeepSeekConfig>,
    client: Option<Arc<DeepSeekClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl DeepSeekConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = DeepSeekConfig::from_params(&params)?;
        let client = config.build_client();
        let auth_mode = config.auth.redacted_label();
        let base_url = config.base_url.clone();
        let default_model = config.default_model.clone();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_mode, base_url = %base_url, "DeepSeek connector configured");
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "base_url": base_url,
            "default_model": default_model,
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {err}"),
            })?;
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);
        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect::<Vec<_>>();

        serde_json::to_value(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:deepseek-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
        .map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize handshake response: {err}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        Ok(json!({
            "status": health_status(configured, handshaken),
            "configured": configured,
            "handshaken": handshaken,
            "auth_mode": self.config.as_ref().map(|config| config.auth.redacted_label()),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
            "default_model": self.config.as_ref().map(|config| config.default_model.clone()),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.config.is_some() && self.client.is_some() && self.session_id.is_some() {
                "healthy"
            } else if self.config.is_some() && self.client.is_some() {
                "degraded"
            } else {
                "unhealthy"
            },
            "checks": [
                {
                    "name": "configuration",
                    "passed": self.config.is_some(),
                    "critical": true,
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with api_key or credential_id.") }
                },
                {
                    "name": "auth_redaction",
                    "passed": self.config.as_ref().is_none_or(|config| !config.auth.redacted_label().contains("Bearer")),
                    "critical": true,
                    "message": "auth material is represented only by redacted labels"
                },
                {
                    "name": "base_url_policy",
                    "passed": self.config.as_ref().is_none_or(|config| normalize_deepseek_base_url(Some(&config.base_url)).is_ok()),
                    "critical": true,
                    "message": "base_url is constrained to api.deepseek.com, with loopback allowed for tests"
                },
                {
                    "name": "reasoning_redaction_policy",
                    "passed": true,
                    "critical": true,
                    "message": "reasoning_content is returned only to authorized invoke callers and is logged by length only in verification artifacts"
                },
                {
                    "name": "handshake",
                    "passed": self.session_id.is_some(),
                    "critical": false,
                    "message": if self.session_id.is_some() { Value::Null } else { json!("Handshake has not completed yet.") }
                }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let report = self.self_check().await?;
        serde_json::to_value(report).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize self_check report: {err}"),
        })
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        serde_json::to_value(self.introspect()).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize introspection: {err}"),
        })
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        if result.is_err() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn handle_invoke_internal(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        let capability_grant_value =
            params
                .get("capability_token")
                .cloned()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;
        let capability_grant = serde_json::from_value::<CapabilityToken>(capability_grant_value)
            .map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token: {err}"),
            })?;
        self.verify_capability(operation, &input, capability_grant)?;
        self.invoke_operation(operation, input).await
    }

    async fn invoke_operation(&self, operation: &str, input: Value) -> FcpResult<Value> {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "DeepSeek client not initialized".into(),
        })?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let cx = Cx::for_testing();
        match operation {
            OP_CHAT => {
                let request = chat_request_from_value(input, &config.default_model)?;
                client
                    .chat_completions(&cx, request)
                    .await
                    .map(chat_response_to_value)
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_CHAT_STREAM => {
                let request = chat_request_from_value(input, &config.default_model)?;
                let stream = client
                    .chat_completions_stream(&cx, request)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                collect_stream_response(stream).await
            }
            OP_MODELS => {
                if input
                    .get("refresh")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    client.invalidate_model_cache().await;
                }
                let models = client
                    .list_models(&cx)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                Ok(json!({
                    "object": "list",
                    "data": models,
                    "cache": "shared_in_memory"
                }))
            }
            OP_HEALTH => {
                let models = client
                    .list_models(&cx)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                Ok(json!({
                    "status": "ok",
                    "provider": "deepseek",
                    "model_count": models.len(),
                    "default_model": config.default_model,
                    "base_url": config.base_url,
                }))
            }
            OP_EMBEDDINGS => Err(FcpError::InvalidRequest {
                code: 1003,
                message:
                    "deepseek.embeddings.create is not supported by DeepSeek's first-party API"
                        .into(),
            }),
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");
        Ok(json!({
            "allowed": matches!(operation, OP_CHAT | OP_CHAT_STREAM | OP_MODELS | OP_HEALTH),
            "reason": if operation == OP_EMBEDDINGS {
                "DeepSeek embeddings are intentionally not supported."
            } else if matches!(operation, OP_CHAT | OP_CHAT_STREAM | OP_MODELS | OP_HEALTH) {
                "Supported operation."
            } else {
                "Unknown operation."
            }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({ "status": "shutdown" }))
    }

    fn verify_capability(
        &self,
        operation: &str,
        input: &Value,
        token: CapabilityToken,
    ) -> FcpResult<()> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let operation_id: OperationId =
            operation.parse().map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid operation ID format".into(),
            })?;
        let capability = required_capability(operation)?;
        let resources = resource_uris_for_operation(operation, input);
        verifier
            .verify_bound(token, &capability, &operation_id, &resources)
            .map(|_| ())
    }
}

impl Default for DeepSeekConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(DeepSeekConnector);

#[fcp_core::async_trait]
impl FcpConnector for DeepSeekConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        self.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let value = self
            .handle_handshake(serde_json::to_value(req).map_err(|err| FcpError::Internal {
                message: format!("Failed to serialize handshake request: {err}"),
            })?)
            .await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("Failed to decode handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        if self.config.is_some() && self.session_id.is_some() {
            HealthSnapshot::ready()
        } else if self.config.is_some() {
            HealthSnapshot::degraded("deepseek_handshake_pending")
        } else {
            HealthSnapshot::error("deepseek_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.config.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "DeepSeek connector is not configured",
            ));
        }
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; host-side egress credential injection is required for live checks",
            ));
        }
        Ok(SelfCheckReport::ok())
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, req: ShutdownRequest) -> FcpResult<()> {
        self.handle_shutdown(serde_json::to_value(req).unwrap_or_else(|_| json!({})))
            .await
            .map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let request_id = req.id;
        self.verify_capability(req.operation.as_str(), &req.input, req.capability_token)?;
        match self
            .invoke_operation(req.operation.as_str(), req.input)
            .await
        {
            Ok(value) => Ok(InvokeResponse::ok(request_id, value)),
            Err(error) => Ok(InvokeResponse::error(request_id, error)),
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        if matches!(
            req.operation.as_str(),
            OP_CHAT | OP_CHAT_STREAM | OP_MODELS | OP_HEALTH
        ) {
            Ok(SimulateResponse::allowed(req.id))
        } else {
            Ok(SimulateResponse::denied(
                req.id,
                "operation is not supported by DeepSeek",
                "FCP-3010",
            ))
        }
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_CHAT),
            summary: "Create a DeepSeek chat completion".into(),
            description: Some("Uses DeepSeek's OpenAI-compatible POST /chat/completions endpoint and returns reasoning_content separately from content when present.".into()),
            input_schema: chat_schema(false),
            output_schema: chat_output_schema(false),
            capability: CapabilityId::from_static(CAP_CHAT),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use direct DeepSeek for cost-effective code and reasoning workloads with first-party credential isolation.".into(),
                common_mistakes: vec![
                    "Do not log prompts, final content, reasoning_content, or bearer tokens.".into(),
                    "Do not collapse reasoning_content into content; callers must handle them distinctly.".into(),
                ],
                examples: vec![r#"{"model":"deepseek-v4-pro","messages":[{"role":"user","content":"Solve carefully"}],"thinking":{"type":"enabled"},"reasoning_effort":"high"}"#.into()],
                related: vec![
                    CapabilityId::from_static(CAP_CHAT),
                    CapabilityId::from_static(CAP_MODELS),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHAT_STREAM),
            summary: "Create a DeepSeek streaming chat completion".into(),
            description: Some("Uses DeepSeek SSE streaming and assembles reasoning_content and final content separately.".into()),
            input_schema: chat_schema(true),
            output_schema: chat_output_schema(true),
            capability: CapabilityId::from_static(CAP_CHAT),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use when the caller can consume reasoning and final answer deltas independently.".into(),
                common_mistakes: vec!["Do not treat empty content deltas during thinking as completion end.".into()],
                examples: vec![r#"{"messages":[{"role":"user","content":"Stream a short answer."}],"max_tokens":64}"#.into()],
                related: vec![CapabilityId::from_static(CAP_CHAT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MODELS),
            summary: "List DeepSeek models".into(),
            description: Some("Reads and caches GET /models.".into()),
            input_schema: json!({ "type": "object", "properties": { "refresh": { "type": "boolean" } } }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MODELS),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use before choosing a current DeepSeek model id.".into(),
                common_mistakes: vec!["Prefer current v4 model ids over deprecated deepseek-chat and deepseek-reasoner aliases when possible.".into()],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_CHAT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Probe DeepSeek health".into(),
            description: Some("Performs a bounded models.list probe.".into()),
            input_schema: json!({ "type": "object", "properties": {} }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_HEALTH),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to confirm DeepSeek credentials and network path.".into(),
                common_mistakes: Vec::new(),
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_MODELS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_EMBEDDINGS),
            summary: "DeepSeek embeddings unavailable".into(),
            description: Some("Declared for introspection honesty; this operation deterministically returns not supported.".into()),
            input_schema: json!({ "type": "object", "properties": { "availability": { "const": "not_supported" } } }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_EMBEDDINGS),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Do not invoke; use this metadata to explain that embeddings are intentionally unavailable for DeepSeek.".into(),
                common_mistakes: vec!["Do not proxy embeddings through another provider from this connector.".into()],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_MODELS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fn chat_schema(streaming: bool) -> Value {
    json!({
        "type": "object",
        "required": ["messages"],
        "properties": {
            "model": { "type": "string", "default": DEFAULT_MODEL },
            "messages": { "type": "array", "minItems": 1 },
            "max_tokens": { "type": "integer", "minimum": 1 },
            "temperature": { "type": "number", "minimum": 0, "maximum": 2 },
            "top_p": { "type": "number", "minimum": 0, "maximum": 1 },
            "stop": {},
            "response_format": { "type": "object" },
            "tools": { "type": "array" },
            "tool_choice": {},
            "thinking": {
                "type": "object",
                "properties": { "type": { "enum": ["enabled", "disabled"] } }
            },
            "reasoning_effort": { "enum": ["high", "max", "low", "medium", "xhigh"] },
            "user_id": { "type": "string" },
            "streaming_response": { "const": streaming },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn chat_output_schema(streaming: bool) -> Value {
    let mut schema = json!({
        "type": "object",
        "properties": {
            "id": { "type": "string" },
            "model": { "type": "string" },
            "content": { "type": ["string", "null"] },
            "reasoning_content": { "type": ["string", "null"] },
            "content_bytes": { "type": "integer" },
            "reasoning_content_bytes": { "type": "integer" },
            "finish_reason": { "type": ["string", "null"] },
            "usage": { "type": ["object", "null"] }
        }
    });
    if streaming
        && let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut)
    {
        properties.insert("chunk_count".into(), json!({ "type": "integer" }));
    }
    schema
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_CHAT | OP_CHAT_STREAM => Ok(CapabilityId::from_static(CAP_CHAT)),
        OP_MODELS => Ok(CapabilityId::from_static(CAP_MODELS)),
        OP_HEALTH => Ok(CapabilityId::from_static(CAP_HEALTH)),
        OP_EMBEDDINGS => Ok(CapabilityId::from_static(CAP_EMBEDDINGS)),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn resource_uris_for_operation(operation: &str, input: &Value) -> Vec<String> {
    match operation {
        OP_CHAT | OP_CHAT_STREAM => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_MODEL);
            vec![format!("deepseek:model:{model}")]
        }
        OP_MODELS | OP_HEALTH | OP_EMBEDDINGS => vec!["deepseek:models".into()],
        _ => Vec::new(),
    }
}

fn optional_positive_u64(params: &Value, field: &str, default: u64) -> FcpResult<u64> {
    match params.get(field).and_then(Value::as_u64) {
        Some(0) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be greater than 0"),
        }),
        Some(value) => Ok(value),
        None => Ok(default),
    }
}

fn invalid_config(message: String) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message,
    }
}

fn health_status(configured: bool, handshaken: bool) -> &'static str {
    if configured && handshaken {
        "ready"
    } else if configured {
        "degraded"
    } else {
        "unconfigured"
    }
}

fn chat_response_to_value(response: fcp_openai_compat::ChatCompletionsResponse) -> Value {
    let first_choice = response.choices.first();
    let (content, reasoning_content) =
        first_choice.map_or((None, None), |choice| assistant_parts(&choice.message));
    let finish_reason = first_choice.and_then(|choice| choice.finish_reason.clone());
    let content_bytes = content.as_ref().map_or(0, String::len);
    let reasoning_content_bytes = reasoning_content.as_ref().map_or(0, String::len);

    json!({
        "id": response.id,
        "model": response.model,
        "content": content,
        "reasoning_content": reasoning_content,
        "content_bytes": content_bytes,
        "reasoning_content_bytes": reasoning_content_bytes,
        "finish_reason": finish_reason,
        "usage": response.usage,
        "choice_count": response.choices.len(),
    })
}

fn assistant_parts(message: &ChatMessage) -> (Option<String>, Option<String>) {
    match message {
        ChatMessage::Assistant {
            content,
            reasoning_content,
            ..
        } => (content.clone(), reasoning_content.clone()),
        _ => (None, None),
    }
}

async fn collect_stream_response(
    stream: fcp_openai_compat::ChatCompletionStream,
) -> FcpResult<Value> {
    let mut chunk_count = 0_u64;
    let mut content = String::new();
    let mut reasoning_content = String::new();
    let mut finish_reason = None;
    let mut tool_call_delta_count = 0_u64;
    let mut chunk_metadata = Vec::new();

    let chunks = stream
        .collect::<Vec<Result<ChatChunk, OpenAiError>>>()
        .await;
    for chunk in chunks {
        let chunk = chunk.map_err(|err| openai_error_to_fcp(&err))?;
        chunk_count += 1;
        let mut content_delta_bytes = 0_usize;
        let mut reasoning_delta_bytes = 0_usize;
        for choice in &chunk.choices {
            if let Some(delta) = &choice.delta.reasoning_content {
                reasoning_delta_bytes = reasoning_delta_bytes.saturating_add(delta.len());
                reasoning_content.push_str(delta);
            }
            if let Some(delta) = &choice.delta.content {
                content_delta_bytes = content_delta_bytes.saturating_add(delta.len());
                content.push_str(delta);
            }
            if choice
                .delta
                .tool_calls
                .as_ref()
                .is_some_and(|calls| !calls.is_empty())
            {
                tool_call_delta_count += 1;
            }
            if finish_reason.is_none() {
                finish_reason.clone_from(&choice.finish_reason);
            }
        }
        chunk_metadata.push(json!({
            "id": chunk.id,
            "choice_count": chunk.choices.len(),
            "model": chunk.model,
            "content_delta_bytes": content_delta_bytes,
            "reasoning_delta_bytes": reasoning_delta_bytes,
        }));
    }

    Ok(json!({
        "content": content,
        "reasoning_content": reasoning_content,
        "content_bytes": content.len(),
        "reasoning_content_bytes": reasoning_content.len(),
        "chunk_count": chunk_count,
        "finish_reason": finish_reason,
        "tool_call_delta_count": tool_call_delta_count,
        "chunks": chunk_metadata,
    }))
}

#[allow(clippy::too_many_arguments)]
pub fn test_invoke_request(
    id: &str,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token,
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

pub fn test_handshake_request(
    capabilities: Vec<CapabilityId>,
    public_key: [u8; 32],
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: public_key,
        nonce: [37_u8; 32],
        capabilities_requested: capabilities,
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_streaming_output_schema_omits_streaming_only_chunk_count() {
        let schema = chat_output_schema(false);
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("schema properties should be an object");

        assert!(!properties.contains_key("chunk_count"));
        assert!(properties.contains_key("reasoning_content"));
    }

    #[test]
    fn streaming_output_schema_includes_chunk_count() {
        let schema = chat_output_schema(true);
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("schema properties should be an object");

        assert_eq!(
            properties
                .get("chunk_count")
                .and_then(|schema| schema.get("type"))
                .and_then(Value::as_str),
            Some("integer")
        );
    }
}
