use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_async_core::Cx;
use fcp_openai_compat::RateLimitPolicy;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError,
    FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, RequestId, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::{Value, json};
use tracing::info;

use crate::client::{
    DEFAULT_BASE_URL, DEFAULT_EMBEDDING_MODEL, DEFAULT_MULTIMODAL_MODEL, DEFAULT_RERANK_MODEL,
    VoyageAuth, VoyageClient, VoyageProvider, normalize_voyage_base_url, validate_auth_material,
};
use crate::error::openai_error_to_fcp;
use crate::types::{
    embeddings_request_from_value, multimodal_request_from_value, rerank_request_from_value,
};

pub const CONNECTOR_ID: &str = "fcp.voyage";
pub const CONNECTOR_VERSION: &str = "0.1.0";

const OP_EMBEDDINGS: &str = "voyage.embeddings.create";
const OP_MULTIMODAL: &str = "voyage.embeddings.create_multimodal";
const OP_RERANK: &str = "voyage.rerank";
const OP_MODELS: &str = "voyage.models.list";
const OP_HEALTH: &str = "voyage.health";

const CAP_EMBEDDINGS: &str = "voyage.embeddings";
const CAP_RERANK: &str = "voyage.rerank";
const CAP_MODELS: &str = "voyage.models.read";
const CAP_HEALTH: &str = "voyage.health.read";

#[derive(Debug, Clone)]
struct VoyageConfig {
    auth: VoyageAuth,
    base_url: String,
    default_embedding_model: String,
    default_multimodal_model: String,
    default_rerank_model: String,
    request_timeout: Duration,
    model_cache_ttl: Duration,
    rate_limit_policy: RateLimitPolicy,
}

impl VoyageConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let direct_bearer = optional_auth(params, &config_field(&["api", "key"]))?;
        let credential_id = optional_auth(params, "credential_id")?;
        let auth = build_auth(direct_bearer, credential_id)?;
        let base_url = normalize_voyage_base_url(params.get("base_url").and_then(Value::as_str))
            .map_err(invalid_config)?;
        let default_embedding_model =
            optional_string(params, "default_embedding_model").unwrap_or(DEFAULT_EMBEDDING_MODEL);
        let default_multimodal_model =
            optional_string(params, "default_multimodal_model").unwrap_or(DEFAULT_MULTIMODAL_MODEL);
        let default_rerank_model =
            optional_string(params, "default_rerank_model").unwrap_or(DEFAULT_RERANK_MODEL);
        let request_timeout =
            Duration::from_millis(optional_positive_u64(params, "request_timeout_ms", 60_000)?);
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
            default_embedding_model: default_embedding_model.to_string(),
            default_multimodal_model: default_multimodal_model.to_string(),
            default_rerank_model: default_rerank_model.to_string(),
            request_timeout,
            model_cache_ttl,
            rate_limit_policy,
        })
    }

    fn build_client(&self) -> VoyageClient {
        VoyageClient::new(
            VoyageProvider::new(self.base_url.clone(), self.auth.clone()),
            self.request_timeout,
            self.model_cache_ttl,
            self.rate_limit_policy,
        )
    }
}

pub struct VoyageConnector {
    base: Arc<BaseConnector>,
    config: Option<VoyageConfig>,
    client: Option<Arc<VoyageClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl VoyageConnector {
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
        let config = VoyageConfig::from_params(&params)?;
        let client = config.build_client();
        let auth_mode = config.auth.redacted_label();
        let base_url = config.base_url.clone();
        let default_embedding_model = config.default_embedding_model.clone();
        let default_multimodal_model = config.default_multimodal_model.clone();
        let default_rerank_model = config.default_rerank_model.clone();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_mode, base_url = %base_url, "Voyage connector configured");
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "base_url": base_url,
            "default_embedding_model": default_embedding_model,
            "default_multimodal_model": default_multimodal_model,
            "default_rerank_model": default_rerank_model,
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
            manifest_hash: "sha256:voyage-connector-v1".into(),
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
            "default_embedding_model": self.config.as_ref().map(|config| config.default_embedding_model.clone()),
            "default_multimodal_model": self.config.as_ref().map(|config| config.default_multimodal_model.clone()),
            "default_rerank_model": self.config.as_ref().map(|config| config.default_rerank_model.clone()),
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
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with exactly one Voyage bearer or host credential reference.") }
                },
                {
                    "name": "auth_redaction",
                    "passed": self.config.as_ref().is_none_or(|config| !config.auth.redacted_label().contains("Bearer")),
                    "critical": true,
                    "message": "auth material is represented only by redacted labels"
                },
                {
                    "name": "base_url_policy",
                    "passed": self.config.as_ref().is_none_or(|config| config.base_url == DEFAULT_BASE_URL || config.base_url.contains("127.0.0.1") || config.base_url.contains("localhost")),
                    "critical": true,
                    "message": "base_url is constrained to api.voyageai.com/v1, with loopback allowed for tests"
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
            message: "Voyage client not initialized".into(),
        })?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let cx = Cx::for_testing();
        match operation {
            OP_EMBEDDINGS => {
                let request =
                    embeddings_request_from_value(input, &config.default_embedding_model)?;
                client
                    .embeddings(&cx, request)
                    .await
                    .map(embedding_response_to_value)
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_MULTIMODAL => {
                let request =
                    multimodal_request_from_value(input, &config.default_multimodal_model)?;
                client
                    .multimodal_embeddings(&cx, request)
                    .await
                    .map(|raw| {
                        json!({
                            "object": raw.get("object").cloned().unwrap_or_else(|| json!("list")),
                            "model": raw.get("model").cloned(),
                            "data_count": raw.get("data").and_then(Value::as_array).map(Vec::len),
                            "raw": raw,
                        })
                    })
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_RERANK => {
                let request = rerank_request_from_value(input, &config.default_rerank_model)?;
                client
                    .rerank(&cx, request)
                    .await
                    .map(|raw| {
                        json!({
                            "object": raw.get("object").cloned().unwrap_or_else(|| json!("list")),
                            "model": raw.get("model").cloned(),
                            "result_count": raw.get("data").and_then(Value::as_array).map(Vec::len),
                            "raw": raw,
                        })
                    })
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_MODELS => {
                let models = client.list_models().await;
                Ok(json!({
                    "object": "list",
                    "data": models,
                    "source": "documented_static_catalog"
                }))
            }
            OP_HEALTH => {
                let models = client.list_models().await;
                Ok(json!({
                    "status": "ok",
                    "provider": "voyage",
                    "model_count": models.len(),
                    "default_embedding_model": config.default_embedding_model,
                    "default_multimodal_model": config.default_multimodal_model,
                    "default_rerank_model": config.default_rerank_model,
                    "base_url": config.base_url,
                }))
            }
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
            "allowed": is_supported_operation(operation),
            "reason": if is_supported_operation(operation) {
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

impl Default for VoyageConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(VoyageConnector);

#[fcp_core::async_trait]
impl FcpConnector for VoyageConnector {
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
            HealthSnapshot::degraded("voyage_handshake_pending")
        } else {
            HealthSnapshot::error("voyage_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.config.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Voyage connector is not configured",
            ));
        }
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.uses_host_credential_reference())
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
                streaming: false,
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
        if is_supported_operation(req.operation.as_str()) {
            Ok(SimulateResponse::allowed(req.id))
        } else {
            Ok(SimulateResponse::denied(
                req.id,
                "operation is not supported by Voyage",
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
            id: OperationId::from_static(OP_EMBEDDINGS),
            summary: "Create Voyage text embeddings".into(),
            description: Some("Uses Voyage POST /embeddings with retrieval-aware input_type support.".into()),
            input_schema: embeddings_schema(),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_EMBEDDINGS),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use for high-quality query/document embeddings for RAG.".into(),
                common_mistakes: vec!["Do not log input text or embedding vectors.".into()],
                examples: vec![r#"{"model":"voyage-3.5","input":"hello","input_type":"document"}"#.into()],
                related: vec![CapabilityId::from_static(CAP_RERANK)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MULTIMODAL),
            summary: "Create Voyage multimodal embeddings".into(),
            description: Some("Uses Voyage POST /multimodalembeddings for interleaved text/image inputs.".into()),
            input_schema: multimodal_schema(),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_EMBEDDINGS),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use for Voyage multimodal retrieval vectors.".into(),
                common_mistakes: vec!["Do not log image URLs, text, or vector contents.".into()],
                examples: vec![r#"{"inputs":[{"content":[{"type":"text","text":"chart"}]}],"input_type":"query"}"#.into()],
                related: vec![CapabilityId::from_static(CAP_EMBEDDINGS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RERANK),
            summary: "Rerank documents with Voyage".into(),
            description: Some("Uses Voyage POST /rerank with top_k and optional document return.".into()),
            input_schema: rerank_schema(),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_RERANK),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use after vector retrieval to refine candidate documents.".into(),
                common_mistakes: vec!["Do not log query or document content.".into()],
                examples: vec![r#"{"query":"q","documents":["d1","d2"],"top_k":1}"#.into()],
                related: vec![CapabilityId::from_static(CAP_EMBEDDINGS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MODELS),
            summary: "List documented Voyage models".into(),
            description: Some("Returns a conservative static catalog from current Voyage docs.".into()),
            input_schema: json!({ "type": "object", "properties": {} }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MODELS),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use before selecting a Voyage model id.".into(),
                common_mistakes: Vec::new(),
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_EMBEDDINGS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Probe Voyage connector health".into(),
            description: Some("Reports connector readiness and documented model catalog count.".into()),
            input_schema: json!({ "type": "object", "properties": {} }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_HEALTH),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use for a bounded readiness check before user-visible Voyage calls.".into(),
                common_mistakes: Vec::new(),
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_MODELS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fn embeddings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["input"],
        "properties": {
            "model": { "type": "string", "default": DEFAULT_EMBEDDING_MODEL },
            "input": {},
            "input_type": { "type": "string", "enum": ["query", "document"] },
            "truncation": { "type": "boolean" },
            "output_dimension": { "type": "integer", "enum": [256, 512, 1024, 2048] },
            "output_dtype": { "type": "string", "enum": ["float", "int8", "uint8", "binary", "ubinary"] },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn multimodal_schema() -> Value {
    json!({
        "type": "object",
        "required": ["inputs"],
        "properties": {
            "model": { "type": "string", "default": DEFAULT_MULTIMODAL_MODEL },
            "inputs": { "type": "array", "minItems": 1, "maxItems": 1000 },
            "input_type": { "type": "string", "enum": ["query", "document"] },
            "truncation": { "type": "boolean" },
            "output_encoding": { "type": "string", "enum": ["base64"] },
            "output_dimension": { "type": "integer", "enum": [256, 512, 1024, 2048] },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn rerank_schema() -> Value {
    json!({
        "type": "object",
        "required": ["query", "documents"],
        "properties": {
            "query": { "type": "string", "minLength": 1 },
            "documents": { "type": "array", "minItems": 1, "maxItems": 1000 },
            "model": { "type": "string", "default": DEFAULT_RERANK_MODEL },
            "top_k": { "type": "integer", "minimum": 1 },
            "return_documents": { "type": "boolean" },
            "truncation": { "type": "boolean" },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_EMBEDDINGS | OP_MULTIMODAL => Ok(CapabilityId::from_static(CAP_EMBEDDINGS)),
        OP_RERANK => Ok(CapabilityId::from_static(CAP_RERANK)),
        OP_MODELS => Ok(CapabilityId::from_static(CAP_MODELS)),
        OP_HEALTH => Ok(CapabilityId::from_static(CAP_HEALTH)),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn resource_uris_for_operation(operation: &str, input: &Value) -> Vec<String> {
    match operation {
        OP_EMBEDDINGS => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_EMBEDDING_MODEL);
            vec![format!("voyage:embedding-model:{model}")]
        }
        OP_MULTIMODAL => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_MULTIMODAL_MODEL);
            vec![format!("voyage:multimodal-model:{model}")]
        }
        OP_RERANK => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_RERANK_MODEL);
            vec![format!("voyage:rerank-model:{model}")]
        }
        OP_MODELS | OP_HEALTH => vec!["voyage:models".into()],
        _ => Vec::new(),
    }
}

fn optional_auth(params: &Value, field: &str) -> FcpResult<Option<String>> {
    params
        .get(field)
        .and_then(Value::as_str)
        .map(|value| validate_auth_material(field, value))
        .transpose()
        .map_err(invalid_config)
}

fn config_field(parts: &[&str]) -> String {
    parts.join("_")
}

fn build_auth(
    direct_bearer: Option<String>,
    credential_id: Option<String>,
) -> FcpResult<VoyageAuth> {
    match (direct_bearer, credential_id) {
        (Some(key), None) => Ok(VoyageAuth::ApiKey(key)),
        (None, Some(id)) => Ok(VoyageAuth::CredentialId(id)),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Provide exactly one Voyage auth mode".into(),
        }),
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

fn optional_string<'a>(params: &'a Value, field: &str) -> Option<&'a str> {
    params
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
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

fn is_supported_operation(operation: &str) -> bool {
    matches!(
        operation,
        OP_EMBEDDINGS | OP_MULTIMODAL | OP_RERANK | OP_MODELS | OP_HEALTH
    )
}

fn embedding_response_to_value(response: fcp_openai_compat::EmbeddingsResponse) -> Value {
    json!({
        "object": response.object,
        "model": response.model,
        "data": response.data,
        "usage": response.usage,
        "raw": response,
    })
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
        nonce: [59_u8; 32],
        capabilities_requested: capabilities,
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}
