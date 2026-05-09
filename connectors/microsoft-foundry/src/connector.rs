use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_async_core::Cx;
use fcp_openai_compat::{ChatMessage, RateLimitPolicy};
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
    DEFAULT_MODEL, MicrosoftFoundryAuth, MicrosoftFoundryClient, MicrosoftFoundryEndpointClass,
    MicrosoftFoundryProvider, auth_policy_from_str, normalize_microsoft_foundry_base_url,
    validate_auth_material,
};
use crate::error::openai_error_to_fcp;
use crate::types::{
    chat_request_from_value, embeddings_request_from_value, responses_request_from_value,
    summarize_responses_value,
};

pub const CONNECTOR_ID: &str = "fcp.microsoft-foundry";
pub const CONNECTOR_VERSION: &str = "0.1.0";

const OP_CHAT: &str = "microsoft_foundry.chat.completions";
const OP_CHAT_STREAM: &str = "microsoft_foundry.chat.completions_stream";
const OP_EMBEDDINGS: &str = "microsoft_foundry.embeddings.create";
const OP_MODELS: &str = "microsoft_foundry.deployments.list";
const OP_RESPONSES_CREATE: &str = "microsoft_foundry.responses.create";
const OP_RESPONSES_CANCEL: &str = "microsoft_foundry.responses.cancel";
const OP_RESPONSES_INPUT_ITEMS: &str = "microsoft_foundry.responses.input_items.list";
const OP_HEALTH: &str = "microsoft_foundry.health";

const CAP_CHAT: &str = "microsoft_foundry.chat";
const CAP_EMBEDDINGS: &str = "microsoft_foundry.embeddings";
const CAP_MODELS: &str = "microsoft_foundry.deployments.read";
const CAP_RESPONSES: &str = "microsoft_foundry.responses";
const CAP_HEALTH: &str = "microsoft_foundry.health";

#[derive(Debug, Clone)]
struct MicrosoftFoundryConfig {
    auth: MicrosoftFoundryAuth,
    base_url: String,
    endpoint_class: MicrosoftFoundryEndpointClass,
    host_hash: String,
    default_model: String,
    request_timeout: Duration,
    model_cache_ttl: Duration,
    rate_limit_policy: RateLimitPolicy,
}

impl MicrosoftFoundryConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let inline_key_material = params
            .get("api_key")
            .and_then(Value::as_str)
            .map(|value| validate_auth_material("api_key", value))
            .transpose()
            .map_err(invalid_config)?;
        let inline_bearer_material = params
            .get("entra_access_token")
            .or_else(|| params.get("access_token"))
            .and_then(Value::as_str)
            .map(|value| validate_auth_material("entra_access_token", value))
            .transpose()
            .map_err(invalid_config)?;
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(|value| validate_auth_material("credential_id", value))
            .transpose()
            .map_err(invalid_config)?;
        let credential_policy =
            auth_policy_from_str(params.get("credential_auth_policy").and_then(Value::as_str))
                .map_err(invalid_config)?;

        let auth = match (inline_key_material, inline_bearer_material, credential_id) {
            (Some(key), None, None) => MicrosoftFoundryAuth::ApiKey(key),
            (None, Some(token), None) => MicrosoftFoundryAuth::EntraBearer(token),
            (None, None, Some(id)) => MicrosoftFoundryAuth::CredentialId {
                id,
                policy: credential_policy,
            },
            (None, None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key, entra_access_token, or credential_id".into(),
                });
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key, entra_access_token, or credential_id"
                        .into(),
                });
            }
        };

        let endpoint =
            normalize_microsoft_foundry_base_url(params.get("base_url").and_then(Value::as_str))
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
            180_000,
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
            base_url: endpoint.base_url,
            endpoint_class: endpoint.endpoint_class,
            host_hash: endpoint.host_hash,
            default_model,
            request_timeout,
            model_cache_ttl,
            rate_limit_policy,
        })
    }

    fn build_client(&self) -> MicrosoftFoundryClient {
        MicrosoftFoundryClient::new(
            MicrosoftFoundryProvider::new(
                self.base_url.clone(),
                self.endpoint_class,
                self.auth.clone(),
            ),
            self.request_timeout,
            self.model_cache_ttl,
            self.rate_limit_policy,
        )
    }
}

pub struct MicrosoftFoundryConnector {
    base: Arc<BaseConnector>,
    config: Option<MicrosoftFoundryConfig>,
    client: Option<Arc<MicrosoftFoundryClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl MicrosoftFoundryConnector {
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
        let config = MicrosoftFoundryConfig::from_params(&params)?;
        let client = config.build_client();
        let auth_mode = config.auth.redacted_label();
        let endpoint_class = config.endpoint_class.as_str();
        let base_url = config.base_url.clone();
        let host_hash = config.host_hash.clone();
        let default_model = config.default_model.clone();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_mode, endpoint_class = %endpoint_class, host_hash = %host_hash, "Microsoft Foundry connector configured");
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "base_url": base_url,
            "endpoint_class": endpoint_class,
            "host_hash": host_hash,
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
            manifest_hash: "sha256:microsoft-foundry-connector-v1".into(),
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
            "endpoint_class": self.config.as_ref().map(|config| config.endpoint_class.as_str()),
            "host_hash": self.config.as_ref().map(|config| config.host_hash.clone()),
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
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with base_url plus api_key, entra_access_token, or credential_id.") }
                },
                {
                    "name": "auth_redaction",
                    "passed": self.config.as_ref().is_none_or(|config| !config.auth.redacted_label().contains("Bearer")),
                    "critical": true,
                    "message": "auth material is represented only by redacted labels"
                },
                {
                    "name": "endpoint_policy",
                    "passed": self.config.as_ref().is_none_or(|config| matches!(
                        config.endpoint_class,
                        MicrosoftFoundryEndpointClass::AzureOpenAi
                            | MicrosoftFoundryEndpointClass::FoundryServices
                            | MicrosoftFoundryEndpointClass::Loopback
                    )),
                    "critical": true,
                    "message": "base_url must end in /openai/v1 and use openai.azure.com or services.ai.azure.com unless loopback fixture mode is configured"
                },
                {
                    "name": "entra_scope",
                    "passed": true,
                    "critical": false,
                    "message": "Entra credential_id mode requests the https://ai.azure.com/.default token scope through host credential injection"
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
            message: "Microsoft Foundry client not initialized".into(),
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
            OP_EMBEDDINGS => {
                let request = embeddings_request_from_value(input, &config.default_model)?;
                client
                    .embeddings(&cx, request)
                    .await
                    .map(|response| {
                        json!({
                            "object": response.object,
                            "model": response.model,
                            "embedding_count": response.data.len(),
                            "dimensions": response.data.first().map_or(0, |item| item.embedding.len()),
                            "usage": response.usage,
                            "data": response.data,
                        })
                    })
                    .map_err(|err| openai_error_to_fcp(&err))
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
                    "endpoint_class": config.endpoint_class.as_str(),
                    "data": models,
                    "cache": "shared_in_memory"
                }))
            }
            OP_RESPONSES_CREATE => {
                let request = responses_request_from_value(input, &config.default_model)?;
                let raw = client
                    .responses_create(&cx, request)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                let summary = summarize_responses_value(&raw);
                Ok(json!({
                    "id": summary.id,
                    "model": summary.model,
                    "status": summary.status,
                    "output_text": summary.output_text,
                    "output_text_bytes": summary.output_text_bytes,
                    "usage": summary.usage,
                    "raw": raw,
                }))
            }
            OP_RESPONSES_CANCEL => {
                let response_id = input
                    .get("response_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1003,
                        message: "response_id is required".into(),
                    })?;
                client
                    .responses_cancel(&cx, response_id)
                    .await
                    .map(|raw| json!({ "raw": raw }))
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_RESPONSES_INPUT_ITEMS => {
                let response_id = input
                    .get("response_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1003,
                        message: "response_id is required".into(),
                    })?;
                client
                    .responses_input_items(&cx, response_id)
                    .await
                    .map(|raw| json!({ "raw": raw }))
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_HEALTH => {
                let models = client
                    .list_models(&cx)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                Ok(json!({
                    "status": "ok",
                    "provider": "microsoft_foundry",
                    "model_count": models.len(),
                    "default_model": config.default_model,
                    "endpoint_class": config.endpoint_class.as_str(),
                    "host_hash": config.host_hash,
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
            "allowed": supported_operation(operation),
            "reason": if supported_operation(operation) {
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

impl Default for MicrosoftFoundryConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(MicrosoftFoundryConnector);

#[fcp_core::async_trait]
impl FcpConnector for MicrosoftFoundryConnector {
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
            HealthSnapshot::degraded("microsoft_foundry_handshake_pending")
        } else {
            HealthSnapshot::error("microsoft_foundry_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = self.config.as_ref() else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Microsoft Foundry connector is not configured",
            ));
        };
        if config.auth.uses_host_credential_reference() {
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
        if supported_operation(req.operation.as_str()) {
            Ok(SimulateResponse::allowed(req.id))
        } else {
            Ok(SimulateResponse::denied(
                req.id,
                "operation is not supported by Microsoft Foundry",
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
        op_info(
            OP_RESPONSES_CREATE,
            "Create a Microsoft Foundry Responses API response",
            "Uses POST /responses. The request model field is the Azure deployment name.",
            responses_schema(),
            CAP_RESPONSES,
            RiskLevel::Medium,
            IdempotencyClass::None,
            "Use for Azure OpenAI deployments where Responses API features, background mode, or input item tracking are needed.",
        ),
        op_info(
            OP_RESPONSES_CANCEL,
            "Cancel a background Microsoft Foundry response",
            "Uses POST /responses/{response_id}/cancel for background Responses API work.",
            json!({ "type": "object", "required": ["response_id"], "properties": { "response_id": { "type": "string" } } }),
            CAP_RESPONSES,
            RiskLevel::Low,
            IdempotencyClass::BestEffort,
            "Use to stop a background Responses API job that is no longer needed.",
        ),
        op_info(
            OP_RESPONSES_INPUT_ITEMS,
            "List Microsoft Foundry response input items",
            "Uses GET /responses/{response_id}/input_items for Responses API diagnostics.",
            json!({ "type": "object", "required": ["response_id"], "properties": { "response_id": { "type": "string" } } }),
            CAP_RESPONSES,
            RiskLevel::Low,
            IdempotencyClass::Strict,
            "Use for redaction-aware diagnostics of a Responses API job without logging prompt bodies.",
        ),
        op_info(
            OP_CHAT,
            "Create a Microsoft Foundry chat completion",
            "Uses OpenAI-compatible POST /chat/completions via fcp-openai-compat.",
            chat_schema(false),
            CAP_CHAT,
            RiskLevel::Medium,
            IdempotencyClass::None,
            "Use for compatible Foundry deployments and third-party Foundry models that require chat completions.",
        ),
        op_info(
            OP_CHAT_STREAM,
            "Create a Microsoft Foundry streaming chat completion",
            "Uses OpenAI-compatible SSE chat streaming via fcp-openai-compat.",
            chat_schema(true),
            CAP_CHAT,
            RiskLevel::Medium,
            IdempotencyClass::None,
            "Use when the caller can consume incremental stream chunk metadata.",
        ),
        op_info(
            OP_EMBEDDINGS,
            "Create Microsoft Foundry embeddings",
            "Uses OpenAI-compatible POST /embeddings through a Foundry embeddings deployment.",
            embeddings_schema(),
            CAP_EMBEDDINGS,
            RiskLevel::Medium,
            IdempotencyClass::None,
            "Use only with a deployment that supports embeddings; do not route raw vectors into logs.",
        ),
        op_info(
            OP_MODELS,
            "List Microsoft Foundry deployments/models",
            "Uses GET /models; callers should treat returned IDs as deployment names.",
            json!({ "type": "object", "properties": { "refresh": { "type": "boolean" } } }),
            CAP_MODELS,
            RiskLevel::Low,
            IdempotencyClass::Strict,
            "Use to discover configured Foundry deployment IDs before invoking chat, responses, or embeddings.",
        ),
        op_info(
            OP_HEALTH,
            "Probe Microsoft Foundry health",
            "Performs a bounded deployment/model listing probe.",
            json!({ "type": "object", "properties": {} }),
            CAP_HEALTH,
            RiskLevel::Low,
            IdempotencyClass::Strict,
            "Use before dispatching user-visible Foundry work.",
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn op_info(
    id: &'static str,
    summary: &'static str,
    description: &'static str,
    input_schema: Value,
    capability: &'static str,
    risk_level: RiskLevel,
    idempotency: IdempotencyClass,
    when_to_use: &'static str,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(description.into()),
        input_schema,
        output_schema: json!({ "type": "object" }),
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier: SafetyTier::Safe,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: vec![
                "Do not log prompts, completions, embeddings, bearer tokens, API keys, tenant IDs, or full resource hostnames.".into(),
                "Use the deployment name in model; do not pass an Azure resource path.".into(),
            ],
            examples: vec![r#"{"model":"prod-gpt4o","input":[{"role":"user","content":"Hello"}]}"#.into()],
            related: vec![CapabilityId::from_static(capability)],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn chat_schema(streaming: bool) -> Value {
    json!({
        "type": "object",
        "required": ["messages"],
        "properties": {
            "model": { "type": "string", "default": DEFAULT_MODEL, "description": "Foundry deployment name" },
            "messages": { "type": "array", "minItems": 1 },
            "max_tokens": { "type": "integer", "minimum": 1 },
            "max_completion_tokens": { "type": "integer", "minimum": 1 },
            "temperature": { "type": "number", "minimum": 0, "maximum": 2 },
            "top_p": { "type": "number", "minimum": 0, "maximum": 1 },
            "stop": {},
            "response_format": { "type": "object" },
            "tools": { "type": "array" },
            "tool_choice": {},
            "reasoning_effort": { "type": "string" },
            "streaming_response": { "const": streaming },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn responses_schema() -> Value {
    json!({
        "type": "object",
        "required": ["input"],
        "properties": {
            "model": { "type": "string", "default": DEFAULT_MODEL, "description": "Foundry deployment name" },
            "input": {},
            "instructions": { "type": "string" },
            "include": { "type": "array", "items": { "type": "string" } },
            "tools": { "type": "array" },
            "tool_choice": {},
            "max_output_tokens": { "type": "integer", "minimum": 1 },
            "temperature": { "type": "number", "minimum": 0, "maximum": 2 },
            "top_p": { "type": "number", "minimum": 0, "maximum": 1 },
            "store": { "type": "boolean" },
            "background": { "type": "boolean" },
            "previous_response_id": { "type": "string" },
            "metadata": { "type": "object" },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn embeddings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["input"],
        "properties": {
            "model": { "type": "string", "description": "Foundry embeddings deployment name" },
            "input": {},
            "encoding_format": { "type": "string" },
            "dimensions": { "type": "integer", "minimum": 1 },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_CHAT | OP_CHAT_STREAM => Ok(CapabilityId::from_static(CAP_CHAT)),
        OP_EMBEDDINGS => Ok(CapabilityId::from_static(CAP_EMBEDDINGS)),
        OP_MODELS => Ok(CapabilityId::from_static(CAP_MODELS)),
        OP_RESPONSES_CREATE | OP_RESPONSES_CANCEL | OP_RESPONSES_INPUT_ITEMS => {
            Ok(CapabilityId::from_static(CAP_RESPONSES))
        }
        OP_HEALTH => Ok(CapabilityId::from_static(CAP_HEALTH)),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn resource_uris_for_operation(operation: &str, input: &Value) -> Vec<String> {
    match operation {
        OP_CHAT | OP_CHAT_STREAM | OP_EMBEDDINGS | OP_RESPONSES_CREATE => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_MODEL);
            vec![format!("microsoft_foundry:deployment:{model}")]
        }
        OP_RESPONSES_CANCEL | OP_RESPONSES_INPUT_ITEMS => input
            .get("response_id")
            .and_then(Value::as_str)
            .map(|id| vec![format!("microsoft_foundry:response:{id}")])
            .unwrap_or_default(),
        OP_MODELS | OP_HEALTH => vec!["microsoft_foundry:deployments".into()],
        _ => Vec::new(),
    }
}

fn supported_operation(operation: &str) -> bool {
    matches!(
        operation,
        OP_CHAT
            | OP_CHAT_STREAM
            | OP_EMBEDDINGS
            | OP_MODELS
            | OP_RESPONSES_CREATE
            | OP_RESPONSES_CANCEL
            | OP_RESPONSES_INPUT_ITEMS
            | OP_HEALTH
    )
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

async fn collect_stream_response(
    mut stream: fcp_openai_compat::ChatCompletionStream,
) -> FcpResult<Value> {
    let mut content = String::new();
    let mut finish_reason = None;
    let mut chunk_count = 0_u64;
    let mut tool_call_delta_count = 0_u64;
    let mut chunk_metadata = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| openai_error_to_fcp(&err))?;
        chunk_count += 1;
        for choice in &chunk.choices {
            if let Some(delta) = &choice.delta.content {
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
        }));
    }
    Ok(json!({
        "content": content,
        "finish_reason": finish_reason,
        "chunk_count": chunk_count,
        "tool_call_delta_count": tool_call_delta_count,
        "chunks": chunk_metadata,
    }))
}

fn chat_response_to_value(response: fcp_openai_compat::ChatCompletionsResponse) -> Value {
    let first = response.choices.first();
    json!({
        "id": response.id,
        "model": response.model,
        "content": first.and_then(|choice| assistant_content(&choice.message)),
        "finish_reason": first.and_then(|choice| choice.finish_reason.clone()),
        "usage": response.usage,
        "choice_count": response.choices.len(),
    })
}

fn assistant_content(message: &ChatMessage) -> Option<String> {
    match message {
        ChatMessage::Assistant { content, .. } => content.clone(),
        _ => None,
    }
}

fn health_status(configured: bool, handshaken: bool) -> &'static str {
    match (configured, handshaken) {
        (true, true) => "ok",
        (true, false) => "degraded",
        (false, _) => "unconfigured",
    }
}

#[must_use]
pub fn test_handshake_request(
    capabilities_requested: Vec<CapabilityId>,
    host_public_key: [u8; 32],
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [43_u8; 32],
        capabilities_requested,
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

#[must_use]
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
