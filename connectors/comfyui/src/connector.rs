use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fcp_async_core::time;
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
    ComfyUiAuth, ComfyUiClient, ComfyUiUrlPolicy, classify_comfyui_base_url,
    normalize_comfyui_base_url, validate_auth_material,
};
use crate::types::{CancelInput, PromptIdInput, SubmitWorkflowInput, WaitInput};

pub const CONNECTOR_ID: &str = "fcp.comfyui";
pub const CONNECTOR_VERSION: &str = "0.1.0";

const OP_SUBMIT: &str = "comfyui.workflow.submit";
const OP_STATUS: &str = "comfyui.workflow.status";
const OP_RESULT: &str = "comfyui.workflow.result";
const OP_CANCEL: &str = "comfyui.workflow.cancel";
const OP_WAIT: &str = "comfyui.workflow.wait_until_complete";
const OP_HEALTH: &str = "comfyui.health";

const CAP_WORKFLOW_RUN: &str = "comfyui.workflow.run";
const CAP_WORKFLOW_READ: &str = "comfyui.workflow.read";
const CAP_HEALTH: &str = "comfyui.health.read";

#[derive(Debug, Clone)]
struct ComfyUiConfig {
    auth: ComfyUiAuth,
    base_url: String,
    base_url_class: &'static str,
    request_timeout: Duration,
    default_wait_timeout: Duration,
    default_poll_interval: Duration,
    tailnet_only: bool,
    allowed_hosts: Vec<String>,
    allow_private_ranges: bool,
    allow_tailnet_ranges: bool,
    default_client_id: String,
}

impl ComfyUiConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let inline_bearer_header = params
            .get("api_key")
            .and_then(Value::as_str)
            .map(|value| {
                validate_auth_material("api_key", value).map(|key| format!("Bearer {key}"))
            })
            .transpose()
            .map_err(invalid_config)?;
        let authorization_header = params
            .get("authorization_header")
            .and_then(Value::as_str)
            .map(|value| validate_auth_material("authorization_header", value))
            .transpose()
            .map_err(invalid_config)?;
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(|value| validate_auth_material("credential_id", value))
            .transpose()
            .map_err(invalid_config)?;
        let auth = match (inline_bearer_header, authorization_header, credential_id) {
            (None, None, None) => ComfyUiAuth::None,
            (Some(header), None, None) | (None, Some(header), None) => {
                ComfyUiAuth::AuthorizationHeader(header)
            }
            (None, None, Some(id)) => ComfyUiAuth::CredentialId(id),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "Provide at most one of api_key, authorization_header, or credential_id"
                            .into(),
                });
            }
        };

        let allowed_hosts = parse_allowed_hosts(params)?;
        let tailnet_only = params
            .get("tailnet_only")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let allow_private_ranges = params
            .get("allow_private_ranges")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let allow_tailnet_ranges = params
            .get("allow_tailnet_ranges")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let url_policy = ComfyUiUrlPolicy::new(
            tailnet_only,
            allowed_hosts.clone(),
            allow_private_ranges,
            allow_tailnet_ranges,
        );
        let base_url =
            normalize_comfyui_base_url(params.get("base_url").and_then(Value::as_str), &url_policy)
                .map_err(invalid_config)?;
        let base_url_class = classify_comfyui_base_url(&base_url);
        let request_timeout = Duration::from_millis(optional_positive_u64(
            params,
            "request_timeout_ms",
            300_000,
        )?);
        let default_wait_timeout =
            Duration::from_millis(optional_positive_u64(params, "wait_timeout_ms", 600_000)?);
        let default_poll_interval =
            Duration::from_millis(optional_positive_u64(params, "poll_interval_ms", 1000)?);
        let default_client_id = params
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or("fcp-comfyui")
            .to_string();

        Ok(Self {
            auth,
            base_url,
            base_url_class,
            request_timeout,
            default_wait_timeout,
            default_poll_interval,
            tailnet_only,
            allowed_hosts,
            allow_private_ranges,
            allow_tailnet_ranges,
            default_client_id,
        })
    }

    fn build_client(&self) -> Result<ComfyUiClient, FcpError> {
        ComfyUiClient::new(
            self.auth.clone(),
            self.base_url.clone(),
            self.request_timeout,
        )
        .map_err(|error| error.to_fcp_error())
    }
}

pub struct ComfyUiConnector {
    base: Arc<BaseConnector>,
    config: Option<ComfyUiConfig>,
    client: Option<Arc<ComfyUiClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl ComfyUiConnector {
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

    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = ComfyUiConfig::from_params(&params)?;
        let client = config.build_client()?;
        let auth_mode = config.auth.redacted_label();
        let base_url_class = config.base_url_class;
        let tailnet_only = config.tailnet_only;
        let allowed_hosts_count = config.allowed_hosts.len();
        let allow_private_ranges = config.allow_private_ranges;
        let allow_tailnet_ranges = config.allow_tailnet_ranges;
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(
            auth = %auth_mode,
            base_url_class = %base_url_class,
            "ComfyUI connector configured"
        );
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "base_url_class": base_url_class,
            "tailnet_only": tailnet_only,
            "allowed_hosts_count": allowed_hosts_count,
            "allow_private_ranges": allow_private_ranges,
            "allow_tailnet_ranges": allow_tailnet_ranges,
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
            manifest_hash: "sha256:comfyui-connector-v1".into(),
            nonce: req.nonce,
            event_caps: None,
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
            "base_url_class": self.config.as_ref().map(|config| config.base_url_class),
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
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with base_url and any optional auth material.") }
                },
                {
                    "name": "self_hosted_allowlist",
                    "passed": self.config.as_ref().is_none_or(|config| {
                        config.base_url_class == "loopback"
                            || !config.allowed_hosts.is_empty()
                    }),
                    "critical": true,
                    "message": "loopback is allowed by default; every non-loopback ComfyUI endpoint must be listed in allowed_hosts, with private/tailnet opt-in flags as needed"
                },
                {
                    "name": "workflow_redaction",
                    "passed": true,
                    "critical": true,
                    "message": "workflow JSON, prompt text, full output URLs, and auth material are not logged by connector code"
                },
                {
                    "name": "websocket_surface",
                    "passed": true,
                    "critical": false,
                    "message": "WebSocket progress is intentionally deferred; REST polling is the default path"
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
            message: "ComfyUI client not initialized".into(),
        })?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        match operation {
            OP_SUBMIT => {
                let input = SubmitWorkflowInput::parse(input, &config.default_client_id)?;
                client
                    .submit_workflow(&input)
                    .await
                    .map(|response| {
                        json!({
                            "prompt_id": response.prompt_id,
                            "number": response.number,
                            "node_errors": response.node_errors,
                            "base_url_class": config.base_url_class,
                        })
                    })
                    .map_err(|error| error.to_fcp_error())
            }
            OP_STATUS => {
                let input = PromptIdInput::parse(input)?;
                client
                    .workflow_status(&input.prompt_id)
                    .await
                    .map_err(|error| error.to_fcp_error())
            }
            OP_RESULT => {
                let input = PromptIdInput::parse(input)?;
                client
                    .workflow_result(&input.prompt_id)
                    .await
                    .map_err(|error| error.to_fcp_error())
            }
            OP_CANCEL => {
                let input = CancelInput::parse(input)?;
                client
                    .cancel_workflow(&input.prompt_id, input.interrupt_running)
                    .await
                    .map_err(|error| error.to_fcp_error())
            }
            OP_WAIT => {
                let input = WaitInput::parse(input)?;
                self.wait_until_complete(client, config, input).await
            }
            OP_HEALTH => client.health().await.map_err(|error| error.to_fcp_error()),
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    async fn wait_until_complete(
        &self,
        client: &ComfyUiClient,
        config: &ComfyUiConfig,
        input: WaitInput,
    ) -> FcpResult<Value> {
        let timeout = input
            .timeout_ms
            .map_or(config.default_wait_timeout, Duration::from_millis);
        let poll_interval = input
            .poll_interval_ms
            .map_or(config.default_poll_interval, Duration::from_millis);
        let started = Instant::now();
        let mut poll_count = 0_u64;
        loop {
            poll_count += 1;
            let status = client
                .workflow_status(&input.prompt_id)
                .await
                .map_err(|error| error.to_fcp_error())?;
            if status
                .get("complete")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let result = client
                    .workflow_result(&input.prompt_id)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                return Ok(json!({
                    "prompt_id": input.prompt_id,
                    "complete": true,
                    "poll_count": poll_count,
                    "elapsed_ms": elapsed_millis(started),
                    "result": result,
                }));
            }
            if started.elapsed() >= timeout {
                return Err(FcpError::UpstreamTimeout {
                    service: "comfyui".into(),
                });
            }
            time::sleep(poll_interval).await;
        }
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");
        Ok(json!({
            "allowed": is_supported_runtime_operation(operation),
            "reason": if is_supported_runtime_operation(operation) {
                "Supported REST operation."
            } else {
                "Unknown operation or WebSocket progress operation deferred."
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

impl Default for ComfyUiConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(ComfyUiConnector);

#[fcp_core::async_trait]
impl FcpConnector for ComfyUiConnector {
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
            HealthSnapshot::degraded("comfyui_handshake_pending")
        } else {
            HealthSnapshot::error("comfyui_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.config.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "ComfyUI connector is not configured",
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
        if is_supported_runtime_operation(req.operation.as_str()) {
            Ok(SimulateResponse::allowed(req.id))
        } else {
            Ok(SimulateResponse::denied(
                req.id,
                "operation is not supported by ComfyUI REST connector",
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
            id: OperationId::from_static(OP_SUBMIT),
            summary: "Submit a ComfyUI workflow".into(),
            description: Some("Posts pass-through workflow JSON to ComfyUI POST /prompt and returns prompt_id without logging workflow content.".into()),
            input_schema: submit_schema(),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_WORKFLOW_RUN),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use to queue an operator-authored ComfyUI workflow on a configured self-hosted server.".into(),
                common_mistakes: vec![
                    "Do not log workflow JSON, prompts, seeds, or input URLs.".into(),
                    "Non-loopback endpoints require explicit allowed_hosts and private/tailnet opt-in where applicable.".into(),
                    "The connector does not validate workflow graph structure.".into(),
                ],
                examples: vec![r#"{"workflow":{"3":{"class_type":"KSampler","inputs":{}}}}"#.into()],
                related: vec![CapabilityId::from_static(CAP_WORKFLOW_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_STATUS),
            summary: "Read ComfyUI workflow status".into(),
            description: Some("Polls GET /history/{prompt_id}; completion is true once history contains the prompt id.".into()),
            input_schema: prompt_id_schema(),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_WORKFLOW_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to poll a queued workflow without fetching output bytes.".into(),
                common_mistakes: vec!["Do not infer image bytes are proxied; result returns /view URLs only.".into()],
                examples: vec![r#"{"prompt_id":"prompt-123"}"#.into()],
                related: vec![CapabilityId::from_static(CAP_WORKFLOW_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RESULT),
            summary: "Return ComfyUI output URLs".into(),
            description: Some("Builds redaction-aware /view URLs from GET /history/{prompt_id}; image bytes are not proxied.".into()),
            input_schema: prompt_id_schema(),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_WORKFLOW_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use after status complete to get artifact metadata and ComfyUI /view URLs.".into(),
                common_mistakes: vec!["Do not log full artifact URLs; evidence should include host class and hashes only.".into()],
                examples: vec![r#"{"prompt_id":"prompt-123"}"#.into()],
                related: vec![CapabilityId::from_static(CAP_WORKFLOW_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CANCEL),
            summary: "Cancel a ComfyUI workflow".into(),
            description: Some("Posts delete request to /queue and can optionally call /interrupt for currently executing workflows.".into()),
            input_schema: json!({ "type": "object", "required": ["prompt_id"], "properties": { "prompt_id": { "type": "string" }, "interrupt_running": { "type": "boolean", "default": false } } }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_WORKFLOW_RUN),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to remove a pending workflow from the queue or explicitly interrupt a running workflow.".into(),
                common_mistakes: vec!["Do not call interrupt_running=true unless the operator intends to stop the active ComfyUI execution.".into()],
                examples: vec![r#"{"prompt_id":"prompt-123","interrupt_running":false}"#.into()],
                related: vec![CapabilityId::from_static(CAP_WORKFLOW_RUN)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WAIT),
            summary: "Wait for ComfyUI workflow completion".into(),
            description: Some("Performs bounded REST polling and returns output URL metadata when history is available.".into()),
            input_schema: json!({ "type": "object", "required": ["prompt_id"], "properties": { "prompt_id": { "type": "string" }, "timeout_ms": { "type": "integer", "minimum": 1 }, "poll_interval_ms": { "type": "integer", "minimum": 1, "maximum": 60000 } } }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_WORKFLOW_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use when the caller explicitly wants connector-side bounded polling.".into(),
                common_mistakes: vec!["Set an explicit timeout for slow workflows; default is ten minutes.".into()],
                examples: vec![r#"{"prompt_id":"prompt-123","timeout_ms":60000}"#.into()],
                related: vec![CapabilityId::from_static(CAP_WORKFLOW_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Probe ComfyUI server health".into(),
            description: Some("Calls GET /system_stats and returns redaction-safe endpoint class metadata.".into()),
            input_schema: json!({ "type": "object", "properties": {} }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_HEALTH),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use for a bounded readiness check before workflow submission.".into(),
                common_mistakes: vec!["Unauthenticated health is normal for default local ComfyUI deployments.".into()],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_HEALTH)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fn submit_schema() -> Value {
    json!({
        "type": "object",
        "required": ["workflow"],
        "properties": {
            "workflow": { "type": "object" },
            "prompt": { "type": "object" },
            "client_id": { "type": "string" }
        }
    })
}

fn prompt_id_schema() -> Value {
    json!({
        "type": "object",
        "required": ["prompt_id"],
        "properties": { "prompt_id": { "type": "string" } }
    })
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_SUBMIT | OP_CANCEL => Ok(CapabilityId::from_static(CAP_WORKFLOW_RUN)),
        OP_STATUS | OP_RESULT | OP_WAIT => Ok(CapabilityId::from_static(CAP_WORKFLOW_READ)),
        OP_HEALTH => Ok(CapabilityId::from_static(CAP_HEALTH)),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn resource_uris_for_operation(operation: &str, input: &Value) -> Vec<String> {
    match operation {
        OP_SUBMIT => vec!["comfyui:workflow:submit".into()],
        OP_STATUS | OP_RESULT | OP_CANCEL | OP_WAIT => input
            .get("prompt_id")
            .and_then(Value::as_str)
            .map_or_else(Vec::new, |prompt_id| {
                vec![format!("comfyui:prompt:{prompt_id}")]
            }),
        OP_HEALTH => vec!["comfyui:health".into()],
        _ => Vec::new(),
    }
}

fn is_supported_runtime_operation(operation: &str) -> bool {
    matches!(
        operation,
        OP_SUBMIT | OP_STATUS | OP_RESULT | OP_CANCEL | OP_WAIT | OP_HEALTH
    )
}

fn parse_allowed_hosts(params: &Value) -> FcpResult<Vec<String>> {
    let Some(value) = params.get("allowed_hosts") else {
        return Ok(Vec::new());
    };
    let hosts = value
        .as_array()
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "allowed_hosts must be an array of host names".into(),
        })?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "allowed_hosts entries must be strings".into(),
                })
        })
        .collect::<FcpResult<Vec<_>>>()?;
    Ok(hosts)
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

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

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
        nonce: [47_u8; 32],
        capabilities_requested: capabilities,
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}
