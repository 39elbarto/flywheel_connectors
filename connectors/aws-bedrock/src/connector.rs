//! AWS Bedrock connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use crate::client::BedrockClient;
use crate::types::{BedrockAuth, ConverseInput, InvokeModelInput, ListModelsInput};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_CONVERSE: &str = "aws_bedrock.converse";
const OP_CONVERSE_STREAM: &str = "aws_bedrock.converse_stream";
const OP_INVOKE_MODEL: &str = "aws_bedrock.invoke_model";
const OP_INVOKE_MODEL_STREAM: &str = "aws_bedrock.invoke_model_stream";
const OP_MODELS_LIST: &str = "aws_bedrock.models.list";
const OP_HEALTH: &str = "aws_bedrock.health";

const CAP_CHAT: &str = "aws_bedrock.chat";
const CAP_MODELS_READ: &str = "aws_bedrock.models.read";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/aws_bedrock_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/aws_bedrock/<timestamp>";

const VERIFY_COMMANDS: [&str; 6] = [
    "scripts/e2e/aws_bedrock_connector_verification.sh",
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/aws-bedrock/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-aws-bedrock --all-targets",
    "rch exec -- cargo fmt -p fcp-aws-bedrock -- --check",
    "rch exec -- cargo test -p fcp-aws-bedrock --test integration -- --nocapture",
    "rch exec -- cargo clippy -p fcp-aws-bedrock --all-targets -- -D warnings",
];

#[derive(Clone, serde::Deserialize)]
pub struct BedrockConfig {
    pub region: String,
    #[serde(flatten)]
    pub auth: BedrockAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub runtime_base_url: Option<String>,
    #[serde(default)]
    pub control_base_url: Option<String>,
}

const fn default_timeout_ms() -> u64 {
    240_000
}

fn trim_optional_nonempty(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

impl std::fmt::Debug for BedrockConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BedrockConfig")
            .field("region", &self.region)
            .field("auth", &self.auth)
            .finish()
    }
}

impl BedrockConfig {
    fn normalize(&mut self) {
        self.region = self.region.trim().to_string();
        self.auth.access_key_id = self.auth.access_key_id.trim().to_string();
        self.auth.secret_access_key = self.auth.secret_access_key.trim().to_string();
        let optional_session = &mut self.auth.session_token; // ubs:ignore - caller-supplied optional credential slot
        *optional_session = trim_optional_nonempty(optional_session.take());
        normalize_endpoint_override(&mut self.runtime_base_url);
        normalize_endpoint_override(&mut self.control_base_url);
    }

    fn validate(&self) -> Result<(), String> {
        validate_region(&self.region)?;
        if self.auth.access_key_id.is_empty() {
            return Err("access_key_id is required".into());
        }
        if self.auth.secret_access_key.is_empty() {
            return Err("secret_access_key is required".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than 0".into());
        }
        if let Some(url) = &self.runtime_base_url {
            validate_endpoint_override(url, "runtime_base_url")?;
        }
        if let Some(url) = &self.control_base_url {
            validate_endpoint_override(url, "control_base_url")?;
        }
        Ok(())
    }

    fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {error}"),
            })?;
        config.normalize();
        config
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1001,
                message,
            })?;
        Ok(config)
    }

    fn auth_mode(&self) -> &'static str {
        if self.auth.session_token.is_some() {
            "static_keys_with_session_token"
        } else {
            "static_keys"
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        ProvisioningReadiness {
            region: self.region.clone(),
            auth_mode: self.auth_mode(),
            request_timeout_ms: self.request_timeout_ms,
            runtime_base_url: self.runtime_base_url.clone(),
            control_base_url: self.control_base_url.clone(),
            default_control_plane_would_touch_aws: self.control_base_url.is_none(),
            aws_sigv4_supported: true,
            event_stream_decoder_supported: true,
        }
    }
}

fn validate_region(region: &str) -> Result<(), String> {
    if region.is_empty() {
        return Err("region is required".into());
    }
    if !region
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("region must contain only lowercase ASCII letters, digits, and '-'".into());
    }
    if region.contains("..") || region.starts_with('-') || region.ends_with('-') {
        return Err("region is not a valid AWS region name".into());
    }
    Ok(())
}

fn normalize_endpoint_override(url: &mut Option<String>) {
    *url = url.take().and_then(|value| {
        let trimmed = value.trim().trim_end_matches('/').to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host.ends_with(".localhost")
}

fn validate_endpoint_override(url: &str, label: &str) -> Result<(), String> {
    let parsed =
        Url::parse(url).map_err(|error| format!("{label} must be a valid URL: {error}"))?;
    let Some(host) = parsed.host_str() else {
        return Err(format!("{label} must include a host"));
    };
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_local_test_host(host)) {
        return Err(format!(
            "{label} must use https unless it targets localhost for verification"
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!("{label} must not include embedded credentials"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "{label} must not include a query string or fragment"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvisioningReadiness {
    region: String,
    auth_mode: &'static str,
    request_timeout_ms: u64,
    runtime_base_url: Option<String>,
    control_base_url: Option<String>,
    default_control_plane_would_touch_aws: bool,
    aws_sigv4_supported: bool,
    event_stream_decoder_supported: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Provision Bedrock Runtime credentials scoped to bedrock:InvokeModel, bedrock:InvokeModelWithResponseStream, and bedrock:ListFoundationModels for the intended region.",
            "Use runtime_base_url and control_base_url overrides for deterministic wiremock or signing-proxy verification.",
            "Set AWS_BEDROCK_E2E=1 only in a disposable verification account with cheapest-model smoke settings.",
        ],
        redaction_rules: vec![
            "Never log prompts, completions, AWS keys, session tokens, or full SigV4 signatures.",
            "Only emit model ids, body sizes, token counts, stream chunk counts, HTTP status, and signature prefix hashes in verification artifacts.",
        ],
        limitations: vec![
            "Model ARNs with slash path components are intentionally rejected until the shared SigV4 path canonicalizer supports encoded path parameters without double-encoding.",
            "Bedrock Agents and Knowledge Bases are outside this connector bead.",
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
    verification_script: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let ready = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        Self {
            ready,
            passed: ready,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }
}

#[derive(Debug)]
pub struct BedrockConnector {
    base: BaseConnector,
    config: Option<BedrockConfig>,
    client: Option<BedrockClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl BedrockConnector {
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.aws-bedrock")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    pub fn instance_id(&self) -> &fcp_prelude::InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self
            .config
            .as_ref()
            .map(BedrockConfig::provisioning_readiness);
        let mut checks = vec![
            DoctorCheck {
                name: "configuration".into(),
                passed: self.config.is_some(),
                message: Some(if self.config.is_some() {
                    "Configuration loaded".into()
                } else {
                    "Not configured; run configure before handshake or invoke".into()
                }),
                critical: true,
            },
            DoctorCheck {
                name: "client".into(),
                passed: self.client.is_some(),
                message: Some(if self.client.is_some() {
                    "Client initialized".into()
                } else {
                    "Client not initialized; re-run configure".into()
                }),
                critical: true,
            },
            DoctorCheck {
                name: "runtime".into(),
                passed: self.runtime.is_some(),
                message: Some(if self.runtime.is_some() {
                    "Runtime initialized".into()
                } else {
                    "Runtime not initialized; re-run configure".into()
                }),
                critical: true,
            },
        ];
        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "request_signing".into(),
                passed: readiness.aws_sigv4_supported,
                message: Some(
                    "SigV4 signing is active for Bedrock Runtime and control-plane calls".into(),
                ),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "event_stream_decoder".into(),
                passed: readiness.event_stream_decoder_supported,
                message: Some("AWS event-stream decoder validates prelude and message CRCs".into()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "deterministic_control_plane".into(),
                passed: !readiness.default_control_plane_would_touch_aws,
                message: Some(if readiness.default_control_plane_would_touch_aws {
                    "Self-check abstains on the default control-plane endpoint to avoid touching production AWS".into()
                } else {
                    "Self-check can use the configured control_base_url verification endpoint".into()
                }),
                critical: false,
            });
        }
        DoctorResult::from_checks(checks, provisioning)
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        provisioning: Option<ProvisioningReadiness>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
        }));
        report
    }
}

impl Default for BedrockConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_CONVERSE | OP_CONVERSE_STREAM | OP_INVOKE_MODEL | OP_INVOKE_MODEL_STREAM => {
            CapabilityId::from_static(CAP_CHAT)
        }
        OP_MODELS_LIST | OP_HEALTH => CapabilityId::from_static(CAP_MODELS_READ),
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };
    Ok(capability)
}

fn operation_info(
    id: &'static str,
    summary: &'static str,
    capability: &'static str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level: if safety_tier == SafetyTier::Safe {
            RiskLevel::Low
        } else {
            RiskLevel::Medium
        },
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: summary.into(),
            common_mistakes: vec![
                "Do not log prompts, completions, AWS credentials, session tokens, or full signatures".into(),
            ],
            examples: Vec::new(),
            related: vec![CapabilityId::from_static(capability)],
        },
        rate_limit: None,
        requires_approval: None,
    }
}

fn operations_info() -> Vec<OperationInfo> {
    vec![
        operation_info(
            OP_CONVERSE,
            "Invoke Bedrock Converse",
            CAP_CHAT,
            json!({"type":"object","required":["model_id","messages"]}),
            json!({"type":"object"}),
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        operation_info(
            OP_CONVERSE_STREAM,
            "Invoke Bedrock ConverseStream",
            CAP_CHAT,
            json!({"type":"object","required":["model_id","messages"]}),
            json!({"type":"object"}),
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        operation_info(
            OP_INVOKE_MODEL,
            "Invoke legacy Bedrock InvokeModel",
            CAP_CHAT,
            json!({"type":"object","required":["model_id"]}),
            json!({"type":"object"}),
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        operation_info(
            OP_INVOKE_MODEL_STREAM,
            "Invoke legacy Bedrock InvokeModelWithResponseStream",
            CAP_CHAT,
            json!({"type":"object","required":["model_id"]}),
            json!({"type":"object"}),
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        operation_info(
            OP_MODELS_LIST,
            "List Bedrock foundation models",
            CAP_MODELS_READ,
            json!({"type":"object"}),
            json!({"type":"object"}),
            SafetyTier::Safe,
            IdempotencyClass::None,
        ),
        operation_info(
            OP_HEALTH,
            "Check Bedrock connector health",
            CAP_MODELS_READ,
            json!({"type":"object"}),
            json!({"type":"object"}),
            SafetyTier::Safe,
            IdempotencyClass::None,
        ),
    ]
}

fcp_core::impl_fcp_sealed!(BedrockConnector);

#[async_trait]
impl FcpConnector for BedrockConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = BedrockConfig::from_value(config)?;
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        ));
        let client = BedrockClient::new(
            cfg.auth.clone(),
            &cfg.region,
            cfg.retry.clone(),
            cfg.request_timeout_ms,
            cfg.runtime_base_url.clone(),
            cfg.control_base_url.clone(),
        )
        .await
        .map_err(|error| FcpError::Internal {
            message: format!("Client init: {error}"),
        })?;
        self.client = Some(client);
        self.config = Some(cfg);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if !self.base.configured.load(Ordering::Acquire) {
            return Err(FcpError::NotConfigured);
        }
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
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
    }

    async fn health(&self) -> HealthSnapshot {
        let provisioning = self
            .config
            .as_ref()
            .map(BedrockConfig::provisioning_readiness);
        let mut snapshot = match &provisioning {
            None => HealthSnapshot::degraded("not configured"),
            Some(_) if self.client.is_none() => HealthSnapshot::error("client not initialized"),
            Some(_) if self.runtime.is_none() => HealthSnapshot::error("runtime not initialized"),
            Some(readiness) if readiness.default_control_plane_would_touch_aws => {
                HealthSnapshot::degraded(
                    "default Bedrock endpoints configured; self_check abstains from production AWS",
                )
            }
            Some(_) => HealthSnapshot::ready(),
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };
        let provisioning = config.provisioning_readiness();
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed(
                    "client_missing",
                    "Bedrock HTTP client not initialized; re-run configure",
                ),
                Some(provisioning),
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed(
                    "runtime_missing",
                    "ConnectorRuntime not initialized; re-run configure",
                ),
                Some(provisioning),
            ));
        };
        if config.control_base_url.is_none() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded(
                    "self_check_unsupported_on_default_bedrock",
                    "self_check abstains against the default Bedrock control-plane endpoint to avoid hitting production with operator credentials; set control_base_url to a staging endpoint or wiremock verifier",
                ),
                Some(provisioning),
            ));
        }
        let report = match client.health_check(runtime).await {
            Ok(status) if status.control_plane_reachable => SelfCheckReport::ok(),
            Ok(_) => SelfCheckReport::degraded(
                "bedrock_unreachable",
                "Control-plane endpoint returned an unauthenticated result",
            ),
            Err(error) if error.is_retryable() => {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            }
            Err(error) => SelfCheckReport::failed("self_check_failed", error.to_string()),
        };
        Ok(self.attach_self_check_details(report, Some(provisioning)))
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
        if self.client.is_none() || self.runtime.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector has not completed handshake",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])
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

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.runtime = None;
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
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
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl BedrockConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        let capability = required_capability(operation)?;
        let Some(verifier) = &self.verifier else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        };
        verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Bedrock client".into(),
        })?;

        let output = match operation {
            OP_CONVERSE => {
                let input: ConverseInput =
                    serde_json::from_value(req.input.clone()).map_err(invalid_invoke_input)?;
                client
                    .converse(runtime, &input)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_CONVERSE_STREAM => {
                let input: ConverseInput =
                    serde_json::from_value(req.input.clone()).map_err(invalid_invoke_input)?;
                serde_json::to_value(
                    client
                        .converse_stream(runtime, &input)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
                .map_err(serialize_error)?
            }
            OP_INVOKE_MODEL => {
                let input: InvokeModelInput =
                    serde_json::from_value(req.input.clone()).map_err(invalid_invoke_input)?;
                client
                    .invoke_model(runtime, &input)
                    .await
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_INVOKE_MODEL_STREAM => {
                let input: InvokeModelInput =
                    serde_json::from_value(req.input.clone()).map_err(invalid_invoke_input)?;
                serde_json::to_value(
                    client
                        .invoke_model_stream(runtime, &input)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
                .map_err(serialize_error)?
            }
            OP_MODELS_LIST => {
                let input: ListModelsInput =
                    serde_json::from_value(req.input.clone()).map_err(invalid_invoke_input)?;
                serde_json::to_value(
                    client
                        .list_models(runtime, &input)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
                .map_err(serialize_error)?
            }
            OP_HEALTH => serde_json::to_value(
                client
                    .health_check(runtime)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(serialize_error)?,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

fn invalid_invoke_input(error: serde_json::Error) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid invoke input: {error}"),
    }
}

fn serialize_error(error: serde_json::Error) -> FcpError {
    FcpError::Internal {
        message: format!("Failed to serialize response: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_validation_rejects_injection() {
        assert!(validate_region("us-east-1").is_ok());
        assert!(validate_region("US-EAST-1").is_err());
        assert!(validate_region("../us-east-1").is_err());
    }

    #[test]
    fn introspection_has_required_operations() {
        let connector = BedrockConnector::new();
        let operations = connector.introspect().operations;
        let ids = operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(operations.len(), 6);
        assert!(ids.contains(&OP_CONVERSE));
        assert!(ids.contains(&OP_CONVERSE_STREAM));
        assert!(ids.contains(&OP_INVOKE_MODEL));
        assert!(ids.contains(&OP_INVOKE_MODEL_STREAM));
        assert!(ids.contains(&OP_MODELS_LIST));
        assert!(ids.contains(&OP_HEALTH));
    }
}
