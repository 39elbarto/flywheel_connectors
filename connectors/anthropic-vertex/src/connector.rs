//! Anthropic Claude on Google Vertex AI connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_google_discovery::auth::{
    GoogleAuthError, GoogleAuthSelection, GoogleAuthSourceKind, GoogleMaterializedAuth,
};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::client::{AnthropicVertexClient, VertexClientConfig};
use crate::types::{
    CLOUD_PLATFORM_SCOPE, DEFAULT_LOCATION, auth_policy_report, catalog_entry, model_catalog,
    normalize_model_id, validate_location, validate_path_component,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

pub const OP_MESSAGES_CREATE: &str = "anthropic_vertex.messages.create";
pub const OP_MESSAGES_STREAM: &str = "anthropic_vertex.messages.stream";
pub const OP_MODELS_NORMALIZE: &str = "anthropic_vertex.models.normalize";
pub const OP_HEALTH: &str = "anthropic_vertex.health";

const CAP_MESSAGES: &str = "anthropic_vertex.messages";
const CAP_MODELS_READ: &str = "anthropic_vertex.models.read";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/anthropic_vertex_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/anthropic_vertex/<timestamp>";

const VERIFY_COMMANDS: [&str; 5] = [
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/anthropic-vertex/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-anthropic-vertex --all-targets",
    "rch exec -- cargo fmt -p fcp-anthropic-vertex -- --check",
    "rch exec -- cargo test -p fcp-anthropic-vertex --test integration -- --nocapture",
    "rch exec -- cargo clippy -p fcp-anthropic-vertex --all-targets -- -D warnings",
];

#[derive(Clone, serde::Deserialize)]
struct VertexConfigParams {
    project_id: String,
    #[serde(default, alias = "region")]
    location: Option<String>,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    request_timeout_ms: u64,
    #[serde(default)]
    base_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VertexConfig {
    project_id: String,
    location: String,
    auth: GoogleMaterializedAuth,
    auth_source: GoogleAuthSourceKind,
    retry: HttpRetryConfig,
    request_timeout_ms: u64,
    base_url: Option<String>,
}

const fn default_timeout_ms() -> u64 {
    240_000
}

fn trim_optional_nonempty(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim().trim_end_matches('/').to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

impl VertexConfig {
    async fn from_value(value: Value) -> FcpResult<Self> {
        let params: VertexConfigParams =
            serde_json::from_value(value.clone()).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {error}"),
            })?;
        let project_id = validate_path_component(&params.project_id, "project_id")
            .map_err(|error| error.to_fcp_error())?;
        let location = validate_location(params.location.as_deref().unwrap_or(DEFAULT_LOCATION))
            .map_err(|error| error.to_fcp_error())?;
        if params.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than 0".into(),
            });
        }

        let base_url = trim_optional_nonempty(params.base_url);
        if let Some(base_url) = base_url.as_deref() {
            validate_base_url(base_url)?;
        }

        let mut auth_params = value;
        let object = auth_params
            .as_object_mut()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: "configure params must be a JSON object".into(),
            })?;
        object.insert("required_scopes".to_string(), json!([CLOUD_PLATFORM_SCOPE]));
        let selection = GoogleAuthSelection::from_connector_config(&auth_params)
            .map_err(|error| map_auth_error(&error))?;
        let auth_source = selection.source_kind();
        let auth = selection
            .materialize()
            .await
            .map_err(|error| map_auth_error(&error))?;

        Ok(Self {
            project_id,
            location,
            auth,
            auth_source,
            retry: params.retry,
            request_timeout_ms: params.request_timeout_ms,
            base_url,
        })
    }

    fn client_config(&self) -> VertexClientConfig {
        VertexClientConfig {
            project_id: self.project_id.clone(),
            location: self.location.clone(),
            auth: self.auth.clone(),
            retry_config: self.retry.clone(),
            request_timeout_ms: self.request_timeout_ms,
            base_url: self.base_url.clone(),
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        ProvisioningReadiness {
            project_id: self.project_id.clone(),
            location: self.location.clone(),
            auth_mode: auth_label_for_materialized(&self.auth),
            auth_source: self.auth_source.to_string(),
            request_timeout_ms: self.request_timeout_ms,
            base_url: self.base_url.clone(),
            default_endpoint_would_touch_vertex: self.base_url.is_none(),
            credential_injection_required: matches!(
                self.auth,
                GoogleMaterializedAuth::CredentialReference { .. }
            ),
            auth_policy: auth_policy_report(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvisioningReadiness {
    project_id: String,
    location: String,
    auth_mode: String,
    auth_source: String,
    request_timeout_ms: u64,
    base_url: Option<String>,
    default_endpoint_would_touch_vertex: bool,
    credential_injection_required: bool,
    auth_policy: Value,
    verification_script: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    critical: bool,
    message: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: Value,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self {
            status,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
        }
    }
}

pub struct AnthropicVertexConnector {
    base: BaseConnector,
    config: Option<VertexConfig>,
    client: Option<AnthropicVertexClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl AnthropicVertexConnector {
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.anthropic-vertex")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    pub const fn instance_id(&self) -> &fcp_prelude::InstanceId {
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
            .map(VertexConfig::provisioning_readiness);
        let mut checks = vec![
            DoctorCheck {
                name: "configuration".into(),
                passed: self.config.is_some(),
                critical: true,
                message: Some(if self.config.is_some() {
                    "Configuration loaded".into()
                } else {
                    "Connector has not been configured".into()
                }),
            },
            DoctorCheck {
                name: "client".into(),
                passed: self.client.is_some(),
                critical: true,
                message: Some(if self.client.is_some() {
                    "HTTP client initialized".into()
                } else {
                    "HTTP client missing".into()
                }),
            },
            DoctorCheck {
                name: "runtime".into(),
                passed: self.runtime.is_some(),
                critical: true,
                message: Some(if self.runtime.is_some() {
                    "ConnectorRuntime initialized".into()
                } else {
                    "ConnectorRuntime missing".into()
                }),
            },
        ];
        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "vertex_endpoint".into(),
                passed: !readiness.default_endpoint_would_touch_vertex,
                critical: false,
                message: Some(if readiness.default_endpoint_would_touch_vertex {
                    "Default Vertex endpoint configured; self_check abstains from live Google calls"
                        .into()
                } else {
                    "Custom verifier endpoint configured".into()
                }),
            });
            checks.push(DoctorCheck {
                name: "credential_materialization".into(),
                passed: !readiness.credential_injection_required,
                critical: false,
                message: Some(if readiness.credential_injection_required {
                    "credential_id configured; egress proxy must inject Google bearer material"
                        .into()
                } else {
                    "Runtime bearer material available in memory".into()
                }),
            });
        }
        DoctorResult::from_checks(checks, provisioning)
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        provisioning: Option<&ProvisioningReadiness>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "verify_commands": VERIFY_COMMANDS,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
        }));
        report
    }
}

impl Default for AnthropicVertexConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn auth_label_for_materialized(auth: &GoogleMaterializedAuth) -> String {
    match auth {
        GoogleMaterializedAuth::BearerToken { source, .. } => source.to_string(),
        GoogleMaterializedAuth::CredentialReference { credential_id, .. } => {
            format!("credential_id:{credential_id}")
        }
    }
}

fn map_auth_error(error: &GoogleAuthError) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid Google auth configuration: {error}"),
    }
}

fn validate_base_url(raw: &str) -> FcpResult<()> {
    let parsed = Url::parse(raw).map_err(|error| FcpError::InvalidRequest {
        code: 1001,
        message: format!("Invalid base_url: {error}"),
    })?;
    let Some(host) = parsed.host_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must include a host".into(),
        });
    };
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_local_test_host(host)) {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must use https unless it targets localhost for verification".into(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include embedded credentials".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include query or fragment components".into(),
        });
    }
    Ok(())
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn operator_guidance() -> Value {
    json!({
        "docs_checked": [
            "Anthropic Claude on Vertex AI",
            "Google Vertex AI partner model rawPredict/streamRawPredict"
        ],
        "auth": "Use access_token, oauth_refresh, or credential_id at connector runtime. ADC/default credentials/metadata-server discovery belongs in host provisioning and should materialize a credential_id or ephemeral bearer token before configure.",
        "redaction": [
            "Never log Google bearer tokens, refresh tokens, credential files, prompts, completions, thinking blocks, or cache contents.",
            "Diagnostics may include project_id, location, credential_id handle, model id, and retry metadata."
        ],
        "no_live_default_self_check": "self_check does not call default Vertex endpoints; set base_url to a verifier endpoint for loopback proof."
    })
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_MESSAGES_CREATE | OP_MESSAGES_STREAM => CapabilityId::from_static(CAP_MESSAGES),
        OP_MODELS_NORMALIZE | OP_HEALTH => CapabilityId::from_static(CAP_MODELS_READ),
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };
    Ok(capability)
}

fn nonblank_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "\\S"
    })
}

fn message_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["messages", "max_tokens"],
        "anyOf": [
            { "required": ["model"] },
            { "required": ["model_id"] },
            { "required": ["body"] }
        ],
        "additionalProperties": true,
        "properties": {
            "model": nonblank_string_schema(),
            "model_id": nonblank_string_schema(),
            "body": {
                "type": "object",
                "additionalProperties": true
            },
            "messages": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": true
                }
            },
            "system": {
                "type": ["string", "array"],
                "items": {
                    "type": "object",
                    "additionalProperties": true
                }
            },
            "max_tokens": {
                "type": "integer",
                "minimum": 1,
                "maximum": i64::from(u32::MAX)
            },
            "temperature": {
                "type": "number",
                "minimum": 0
            },
            "tools": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": true
                }
            },
            "tool_choice": {
                "type": "object",
                "additionalProperties": true
            },
            "thinking": {
                "type": "object",
                "additionalProperties": true
            },
            "cache_control": {
                "type": "object",
                "additionalProperties": true
            },
            "output_config": {
                "type": "object",
                "additionalProperties": true
            }
        }
    })
}

fn normalize_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["model"],
        "additionalProperties": false,
        "properties": {
            "model": nonblank_string_schema()
        }
    })
}

fn empty_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "maxProperties": 0
    })
}

fn provider_json_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": true
    })
}

fn stream_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["events", "event_count", "total_payload_bytes"],
        "additionalProperties": false,
        "properties": {
            "events": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["payload_utf8", "payload_bytes"],
                    "additionalProperties": false,
                    "properties": {
                        "event_type": { "type": ["string", "null"] },
                        "payload_json": {
                            "type": ["object", "array", "string", "number", "boolean", "null"]
                        },
                        "payload_utf8": { "type": "string" },
                        "payload_bytes": { "type": "integer", "minimum": 0 }
                    }
                }
            },
            "event_count": { "type": "integer", "minimum": 0 },
            "total_payload_bytes": { "type": "integer", "minimum": 0 }
        }
    })
}

fn input_schema_for(operation: &str) -> Value {
    match operation {
        OP_MESSAGES_CREATE | OP_MESSAGES_STREAM => message_input_schema(),
        OP_MODELS_NORMALIZE => normalize_input_schema(),
        _ => empty_input_schema(),
    }
}

fn output_schema_for(operation: &str) -> Value {
    match operation {
        OP_MESSAGES_STREAM => stream_output_schema(),
        _ => provider_json_output_schema(),
    }
}

fn operation_info(
    id: &'static str,
    summary: &'static str,
    capability: &'static str,
    input_schema: Value,
    output_schema: Value,
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
                "Do not send direct Anthropic API keys to this connector; configure Google Vertex auth instead.".into(),
                "Do not put the model field in the raw Vertex body; this connector moves the normalized model into the Vertex URL path.".into(),
                "Do not use Anthropic beta headers; Claude on Vertex uses anthropic_version in the JSON body.".into(),
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
            OP_MESSAGES_CREATE,
            "Invoke Claude Messages through Vertex rawPredict",
            CAP_MESSAGES,
            input_schema_for(OP_MESSAGES_CREATE),
            output_schema_for(OP_MESSAGES_CREATE),
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        operation_info(
            OP_MESSAGES_STREAM,
            "Invoke Claude Messages streaming through Vertex streamRawPredict",
            CAP_MESSAGES,
            input_schema_for(OP_MESSAGES_STREAM),
            output_schema_for(OP_MESSAGES_STREAM),
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        operation_info(
            OP_MODELS_NORMALIZE,
            "Normalize Claude model aliases to Vertex model ids",
            CAP_MODELS_READ,
            input_schema_for(OP_MODELS_NORMALIZE),
            output_schema_for(OP_MODELS_NORMALIZE),
            SafetyTier::Safe,
            IdempotencyClass::None,
        ),
        operation_info(
            OP_HEALTH,
            "Inspect Anthropic Vertex connector readiness without live calls",
            CAP_MODELS_READ,
            input_schema_for(OP_HEALTH),
            output_schema_for(OP_HEALTH),
            SafetyTier::Safe,
            IdempotencyClass::None,
        ),
    ]
}

fcp_core::impl_fcp_sealed!(AnthropicVertexConnector);

#[async_trait]
impl FcpConnector for AnthropicVertexConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let cfg = VertexConfig::from_value(config).await?;
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        ));
        let client = AnthropicVertexClient::new(cfg.client_config()).map_err(|error| {
            FcpError::Internal {
                message: format!("Client init: {error}"),
            }
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
            .map(VertexConfig::provisioning_readiness);
        let mut snapshot = match &provisioning {
            None => HealthSnapshot::degraded("not configured"),
            Some(_) if self.client.is_none() => HealthSnapshot::error("client not initialized"),
            Some(_) if self.runtime.is_none() => HealthSnapshot::error("runtime not initialized"),
            Some(readiness) if readiness.default_endpoint_would_touch_vertex => {
                HealthSnapshot::degraded(
                    "default Vertex endpoint configured; self_check abstains from live Google calls",
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
        if self.client.is_none() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed(
                    "client_missing",
                    "Anthropic Vertex HTTP client not initialized; re-run configure",
                ),
                Some(&provisioning),
            ));
        }
        if self.runtime.is_none() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed(
                    "runtime_missing",
                    "ConnectorRuntime not initialized; re-run configure",
                ),
                Some(&provisioning),
            ));
        }
        if config.base_url.is_none() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded(
                    "self_check_unsupported_on_default_vertex",
                    "self_check abstains against default Vertex endpoints to avoid live Google calls; set base_url to a verifier endpoint for loopback proof",
                ),
                Some(&provisioning),
            ));
        }
        if matches!(
            config.auth,
            GoogleMaterializedAuth::CredentialReference { .. }
        ) {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded(
                    "credential_injection_required",
                    "credential_id mode requires egress proxy token injection for live calls",
                ),
                Some(&provisioning),
            ));
        }
        Ok(self.attach_self_check_details(SelfCheckReport::ok(), Some(&provisioning)))
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

impl AnthropicVertexConnector {
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
            message: "connector ready state missing Anthropic Vertex client".into(),
        })?;

        let output = match operation {
            OP_MESSAGES_CREATE => client
                .message(runtime, &req.input)
                .await
                .map_err(|error| error.to_fcp_error())?,
            OP_MESSAGES_STREAM => serde_json::to_value(
                client
                    .message_stream(runtime, &req.input)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| serialize_error(&error))?,
            OP_MODELS_NORMALIZE => normalize_model_output(&req.input)?,
            OP_HEALTH => client.readiness(),
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

fn normalize_model_output(input: &Value) -> FcpResult<Value> {
    let model =
        input
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "model is required".into(),
            })?;
    let vertex_model = normalize_model_id(model).ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Unsupported Anthropic Vertex model: {model}"),
    })?;
    Ok(json!({
        "input": model,
        "vertex_model": vertex_model,
        "catalog_entry": catalog_entry(vertex_model),
        "catalog": model_catalog(),
    }))
}

fn serialize_error(error: &serde_json::Error) -> FcpError {
    FcpError::Internal {
        message: format!("Failed to serialize response: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_OPS: &[(&str, &str)] = &[
        (OP_MESSAGES_CREATE, "anthropic_vertex.messages.create"),
        (OP_MESSAGES_STREAM, "anthropic_vertex.messages.stream"),
        (OP_MODELS_NORMALIZE, "anthropic_vertex.models.normalize"),
        (OP_HEALTH, "anthropic_vertex.health"),
    ];

    fn manifest_operations(
        manifest: &toml::Value,
    ) -> Result<&toml::map::Map<String, toml::Value>, String> {
        manifest
            .get("provides")
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| "manifest should declare operation tables".to_string())
    }

    #[test]
    fn introspection_and_manifest_expose_same_operations() -> Result<(), String> {
        let manifest = toml::from_str::<toml::Value>(MANIFEST_TOML)
            .map_err(|error| format!("manifest TOML should parse: {error}"))?;
        let manifest_ops = manifest_operations(&manifest)?;
        let runtime_ops = AnthropicVertexConnector::new().introspect().operations;
        assert_eq!(manifest_ops.len(), EXPECTED_OPS.len());
        assert_eq!(runtime_ops.len(), EXPECTED_OPS.len());
        for (runtime_id, manifest_id) in EXPECTED_OPS {
            assert!(manifest_ops.contains_key(*manifest_id));
            assert!(
                runtime_ops
                    .iter()
                    .any(|operation| operation.id.as_str() == *runtime_id),
                "missing runtime operation {runtime_id}"
            );
        }
        Ok(())
    }

    #[test]
    fn model_normalization_output_contains_catalog_entry() {
        let output = normalize_model_output(&json!({ "model": "sonnet-4.6" })).unwrap();
        assert_eq!(output["vertex_model"], "claude-sonnet-4-6");
        assert_eq!(output["catalog_entry"]["display_name"], "Claude Sonnet 4.6");
    }
}
