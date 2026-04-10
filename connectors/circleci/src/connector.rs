//! CircleCI connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use reqwest::Url;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{client::CircleCiClient, error::Error as CircleCiError};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_PIPELINES_LIST: &str = "circleci.pipelines.list";
const OP_PIPELINES_GET: &str = "circleci.pipelines.get";
const OP_PIPELINES_TRIGGER: &str = "circleci.pipelines.trigger";
const OP_WORKFLOWS_LIST: &str = "circleci.workflows.list";
const OP_WORKFLOWS_GET: &str = "circleci.workflows.get";
const OP_WORKFLOWS_CANCEL: &str = "circleci.workflows.cancel";
const OP_WORKFLOWS_RERUN: &str = "circleci.workflows.rerun";
const OP_JOBS_LIST: &str = "circleci.jobs.list";
const OP_JOBS_GET: &str = "circleci.jobs.get";
const OP_PROJECTS_LIST: &str = "circleci.projects.list";
const OP_HEALTH: &str = "circleci.health";

// Capability IDs
const CAP_PIPELINES_READ: &str = "circleci.pipelines.read";
const CAP_PIPELINES_WRITE: &str = "circleci.pipelines.write";
const CAP_WORKFLOWS_READ: &str = "circleci.workflows.read";
const CAP_WORKFLOWS_WRITE: &str = "circleci.workflows.write";
const CAP_JOBS_READ: &str = "circleci.jobs.read";
const CAP_PROJECTS_READ: &str = "circleci.projects.read";

/// CircleCI connector configuration.
#[derive(Clone, Deserialize)]
struct CircleCiConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    api_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for CircleCiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircleCiConfig")
            .field("base_url", &self.base_url)
            .field("api_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://circleci.com/api/v2".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

const HOSTED_CIRCLECI_HOST: &str = "circleci.com";

impl CircleCiConfig {
    fn validate(mut self) -> Result<Self, String> {
        self.base_url = self.base_url.trim().trim_end_matches('/').to_string();
        if self.base_url.is_empty() {
            return Err("base_url must not be empty".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than 0".into());
        }

        let parsed = Url::parse(&self.base_url)
            .map_err(|error| format!("base_url must be a valid URL: {error}"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "base_url must include a host".to_string())?;
        let is_local_test_host = matches!(host, "localhost" | "127.0.0.1");

        match parsed.scheme() {
            "https" => Ok(self),
            "http" if is_local_test_host => Ok(self),
            scheme => Err(format!(
                "base_url must use https unless targeting a localhost test override (found scheme {scheme})"
            )),
        }
    }
}

fn base_url_manifest_alignment(base_url: &str) -> (bool, String) {
    let Ok(parsed) = Url::parse(base_url) else {
        return (false, format!("Invalid base_url: {base_url}"));
    };
    let Some(host) = parsed.host_str() else {
        return (false, format!("base_url {base_url} is missing a host"));
    };

    if host == HOSTED_CIRCLECI_HOST {
        return (
            true,
            "Base URL matches the hosted CircleCI SaaS API policy.".into(),
        );
    }
    if matches!(host, "localhost" | "127.0.0.1") {
        return (
            true,
            "Base URL uses a localhost test override outside production policy.".into(),
        );
    }

    (
        false,
        format!(
            "Base URL host {host} is outside the first-slice manifest network policy ({HOSTED_CIRCLECI_HOST})."
        ),
    )
}

fn classify_self_check_error(error: &CircleCiError) -> (&'static str, bool) {
    match error {
        CircleCiError::RateLimited { .. } => ("circleci_rate_limited", true),
        CircleCiError::Unauthorized(_) => ("invalid_api_token", false),
        CircleCiError::Api { status: 403, .. } => ("permissions_or_scope_missing", false),
        CircleCiError::Api { status: 404, .. } => ("circleci_resource_not_found", false),
        CircleCiError::Api { status, .. } if (500..=599).contains(status) => {
            ("circleci_api_retryable", true)
        }
        CircleCiError::Http(_) | CircleCiError::Async(_) => ("self_check_retryable", true),
        CircleCiError::Json(_) => ("response_decode_failed", false),
        CircleCiError::Config(_) => ("config_invalid", false),
        CircleCiError::InvalidInput(_) => ("invalid_input", false),
        CircleCiError::Api { .. } => ("self_check_failed", false),
    }
}

// Doctor types
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self { passed, checks }
    }
}

/// CircleCI connector state.
#[derive(Debug)]
pub struct CircleCiConnector {
    base: BaseConnector,
    config: Option<CircleCiConfig>,
    client: Option<CircleCiClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl CircleCiConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.circleci")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.runtime.is_some();
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });

        if let Some(config) = &self.config {
            let (host_ok, host_message) = base_url_manifest_alignment(&config.base_url);
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(host_message),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "request_timeout_ms".into(),
                passed: config.request_timeout_ms > 0,
                message: Some(format!(
                    "HTTP client timeout is configured to {} ms",
                    config.request_timeout_ms
                )),
                critical: true,
            });

            let secretless = self.client.as_ref().is_some_and(|c| c.is_secretless());
            checks.push(DoctorCheck {
                name: "credential_mode".into(),
                passed: !secretless,
                message: Some(if secretless {
                    "Credential injection required via egress proxy before live health verification can pass".into()
                } else {
                    "API token configured".into()
                }),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for CircleCiConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_PIPELINES_LIST),
            summary: "List pipelines for a project".into(),
            description: Some("Returns recent pipelines for a CircleCI project".into()),
            input_schema: json!({
                "type": "object",
                "required": ["project_slug"],
                "properties": {
                    "project_slug": { "type": "string", "description": "Project slug (e.g., gh/org/repo)" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "next_page_token": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PIPELINES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list recent pipelines for a project".into(),
                common_mistakes: vec![
                    "Project slug must be in format vcs/org/repo (e.g., gh/org/repo)".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PIPELINES_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PIPELINES_GET),
            summary: "Get a pipeline by ID".into(),
            description: Some("Returns details for a specific pipeline".into()),
            input_schema: json!({
                "type": "object",
                "required": ["pipeline_id"],
                "properties": {
                    "pipeline_id": { "type": "string", "description": "Pipeline UUID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "state": { "type": "string" },
                    "number": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PIPELINES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific pipeline".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PIPELINES_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PIPELINES_TRIGGER),
            summary: "Trigger a new pipeline".into(),
            description: Some("Triggers a new pipeline run on a project".into()),
            input_schema: json!({
                "type": "object",
                "required": ["project_slug"],
                "properties": {
                    "project_slug": { "type": "string", "description": "Project slug (e.g., gh/org/repo)" },
                    "branch": { "type": "string", "description": "Branch to run on" },
                    "tag": { "type": "string", "description": "Tag to run on" },
                    "parameters": { "type": "object", "description": "Pipeline parameters" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "state": { "type": "string" },
                    "number": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PIPELINES_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When you need to trigger a new CI/CD pipeline run".into(),
                common_mistakes: vec![
                    "Only specify branch OR tag, not both".into(),
                    "Pipeline parameters must match the project configuration".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PIPELINES_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Policy),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WORKFLOWS_LIST),
            summary: "List workflows for a pipeline".into(),
            description: Some("Returns workflows triggered by a specific pipeline".into()),
            input_schema: json!({
                "type": "object",
                "required": ["pipeline_id"],
                "properties": {
                    "pipeline_id": { "type": "string", "description": "Pipeline UUID" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "next_page_token": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WORKFLOWS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to see workflows triggered by a pipeline".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_WORKFLOWS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WORKFLOWS_GET),
            summary: "Get a workflow by ID".into(),
            description: Some("Returns details for a specific workflow".into()),
            input_schema: json!({
                "type": "object",
                "required": ["workflow_id"],
                "properties": {
                    "workflow_id": { "type": "string", "description": "Workflow UUID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "name": { "type": "string" },
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WORKFLOWS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific workflow".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_WORKFLOWS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WORKFLOWS_CANCEL),
            summary: "Cancel a running workflow".into(),
            description: Some("Cancels a currently running workflow".into()),
            input_schema: json!({
                "type": "object",
                "required": ["workflow_id"],
                "properties": {
                    "workflow_id": { "type": "string", "description": "Workflow UUID to cancel" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WORKFLOWS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to cancel a running workflow".into(),
                common_mistakes: vec!["Cannot cancel already-completed workflows".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_WORKFLOWS_RERUN)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WORKFLOWS_RERUN),
            summary: "Rerun a workflow".into(),
            description: Some("Reruns a workflow, optionally from failed jobs only".into()),
            input_schema: json!({
                "type": "object",
                "required": ["workflow_id"],
                "properties": {
                    "workflow_id": { "type": "string", "description": "Workflow UUID to rerun" },
                    "from_failed": { "type": "boolean", "description": "Only rerun from failed jobs", "default": false }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WORKFLOWS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When you need to rerun a failed or completed workflow".into(),
                common_mistakes: vec!["Use from_failed=true to save time on partial reruns".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_WORKFLOWS_CANCEL)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Policy),
        },
        OperationInfo {
            id: OperationId::from_static(OP_JOBS_LIST),
            summary: "List jobs for a workflow".into(),
            description: Some("Returns all jobs in a specific workflow".into()),
            input_schema: json!({
                "type": "object",
                "required": ["workflow_id"],
                "properties": {
                    "workflow_id": { "type": "string", "description": "Workflow UUID" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "next_page_token": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_JOBS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list jobs in a workflow".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_JOBS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_JOBS_GET),
            summary: "Get a job by project and number".into(),
            description: Some("Returns details for a specific job in a project".into()),
            input_schema: json!({
                "type": "object",
                "required": ["project_slug", "job_number"],
                "properties": {
                    "project_slug": { "type": "string", "description": "Project slug (e.g., gh/org/repo)" },
                    "job_number": { "type": "integer", "description": "Job number" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "name": { "type": "string" },
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_JOBS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific job".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_JOBS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PROJECTS_LIST),
            summary: "List followed projects".into(),
            description: Some("Returns projects the authenticated user follows".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "next_page_token": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PROJECTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list projects the user has access to".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check CircleCI API health".into(),
            description: Some("Validates CircleCI API reachability and auth".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PROJECTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to verify CircleCI connectivity".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(CircleCiConnector);

#[async_trait]
impl FcpConnector for CircleCiConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: CircleCiConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid CircleCI config: {e}"),
            })?;
        let config = config
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid CircleCI config: {message}"),
            })?;

        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = CircleCiClient::new(
            &config.base_url,
            &config.api_token,
            config.retry.clone(),
            config.request_timeout_ms,
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create CircleCI client: {e}"),
        })?;

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
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
        let mut snapshot = if let Some(config) = self.config.as_ref() {
            let credential_injection_required = self
                .client
                .as_ref()
                .is_some_and(|client| client.is_secretless());
            let (manifest_network_policy_aligned, manifest_network_policy_message) =
                base_url_manifest_alignment(&config.base_url);

            let mut snapshot = if credential_injection_required {
                HealthSnapshot::degraded("credential injection required")
            } else if manifest_network_policy_aligned {
                HealthSnapshot::ready()
            } else {
                HealthSnapshot::degraded("base_url outside manifest policy")
            };
            snapshot.details = Some(json!({
                "configured": true,
                "client_initialized": self.client.is_some(),
                "base_url": config.base_url.as_str(),
                "request_timeout_ms": config.request_timeout_ms,
                "auth_mode": if credential_injection_required { "credential_injection" } else { "api_token" },
                "credential_injection_required": credential_injection_required,
                "manifest_network_policy_aligned": manifest_network_policy_aligned,
                "manifest_network_policy_message": manifest_network_policy_message,
            }));
            snapshot
        } else {
            let mut snapshot = HealthSnapshot::degraded("not configured");
            snapshot.details = Some(json!({
                "configured": false,
                "client_initialized": false,
            }));
            snapshot
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        let (manifest_network_policy_aligned, manifest_network_policy_message) =
            base_url_manifest_alignment(client.base_url());
        if !manifest_network_policy_aligned {
            let mut report = SelfCheckReport::degraded(
                "base_url_outside_manifest_policy",
                manifest_network_policy_message,
            );
            report.details = Some(json!({
                "base_url": client.base_url(),
                "auth_mode": if client.is_secretless() { "credential_injection" } else { "api_token" },
                "manifest_network_policy_aligned": manifest_network_policy_aligned,
            }));
            return Ok(report);
        }

        if client.is_secretless() {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with empty token; egress proxy injection required",
            );
            report.details = Some(json!({
                "base_url": client.base_url(),
                "auth_mode": "credential_injection",
                "manifest_network_policy_aligned": manifest_network_policy_aligned,
            }));
            return Ok(report);
        }

        match client.health_check().await {
            Ok(()) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "base_url": client.base_url(),
                    "auth_mode": "api_token",
                    "manifest_network_policy_aligned": manifest_network_policy_aligned,
                }));
                Ok(report)
            }
            Err(error) => {
                let (reason_code, degraded) = classify_self_check_error(&error);
                let mut report = if degraded {
                    SelfCheckReport::degraded(reason_code, error.to_string())
                } else {
                    SelfCheckReport::failed(reason_code, error.to_string())
                };
                report.details = Some(json!({
                    "base_url": client.base_url(),
                    "auth_mode": "api_token",
                    "manifest_network_policy_aligned": manifest_network_policy_aligned,
                }));
                Ok(report)
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        Ok(())
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

impl CircleCiConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_PIPELINES_LIST | OP_PIPELINES_GET => CapabilityId::from_static(CAP_PIPELINES_READ),
            OP_PIPELINES_TRIGGER => CapabilityId::from_static(CAP_PIPELINES_WRITE),
            OP_WORKFLOWS_LIST | OP_WORKFLOWS_GET => CapabilityId::from_static(CAP_WORKFLOWS_READ),
            OP_WORKFLOWS_CANCEL | OP_WORKFLOWS_RERUN => {
                CapabilityId::from_static(CAP_WORKFLOWS_WRITE)
            }
            OP_JOBS_LIST | OP_JOBS_GET => CapabilityId::from_static(CAP_JOBS_READ),
            OP_PROJECTS_LIST | OP_HEALTH => CapabilityId::from_static(CAP_PROJECTS_READ),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "CircleCI client missing after configure".into(),
        })?;

        let output = match operation {
            OP_PIPELINES_LIST => {
                let project_slug = req
                    .input
                    .get("project_slug")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'project_slug' field".into(),
                    })?;
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_pipelines(runtime, project_slug, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PIPELINES_GET => {
                let pipeline_id = req
                    .input
                    .get("pipeline_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'pipeline_id' field".into(),
                    })?;
                let resp = client
                    .get_pipeline(runtime, pipeline_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PIPELINES_TRIGGER => {
                let project_slug = req
                    .input
                    .get("project_slug")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'project_slug' field".into(),
                    })?;
                let mut body = json!({});
                if let Some(branch) = req.input.get("branch").and_then(|v| v.as_str()) {
                    body["branch"] = json!(branch);
                }
                if let Some(tag) = req.input.get("tag").and_then(|v| v.as_str()) {
                    body["tag"] = json!(tag);
                }
                if let Some(params) = req.input.get("parameters") {
                    body["parameters"] = params.clone();
                }
                let resp = client
                    .trigger_pipeline(runtime, project_slug, &body)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_WORKFLOWS_LIST => {
                let pipeline_id = req
                    .input
                    .get("pipeline_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'pipeline_id' field".into(),
                    })?;
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_workflows(runtime, pipeline_id, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_WORKFLOWS_GET => {
                let workflow_id = req
                    .input
                    .get("workflow_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'workflow_id' field".into(),
                    })?;
                let resp = client
                    .get_workflow(runtime, workflow_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_WORKFLOWS_CANCEL => {
                let workflow_id = req
                    .input
                    .get("workflow_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'workflow_id' field".into(),
                    })?;
                let resp = client
                    .cancel_workflow(runtime, workflow_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_WORKFLOWS_RERUN => {
                let workflow_id = req
                    .input
                    .get("workflow_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'workflow_id' field".into(),
                    })?;
                let from_failed = req
                    .input
                    .get("from_failed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let resp = client
                    .rerun_workflow(runtime, workflow_id, from_failed)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_JOBS_LIST => {
                let workflow_id = req
                    .input
                    .get("workflow_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'workflow_id' field".into(),
                    })?;
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_jobs(runtime, workflow_id, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_JOBS_GET => {
                let project_slug = req
                    .input
                    .get("project_slug")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'project_slug' field".into(),
                    })?;
                let job_number = req.input.get("job_number").and_then(|v| v.as_u64()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing or invalid 'job_number' field".into(),
                    },
                )?;
                let resp = client
                    .get_job(runtime, project_slug, job_number)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PROJECTS_LIST => {
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_projects(runtime, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_HEALTH => {
                client.health_check().await.map_err(|e| e.to_fcp_error())?;
                json!({ "status": "ok" })
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn all_caps() -> Vec<CapabilityId> {
        vec![
            CapabilityId::from_static(CAP_PIPELINES_READ),
            CapabilityId::from_static(CAP_PIPELINES_WRITE),
            CapabilityId::from_static(CAP_WORKFLOWS_READ),
            CapabilityId::from_static(CAP_WORKFLOWS_WRITE),
            CapabilityId::from_static(CAP_JOBS_READ),
            CapabilityId::from_static(CAP_PROJECTS_READ),
        ]
    }

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: all_caps(),
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(connector_id: &ConnectorId, operation: &'static str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
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

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = CircleCiConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = CircleCiConnector::new();
        let config = json!({ "api_token": "test_token" });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = CircleCiConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = CircleCiConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_secretless_mode_is_degraded() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "" }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(
            health.status,
            HealthState::Degraded { ref reason } if reason == "credential injection required"
        ));
        assert_eq!(
            health
                .details
                .as_ref()
                .and_then(|details| details.get("credential_injection_required"))
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = CircleCiConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_custom_host_reports_manifest_policy_failure() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({
                "api_token": "tok",
                "base_url": "https://custom.circleci.example/api/v2"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        let network_check = report
            .checks
            .iter()
            .find(|check| check.name == "network_constraints")
            .unwrap();
        assert!(!network_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = CircleCiConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_secretless_reason_code() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "" }))
            .await
            .unwrap();
        let report = connector.self_check().await.unwrap();
        assert_eq!(
            report.reason_code.as_deref(),
            Some("credential_injection_required")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_invalid_token_reason_code() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({
                "api_token": "bad",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert_eq!(report.reason_code.as_deref(), Some("invalid_api_token"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_rate_limited_reason_code() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "2"))
            .mount(&mock_server)
            .await;

        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(report.reason_code.as_deref(), Some("circleci_rate_limited"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = CircleCiConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_PIPELINES_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = CircleCiConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 11);
        let ops: Vec<&str> = intro.operations.iter().map(|o| o.id.as_str()).collect();
        assert!(ops.contains(&OP_PIPELINES_LIST));
        assert!(ops.contains(&OP_PIPELINES_GET));
        assert!(ops.contains(&OP_PIPELINES_TRIGGER));
        assert!(ops.contains(&OP_WORKFLOWS_LIST));
        assert!(ops.contains(&OP_WORKFLOWS_GET));
        assert!(ops.contains(&OP_WORKFLOWS_CANCEL));
        assert!(ops.contains(&OP_WORKFLOWS_RERUN));
        assert!(ops.contains(&OP_JOBS_LIST));
        assert!(ops.contains(&OP_JOBS_GET));
        assert!(ops.contains(&OP_PROJECTS_LIST));
        assert!(ops.contains(&OP_HEALTH));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "circleci.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = CircleCiConnector::new();
        let req = base_invoke(connector.id(), OP_PIPELINES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_project_slug() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PIPELINES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_pipeline_id() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PIPELINES_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_workflow_id_for_cancel() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_WORKFLOWS_CANCEL);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_pipelines_trigger_is_risky() {
        let ops = operations_info();
        let trigger = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PIPELINES_TRIGGER)
            .unwrap();
        assert_eq!(trigger.safety_tier, SafetyTier::Risky);
        assert_eq!(trigger.risk_level, RiskLevel::High);
        assert_eq!(trigger.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(trigger.requires_approval, Some(ApprovalMode::Policy));
    }

    #[test]
    fn test_pipelines_list_is_safe() {
        let ops = operations_info();
        let list = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PIPELINES_LIST)
            .unwrap();
        assert_eq!(list.safety_tier, SafetyTier::Safe);
        assert_eq!(list.risk_level, RiskLevel::Low);
        assert_eq!(list.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_workflows_cancel_is_risky() {
        let ops = operations_info();
        let cancel = ops
            .iter()
            .find(|op| op.id.as_str() == OP_WORKFLOWS_CANCEL)
            .unwrap();
        assert_eq!(cancel.safety_tier, SafetyTier::Risky);
        assert_eq!(cancel.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_workflows_rerun_requires_policy_approval() {
        let ops = operations_info();
        let rerun = ops
            .iter()
            .find(|op| op.id.as_str() == OP_WORKFLOWS_RERUN)
            .unwrap();
        assert_eq!(rerun.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(rerun.requires_approval, Some(ApprovalMode::Policy));
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = CircleCiConnector::manifest_hash();
        let hash2 = CircleCiConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = CircleCiConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[test]
    fn test_connector_id() {
        let connector = CircleCiConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.circleci");
    }

    #[test]
    fn test_default_impl() {
        let connector = CircleCiConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.circleci");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_custom_base_url() {
        let mut connector = CircleCiConnector::new();
        let config = json!({
            "api_token": "tok",
            "base_url": "https://custom.circleci.com/api/v2"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_zero_timeout() {
        let mut connector = CircleCiConnector::new();
        let result = connector
            .configure(json!({
                "api_token": "tok",
                "request_timeout_ms": 0
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_all_caps() {
        let mut connector = CircleCiConnector::new();
        let resp = connector.handshake(base_handshake()).await.unwrap();
        assert_eq!(resp.capabilities_granted.len(), 6);
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        let result = connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 5000,
                drain: false,
                reason: Some("test".into()),
            })
            .await;
        assert!(result.is_ok());
    }
}
