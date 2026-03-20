//! Vercel connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::VercelClient;
use crate::types::{AddDomain, CreateDeployment, CreateEnvVar, CreateProject, GitSource, VercelAuth};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_DEPLOYMENTS_LIST: &str = "vercel.deployments.list";
const OP_DEPLOYMENTS_GET: &str = "vercel.deployments.get";
const OP_DEPLOYMENTS_CREATE: &str = "vercel.deployments.create";
const OP_DEPLOYMENTS_DELETE: &str = "vercel.deployments.delete";
const OP_PROJECTS_LIST: &str = "vercel.projects.list";
const OP_PROJECTS_GET: &str = "vercel.projects.get";
const OP_PROJECTS_CREATE: &str = "vercel.projects.create";
const OP_PROJECTS_DELETE: &str = "vercel.projects.delete";
const OP_DOMAINS_LIST: &str = "vercel.domains.list";
const OP_DOMAINS_ADD: &str = "vercel.domains.add";
const OP_DOMAINS_REMOVE: &str = "vercel.domains.remove";
const OP_ENV_LIST: &str = "vercel.env.list";
const OP_ENV_CREATE: &str = "vercel.env.create";
const OP_ENV_DELETE: &str = "vercel.env.delete";
const OP_HEALTH: &str = "vercel.health";

const CAP_DEPLOYMENTS_READ: &str = "vercel.deployments.read";
const CAP_DEPLOYMENTS_WRITE: &str = "vercel.deployments.write";
const CAP_PROJECTS_READ: &str = "vercel.projects.read";
const CAP_PROJECTS_WRITE: &str = "vercel.projects.write";
const CAP_DOMAINS_READ: &str = "vercel.domains.read";
const CAP_DOMAINS_WRITE: &str = "vercel.domains.write";
const CAP_ENV_READ: &str = "vercel.env.read";
const CAP_ENV_WRITE: &str = "vercel.env.write";

#[derive(Clone, serde::Deserialize)]
pub struct VercelConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    pub token: String,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}
fn default_base_url() -> String {
    "https://api.vercel.com".into()
}
const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for VercelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VercelConfig")
            .field("base_url", &self.base_url)
            .field("token", &"[REDACTED]")
            .field("team_id", &self.team_id)
            .finish()
    }
}

impl VercelConfig {
    fn validate(&self) -> Result<(), String> {
        if self.base_url.is_empty() {
            return Err("base_url cannot be empty".into());
        }
        Ok(())
    }

    fn from_value(val: serde_json::Value) -> FcpResult<Self> {
        let config: Self = serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Invalid configuration: {e}"),
        })?;
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: e,
        })?;
        Ok(config)
    }
}

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

#[derive(Debug)]
pub struct VercelConnector {
    base: BaseConnector,
    config: Option<VercelConfig>,
    client: Option<VercelClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl VercelConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.vercel")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut h = Sha256::new();
        h.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                None
            } else {
                Some("Not configured".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client".into(),
            passed: self.client.is_some(),
            message: if self.client.is_some() {
                None
            } else {
                Some("Client not initialized".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: self.runtime.is_some(),
            message: if self.runtime.is_some() {
                None
            } else {
                Some("Runtime not initialized".into())
            },
            critical: true,
        });
        if let Some(cfg) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: cfg.base_url.starts_with("https://"),
                message: Some(format!("URL: {}", cfg.base_url)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "team_id".into(),
                passed: true,
                message: Some(if cfg.team_id.is_some() {
                    "Team-scoped".into()
                } else {
                    "Personal account".into()
                }),
                critical: false,
            });
            if let Some(client) = &self.client {
                checks.push(DoctorCheck {
                    name: "credential_mode".into(),
                    passed: true,
                    message: Some(if client.is_secretless() {
                        "Secretless".into()
                    } else {
                        "Direct".into()
                    }),
                    critical: false,
                });
            }
        }
        DoctorResult::from_checks(checks)
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        input
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Missing: {key}"),
            })
    }
}

impl Default for VercelConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_lines)]
fn operations_info() -> Vec<OperationInfo> {
    let hint = |when: &str,
                mistakes: Vec<String>,
                examples: Vec<String>,
                related: Vec<&'static str>|
     -> AgentHint {
        AgentHint {
            when_to_use: when.into(),
            common_mistakes: mistakes,
            examples,
            related: related.into_iter().map(CapabilityId::from_static).collect(),
        }
    };
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_DEPLOYMENTS_LIST),
            summary: "List deployments".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_DEPLOYMENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List recent deployments",
                vec![],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DEPLOYMENTS_GET),
            summary: "Get deployment details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["deployment_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DEPLOYMENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get details of a specific deployment",
                vec!["Use deployment uid not URL".into()],
                vec![],
                vec![CAP_DEPLOYMENTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DEPLOYMENTS_CREATE),
            summary: "Create deployment".into(),
            description: None,
            input_schema: json!({"type":"object","required":["name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DEPLOYMENTS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Trigger a new deployment",
                vec!["Requires git source or files".into()],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DEPLOYMENTS_DELETE),
            summary: "Delete deployment".into(),
            description: None,
            input_schema: json!({"type":"object","required":["deployment_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DEPLOYMENTS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Remove a deployment (irreversible)",
                vec!["Check deployment state first".into()],
                vec![],
                vec![CAP_DEPLOYMENTS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PROJECTS_LIST),
            summary: "List projects".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_PROJECTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint("List all projects", vec![], vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_PROJECTS_GET),
            summary: "Get project details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PROJECTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get details of a specific project",
                vec![],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_PROJECTS_CREATE),
            summary: "Create project".into(),
            description: None,
            input_schema: json!({"type":"object","required":["name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PROJECTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Create a new Vercel project",
                vec!["Name must be unique".into()],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_PROJECTS_DELETE),
            summary: "Delete project".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PROJECTS_WRITE),
            risk_level: RiskLevel::Critical,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently delete project and all deployments",
                vec!["Cannot be undone".into()],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOMAINS_LIST),
            summary: "List project domains".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_DOMAINS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "See domains attached to a project",
                vec![],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOMAINS_ADD),
            summary: "Add domain to project".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id","name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DOMAINS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Assign a custom domain to a project",
                vec!["Domain must be verified".into()],
                vec![],
                vec![CAP_DOMAINS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOMAINS_REMOVE),
            summary: "Remove domain from project".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id","domain"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DOMAINS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Detach domain from project (affects routing)",
                vec!["Traffic will stop routing".into()],
                vec![],
                vec![CAP_DOMAINS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ENV_LIST),
            summary: "List environment variables".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_ENV_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List env vars for a project",
                vec!["Values may be encrypted".into()],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_ENV_CREATE),
            summary: "Create environment variable".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id","key","value","type","target"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ENV_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Add an env var to a project",
                vec!["Must specify target environments".into()],
                vec![],
                vec![CAP_ENV_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_ENV_DELETE),
            summary: "Delete environment variable".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id","env_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ENV_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Remove env var (may break deployments)",
                vec!["Deployments may depend on this var".into()],
                vec![],
                vec![CAP_ENV_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Verify API token".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PROJECTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Check credentials", vec![], vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

#[async_trait]
impl FcpConnector for VercelConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let vc = VercelConfig::from_value(config)?;
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(vc.request_timeout_ms)),
        ));
        let client = VercelClient::new(
            &vc.base_url,
            VercelAuth {
                token: vc.token.clone(),
            },
            vc.team_id.clone(),
            vc.retry.clone(),
        )
        .await
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?;
        self.client = Some(client);
        self.config = Some(vc);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let caps = req
            .capabilities_requested
            .into_iter()
            .map(|c| CapabilityGrant {
                capability: c,
                operation: None,
            })
            .collect();
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: caps,
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
        let mut snap = if self.config.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snap.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snap
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Not configured",
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(SelfCheckReport::degraded("no_runtime", "No runtime"));
        };
        match client.health_check(runtime).await {
            Ok(_user) => Ok(SelfCheckReport::ok()),
            Err(e) if e.is_retryable() => Ok(SelfCheckReport::degraded(
                "self_check_retryable",
                e.to_string(),
            )),
            Err(e) => Ok(SelfCheckReport::failed("self_check_failed", e.to_string())),
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

impl VercelConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_DEPLOYMENTS_LIST | OP_DEPLOYMENTS_GET => {
                    CapabilityId::from_static(CAP_DEPLOYMENTS_READ)
                }
                OP_DEPLOYMENTS_CREATE | OP_DEPLOYMENTS_DELETE => {
                    CapabilityId::from_static(CAP_DEPLOYMENTS_WRITE)
                }
                OP_PROJECTS_LIST | OP_PROJECTS_GET | OP_HEALTH => {
                    CapabilityId::from_static(CAP_PROJECTS_READ)
                }
                OP_PROJECTS_CREATE | OP_PROJECTS_DELETE => {
                    CapabilityId::from_static(CAP_PROJECTS_WRITE)
                }
                OP_DOMAINS_LIST => CapabilityId::from_static(CAP_DOMAINS_READ),
                OP_DOMAINS_ADD | OP_DOMAINS_REMOVE => {
                    CapabilityId::from_static(CAP_DOMAINS_WRITE)
                }
                OP_ENV_LIST => CapabilityId::from_static(CAP_ENV_READ),
                OP_ENV_CREATE | OP_ENV_DELETE => CapabilityId::from_static(CAP_ENV_WRITE),
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            };
            verifier.verify(&req.capability_token, &cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Vercel client".into(),
        })?;

        let output = match operation {
            OP_DEPLOYMENTS_LIST => {
                let project_id = req.input.get("project_id").and_then(|v| v.as_str());
                let limit = req
                    .input
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let deps = client
                    .list_deployments(runtime, project_id, limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&deps).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DEPLOYMENTS_GET => {
                let did = Self::require_str(&req.input, "deployment_id")?;
                let dep = client
                    .get_deployment(runtime, did)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&dep).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DEPLOYMENTS_CREATE => {
                let name = Self::require_str(&req.input, "name")?;
                let git_source = req.input.get("git_source").map(|gs| GitSource {
                    source_type: gs
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("github")
                        .into(),
                    repo: gs
                        .get("repo")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    git_ref: gs.get("ref").and_then(|v| v.as_str()).map(String::from),
                });
                let target = req
                    .input
                    .get("target")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let dep_req = CreateDeployment {
                    name: name.into(),
                    git_source,
                    target,
                    project_settings: req.input.get("project_settings").cloned(),
                };
                let dep = client
                    .create_deployment(runtime, &dep_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&dep).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DEPLOYMENTS_DELETE => {
                let did = Self::require_str(&req.input, "deployment_id")?;
                client
                    .delete_deployment(runtime, did)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_PROJECTS_LIST => {
                let limit = req
                    .input
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let projs = client
                    .list_projects(runtime, limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&projs).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PROJECTS_GET => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let proj = client
                    .get_project(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&proj).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PROJECTS_CREATE => {
                let name = Self::require_str(&req.input, "name")?;
                let framework = req
                    .input
                    .get("framework")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let git_repository = req.input.get("git_repository").and_then(|gr| {
                    Some(crate::types::GitRepository {
                        repo_type: gr.get("type")?.as_str()?.into(),
                        repo: gr.get("repo")?.as_str()?.into(),
                    })
                });
                let proj_req = CreateProject {
                    name: name.into(),
                    framework,
                    git_repository,
                };
                let proj = client
                    .create_project(runtime, &proj_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&proj).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PROJECTS_DELETE => {
                let pid = Self::require_str(&req.input, "project_id")?;
                client
                    .delete_project(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_DOMAINS_LIST => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let domains = client
                    .list_domains(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&domains).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DOMAINS_ADD => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let name = Self::require_str(&req.input, "name")?;
                let domain_req = AddDomain {
                    name: name.into(),
                    git_branch: req
                        .input
                        .get("git_branch")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    redirect: req
                        .input
                        .get("redirect")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    redirect_status_code: req
                        .input
                        .get("redirect_status_code")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u16),
                };
                let domain = client
                    .add_domain(runtime, pid, &domain_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&domain).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DOMAINS_REMOVE => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let domain = Self::require_str(&req.input, "domain")?;
                client
                    .remove_domain(runtime, pid, domain)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_ENV_LIST => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let envs = client
                    .list_env_vars(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&envs).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ENV_CREATE => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let key = Self::require_str(&req.input, "key")?;
                let value = Self::require_str(&req.input, "value")?;
                let env_type = Self::require_str(&req.input, "type")?;
                let target = req
                    .input
                    .get("target")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| vec!["production".into()]);
                let env_req = CreateEnvVar {
                    key: key.into(),
                    value: value.into(),
                    env_type: env_type.into(),
                    target,
                };
                let env = client
                    .create_env_var(runtime, pid, &env_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&env).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ENV_DELETE => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let eid = Self::require_str(&req.input, "env_id")?;
                client
                    .delete_env_var(runtime, pid, eid)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_HEALTH => {
                let user = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "healthy": true,
                    "user_id": user.id,
                    "username": user.username,
                    "email": user.email
                })
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
    use fcp_core::{CapabilityToken, RequestId, ZoneId};

    fn tc() -> serde_json::Value {
        json!({"token": "t"})
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_DEPLOYMENTS_READ),
                CapabilityId::from_static(CAP_PROJECTS_READ),
                CapabilityId::from_static(CAP_DOMAINS_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn invoke_req(op: &'static str, input: serde_json::Value) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("r1"),
            connector_id: ConnectorId::from_static("fcp.vercel"),
            operation: OperationId::from_static(op),
            zone_id: ZoneId::work(),
            input,
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        }
    }

    #[test]
    fn new_ok() {
        assert!(VercelConnector::new().config.is_none());
    }

    #[test]
    fn default_ok() {
        assert!(VercelConnector::default().config.is_none());
    }

    #[test]
    fn manifest_hash_stable() {
        assert_eq!(
            VercelConnector::manifest_hash(),
            VercelConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_empty_base_url() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(json!({"token":"t","base_url":""})).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_bad() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn doctor_unconfigured() {
        assert!(!VercelConnector::new().doctor().passed);
    }

    #[test]
    fn doctor_configured() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(tc()).await.unwrap();
                c.doctor()
            })
            .unwrap()
            .passed
        );
    }

    #[test]
    fn introspect_ops() {
        assert_eq!(VercelConnector::new().introspect().operations.len(), 15);
    }

    #[test]
    fn ops_all_have_hints() {
        for op in operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty(), "{}", op.id);
        }
    }

    #[test]
    fn dangerous_ops_need_approval() {
        for op in operations_info() {
            if op.safety_tier == SafetyTier::Dangerous {
                assert!(op.requires_approval.is_some(), "{}", op.id);
            }
        }
    }

    #[test]
    fn invoke_unknown() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("vercel.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_deployment_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_DEPLOYMENTS_GET, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            VercelConnector::new()
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.vercel"),
                    OperationId::from_static(OP_PROJECTS_LIST),
                    ZoneId::work(),
                    json!({}),
                    CapabilityToken::test_token(),
                ))
                .await
        })
        .unwrap()
        .unwrap();
        assert!(r.would_succeed);
    }

    #[test]
    fn subscribe_unsupported() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                VercelConnector::new()
                    .subscribe(SubscribeRequest {
                        r#type: "subscribe".into(),
                        id: RequestId::new("sub1"),
                        topics: vec![],
                        since: None,
                        max_events_per_sec: None,
                        batch_ms: None,
                        window_size: None,
                        capability_token: None,
                    })
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn shutdown_ok() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut c = VercelConnector::new();
            c.configure(tc()).await.unwrap();
            c.shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 10_000,
                drain: false,
                reason: None,
            })
            .await
            .unwrap();
        })
        .unwrap();
    }

    #[test]
    fn handshake_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = VercelConnector::new();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req()).await.unwrap()
        })
        .unwrap();
        assert_eq!(r.status, "accepted");
        assert_eq!(r.capabilities_granted.len(), 3);
    }

    #[test]
    fn require_str_ok() {
        assert_eq!(
            VercelConnector::require_str(&json!({"k":"v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(VercelConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn health_unconfigured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            VercelConnector::new().health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = VercelConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
    }

    #[test]
    fn config_debug_redacts_token() {
        let cfg = VercelConfig {
            base_url: "https://api.vercel.com".into(),
            token: "super-secret".into(),
            team_id: None,
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug = format!("{cfg:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn config_with_team_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(json!({"token":"t","team_id":"team_abc"})).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn operations_correct_risk_levels() {
        let ops = operations_info();
        let find_op = |id: &str| ops.iter().find(|o| o.id.as_str() == id).unwrap();

        // Safe operations
        assert_eq!(find_op(OP_DEPLOYMENTS_LIST).safety_tier, SafetyTier::Safe);
        assert_eq!(find_op(OP_PROJECTS_LIST).safety_tier, SafetyTier::Safe);
        assert_eq!(find_op(OP_DOMAINS_LIST).safety_tier, SafetyTier::Safe);
        assert_eq!(find_op(OP_ENV_LIST).safety_tier, SafetyTier::Safe);
        assert_eq!(find_op(OP_HEALTH).safety_tier, SafetyTier::Safe);

        // Risky operations
        assert_eq!(find_op(OP_DEPLOYMENTS_CREATE).safety_tier, SafetyTier::Risky);
        assert_eq!(find_op(OP_PROJECTS_CREATE).safety_tier, SafetyTier::Risky);
        assert_eq!(find_op(OP_DOMAINS_ADD).safety_tier, SafetyTier::Risky);
        assert_eq!(find_op(OP_ENV_CREATE).safety_tier, SafetyTier::Risky);

        // Dangerous operations
        assert_eq!(find_op(OP_DEPLOYMENTS_DELETE).safety_tier, SafetyTier::Dangerous);
        assert_eq!(find_op(OP_PROJECTS_DELETE).safety_tier, SafetyTier::Dangerous);
        assert_eq!(find_op(OP_DOMAINS_REMOVE).safety_tier, SafetyTier::Dangerous);
        assert_eq!(find_op(OP_ENV_DELETE).safety_tier, SafetyTier::Dangerous);
    }

    #[test]
    fn operations_correct_capabilities() {
        let ops = operations_info();
        let find_op = |id: &str| ops.iter().find(|o| o.id.as_str() == id).unwrap();

        assert_eq!(find_op(OP_DEPLOYMENTS_LIST).capability.as_str(), CAP_DEPLOYMENTS_READ);
        assert_eq!(find_op(OP_DEPLOYMENTS_CREATE).capability.as_str(), CAP_DEPLOYMENTS_WRITE);
        assert_eq!(find_op(OP_PROJECTS_LIST).capability.as_str(), CAP_PROJECTS_READ);
        assert_eq!(find_op(OP_PROJECTS_DELETE).capability.as_str(), CAP_PROJECTS_WRITE);
        assert_eq!(find_op(OP_DOMAINS_LIST).capability.as_str(), CAP_DOMAINS_READ);
        assert_eq!(find_op(OP_DOMAINS_ADD).capability.as_str(), CAP_DOMAINS_WRITE);
        assert_eq!(find_op(OP_ENV_LIST).capability.as_str(), CAP_ENV_READ);
        assert_eq!(find_op(OP_ENV_CREATE).capability.as_str(), CAP_ENV_WRITE);
        assert_eq!(find_op(OP_HEALTH).capability.as_str(), CAP_PROJECTS_READ);
    }
}
