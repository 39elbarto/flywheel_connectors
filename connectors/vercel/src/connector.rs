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
use crate::types::VercelAuth;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_LIST_PROJECTS: &str = "vercel.projects.list";
const OP_GET_PROJECT: &str = "vercel.projects.get";
const OP_LIST_DEPLOYMENTS: &str = "vercel.deployments.list";
const OP_GET_DEPLOYMENT: &str = "vercel.deployments.get";
const OP_CREATE_DEPLOYMENT: &str = "vercel.deployments.create";
const OP_CANCEL_DEPLOYMENT: &str = "vercel.deployments.cancel";
const OP_LIST_DOMAINS: &str = "vercel.domains.list";
const OP_GET_DOMAIN: &str = "vercel.domains.get";
const OP_LIST_ENV_VARS: &str = "vercel.env.list";
const OP_SET_ENV_VAR: &str = "vercel.env.set";

const CAP_PROJECTS_READ: &str = "vercel.projects.read";
const CAP_DEPLOYMENTS_READ: &str = "vercel.deployments.read";
const CAP_DEPLOYMENTS_WRITE: &str = "vercel.deployments.write";
const CAP_DOMAINS_READ: &str = "vercel.domains.read";
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
                    "Team scope active".into()
                } else {
                    "Personal scope".into()
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
            related: related
                .into_iter()
                .map(CapabilityId::from_static)
                .collect(),
        }
    };
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_LIST_PROJECTS),
            summary: "List all Vercel projects".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_PROJECTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Get a list of all projects in the account",
                vec![],
                vec![],
                vec![CAP_DEPLOYMENTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_PROJECT),
            summary: "Get project details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PROJECTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Get details for a specific project by ID or name",
                vec!["Use project ID or name, not the deployment URL".into()],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_LIST_DEPLOYMENTS),
            summary: "List deployments for a project".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_DEPLOYMENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "See deployment history for a project",
                vec!["Requires project_id, not project name".into()],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_DEPLOYMENT),
            summary: "Get deployment details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["deployment_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DEPLOYMENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Check status or details of a specific deployment",
                vec!["Use deployment uid not URL".into()],
                vec![],
                vec![CAP_DEPLOYMENTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_CREATE_DEPLOYMENT),
            summary: "Trigger a new deployment".into(),
            description: None,
            input_schema: json!({"type":"object","required":["name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DEPLOYMENTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Create a new deployment for a project",
                vec!["Requires project name in body".into()],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_CANCEL_DEPLOYMENT),
            summary: "Cancel an in-progress deployment".into(),
            description: None,
            input_schema: json!({"type":"object","required":["deployment_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DEPLOYMENTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Cancel a deployment that is currently building",
                vec!["Only works on in-progress deployments".into()],
                vec![],
                vec![CAP_DEPLOYMENTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_LIST_DOMAINS),
            summary: "List all domains".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_DOMAINS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "See all domains in the account",
                vec![],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_DOMAIN),
            summary: "Get domain details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["domain_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DOMAINS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Get details about a specific domain",
                vec!["Use the full domain name".into()],
                vec![],
                vec![CAP_DOMAINS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_LIST_ENV_VARS),
            summary: "List environment variables for a project".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_ENV_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "See environment variables configured for a project",
                vec!["Values of encrypted vars may not be returned".into()],
                vec![],
                vec![CAP_PROJECTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_SET_ENV_VAR),
            summary: "Set an environment variable".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_id","key","value","target"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ENV_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Create or update an environment variable for a project",
                vec![
                    "target must be array like [\"production\", \"preview\"]".into(),
                    "Requires a new deployment to take effect".into(),
                ],
                vec![],
                vec![CAP_ENV_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
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
                OP_LIST_PROJECTS | OP_GET_PROJECT => {
                    CapabilityId::from_static(CAP_PROJECTS_READ)
                }
                OP_LIST_DEPLOYMENTS | OP_GET_DEPLOYMENT => {
                    CapabilityId::from_static(CAP_DEPLOYMENTS_READ)
                }
                OP_CREATE_DEPLOYMENT | OP_CANCEL_DEPLOYMENT => {
                    CapabilityId::from_static(CAP_DEPLOYMENTS_WRITE)
                }
                OP_LIST_DOMAINS | OP_GET_DOMAIN => {
                    CapabilityId::from_static(CAP_DOMAINS_READ)
                }
                OP_LIST_ENV_VARS => CapabilityId::from_static(CAP_ENV_READ),
                OP_SET_ENV_VAR => CapabilityId::from_static(CAP_ENV_WRITE),
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
            OP_LIST_PROJECTS => {
                let projects = client
                    .list_projects(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&projects).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_GET_PROJECT => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let project = client
                    .get_project(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&project).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_LIST_DEPLOYMENTS => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let deployments = client
                    .list_deployments(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&deployments).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_GET_DEPLOYMENT => {
                let did = Self::require_str(&req.input, "deployment_id")?;
                let deployment = client
                    .get_deployment(runtime, did)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&deployment).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_CREATE_DEPLOYMENT => {
                let body = req.input.clone();
                let deployment = client
                    .create_deployment(runtime, &body)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&deployment).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_CANCEL_DEPLOYMENT => {
                let did = Self::require_str(&req.input, "deployment_id")?;
                let deployment = client
                    .cancel_deployment(runtime, did)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&deployment).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_LIST_DOMAINS => {
                let domains = client
                    .list_domains(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&domains).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_GET_DOMAIN => {
                let name = Self::require_str(&req.input, "domain_name")?;
                let domain = client
                    .get_domain(runtime, name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&domain).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_LIST_ENV_VARS => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let envs = client
                    .list_env_vars(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&envs).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_SET_ENV_VAR => {
                let pid = Self::require_str(&req.input, "project_id")?;
                let key = Self::require_str(&req.input, "key")?;
                let value = Self::require_str(&req.input, "value")?;
                let target = req
                    .input
                    .get("target")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| vec!["production".into(), "preview".into(), "development".into()]);
                let env_type = req
                    .input
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("encrypted");
                let body = json!({
                    "key": key,
                    "value": value,
                    "target": target,
                    "type": env_type,
                });
                let env_var = client
                    .set_env_var(runtime, pid, &body)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&env_var).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
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
        json!({"token": "test-token"})
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_PROJECTS_READ),
                CapabilityId::from_static(CAP_DEPLOYMENTS_READ),
                CapabilityId::from_static(CAP_DEPLOYMENTS_WRITE),
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
    fn configure_with_team() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(json!({"token": "t", "team_id": "team_abc"}))
                    .await
            })
            .unwrap()
            .is_ok()
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
    fn configure_empty_base_url() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(json!({"token": "t", "base_url": ""})).await
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
        assert_eq!(VercelConnector::new().introspect().operations.len(), 10);
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
    fn env_write_needs_approval() {
        let ops = operations_info();
        let set_env = ops
            .iter()
            .find(|o| o.id.as_str() == OP_SET_ENV_VAR)
            .unwrap();
        assert!(set_env.requires_approval.is_some());
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
    fn invoke_missing_project_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_GET_PROJECT, json!({}))).await
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
                    OperationId::from_static(OP_LIST_PROJECTS),
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
    fn unsubscribe_unsupported() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                VercelConnector::new()
                    .unsubscribe(UnsubscribeRequest {
                        r#type: "unsubscribe".into(),
                        id: RequestId::new("unsub1"),
                        topics: vec![],
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
            token: "my-secret-token".into(),
            team_id: None,
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug = format!("{cfg:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("my-secret"));
    }

    #[test]
    fn invoke_list_deployments_missing_project() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_LIST_DEPLOYMENTS, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_get_deployment_missing_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_GET_DEPLOYMENT, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_set_env_var_missing_key() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = VercelConnector::new();
                c.configure(tc()).await.unwrap();
                let mut hr = handshake_req();
                hr.capabilities_requested.push(CapabilityId::from_static(CAP_ENV_WRITE));
                c.handshake(hr).await.unwrap();
                c.invoke(invoke_req(OP_SET_ENV_VAR, json!({"project_id": "p"}))).await
            })
            .unwrap()
            .is_err()
        );
    }
}
