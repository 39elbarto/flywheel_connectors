//! Netlify connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use reqwest::Url;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::NetlifyClient;
use crate::types::{
    CreateDeployRequest, CreateSiteRequest, NetlifyAuth, SetEnvVarRequest, SetEnvVarValue,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const NETLIFY_ALLOWED_HOSTS: &[&str] = &["api.netlify.com"];

const OP_SITES_LIST: &str = "netlify.sites.list";
const OP_SITES_GET: &str = "netlify.sites.get";
const OP_SITES_CREATE: &str = "netlify.sites.create";
const OP_SITES_DELETE: &str = "netlify.sites.delete";
const OP_DEPLOYS_LIST: &str = "netlify.deploys.list";
const OP_DEPLOYS_GET: &str = "netlify.deploys.get";
const OP_DEPLOYS_CREATE: &str = "netlify.deploys.create";
const OP_DEPLOYS_ROLLBACK: &str = "netlify.deploys.rollback";
const OP_DNS_LIST_ZONES: &str = "netlify.dns.list_zones";
const OP_ENV_LIST: &str = "netlify.env.list";
const OP_ENV_SET: &str = "netlify.env.set";
const OP_ENV_DELETE: &str = "netlify.env.delete";
const OP_HEALTH: &str = "netlify.health";

const CAP_SITES_READ: &str = "netlify.sites.read";
const CAP_SITES_WRITE: &str = "netlify.sites.write";
const CAP_DEPLOYS_READ: &str = "netlify.deploys.read";
const CAP_DEPLOYS_WRITE: &str = "netlify.deploys.write";
const CAP_DNS_READ: &str = "netlify.dns.read";
const CAP_ENV_READ: &str = "netlify.env.read";
const CAP_ENV_WRITE: &str = "netlify.env.write";

#[derive(Clone, serde::Deserialize)]
pub struct NetlifyConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(flatten)]
    pub auth: NetlifyAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub account_slug: Option<String>,
}
fn default_base_url() -> String {
    "https://api.netlify.com".into()
}
const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for NetlifyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetlifyConfig")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .finish()
    }
}

impl NetlifyConfig {
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

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            secret_material_configured: !self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
            allowed_hosts: NETLIFY_ALLOWED_HOSTS.to_vec(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    secret_material_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    base_url: String,
    allowed_hosts: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub status: DoctorStatus,
    pub checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
}

#[derive(Debug, Clone, Serialize)]
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
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self {
            ready,
            status,
            checks,
            provisioning,
        }
    }
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.ends_with(".localhost")
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(url) => url,
        Err(error) => return (false, format!("base_url must be an absolute URL: {error}")),
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    if is_local_test_host(host) {
        return (
            true,
            format!("localhost test endpoint accepted: {base_url}"),
        );
    }

    let mut problems = Vec::new();
    if parsed.scheme() != "https" {
        problems.push(format!("scheme must be https, got {}", parsed.scheme()));
    }
    if !NETLIFY_ALLOWED_HOSTS.contains(&host) {
        problems.push(format!(
            "host must be one of {:?}, got {host}",
            NETLIFY_ALLOWED_HOSTS
        ));
    }

    if problems.is_empty() {
        (true, "Netlify production API endpoint accepted".into())
    } else {
        (false, problems.join("; "))
    }
}

#[derive(Debug)]
pub struct NetlifyConnector {
    base: BaseConnector,
    config: Option<NetlifyConfig>,
    client: Option<NetlifyClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl NetlifyConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.netlify")),
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
        let provisioning = self
            .config
            .as_ref()
            .map(NetlifyConfig::provisioning_readiness);
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                None
            } else {
                Some("Not configured; run configure first".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_some() {
                None
            } else {
                Some("HTTP client not initialized; re-run configure".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "runtime_initialized".into(),
            passed: self.runtime.is_some(),
            message: if self.runtime.is_some() {
                None
            } else {
                Some("ConnectorRuntime not initialized; re-run configure".into())
            },
            critical: true,
        });
        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: readiness.network_ok,
                message: Some(readiness.network_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "secret_material".into(),
                passed: readiness.secret_material_configured,
                message: Some(if readiness.secret_material_configured {
                    "Access token configured".into()
                } else {
                    "Access token omitted; inject at runtime".into()
                }),
                critical: false,
            });
        }
        DoctorResult::from_checks(checks, provisioning)
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value =
            input
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Missing: {key}"),
                })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }
}

impl Default for NetlifyConnector {
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
            id: OperationId::from_static(OP_SITES_LIST),
            summary: "List all sites".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_SITES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint("List Netlify sites", vec![], vec![], vec![CAP_DEPLOYS_READ]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_SITES_GET),
            summary: "Get site details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["site_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_SITES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get info about a specific site",
                vec!["Use site_id not site name".into()],
                vec![],
                vec![CAP_SITES_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_SITES_CREATE),
            summary: "Create a new site".into(),
            description: None,
            input_schema: json!({"type":"object","required":["name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_SITES_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Create new Netlify site",
                vec![],
                vec![],
                vec![CAP_SITES_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_SITES_DELETE),
            summary: "Delete a site".into(),
            description: None,
            input_schema: json!({"type":"object","required":["site_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_SITES_WRITE),
            risk_level: RiskLevel::Critical,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently delete site and all deploys",
                vec!["Irreversible".into()],
                vec![],
                vec![CAP_SITES_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DEPLOYS_LIST),
            summary: "List deploys for a site".into(),
            description: None,
            input_schema: json!({"type":"object","required":["site_id"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_DEPLOYS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint("See deploy history", vec![], vec![], vec![CAP_SITES_READ]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DEPLOYS_GET),
            summary: "Get deploy details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["site_id","deploy_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DEPLOYS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Check deploy status",
                vec![],
                vec![],
                vec![CAP_DEPLOYS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DEPLOYS_CREATE),
            summary: "Create a deploy".into(),
            description: None,
            input_schema: json!({"type":"object","required":["site_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DEPLOYS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Trigger new deploy",
                vec!["Affects live site".into()],
                vec![],
                vec![CAP_DEPLOYS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DEPLOYS_ROLLBACK),
            summary: "Rollback to a deploy".into(),
            description: None,
            input_schema: json!({"type":"object","required":["site_id","deploy_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DEPLOYS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Rollback site to a previous deploy",
                vec!["Changes live site".into()],
                vec![],
                vec![CAP_DEPLOYS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DNS_LIST_ZONES),
            summary: "List DNS zones".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_DNS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint("List Netlify DNS zones", vec![], vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_ENV_LIST),
            summary: "List environment variables".into(),
            description: None,
            input_schema: json!({"type":"object","required":["site_id","account_slug"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_ENV_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List env vars for a site",
                vec!["Requires account_slug".into()],
                vec![],
                vec![CAP_ENV_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_ENV_SET),
            summary: "Set environment variable".into(),
            description: None,
            input_schema: json!({"type":"object","required":["site_id","account_slug","key","value"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ENV_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Set or update env var",
                vec!["May trigger rebuild".into()],
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
            input_schema: json!({"type":"object","required":["site_id","account_slug","key"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ENV_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Remove env var (may break builds)",
                vec!["Verify key first".into()],
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
            capability: CapabilityId::from_static(CAP_SITES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Check credentials", vec![], vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

fcp_core::impl_fcp_sealed!(NetlifyConnector);

#[async_trait]
impl FcpConnector for NetlifyConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = NetlifyConfig::from_value(config)?;
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        ));
        let client = NetlifyClient::new(&cfg.base_url, cfg.auth.clone(), cfg.retry.clone())
            .await
            .map_err(|e| FcpError::Internal {
                message: format!("Client init: {e}"),
            })?;
        self.client = Some(client);
        self.config = Some(cfg);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!(event = "netlify.configure", "Configured Netlify connector");
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
        let provisioning = self
            .config
            .as_ref()
            .map(NetlifyConfig::provisioning_readiness);
        let mut snap = match &provisioning {
            Some(readiness) if !readiness.network_ok => {
                HealthSnapshot::error("network constraints invalid")
            }
            Some(readiness) if readiness.requires_credential_injection => {
                HealthSnapshot::degraded("credential injection required")
            }
            Some(_) => HealthSnapshot::ready(),
            None => HealthSnapshot::degraded("not configured"),
        };
        snap.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snap.details = Some(json!({
            "configured": self.config.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
        }));
        snap
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };
        let provisioning = config.provisioning_readiness();

        if !provisioning.network_ok {
            return Ok(SelfCheckReport::failed(
                "network_constraints_invalid",
                provisioning.network_message.clone(),
            ));
        }

        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::failed(
                "client_missing",
                "HTTP client not initialized",
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(SelfCheckReport::failed(
                "runtime_missing",
                "ConnectorRuntime not initialized",
            ));
        };

        if provisioning.requires_credential_injection {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Access token omitted; inject at runtime",
            ));
        }

        let report = match client.health_check(runtime).await {
            Ok(_user) => SelfCheckReport::ok(),
            Err(error) if error.is_retryable() => {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            }
            Err(error) => SelfCheckReport::failed("self_check_failed", error.to_string()),
        };
        Ok(report)
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

impl NetlifyConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_SITES_LIST | OP_SITES_GET | OP_HEALTH => {
                    CapabilityId::from_static(CAP_SITES_READ)
                }
                OP_SITES_CREATE | OP_SITES_DELETE => CapabilityId::from_static(CAP_SITES_WRITE),
                OP_DEPLOYS_LIST | OP_DEPLOYS_GET => CapabilityId::from_static(CAP_DEPLOYS_READ),
                OP_DEPLOYS_CREATE | OP_DEPLOYS_ROLLBACK => {
                    CapabilityId::from_static(CAP_DEPLOYS_WRITE)
                }
                OP_DNS_LIST_ZONES => CapabilityId::from_static(CAP_DNS_READ),
                OP_ENV_LIST => CapabilityId::from_static(CAP_ENV_READ),
                OP_ENV_SET | OP_ENV_DELETE => CapabilityId::from_static(CAP_ENV_WRITE),
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            };
            // dja9u.1.c: typestate handoff via verify_bound.
            let _bound = verifier.verify_bound(req.capability_token, &cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Netlify client".into(),
        })?;

        let output = match operation {
            OP_SITES_LIST => {
                let sites = client
                    .list_sites(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&sites).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_SITES_GET => {
                let site_id = Self::require_str(&req.input, "site_id")?;
                let site = client
                    .get_site(runtime, site_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&site).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_SITES_CREATE => {
                let name = Self::require_str(&req.input, "name")?;
                let create_req = CreateSiteRequest {
                    name: name.into(),
                    custom_domain: req
                        .input
                        .get("custom_domain")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };
                let site = client
                    .create_site(runtime, &create_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&site).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_SITES_DELETE => {
                let site_id = Self::require_str(&req.input, "site_id")?;
                client
                    .delete_site(runtime, site_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"deleted": true, "site_id": site_id})
            }
            OP_DEPLOYS_LIST => {
                let site_id = Self::require_str(&req.input, "site_id")?;
                let deploys = client
                    .list_deploys(runtime, site_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&deploys).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DEPLOYS_GET => {
                let site_id = Self::require_str(&req.input, "site_id")?;
                let deploy_id = Self::require_str(&req.input, "deploy_id")?;
                let deploy = client
                    .get_deploy(runtime, site_id, deploy_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&deploy).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DEPLOYS_CREATE => {
                let site_id = Self::require_str(&req.input, "site_id")?;
                let deploy_req = CreateDeployRequest {
                    branch: req
                        .input
                        .get("branch")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    title: req
                        .input
                        .get("title")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };
                let deploy = client
                    .create_deploy(runtime, site_id, &deploy_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&deploy).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DEPLOYS_ROLLBACK => {
                let site_id = Self::require_str(&req.input, "site_id")?;
                let deploy_id = Self::require_str(&req.input, "deploy_id")?;
                let deploy = client
                    .rollback_deploy(runtime, site_id, deploy_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&deploy).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DNS_LIST_ZONES => {
                let zones = client
                    .list_dns_zones(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&zones).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ENV_LIST => {
                let site_id = Self::require_str(&req.input, "site_id")?;
                let account_slug = Self::require_str(&req.input, "account_slug")?;
                let envs = client
                    .list_env_vars(runtime, account_slug, site_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&envs).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ENV_SET => {
                let site_id = Self::require_str(&req.input, "site_id")?;
                let account_slug = Self::require_str(&req.input, "account_slug")?;
                let key = Self::require_str(&req.input, "key")?;
                let value = Self::require_str(&req.input, "value")?;
                let context = req
                    .input
                    .get("context")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let is_secret = req.input.get("is_secret").and_then(|v| v.as_bool());
                let set_req = vec![SetEnvVarRequest {
                    key: key.into(),
                    values: vec![SetEnvVarValue {
                        value: value.into(),
                        context,
                    }],
                    scopes: None,
                    is_secret,
                }];
                let envs = client
                    .set_env_var(runtime, account_slug, site_id, &set_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&envs).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ENV_DELETE => {
                let site_id = Self::require_str(&req.input, "site_id")?;
                let account_slug = Self::require_str(&req.input, "account_slug")?;
                let key = Self::require_str(&req.input, "key")?;
                client
                    .delete_env_var(runtime, account_slug, site_id, key)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"deleted": true, "key": key})
            }
            OP_HEALTH => {
                let user = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"healthy": true, "user_id": user.id, "email": user.email})
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

    #[test]
    fn connector_id() {
        let c = NetlifyConnector::new();
        assert_eq!(c.id().as_str(), "fcp.netlify");
    }

    #[test]
    fn default_matches_new() {
        let c1 = NetlifyConnector::new();
        let c2 = NetlifyConnector::default();
        assert_eq!(c1.id(), c2.id());
    }

    #[test]
    fn operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 13);
    }

    #[test]
    fn operations_have_unique_ids() {
        let ops = operations_info();
        let mut ids: Vec<_> = ops.iter().map(|o| o.id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 13);
    }

    #[test]
    fn sites_list_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|o| o.id.as_str() == OP_SITES_LIST).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn sites_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_str() == OP_SITES_DELETE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Dangerous);
        assert_eq!(op.risk_level, RiskLevel::Critical);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn sites_create_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_str() == OP_SITES_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn deploys_create_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_str() == OP_DEPLOYS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::High);
    }

    #[test]
    fn env_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops.iter().find(|o| o.id.as_str() == OP_ENV_DELETE).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Dangerous);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn health_op_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|o| o.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn introspect_returns_operations() {
        let c = NetlifyConnector::new();
        let intro = c.introspect();
        assert_eq!(intro.operations.len(), 13);
        assert!(intro.events.is_empty());
    }

    #[test]
    fn introspect_event_caps() {
        let c = NetlifyConnector::new();
        let intro = c.introspect();
        let ec = intro.event_caps.unwrap();
        assert!(!ec.streaming);
        assert!(!ec.replay);
    }

    #[test]
    fn doctor_unconfigured_is_unhealthy() {
        let c = NetlifyConnector::new();
        let result = c.doctor();
        assert!(!result.ready);
        assert!(matches!(result.status, DoctorStatus::Unhealthy));
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let h1 = NetlifyConnector::manifest_hash();
        let h2 = NetlifyConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn base_url_policy_accepts_production() {
        let (ok, _msg) = base_url_policy("https://api.netlify.com");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http() {
        let (ok, msg) = base_url_policy("http://api.netlify.com");
        assert!(!ok);
        assert!(msg.contains("https"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _msg) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, msg) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(msg.contains("evil.example.com"));
    }

    #[test]
    fn config_validates_empty_base_url() {
        let val = serde_json::json!({
            "access_token": "tok",
            "base_url": ""
        });
        let result = NetlifyConfig::from_value(val);
        assert!(result.is_err());
    }

    #[test]
    fn config_from_value_valid() {
        let val = serde_json::json!({
            "access_token": "nfp_abc123",
            "base_url": "https://api.netlify.com"
        });
        let config = NetlifyConfig::from_value(val).unwrap();
        assert_eq!(config.base_url, "https://api.netlify.com");
        assert!(!config.auth.is_secretless());
    }

    #[test]
    fn config_default_base_url() {
        let val = serde_json::json!({
            "access_token": "nfp_abc123"
        });
        let config = NetlifyConfig::from_value(val).unwrap();
        assert_eq!(config.base_url, "https://api.netlify.com");
    }

    #[test]
    fn provisioning_readiness_with_token() {
        let val = serde_json::json!({
            "access_token": "nfp_abc123"
        });
        let config = NetlifyConfig::from_value(val).unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.secret_material_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_without_token() {
        let val = serde_json::json!({
            "access_token": ""
        });
        let config = NetlifyConfig::from_value(val).unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.secret_material_configured);
        assert!(readiness.requires_credential_injection);
    }

    #[test]
    fn require_str_missing_key() {
        let input = json!({});
        let result = NetlifyConnector::require_str(&input, "site_id");
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"site_id": "abc"});
        let result = NetlifyConnector::require_str(&input, "site_id");
        assert_eq!(result.unwrap(), "abc");
    }

    #[test]
    fn require_str_empty() {
        assert!(NetlifyConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(NetlifyConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }

    #[test]
    fn dns_list_zones_is_safe() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_str() == OP_DNS_LIST_ZONES)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.capability, CapabilityId::from_static(CAP_DNS_READ));
    }

    #[test]
    fn env_set_is_risky() {
        let ops = operations_info();
        let op = ops.iter().find(|o| o.id.as_str() == OP_ENV_SET).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn deploys_rollback_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_str() == OP_DEPLOYS_ROLLBACK)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::High);
    }

    #[test]
    fn health_configured_but_secretless() {
        let c = NetlifyConnector::new();
        let snap = fcp_async_core::runtime::block_on_sync(c.health()).unwrap();
        // Not configured → degraded
        assert_eq!(snap.status.as_str(), "degraded");
    }

    #[test]
    fn self_check_unconfigured() {
        let c = NetlifyConnector::new();
        let report = fcp_async_core::runtime::block_on_sync(c.self_check())
            .unwrap()
            .unwrap();
        assert_eq!(report.reason_code.as_deref(), Some("not_configured"));
    }

    #[test]
    fn simulate_returns_allowed() {
        use fcp_prelude::{CapabilityToken, ZoneId};
        let c = NetlifyConnector::new();
        let req = SimulateRequest::new(
            ConnectorId::from_static("fcp.netlify"),
            OperationId::from_static(OP_SITES_LIST),
            ZoneId::try_from("z:work".to_string()).unwrap(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let req_id = req.id.clone();
        let resp = fcp_async_core::runtime::block_on_sync(c.simulate(req))
            .unwrap()
            .unwrap();
        assert_eq!(resp.id, req_id);
    }

    #[test]
    fn shutdown_clears_state() {
        let mut c = NetlifyConnector::new();
        let req = ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 5000,
            drain: false,
            reason: Some("test".into()),
        };
        let result = fcp_async_core::runtime::block_on_sync(c.shutdown(req)).unwrap();
        assert!(result.is_ok());
        assert!(!c.base.configured.load(Ordering::Acquire));
    }

    #[test]
    fn metrics_initial_state() {
        let c = NetlifyConnector::new();
        let m = c.metrics();
        assert_eq!(m.requests_total, 0);
        assert_eq!(m.requests_error, 0);
    }
}
