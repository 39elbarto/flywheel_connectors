//! Cloudflare connector implementation.

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

use crate::client::CloudflareClient;
use crate::types::{CloudflareAuth, CreateDnsRecord, UpdateDnsRecord};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_ZONES_LIST: &str = "cloudflare.zones.list";
const OP_HEALTH: &str = "cloudflare.health";
const OP_DNS_LIST: &str = "cloudflare.dns.list_records";
const OP_DNS_CREATE: &str = "cloudflare.dns.create_record";
const OP_DNS_UPDATE: &str = "cloudflare.dns.update_record";
const OP_DNS_DELETE: &str = "cloudflare.dns.delete_record";
const OP_WORKERS_LIST: &str = "cloudflare.workers.list";
const OP_WORKERS_GET: &str = "cloudflare.workers.get";
const OP_WORKERS_DEPLOY: &str = "cloudflare.workers.deploy";
const OP_WORKERS_DELETE: &str = "cloudflare.workers.delete";
const OP_PAGES_LIST: &str = "cloudflare.pages.list_projects";
const OP_PAGES_DEPLOY: &str = "cloudflare.pages.create_deployment";
const OP_KV_GET: &str = "cloudflare.kv.get";
const OP_KV_PUT: &str = "cloudflare.kv.put";
const OP_KV_DELETE: &str = "cloudflare.kv.delete";

const CAP_ZONES_READ: &str = "cloudflare.zones.read";
const CAP_DNS_READ: &str = "cloudflare.dns.read";
const CAP_DNS_WRITE: &str = "cloudflare.dns.write";
const CAP_WORKERS_READ: &str = "cloudflare.workers.read";
const CAP_WORKERS_WRITE: &str = "cloudflare.workers.write";
const CAP_PAGES_READ: &str = "cloudflare.pages.read";
const CAP_PAGES_WRITE: &str = "cloudflare.pages.write";
const CAP_KV_READ: &str = "cloudflare.kv.read";
const CAP_KV_WRITE: &str = "cloudflare.kv.write";

#[derive(Clone, serde::Deserialize)]
pub struct CloudflareConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    pub account_id: String,
    #[serde(flatten)]
    pub auth: CloudflareAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}
fn default_base_url() -> String {
    "https://api.cloudflare.com/client/v4".into()
}
const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for CloudflareConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareConfig")
            .field("base_url", &self.base_url)
            .field("account_id", &self.account_id)
            .field("auth", &self.auth)
            .finish()
    }
}

impl CloudflareConfig {
    fn validate(&self) -> Result<(), String> {
        if self.account_id.is_empty() {
            return Err("account_id is required".into());
        }
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
pub struct CloudflareConnector {
    base: BaseConnector,
    config: Option<CloudflareConfig>,
    client: Option<CloudflareClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl CloudflareConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.cloudflare")),
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
                name: "account_id".into(),
                passed: !cfg.account_id.is_empty(),
                message: Some("Account ID present".into()),
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

impl Default for CloudflareConnector {
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
            id: OperationId::from_static(OP_ZONES_LIST),
            summary: "List all zones".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_ZONES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Get zone IDs", vec![], vec![], vec![CAP_DNS_READ]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Verify API token".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ZONES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Check credentials", vec![], vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DNS_LIST),
            summary: "List DNS records for a zone".into(),
            description: None,
            input_schema: json!({"type":"object","required":["zone_id"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_DNS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "See existing DNS records",
                vec!["Use zone ID not domain name".into()],
                vec![],
                vec![CAP_ZONES_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DNS_CREATE),
            summary: "Create DNS record".into(),
            description: None,
            input_schema: json!({"type":"object","required":["zone_id","type","name","content"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DNS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Add new DNS record",
                vec!["MX needs priority".into()],
                vec![],
                vec![CAP_DNS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DNS_UPDATE),
            summary: "Update DNS record".into(),
            description: None,
            input_schema: json!({"type":"object","required":["zone_id","record_id","type","name","content"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DNS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Modify existing DNS record",
                vec![],
                vec![],
                vec![CAP_DNS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DNS_DELETE),
            summary: "Delete DNS record".into(),
            description: None,
            input_schema: json!({"type":"object","required":["zone_id","record_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DNS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Remove DNS record (irreversible)",
                vec!["Verify record_id first".into()],
                vec![],
                vec![CAP_DNS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WORKERS_LIST),
            summary: "List Workers scripts".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_WORKERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Discover deployed Workers", vec![], vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_WORKERS_GET),
            summary: "Get Worker details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["script_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WORKERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Check if Worker exists",
                vec![],
                vec![],
                vec![CAP_WORKERS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_WORKERS_DEPLOY),
            summary: "Deploy Workers script".into(),
            description: None,
            input_schema: json!({"type":"object","required":["script_name","script_content"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WORKERS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Deploy or update Worker",
                vec!["Test before deploying".into()],
                vec![],
                vec![CAP_WORKERS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_WORKERS_DELETE),
            summary: "Delete Workers script".into(),
            description: None,
            input_schema: json!({"type":"object","required":["script_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WORKERS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently remove Worker",
                vec!["May still serve traffic".into()],
                vec![],
                vec![CAP_WORKERS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAGES_LIST),
            summary: "List Pages projects".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_PAGES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("See Pages projects", vec![], vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAGES_DEPLOY),
            summary: "Trigger Pages deployment".into(),
            description: None,
            input_schema: json!({"type":"object","required":["project_name","branch"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PAGES_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Deploy Pages from branch",
                vec!["Branch must exist".into()],
                vec![],
                vec![CAP_PAGES_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_KV_GET),
            summary: "Read KV value".into(),
            description: None,
            input_schema: json!({"type":"object","required":["namespace_id","key"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_KV_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Read from KV",
                vec!["Check namespace ID".into()],
                vec![],
                vec![CAP_KV_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_KV_PUT),
            summary: "Write KV value".into(),
            description: None,
            input_schema: json!({"type":"object","required":["namespace_id","key","value"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_KV_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Store data in KV",
                vec!["Eventually consistent".into()],
                vec![],
                vec![CAP_KV_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_KV_DELETE),
            summary: "Delete KV key".into(),
            description: None,
            input_schema: json!({"type":"object","required":["namespace_id","key"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_KV_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Remove KV entry (irreversible)",
                vec!["Workers may depend on key".into()],
                vec![],
                vec![CAP_KV_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
    ]
}

#[async_trait]
impl FcpConnector for CloudflareConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cf = CloudflareConfig::from_value(config)?;
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cf.request_timeout_ms)),
        ));
        let client = CloudflareClient::new(
            &cf.base_url,
            cf.auth.clone(),
            &cf.account_id,
            cf.retry.clone(),
        )
        .await
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?;
        self.client = Some(client);
        self.config = Some(cf);
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
            Ok(v) if v.status == "active" => Ok(SelfCheckReport::ok()),
            Ok(v) => Ok(SelfCheckReport::degraded(
                "token_inactive",
                format!("Token status: {}", v.status),
            )),
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

impl CloudflareConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_ZONES_LIST | OP_HEALTH => CapabilityId::from_static(CAP_ZONES_READ),
                OP_DNS_LIST => CapabilityId::from_static(CAP_DNS_READ),
                OP_DNS_CREATE | OP_DNS_UPDATE | OP_DNS_DELETE => {
                    CapabilityId::from_static(CAP_DNS_WRITE)
                }
                OP_WORKERS_LIST | OP_WORKERS_GET => CapabilityId::from_static(CAP_WORKERS_READ),
                OP_WORKERS_DEPLOY | OP_WORKERS_DELETE => {
                    CapabilityId::from_static(CAP_WORKERS_WRITE)
                }
                OP_PAGES_LIST => CapabilityId::from_static(CAP_PAGES_READ),
                OP_PAGES_DEPLOY => CapabilityId::from_static(CAP_PAGES_WRITE),
                OP_KV_GET => CapabilityId::from_static(CAP_KV_READ),
                OP_KV_PUT | OP_KV_DELETE => CapabilityId::from_static(CAP_KV_WRITE),
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
            message: "connector ready state missing Cloudflare client".into(),
        })?;

        let output = match operation {
            OP_ZONES_LIST => {
                let z = client
                    .list_zones(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&z).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_HEALTH => {
                let i = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"status": i.status, "token_id": i.id, "healthy": i.status == "active"})
            }
            OP_DNS_LIST => {
                let zid = Self::require_str(&req.input, "zone_id")?;
                let r = client
                    .list_dns_records(runtime, zid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DNS_CREATE => {
                let zid = Self::require_str(&req.input, "zone_id")?;
                let rec = CreateDnsRecord {
                    record_type: Self::require_str(&req.input, "type")?.into(),
                    name: Self::require_str(&req.input, "name")?.into(),
                    content: Self::require_str(&req.input, "content")?.into(),
                    proxied: req.input.get("proxied").and_then(|v| v.as_bool()),
                    ttl: req
                        .input
                        .get("ttl")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    priority: req
                        .input
                        .get("priority")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u16),
                    comment: req
                        .input
                        .get("comment")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };
                let r = client
                    .create_dns_record(runtime, zid, &rec)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DNS_UPDATE => {
                let zid = Self::require_str(&req.input, "zone_id")?;
                let rid = Self::require_str(&req.input, "record_id")?;
                let rec = UpdateDnsRecord {
                    record_type: Self::require_str(&req.input, "type")?.into(),
                    name: Self::require_str(&req.input, "name")?.into(),
                    content: Self::require_str(&req.input, "content")?.into(),
                    proxied: req.input.get("proxied").and_then(|v| v.as_bool()),
                    ttl: req
                        .input
                        .get("ttl")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    comment: req
                        .input
                        .get("comment")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };
                let r = client
                    .update_dns_record(runtime, zid, rid, &rec)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DNS_DELETE => {
                let zid = Self::require_str(&req.input, "zone_id")?;
                let rid = Self::require_str(&req.input, "record_id")?;
                client
                    .delete_dns_record(runtime, zid, rid)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_WORKERS_LIST => {
                let w = client
                    .list_workers(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&w).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_WORKERS_GET => {
                let n = Self::require_str(&req.input, "script_name")?;
                let w = client
                    .get_worker(runtime, n)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&w).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_WORKERS_DEPLOY => {
                let n = Self::require_str(&req.input, "script_name")?;
                let c = Self::require_str(&req.input, "script_content")?;
                let r = client
                    .deploy_worker(runtime, n, c)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_WORKERS_DELETE => {
                let n = Self::require_str(&req.input, "script_name")?;
                client
                    .delete_worker(runtime, n)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_PAGES_LIST => {
                let p = client
                    .list_pages_projects(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&p).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PAGES_DEPLOY => {
                let p = Self::require_str(&req.input, "project_name")?;
                let b = Self::require_str(&req.input, "branch")?;
                let r = client
                    .create_pages_deployment(runtime, p, b)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_KV_GET => {
                let ns = Self::require_str(&req.input, "namespace_id")?;
                let k = Self::require_str(&req.input, "key")?;
                let v = client
                    .kv_get(runtime, ns, k)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"value": v})
            }
            OP_KV_PUT => {
                let ns = Self::require_str(&req.input, "namespace_id")?;
                let k = Self::require_str(&req.input, "key")?;
                let v = Self::require_str(&req.input, "value")?;
                client
                    .kv_put(runtime, ns, k, v)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_KV_DELETE => {
                let ns = Self::require_str(&req.input, "namespace_id")?;
                let k = Self::require_str(&req.input, "key")?;
                client
                    .kv_delete(runtime, ns, k)
                    .await
                    .map_err(|e| e.to_fcp_error())?
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
        json!({"mode": "api_token", "api_token": "t", "account_id": "a"})
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_ZONES_READ),
                CapabilityId::from_static(CAP_DNS_READ),
                CapabilityId::from_static(CAP_DNS_WRITE),
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
            connector_id: ConnectorId::from_static("fcp.cloudflare"),
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
        assert!(CloudflareConnector::new().config.is_none());
    }
    #[test]
    fn default_ok() {
        assert!(CloudflareConnector::default().config.is_none());
    }
    #[test]
    fn manifest_hash_stable() {
        assert_eq!(
            CloudflareConnector::manifest_hash(),
            CloudflareConnector::manifest_hash()
        );
    }
    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }
    #[test]
    fn configure_empty_account() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!({"mode":"api_token","api_token":"t","account_id":""}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn configure_bad() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn doctor_unconfigured() {
        assert!(!CloudflareConnector::new().doctor().passed);
    }
    #[test]
    fn doctor_configured() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(tc()).await.unwrap();
                c.doctor()
            })
            .unwrap()
            .passed
        );
    }
    #[test]
    fn introspect_ops() {
        assert_eq!(CloudflareConnector::new().introspect().operations.len(), 15);
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
                let mut c = CloudflareConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("cf.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn invoke_missing_zone() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_DNS_LIST, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            CloudflareConnector::new()
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.cloudflare"),
                    OperationId::from_static(OP_ZONES_LIST),
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
                CloudflareConnector::new()
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
            let mut c = CloudflareConnector::new();
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
            let mut c = CloudflareConnector::new();
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
            CloudflareConnector::require_str(&json!({"k":"v"}), "k").unwrap(),
            "v"
        );
    }
    #[test]
    fn require_str_miss() {
        assert!(CloudflareConnector::require_str(&json!({}), "k").is_err());
    }
    #[test]
    fn api_key_auth() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!({"mode":"api_key","api_key":"k","email":"u@e","account_id":"a"}))
                    .await
            })
            .unwrap()
            .is_ok()
        );
    }
    #[test]
    fn health_unconfigured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            CloudflareConnector::new().health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }
    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = CloudflareConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
    }
}
