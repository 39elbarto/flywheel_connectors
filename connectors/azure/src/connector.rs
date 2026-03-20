//! Azure connector implementation.

use std::sync::atomic::Ordering;
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
use reqwest::Url;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::AzureClient;
use crate::types::AzureAuth;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const AZURE_ALLOWED_HOSTS: &[&str] = &[
    "management.azure.com",
    "blob.core.windows.net",
];

// ── Operation IDs ──

const OP_VM_LIST: &str = "azure.vm.list";
const OP_VM_GET: &str = "azure.vm.get";
const OP_VM_START: &str = "azure.vm.start";
const OP_VM_STOP: &str = "azure.vm.stop";
const OP_VM_DELETE: &str = "azure.vm.delete";
const OP_STORAGE_LIST_CONTAINERS: &str = "azure.storage.list_containers";
const OP_STORAGE_UPLOAD_BLOB: &str = "azure.storage.upload_blob";
const OP_STORAGE_DOWNLOAD_BLOB: &str = "azure.storage.download_blob";
const OP_STORAGE_DELETE_BLOB: &str = "azure.storage.delete_blob";
const OP_APPSERVICE_LIST_APPS: &str = "azure.appservice.list_apps";
const OP_APPSERVICE_DEPLOY: &str = "azure.appservice.deploy";
const OP_SUBSCRIPTION_GET: &str = "azure.subscription.get";
const OP_HEALTH: &str = "azure.health";

// ── Capability IDs ──

const CAP_COMPUTE_READ: &str = "azure.compute.read";
const CAP_COMPUTE_WRITE: &str = "azure.compute.write";
const CAP_STORAGE_READ: &str = "azure.storage.read";
const CAP_STORAGE_WRITE: &str = "azure.storage.write";
const CAP_APP_READ: &str = "azure.app.read";
const CAP_APP_WRITE: &str = "azure.app.write";
const CAP_IAM_READ: &str = "azure.iam.read";

#[derive(Clone, serde::Deserialize)]
pub struct AzureConfig {
    #[serde(default = "default_management_url")]
    pub management_url: String,
    #[serde(flatten)]
    pub auth: AzureAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}
fn default_management_url() -> String {
    "https://management.azure.com".into()
}
const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for AzureConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureConfig")
            .field("management_url", &self.management_url)
            .field("auth", &self.auth)
            .finish()
    }
}

impl AzureConfig {
    fn validate(&self) -> Result<(), String> {
        if self.auth.subscription_id.is_empty() {
            return Err("subscription_id is required".into());
        }
        if self.management_url.is_empty() {
            return Err("management_url cannot be empty".into());
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
        let (network_ok, network_message) = management_url_policy(&self.management_url);

        ProvisioningReadiness {
            auth_mode: self.auth.redacted_label(),
            secret_material_configured: !self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            subscription_id_configured: !self.auth.subscription_id.trim().is_empty(),
            network_ok,
            network_message,
            management_url: self.management_url.clone(),
            allowed_hosts: AZURE_ALLOWED_HOSTS.to_vec(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    secret_material_configured: bool,
    requires_credential_injection: bool,
    subscription_id_configured: bool,
    network_ok: bool,
    network_message: String,
    management_url: String,
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

    const fn status_label(&self) -> &'static str {
        match self.status {
            DoctorStatus::Healthy => "healthy",
            DoctorStatus::Degraded => "degraded",
            DoctorStatus::Unhealthy => "unhealthy",
        }
    }
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.ends_with(".localhost")
}

fn management_url_policy(management_url: &str) -> (bool, String) {
    let parsed = match Url::parse(management_url) {
        Ok(url) => url,
        Err(error) => {
            return (
                false,
                format!("management_url must be an absolute URL: {error}"),
            )
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "management_url must include a host".into());
    };

    if is_local_test_host(host) {
        return (
            true,
            format!("localhost test endpoint accepted for verification: {management_url}"),
        );
    }

    let mut problems = Vec::new();
    if parsed.scheme() != "https" {
        problems.push(format!("scheme must be https, got {}", parsed.scheme()));
    }
    if !AZURE_ALLOWED_HOSTS
        .iter()
        .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
    {
        problems.push(format!(
            "host must match one of {:?}, got {host}",
            AZURE_ALLOWED_HOSTS
        ));
    }

    if problems.is_empty() {
        (
            true,
            "Azure management API endpoint accepted".into(),
        )
    } else {
        (false, problems.join("; "))
    }
}

#[derive(Debug)]
pub struct AzureConnector {
    base: BaseConnector,
    config: Option<AzureConfig>,
    client: Option<AzureClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl AzureConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.azure")),
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
            .map(AzureConfig::provisioning_readiness);
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                None
            } else {
                Some("Not configured; run configure before handshake or invoke".into())
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
                name: "subscription_id".into(),
                passed: readiness.subscription_id_configured,
                message: Some(if readiness.subscription_id_configured {
                    "Azure subscription_id configured".into()
                } else {
                    "subscription_id missing; Azure resource operations cannot resolve endpoints"
                        .into()
                }),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "secret_material".into(),
                passed: readiness.secret_material_configured,
                message: Some(if readiness.secret_material_configured {
                    "Bearer token configured directly".into()
                } else {
                    "Secret material omitted; host or egress proxy must inject Authorization header at runtime"
                        .into()
                }),
                critical: false,
            });
        }
        let result = DoctorResult::from_checks(checks, provisioning);
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "azure.provisioning.doctor",
            status = result.status_label(),
            check_count = result.checks.len(),
            failed_checks,
            "Azure doctor checks completed"
        );
        result
    }

    fn attach_self_check_details(
        mut report: SelfCheckReport,
        provisioning: Option<ProvisioningReadiness>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "provisioning": provisioning,
            "manifest_hash": Self::manifest_hash(),
        }));
        report
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

impl Default for AzureConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_lines)]
fn operations_info() -> Vec<OperationInfo> {
    let hint =
        |when: &str, mistakes: Vec<String>, examples: Vec<String>, related: Vec<&'static str>| {
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
            id: OperationId::from_static(OP_VM_LIST),
            summary: "List virtual machines in a resource group".into(),
            description: None,
            input_schema: json!({"type":"object","required":["resource_group"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_COMPUTE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List VMs in a resource group",
                vec!["resource_group is required".into()],
                vec![],
                vec![CAP_COMPUTE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_VM_GET),
            summary: "Get virtual machine details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["resource_group","vm_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_COMPUTE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get details of a specific VM",
                vec![],
                vec![],
                vec![CAP_COMPUTE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_VM_START),
            summary: "Start a virtual machine".into(),
            description: None,
            input_schema: json!({"type":"object","required":["resource_group","vm_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_COMPUTE_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Start a stopped VM",
                vec!["VM must exist and be stopped".into()],
                vec![],
                vec![CAP_COMPUTE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_VM_STOP),
            summary: "Stop a virtual machine".into(),
            description: None,
            input_schema: json!({"type":"object","required":["resource_group","vm_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_COMPUTE_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Stop a running VM (power off)",
                vec!["VM continues to incur charges unless deallocated".into()],
                vec![],
                vec![CAP_COMPUTE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_VM_DELETE),
            summary: "Delete a virtual machine".into(),
            description: None,
            input_schema: json!({"type":"object","required":["resource_group","vm_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_COMPUTE_WRITE),
            risk_level: RiskLevel::Critical,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently delete a VM (irreversible)",
                vec!["Verify VM name before deleting".into()],
                vec![],
                vec![CAP_COMPUTE_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_LIST_CONTAINERS),
            summary: "List storage containers".into(),
            description: None,
            input_schema: json!({"type":"object","required":["resource_group","storage_account"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_STORAGE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List blob containers in a storage account",
                vec!["resource_group and storage_account required".into()],
                vec![],
                vec![CAP_STORAGE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_UPLOAD_BLOB),
            summary: "Upload a blob to storage".into(),
            description: None,
            input_schema: json!({"type":"object","required":["storage_account","container","blob_name","content"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Upload content as a blob",
                vec!["Overwrites existing blob if same name".into()],
                vec![],
                vec![CAP_STORAGE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_DOWNLOAD_BLOB),
            summary: "Download a blob from storage".into(),
            description: None,
            input_schema: json!({"type":"object","required":["storage_account","container","blob_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Download blob content",
                vec![],
                vec![],
                vec![CAP_STORAGE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_DELETE_BLOB),
            summary: "Delete a blob from storage".into(),
            description: None,
            input_schema: json!({"type":"object","required":["storage_account","container","blob_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently delete a blob (irreversible without soft delete)",
                vec!["Check soft-delete policy first".into()],
                vec![],
                vec![CAP_STORAGE_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_APPSERVICE_LIST_APPS),
            summary: "List App Service web apps".into(),
            description: None,
            input_schema: json!({"type":"object","required":["resource_group"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_APP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List web apps in a resource group",
                vec![],
                vec![],
                vec![CAP_APP_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_APPSERVICE_DEPLOY),
            summary: "Deploy to App Service".into(),
            description: None,
            input_schema: json!({"type":"object","required":["resource_group","app_name","package_url"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_APP_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Deploy a package to App Service",
                vec!["package_url must be accessible from Azure".into()],
                vec![],
                vec![CAP_APP_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_SUBSCRIPTION_GET),
            summary: "Get subscription details".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_IAM_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint("View subscription info", vec![], vec![], vec![CAP_IAM_READ]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check Azure API health".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_IAM_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Verify Azure credentials", vec![], vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

#[async_trait]
impl FcpConnector for AzureConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let az = AzureConfig::from_value(config)?;
        let provisioning = az.provisioning_readiness();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(az.request_timeout_ms)),
        ));
        let client = AzureClient::new(
            &az.management_url,
            az.auth.clone(),
            az.retry.clone(),
        )
        .await
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?;
        self.client = Some(client);
        self.config = Some(az);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!(
            event = "azure.provisioning.configure",
            auth_mode = provisioning.auth_mode,
            network_ok = provisioning.network_ok,
            requires_credential_injection = provisioning.requires_credential_injection,
            management_url = %provisioning.management_url,
            "Configured Azure connector"
        );
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
            .map(AzureConfig::provisioning_readiness);
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
            "provisioning": provisioning,
            "manifest_hash": Self::manifest_hash(),
        }));
        snap
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };
        let provisioning = config.provisioning_readiness();

        if !provisioning.network_ok {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "network_constraints_invalid",
                    provisioning.network_message.clone(),
                ),
                Some(provisioning),
            ));
        }

        let Some(client) = &self.client else {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "client_missing",
                    "Azure HTTP client not initialized; re-run configure",
                ),
                Some(provisioning),
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "runtime_missing",
                    "ConnectorRuntime not initialized; re-run configure",
                ),
                Some(provisioning),
            ));
        };

        if provisioning.requires_credential_injection {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Access token is intentionally omitted; inject Authorization header at runtime before re-running self_check",
                ),
                Some(provisioning),
            ));
        }

        let report = match client.get_subscription(runtime).await {
            Ok(sub) => {
                let state = sub.state.as_deref().unwrap_or("unknown");
                if state == "Enabled" {
                    SelfCheckReport::ok()
                } else {
                    SelfCheckReport::degraded(
                        "subscription_not_enabled",
                        format!("Subscription state is '{state}' - verify subscription status"),
                    )
                }
            }
            Err(error) if error.is_retryable() => {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            }
            Err(error) => SelfCheckReport::failed("self_check_failed", error.to_string()),
        };
        let report = Self::attach_self_check_details(report, Some(provisioning));
        info!(
            event = "azure.provisioning.self_check",
            status = ?report.status,
            reason_code = report.reason_code.as_deref().unwrap_or("ok"),
            "Azure self_check completed"
        );
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

impl AzureConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_VM_LIST | OP_VM_GET => CapabilityId::from_static(CAP_COMPUTE_READ),
                OP_VM_START | OP_VM_STOP | OP_VM_DELETE => {
                    CapabilityId::from_static(CAP_COMPUTE_WRITE)
                }
                OP_STORAGE_LIST_CONTAINERS | OP_STORAGE_DOWNLOAD_BLOB => {
                    CapabilityId::from_static(CAP_STORAGE_READ)
                }
                OP_STORAGE_UPLOAD_BLOB | OP_STORAGE_DELETE_BLOB => {
                    CapabilityId::from_static(CAP_STORAGE_WRITE)
                }
                OP_APPSERVICE_LIST_APPS => CapabilityId::from_static(CAP_APP_READ),
                OP_APPSERVICE_DEPLOY => CapabilityId::from_static(CAP_APP_WRITE),
                OP_SUBSCRIPTION_GET | OP_HEALTH => CapabilityId::from_static(CAP_IAM_READ),
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
            message: "connector ready state missing Azure client".into(),
        })?;

        let output = match operation {
            OP_VM_LIST => {
                let rg = Self::require_str(&req.input, "resource_group")?;
                let vms = client
                    .list_vms(runtime, rg)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&vms).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_VM_GET => {
                let rg = Self::require_str(&req.input, "resource_group")?;
                let name = Self::require_str(&req.input, "vm_name")?;
                let vm = client
                    .get_vm(runtime, rg, name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&vm).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_VM_START => {
                let rg = Self::require_str(&req.input, "resource_group")?;
                let name = Self::require_str(&req.input, "vm_name")?;
                client
                    .start_vm(runtime, rg, name)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_VM_STOP => {
                let rg = Self::require_str(&req.input, "resource_group")?;
                let name = Self::require_str(&req.input, "vm_name")?;
                client
                    .stop_vm(runtime, rg, name)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_VM_DELETE => {
                let rg = Self::require_str(&req.input, "resource_group")?;
                let name = Self::require_str(&req.input, "vm_name")?;
                client
                    .delete_vm(runtime, rg, name)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_STORAGE_LIST_CONTAINERS => {
                let rg = Self::require_str(&req.input, "resource_group")?;
                let acct = Self::require_str(&req.input, "storage_account")?;
                let containers = client
                    .list_containers(runtime, rg, acct)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&containers).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_STORAGE_UPLOAD_BLOB => {
                let acct = Self::require_str(&req.input, "storage_account")?;
                let container = Self::require_str(&req.input, "container")?;
                let blob = Self::require_str(&req.input, "blob_name")?;
                let content = Self::require_str(&req.input, "content")?;
                client
                    .upload_blob(runtime, acct, container, blob, content)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_STORAGE_DOWNLOAD_BLOB => {
                let acct = Self::require_str(&req.input, "storage_account")?;
                let container = Self::require_str(&req.input, "container")?;
                let blob = Self::require_str(&req.input, "blob_name")?;
                let content = client
                    .download_blob(runtime, acct, container, blob)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"content": content})
            }
            OP_STORAGE_DELETE_BLOB => {
                let acct = Self::require_str(&req.input, "storage_account")?;
                let container = Self::require_str(&req.input, "container")?;
                let blob = Self::require_str(&req.input, "blob_name")?;
                client
                    .delete_blob(runtime, acct, container, blob)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_APPSERVICE_LIST_APPS => {
                let rg = Self::require_str(&req.input, "resource_group")?;
                let apps = client
                    .list_apps(runtime, rg)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&apps).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_APPSERVICE_DEPLOY => {
                let rg = Self::require_str(&req.input, "resource_group")?;
                let app = Self::require_str(&req.input, "app_name")?;
                let pkg = Self::require_str(&req.input, "package_url")?;
                let dep = client
                    .deploy_app(runtime, rg, app, pkg)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&dep).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_SUBSCRIPTION_GET => {
                let sub = client
                    .get_subscription(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&sub).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_HEALTH => {
                let sub = client
                    .get_subscription(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let state = sub.state.as_deref().unwrap_or("unknown");
                json!({
                    "healthy": state == "Enabled",
                    "subscription_state": state,
                    "subscription_id": sub.subscription_id,
                    "display_name": sub.display_name,
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
        json!({"access_token": "t", "subscription_id": "sub-123"})
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_COMPUTE_READ),
                CapabilityId::from_static(CAP_COMPUTE_WRITE),
                CapabilityId::from_static(CAP_IAM_READ),
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
            connector_id: ConnectorId::from_static("fcp.azure"),
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
        assert!(AzureConnector::new().config.is_none());
    }

    #[test]
    fn default_ok() {
        assert!(AzureConnector::default().config.is_none());
    }

    #[test]
    fn manifest_hash_stable() {
        assert_eq!(
            AzureConnector::manifest_hash(),
            AzureConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AzureConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_empty_subscription() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AzureConnector::new();
                c.configure(json!({"access_token":"t","subscription_id":""}))
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
                let mut c = AzureConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn doctor_unconfigured() {
        assert!(!AzureConnector::new().doctor().ready);
    }

    #[test]
    fn doctor_configured() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AzureConnector::new();
                c.configure(tc()).await.unwrap();
                c.doctor()
            })
            .unwrap()
            .ready
        );
    }

    #[test]
    fn introspect_ops() {
        assert_eq!(AzureConnector::new().introspect().operations.len(), 13);
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
                let mut c = AzureConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("azure.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_resource_group() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AzureConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_VM_LIST, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            AzureConnector::new()
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.azure"),
                    OperationId::from_static(OP_VM_LIST),
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
                AzureConnector::new()
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
            let mut c = AzureConnector::new();
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
            let mut c = AzureConnector::new();
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
            AzureConnector::require_str(&json!({"k": "v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(AzureConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn health_unconfigured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            AzureConnector::new().health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AzureConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
    }

    #[test]
    fn management_url_policy_valid() {
        let (ok, _msg) = management_url_policy("https://management.azure.com");
        assert!(ok);
    }

    #[test]
    fn management_url_policy_localhost() {
        let (ok, _msg) = management_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn management_url_policy_invalid_scheme() {
        let (ok, msg) = management_url_policy("http://management.azure.com");
        assert!(!ok);
        assert!(msg.contains("https"));
    }

    #[test]
    fn management_url_policy_invalid_host() {
        let (ok, msg) = management_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(msg.contains("evil.example.com"));
    }

    #[test]
    fn management_url_policy_empty() {
        let (ok, _msg) = management_url_policy("");
        assert!(!ok);
    }

    #[test]
    fn config_debug_redacts() {
        let config = AzureConfig {
            management_url: "https://management.azure.com".into(),
            auth: AzureAuth {
                access_token: "secret".into(),
                subscription_id: "sub-123".into(),
            },
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn config_validate_empty_sub() {
        let config = AzureConfig {
            management_url: "https://management.azure.com".into(),
            auth: AzureAuth {
                access_token: "t".into(),
                subscription_id: String::new(),
            },
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_empty_url() {
        let config = AzureConfig {
            management_url: String::new(),
            auth: AzureAuth {
                access_token: "t".into(),
                subscription_id: "s".into(),
            },
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_from_value_valid() {
        let val = json!({"access_token": "t", "subscription_id": "s"});
        assert!(AzureConfig::from_value(val).is_ok());
    }

    #[test]
    fn config_from_value_invalid() {
        let val = json!("bad");
        assert!(AzureConfig::from_value(val).is_err());
    }

    #[test]
    fn provisioning_readiness_full() {
        let config = AzureConfig {
            management_url: "https://management.azure.com".into(),
            auth: AzureAuth {
                access_token: "t".into(),
                subscription_id: "s".into(),
            },
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
        assert!(readiness.secret_material_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.subscription_id_configured);
    }

    #[test]
    fn provisioning_readiness_secretless() {
        let config = AzureConfig {
            management_url: "https://management.azure.com".into(),
            auth: AzureAuth {
                access_token: String::new(),
                subscription_id: "s".into(),
            },
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let readiness = config.provisioning_readiness();
        assert!(!readiness.secret_material_configured);
        assert!(readiness.requires_credential_injection);
    }

    #[test]
    fn doctor_status_labels() {
        let dr = DoctorResult {
            ready: true,
            status: DoctorStatus::Healthy,
            checks: vec![],
            provisioning: None,
        };
        assert_eq!(dr.status_label(), "healthy");

        let dr2 = DoctorResult {
            ready: false,
            status: DoctorStatus::Degraded,
            checks: vec![],
            provisioning: None,
        };
        assert_eq!(dr2.status_label(), "degraded");

        let dr3 = DoctorResult {
            ready: false,
            status: DoctorStatus::Unhealthy,
            checks: vec![],
            provisioning: None,
        };
        assert_eq!(dr3.status_label(), "unhealthy");
    }

    #[test]
    fn doctor_from_checks_all_pass() {
        let checks = vec![
            DoctorCheck {
                name: "test".into(),
                passed: true,
                message: None,
                critical: true,
            },
        ];
        let result = DoctorResult::from_checks(checks, None);
        assert!(result.ready);
        assert!(matches!(result.status, DoctorStatus::Healthy));
    }

    #[test]
    fn doctor_from_checks_critical_fail() {
        let checks = vec![
            DoctorCheck {
                name: "test".into(),
                passed: false,
                message: Some("failed".into()),
                critical: true,
            },
        ];
        let result = DoctorResult::from_checks(checks, None);
        assert!(!result.ready);
        assert!(matches!(result.status, DoctorStatus::Unhealthy));
    }

    #[test]
    fn doctor_from_checks_noncritical_fail() {
        let checks = vec![
            DoctorCheck {
                name: "critical".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "optional".into(),
                passed: false,
                message: Some("warning".into()),
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks, None);
        assert!(result.ready);
        assert!(matches!(result.status, DoctorStatus::Degraded));
    }

    #[test]
    fn is_local_test_host_checks() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("api.localhost"));
        assert!(!is_local_test_host("management.azure.com"));
    }

    #[test]
    fn op_count_matches_spec() {
        let ops = operations_info();
        assert_eq!(ops.len(), 13);
        let op_ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        assert!(op_ids.contains(&OP_VM_LIST));
        assert!(op_ids.contains(&OP_VM_GET));
        assert!(op_ids.contains(&OP_VM_START));
        assert!(op_ids.contains(&OP_VM_STOP));
        assert!(op_ids.contains(&OP_VM_DELETE));
        assert!(op_ids.contains(&OP_STORAGE_LIST_CONTAINERS));
        assert!(op_ids.contains(&OP_STORAGE_UPLOAD_BLOB));
        assert!(op_ids.contains(&OP_STORAGE_DOWNLOAD_BLOB));
        assert!(op_ids.contains(&OP_STORAGE_DELETE_BLOB));
        assert!(op_ids.contains(&OP_APPSERVICE_LIST_APPS));
        assert!(op_ids.contains(&OP_APPSERVICE_DEPLOY));
        assert!(op_ids.contains(&OP_SUBSCRIPTION_GET));
        assert!(op_ids.contains(&OP_HEALTH));
    }

    #[test]
    fn safety_tiers_match_spec() {
        let ops = operations_info();
        let find_op = |id: &str| ops.iter().find(|o| o.id.as_str() == id).unwrap();

        assert_eq!(find_op(OP_VM_LIST).safety_tier, SafetyTier::Safe);
        assert_eq!(find_op(OP_VM_GET).safety_tier, SafetyTier::Safe);
        assert_eq!(find_op(OP_VM_START).safety_tier, SafetyTier::Risky);
        assert_eq!(find_op(OP_VM_STOP).safety_tier, SafetyTier::Risky);
        assert_eq!(find_op(OP_VM_DELETE).safety_tier, SafetyTier::Dangerous);
        assert_eq!(
            find_op(OP_STORAGE_LIST_CONTAINERS).safety_tier,
            SafetyTier::Safe
        );
        assert_eq!(
            find_op(OP_STORAGE_UPLOAD_BLOB).safety_tier,
            SafetyTier::Risky
        );
        assert_eq!(
            find_op(OP_STORAGE_DOWNLOAD_BLOB).safety_tier,
            SafetyTier::Safe
        );
        assert_eq!(
            find_op(OP_STORAGE_DELETE_BLOB).safety_tier,
            SafetyTier::Dangerous
        );
        assert_eq!(
            find_op(OP_APPSERVICE_LIST_APPS).safety_tier,
            SafetyTier::Safe
        );
        assert_eq!(find_op(OP_APPSERVICE_DEPLOY).safety_tier, SafetyTier::Risky);
        assert_eq!(find_op(OP_SUBSCRIPTION_GET).safety_tier, SafetyTier::Safe);
        assert_eq!(find_op(OP_HEALTH).safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn capabilities_match_spec() {
        let ops = operations_info();
        let find_op = |id: &str| ops.iter().find(|o| o.id.as_str() == id).unwrap();

        assert_eq!(find_op(OP_VM_LIST).capability.as_str(), CAP_COMPUTE_READ);
        assert_eq!(find_op(OP_VM_START).capability.as_str(), CAP_COMPUTE_WRITE);
        assert_eq!(
            find_op(OP_STORAGE_LIST_CONTAINERS).capability.as_str(),
            CAP_STORAGE_READ
        );
        assert_eq!(
            find_op(OP_STORAGE_UPLOAD_BLOB).capability.as_str(),
            CAP_STORAGE_WRITE
        );
        assert_eq!(
            find_op(OP_APPSERVICE_LIST_APPS).capability.as_str(),
            CAP_APP_READ
        );
        assert_eq!(
            find_op(OP_APPSERVICE_DEPLOY).capability.as_str(),
            CAP_APP_WRITE
        );
        assert_eq!(
            find_op(OP_SUBSCRIPTION_GET).capability.as_str(),
            CAP_IAM_READ
        );
        assert_eq!(find_op(OP_HEALTH).capability.as_str(), CAP_IAM_READ);
    }

    #[test]
    fn self_check_unconfigured() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            AzureConnector::new().self_check().await
        })
        .unwrap()
        .unwrap();
        assert_eq!(r.reason_code.as_deref(), Some("not_configured"));
    }

    #[test]
    fn event_caps_no_streaming() {
        let intro = AzureConnector::new().introspect();
        let caps = intro.event_caps.unwrap();
        assert!(!caps.streaming);
        assert!(!caps.replay);
    }

    #[test]
    fn metrics_initial() {
        let c = AzureConnector::new();
        let m = c.metrics();
        assert_eq!(m.requests_total, 0);
    }
}
