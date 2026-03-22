use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_sdk::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::PackageRegistryClient;
use crate::types::PackageRegistryConfig;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_SEARCH: &str = "registry.search";
const OP_PACKAGES_GET: &str = "registry.packages.get";
const OP_VERSIONS_LIST: &str = "registry.versions.list";
const OP_DEPENDENCIES_GET: &str = "registry.dependencies.get";
const OP_ARTIFACTS_LIST: &str = "registry.artifacts.list";
const OP_DOWNLOADS_GET: &str = "registry.downloads.get";
const OP_HEALTH: &str = "registry.health";

const CAP_SEARCH: &str = "registry.search";
const CAP_PACKAGES_READ: &str = "registry.packages.read";
const CAP_VERSIONS_READ: &str = "registry.versions.read";
const CAP_DEPENDENCIES_READ: &str = "registry.dependencies.read";
const CAP_ARTIFACTS_READ: &str = "registry.artifacts.read";
const CAP_DOWNLOADS_READ: &str = "registry.downloads.read";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/package_registry_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/package_registry_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 6] = [
    "scripts/e2e/package_registry_connector_verification.sh",
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/package-registry/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-package-registry --all-targets",
    "cargo fmt --manifest-path connectors/package-registry/Cargo.toml --check",
    "rch exec -- cargo test -p fcp-package-registry --test integration -- --nocapture",
    "rch exec -- cargo clippy -p fcp-package-registry --all-targets -- -D warnings",
];

#[derive(Debug, Clone, serde::Serialize)]
struct RetryReadiness {
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    jitter_enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProvisioningReadiness {
    provider: &'static str,
    base_url: String,
    auth_mode: &'static str,
    anonymous_allowed: bool,
    request_timeout_ms: u64,
    retry: RetryReadiness,
    search_supported: bool,
    downloads_supported: bool,
    publication_supported: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
    provider_auth: Vec<ProviderAuthGuidance>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProviderAuthGuidance {
    provider: &'static str,
    metadata_access: &'static str,
    elevated_auth: &'static str,
    remediation: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
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
        let passed = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        Self {
            ready: passed,
            passed,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }
}

#[derive(Debug)]
pub struct PackageRegistryConnector {
    base: BaseConnector,
    config: Option<PackageRegistryConfig>,
    client: Option<PackageRegistryClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl PackageRegistryConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.package-registry")),
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

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.config.as_ref().map(|config| ProvisioningReadiness {
            provider: config.provider.as_str(),
            base_url: config.resolved_base_url(),
            auth_mode: config.auth_label(),
            anonymous_allowed: true,
            request_timeout_ms: config.request_timeout_ms,
            retry: RetryReadiness {
                max_retries: config.retry.max_retries,
                initial_delay_ms: config.retry.initial_delay_ms,
                max_delay_ms: config.retry.max_delay_ms,
                jitter_enabled: config.retry.jitter_enabled,
            },
            search_supported: config.provider.supports_search(),
            downloads_supported: config.provider.supports_downloads(),
            publication_supported: false,
        })
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        live_probe: Option<&serde_json::Value>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": self.provisioning_readiness(),
            "live_probe": live_probe,
            "operator_guidance": operator_guidance(),
        }));
        report
    }

    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self.provisioning_readiness();
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: Some(if self.config.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: self.runtime.is_some(),
            message: Some(if self.runtime.is_some() {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "provider".into(),
                passed: true,
                message: Some(format!("Provider: {}", config.provider)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: true,
                message: Some(format!("Base URL: {}", config.resolved_base_url())),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(auth_mode_message(config)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "search_support".into(),
                passed: config.provider.supports_search(),
                message: Some(if config.provider.supports_search() {
                    "Search is supported for the configured provider".into()
                } else {
                    "Search is intentionally unsupported for the configured provider in the first slice".into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "downloads_support".into(),
                passed: config.provider.supports_downloads(),
                message: Some(if config.provider.supports_downloads() {
                    "Download statistics are supported for the configured provider".into()
                } else {
                    "Download statistics are intentionally unsupported for the configured provider in the first slice".into()
                }),
                critical: false,
            });
        }
        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for PackageRegistryConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use provider-approved public test packages or a localhost/mock registry override before running verification.",
            "If you override base_url for verification, keep it on https or localhost only and capture the override in the evidence bundle.",
            "Treat this first slice as read-only: search, metadata, versions, dependencies, artifacts, downloads, and health only.",
        ],
        dedicated_environment: "Prefer public fixture packages or a disposable localhost mirror. Do not point verification at private internal mirrors unless the evidence bundle can be safely redacted.",
        redaction_rules: vec![
            "Redact bearer tokens, Authorization headers, and any copied request logs before sharing evidence.",
            "If base_url points at a private mirror, redact hostnames, package names, and repository links that would reveal internal package inventory.",
            "Avoid preserving raw JSON for private packages unless the artifact bundle is restricted to the owning team.",
        ],
        limitations: vec![
            "Package Registry is provider-bound per runtime instance; one connector instance speaks to exactly one of npm, PyPI, or crates.io.",
            "Publish, yank, owner mutation, audit, and admin workflows are intentionally out of scope for the first slice.",
            "PyPI search and provider-normalized download metrics are intentionally unsupported in the first slice.",
        ],
        provider_auth: vec![
            ProviderAuthGuidance {
                provider: "npm",
                metadata_access: "Public metadata and search work anonymously against registry.npmjs.org.",
                elevated_auth: "A bearer token is optional for this first slice and is only useful for higher quotas or future publish-oriented work that is not exposed here.",
                remediation: "If a custom npm mirror rejects anonymous requests, provide a read-scoped token and re-run self_check to confirm the mirror accepts bearer auth.",
            },
            ProviderAuthGuidance {
                provider: "pypi",
                metadata_access: "Project metadata and release files are public on pypi.org in the first slice.",
                elevated_auth: "PyPI upload tokens and Trusted Publisher flows are intentionally not exercised by this connector yet.",
                remediation: "If a private package index requires auth, use a dedicated read credential for the mirror and document the alternate base_url in the evidence bundle.",
            },
            ProviderAuthGuidance {
                provider: "crates_io",
                metadata_access: "crates.io metadata, owners, versions, dependencies, and downloads are public in the first slice.",
                elevated_auth: "A crates.io token is optional for this slice and reserved for future owner/publish flows outside the current contract.",
                remediation: "If a registry proxy requires auth or blocks anonymous probes, inject a read token, rerun self_check, and capture the successful probe details.",
            },
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "health or self_check reports that the connector is not configured",
                action: "Configure provider, optional base_url override, timeout, and retry settings, then rerun self_check.",
            },
            RemediationHint {
                code: "registry_auth_rejected",
                symptom: "self_check or invoke fails with HTTP 401/403 from the registry or mirror",
                action: "Provide a valid read credential for the selected provider or mirror, then rerun self_check to confirm reachability.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "live probe failed with timeout, rate limit, or transient 5xx",
                action: "Increase request_timeout_ms or retry settings for the environment, wait for the upstream to recover, and rerun the verification script.",
            },
            RemediationHint {
                code: "provider_feature_unsupported",
                symptom: "invoke rejects PyPI search or unsupported provider-native downloads",
                action: "Switch to a provider that supports the requested surface or stay within the documented first-slice service inventory.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "self_check reports an invalid base_url or non-https endpoint",
                action: "Use the default provider host or a localhost/https override that matches the manifest network policy.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn auth_mode_message(config: &PackageRegistryConfig) -> String {
    match (config.provider.as_str(), config.auth_label()) {
        ("npm", "token") => "Auth: token supplied for npm registry access".into(),
        ("npm", _) => "Auth: anonymous npm metadata mode".into(),
        ("pypi", "token") => "Auth: token supplied for alternate PyPI-compatible registry access".into(),
        ("pypi", _) => "Auth: anonymous PyPI metadata mode".into(),
        ("crates_io", "token") => "Auth: token supplied for crates.io or registry proxy access".into(),
        ("crates_io", _) => "Auth: anonymous crates.io metadata mode".into(),
        _ => format!("Auth: {}", config.auth_label()),
    }
}

struct OperationSpec {
    id: &'static str,
    summary: &'static str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    when_to_use: &'static str,
}

#[must_use]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        operation_info(OperationSpec {
            id: OP_SEARCH,
            summary: "Search packages on the configured registry provider",
            capability: CAP_SEARCH,
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            input_schema: json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string" },
                    "limit": { "type": "integer", "default": 20 },
                    "page": { "type": "integer", "default": 1 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "provider": { "type": "string" },
                    "query": { "type": "string" },
                    "results": { "type": "array" }
                }
            }),
            when_to_use: "When you need to search npm or crates.io for packages matching a query",
        }),
        operation_info(OperationSpec {
            id: OP_PACKAGES_GET,
            summary: "Get package metadata",
            capability: CAP_PACKAGES_READ,
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            input_schema: json!({
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "provider": { "type": "string" },
                    "name": { "type": "string" },
                    "latest_version": { "type": ["string", "null"] }
                }
            }),
            when_to_use: "When you need package-level metadata, links, ownership hints, and release summary",
        }),
        operation_info(OperationSpec {
            id: OP_VERSIONS_LIST,
            summary: "List package versions or releases",
            capability: CAP_VERSIONS_READ,
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            input_schema: json!({
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "provider": { "type": "string" },
                    "name": { "type": "string" },
                    "versions": { "type": "array" }
                }
            }),
            when_to_use: "When you need release history, dist-tags, yanked state, or version metadata",
        }),
        operation_info(OperationSpec {
            id: OP_DEPENDENCIES_GET,
            summary: "Get dependency metadata for a version",
            capability: CAP_DEPENDENCIES_READ,
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            input_schema: json!({
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string" },
                    "version": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "provider": { "type": "string" },
                    "name": { "type": "string" },
                    "version": { "type": "string" },
                    "dependencies": { "type": "array" }
                }
            }),
            when_to_use: "When you need dependency declarations for a selected package version",
        }),
        operation_info(OperationSpec {
            id: OP_ARTIFACTS_LIST,
            summary: "List release files or artifact metadata",
            capability: CAP_ARTIFACTS_READ,
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            input_schema: json!({
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string" },
                    "version": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "provider": { "type": "string" },
                    "name": { "type": "string" },
                    "version": { "type": "string" },
                    "artifacts": { "type": "array" }
                }
            }),
            when_to_use: "When you need tarball, wheel, sdist, or crate metadata without downloading bodies",
        }),
        operation_info(OperationSpec {
            id: OP_DOWNLOADS_GET,
            summary: "Get package download statistics",
            capability: CAP_DOWNLOADS_READ,
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            input_schema: json!({
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "provider": { "type": "string" },
                    "name": { "type": "string" },
                    "points": { "type": "array" }
                }
            }),
            when_to_use: "When you need provider-native package download statistics where they are supported",
        }),
        operation_info(OperationSpec {
            id: OP_HEALTH,
            summary: "Check registry provider reachability",
            capability: CAP_PACKAGES_READ,
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" },
                    "provider": { "type": "string" }
                }
            }),
            when_to_use: "When you need to verify that the configured registry provider is reachable",
        }),
    ]
}

fn operation_info(spec: OperationSpec) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(spec.id),
        summary: spec.summary.into(),
        description: None,
        input_schema: spec.input_schema,
        output_schema: spec.output_schema,
        capability: CapabilityId::from_static(spec.capability),
        risk_level: spec.risk_level,
        safety_tier: spec.safety_tier,
        idempotency: spec.idempotency,
        ai_hints: AgentHint {
            when_to_use: spec.when_to_use.into(),
            common_mistakes: operation_common_mistakes(spec.id),
            examples: operation_examples(spec.id),
            related: Vec::new(),
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

fn operation_common_mistakes(id: &str) -> Vec<String> {
    match id {
        OP_SEARCH => vec![
            "PyPI search is intentionally unsupported in the first slice; use package lookup instead.".into(),
            "Page is 1-based for npm/crates.io pagination in this connector.".into(),
        ],
        OP_DEPENDENCIES_GET | OP_ARTIFACTS_LIST => vec![
            "If version is omitted, the connector falls back to the provider's latest or max version.".into(),
            "Artifact metadata does not download tarball, wheel, sdist, or crate bodies.".into(),
        ],
        OP_DOWNLOADS_GET => vec![
            "Download statistics are only supported for crates.io in the first slice.".into(),
        ],
        _ => vec![
            "This connector is provider-bound; do not expect one instance to query npm, PyPI, and crates.io simultaneously.".into(),
        ],
    }
}

fn operation_examples(id: &str) -> Vec<String> {
    match id {
        OP_SEARCH => vec![
            r#"registry.search({"query":"serde","limit":5,"page":1})"#.into(),
            r#"registry.search({"query":"react","limit":10,"page":2})"#.into(),
        ],
        OP_PACKAGES_GET => vec![
            r#"registry.packages.get({"name":"serde"})"#.into(),
            r#"registry.packages.get({"name":"@types/node"})"#.into(),
        ],
        OP_VERSIONS_LIST => vec![
            r#"registry.versions.list({"name":"pip"})"#.into(),
            r#"registry.versions.list({"name":"tokio"})"#.into(),
        ],
        OP_DEPENDENCIES_GET => vec![
            r#"registry.dependencies.get({"name":"requests","version":"2.32.0"})"#.into(),
            r#"registry.dependencies.get({"name":"serde","version":"1.0.228"})"#.into(),
        ],
        OP_ARTIFACTS_LIST => vec![
            r#"registry.artifacts.list({"name":"sampleproject","version":"4.0.0"})"#.into(),
            r#"registry.artifacts.list({"name":"react","version":"19.2.0"})"#.into(),
        ],
        OP_DOWNLOADS_GET => vec![
            r#"registry.downloads.get({"name":"serde"})"#.into(),
        ],
        OP_HEALTH => vec![
            r#"registry.health({})"#.into(),
        ],
        _ => Vec::new(),
    }
}

#[async_trait]
impl FcpConnector for PackageRegistryConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config =
            PackageRegistryConfig::from_value(config).map_err(|error| error.to_fcp_error())?;
        let base_url = config.resolved_base_url();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));
        let client = PackageRegistryClient::new(
            config.provider,
            base_url,
            config.token.clone(),
            config.retry.clone(),
            config.request_timeout_ms,
        )
        .map_err(|error| error.to_fcp_error())?;
        self.client = Some(client);
        self.config = Some(config);
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
        let provisioning = self.provisioning_readiness();
        let mut snapshot = match &self.client {
            None if self.config.is_none() => HealthSnapshot::degraded("not configured"),
            None => HealthSnapshot::error("registry client not initialized"),
            Some(_) if self.runtime.is_none() => HealthSnapshot::error("runtime not initialized"),
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
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed("runtime_missing", "Connector runtime is not initialized"),
                None,
            ));
        };

        match client.health_check(runtime).await {
            Ok(live_probe) => Ok(self.attach_self_check_details(
                SelfCheckReport::ok(),
                Some(&live_probe),
            )),
            Err(crate::error::Error::Unauthorized(message)) => Ok(self.attach_self_check_details(
                SelfCheckReport::failed("registry_auth_rejected", message),
                None,
            )),
            Err(error) if error.is_retryable() => Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("self_check_retryable", error.to_string()),
                None,
            )),
            Err(error) => Ok(self.attach_self_check_details(
                SelfCheckReport::failed("self_check_failed", error.to_string()),
                None,
            )),
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

impl PackageRegistryConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_capability = match req.operation.as_str() {
            OP_SEARCH => CapabilityId::from_static(CAP_SEARCH),
            OP_PACKAGES_GET | OP_HEALTH => CapabilityId::from_static(CAP_PACKAGES_READ),
            OP_VERSIONS_LIST => CapabilityId::from_static(CAP_VERSIONS_READ),
            OP_DEPENDENCIES_GET => CapabilityId::from_static(CAP_DEPENDENCIES_READ),
            OP_ARTIFACTS_LIST => CapabilityId::from_static(CAP_ARTIFACTS_READ),
            OP_DOWNLOADS_GET => CapabilityId::from_static(CAP_DOWNLOADS_READ),
            other => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {other}"),
                });
            }
        };
        verifier.verify(
            &req.capability_token,
            &required_capability,
            &req.operation,
            &[],
        )?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Package registry client missing after configure".into(),
        })?;
        let config = self.config.as_ref().ok_or(FcpError::Internal {
            message: "Package registry config missing after configure".into(),
        })?;

        let output = match req.operation.as_str() {
            OP_SEARCH => {
                let query = require_str(&req.input, "query")?;
                let limit = req
                    .input
                    .get("limit")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(20);
                let page = req
                    .input
                    .get("page")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(1);
                serde_json::to_value(
                    client
                        .search(runtime, query, limit, page)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
            }
            OP_PACKAGES_GET => {
                let name = require_str(&req.input, "name")?;
                serde_json::to_value(
                    client
                        .get_package(runtime, name)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
            }
            OP_VERSIONS_LIST => {
                let name = require_str(&req.input, "name")?;
                serde_json::to_value(
                    client
                        .list_versions(runtime, name)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
            }
            OP_DEPENDENCIES_GET => {
                let name = require_str(&req.input, "name")?;
                let version = req.input.get("version").and_then(serde_json::Value::as_str);
                serde_json::to_value(
                    client
                        .get_dependencies(runtime, name, version)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
            }
            OP_ARTIFACTS_LIST => {
                let name = require_str(&req.input, "name")?;
                let version = req.input.get("version").and_then(serde_json::Value::as_str);
                serde_json::to_value(
                    client
                        .list_artifacts(runtime, name, version)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
            }
            OP_DOWNLOADS_GET => {
                let name = require_str(&req.input, "name")?;
                serde_json::to_value(
                    client
                        .get_downloads(runtime, name)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
            }
            OP_HEALTH => serde_json::to_value(json!({
                "status": "ok",
                "provider": config.provider.as_str(),
                "auth_mode": config.auth_label(),
                "live_probe": client
                    .health_check(runtime)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            })),
            _ => unreachable!(),
        }
        .map_err(|error| FcpError::Internal {
            message: format!("JSON serialization error: {error}"),
        })?;

        Ok(InvokeResponse::ok(req.id, output))
    }
}

fn require_str<'a>(value: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{key}' field"),
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::types::RegistryProvider;

    fn configured(provider: RegistryProvider) -> PackageRegistryConnector {
        let mut connector = PackageRegistryConnector::new();
        fcp_async_core::runtime::block_on_sync(async {
            connector
                .configure(json!({
                    "provider": provider,
                    "base_url": provider.default_base_url(),
                }))
                .await
                .unwrap();
        })
        .unwrap();
        connector
    }

    #[test]
    fn operations_catalog_has_expected_count() {
        assert_eq!(operations_info().len(), 7);
    }

    #[test]
    fn doctor_reports_provider_specific_support() {
        let connector = configured(RegistryProvider::Pypi);
        let doctor = connector.doctor();
        let search_check = doctor
            .checks
            .iter()
            .find(|check| check.name == "search_support")
            .unwrap();
        assert!(!search_check.passed);
        let downloads_check = doctor
            .checks
            .iter()
            .find(|check| check.name == "downloads_support")
            .unwrap();
        assert!(!downloads_check.passed);
    }
}
