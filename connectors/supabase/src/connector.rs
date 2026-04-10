//! Supabase connector implementation.

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
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
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::Url;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::{DEFAULT_PROJECT_URL, SupabaseAuth, SupabaseClient};
use crate::types::{
    DeleteRequest, InsertRequest, RpcRequest, SchemaTablesRequest, StorageDeleteRequest,
    StorageDownloadRequest, StorageUploadRequest, TableQueryRequest, UpdateRequest, UpsertRequest,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/supabase_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/supabase_connector/<timestamp>";
const SUPABASE_ALLOWED_HOST_SUFFIX: &str = ".supabase.co";

const OP_QUERY: &str = "supabase.query";
const OP_INSERT: &str = "supabase.insert";
const OP_UPDATE: &str = "supabase.update";
const OP_UPSERT: &str = "supabase.upsert";
const OP_DELETE: &str = "supabase.delete";
const OP_RPC: &str = "supabase.rpc";
const OP_SCHEMA_TABLES: &str = "supabase.schema.tables";
const OP_STORAGE_UPLOAD: &str = "supabase.storage.upload";
const OP_STORAGE_DOWNLOAD: &str = "supabase.storage.download";
const OP_STORAGE_DELETE: &str = "supabase.storage.delete";
const OP_HEALTH: &str = "supabase.health";

const CAP_READ: &str = "supabase.read";
const CAP_WRITE: &str = "supabase.write";
const CAP_STORAGE: &str = "supabase.storage";

#[derive(Clone, serde::Deserialize)]
pub struct SupabaseConfig {
    #[serde(default = "default_project_url")]
    pub project_url: String,
    pub api_key: Option<String>,
    #[serde(default = "default_schema")]
    pub schema: String,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

fn default_project_url() -> String {
    DEFAULT_PROJECT_URL.into()
}
fn default_schema() -> String {
    "public".into()
}
const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for SupabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupabaseConfig")
            .field("project_url", &self.project_url)
            .field("api_key", &"[REDACTED]")
            .field("schema", &self.schema)
            .finish()
    }
}

impl SupabaseConfig {
    fn validate(&self) -> Result<(), String> {
        if self.project_url.is_empty() {
            return Err("project_url cannot be empty".into());
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

    fn auth(&self) -> SupabaseAuth {
        match &self.api_key {
            Some(key) if !key.trim().is_empty() => SupabaseAuth::ApiKey(key.clone()),
            _ => SupabaseAuth::Secretless,
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message, project_ref) = project_url_policy(&self.project_url);
        let auth = self.auth();
        let (key_classification, key_role_hint, token_project_ref, permissions_guidance) =
            match &auth {
                SupabaseAuth::Secretless => (
                    "secretless".to_string(),
                    None,
                    None,
                    "No raw API key is configured. The host or egress proxy must inject a concrete Supabase key before self_check can verify live permissions.".into(),
                ),
                SupabaseAuth::ApiKey(key) => {
                    let classification = classify_api_key(key);
                    let role_hint = match &classification {
                        ApiKeyClassification::JwtRole(role) => Some(role.clone()),
                        _ => None,
                    };
                    let token_project_ref = decode_jwt_claim(key, "ref");
                    (
                        classification.label(),
                        role_hint,
                        token_project_ref,
                        classification.permissions_guidance(),
                    )
                }
            };
        let project_ref_matches_token = match (&project_ref, &token_project_ref) {
            (Some(project_ref), Some(token_project_ref)) => Some(project_ref == token_project_ref),
            _ => None,
        };

        ProvisioningReadiness {
            auth_mode: auth.redacted_label(),
            secret_material_configured: !auth.is_secretless(),
            requires_credential_injection: auth.is_secretless(),
            key_classification,
            key_role_hint,
            project_url: self.project_url.clone(),
            project_ref,
            token_project_ref,
            project_ref_matches_token,
            network_ok,
            network_message,
            default_schema: self.schema.clone(),
            request_timeout_ms: self.request_timeout_ms,
            permissions_guidance,
            storage_policy_guidance: "Storage upload/download/delete also depend on bucket-level policies. Verify bucket existence plus insert/select/delete policies before rerunning mutation checks.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApiKeyClassification {
    Publishable,
    Secret,
    JwtRole(String),
    Opaque,
}

impl ApiKeyClassification {
    fn label(&self) -> String {
        match self {
            Self::Publishable => "publishable".into(),
            Self::Secret => "secret".into(),
            Self::JwtRole(role) => format!("jwt:{role}"),
            Self::Opaque => "opaque".into(),
        }
    }

    fn permissions_guidance(&self) -> String {
        match self {
            Self::Publishable => "Publishable keys are intended for constrained client traffic. Read and mutation flows still depend on RLS and Storage bucket policies.".into(),
            Self::Secret => "Secret keys can exercise broader Supabase APIs. Use them only in a dedicated staging project and redact them from every artifact.".into(),
            Self::JwtRole(role) if role == "anon" => "Anon JWT keys are limited by RLS and Storage bucket policies. Expect write and delete operations to fail unless the target project explicitly permits them.".into(),
            Self::JwtRole(role) if role == "service_role" => "service_role JWT keys bypass many RLS checks. Restrict them to disposable verification environments.".into(),
            Self::JwtRole(role) => format!("JWT key carries role `{role}`. Verify that role has the table, RPC, and Storage permissions needed for the operations you intend to test."),
            Self::Opaque => "Custom or opaque API key format detected. Verify table/RPC/Storage permissions out of band because role inference is unavailable.".into(),
        }
    }

    fn implies_limited_scope(&self) -> bool {
        matches!(self, Self::Publishable) || matches!(self, Self::JwtRole(role) if role == "anon")
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    secret_material_configured: bool,
    requires_credential_injection: bool,
    key_classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_role_hint: Option<String>,
    project_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_project_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_ref_matches_token: Option<bool>,
    network_ok: bool,
    network_message: String,
    default_schema: String,
    request_timeout_ms: u64,
    permissions_guidance: String,
    storage_policy_guidance: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorResult {
    ready: bool,
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
    verification_script: &'static str,
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
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }

    fn status_label(&self) -> &'static str {
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

fn project_url_policy(project_url: &str) -> (bool, String, Option<String>) {
    let parsed = match Url::parse(project_url) {
        Ok(url) => url,
        Err(error) => {
            return (
                false,
                format!("project_url must be an absolute URL: {error}"),
                None,
            );
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "project_url must include a host".into(), None);
    };

    if is_local_test_host(host) {
        return (
            true,
            format!("localhost test endpoint accepted for verification: {project_url}"),
            None,
        );
    }

    let mut problems = Vec::new();
    if parsed.scheme() != "https" {
        problems.push(format!("scheme must be https, got {}", parsed.scheme()));
    }
    if !host.ends_with(SUPABASE_ALLOWED_HOST_SUFFIX) {
        problems.push(format!(
            "host must end with {SUPABASE_ALLOWED_HOST_SUFFIX}, got {host}"
        ));
    }
    if !(parsed.path().is_empty() || parsed.path() == "/") {
        problems.push(format!(
            "project_url must not include a path beyond '/', got {}",
            parsed.path()
        ));
    }

    let project_ref = host
        .strip_suffix(SUPABASE_ALLOWED_HOST_SUFFIX)
        .map(str::to_string)
        .filter(|value| !value.is_empty());

    if problems.is_empty() {
        (
            true,
            "Supabase project endpoint accepted".into(),
            project_ref,
        )
    } else {
        (false, problems.join("; "), project_ref)
    }
}

fn classify_api_key(key: &str) -> ApiKeyClassification {
    let trimmed = key.trim();
    if trimmed.starts_with("sb_publishable_") {
        ApiKeyClassification::Publishable
    } else if trimmed.starts_with("sb_secret_") {
        ApiKeyClassification::Secret
    } else if let Some(role) = decode_jwt_claim(trimmed, "role") {
        ApiKeyClassification::JwtRole(role)
    } else {
        ApiKeyClassification::Opaque
    }
}

fn decode_jwt_claim(token: &str, field: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get(field)?.as_str().map(str::to_string)
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a dedicated Supabase staging project with disposable tables, RPC functions, and Storage buckets.",
            "Provision the exact key type you want to verify: publishable/anon for policy-constrained reads, or secret/service-role for full mutation coverage.",
            "Seed representative test data and bucket policies before running destructive verification flows.",
        ],
        dedicated_environment: "Run verification only against a disposable staging project. Row deletes and Storage deletes are dangerous and should never target production data.",
        redaction_rules: vec![
            "Never print raw api_key values or Authorization headers.",
            "Treat project refs, JWT role claims, and bucket names as environment metadata; only share them when the environment is already public or disposable.",
            "Do not paste full row payloads or object contents from private datasets into shared transcripts unless they are synthetic fixtures.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "project_url_invalid",
                symptom: "doctor/self_check reports invalid network policy or malformed project_url",
                action: "Use the project root URL in the form https://<project-ref>.supabase.co for production, or a localhost mock endpoint during deterministic verification.",
            },
            RemediationHint {
                code: "project_ref_mismatch",
                symptom: "JWT ref claim and project_url host do not match",
                action: "Pair each JWT-style key with the Supabase project that minted it. Update either project_url or the injected key, then rerun self_check.",
            },
            RemediationHint {
                code: "credential_injection_required",
                symptom: "secretless mode is configured but self_check cannot prove live connectivity",
                action: "Configure the host or egress proxy to inject a concrete Supabase key at runtime, then rerun self_check before invoking writes or deletes.",
            },
            RemediationHint {
                code: "limited_key_scope",
                symptom: "REST root is reachable but write/storage checks remain degraded",
                action: "Use a service_role or secret key for full mutation verification, or loosen staging-only RLS and bucket policies for the publishable/anon key under test.",
            },
            RemediationHint {
                code: "permissions_insufficient",
                symptom: "invoke or self_check returns 401/403 from PostgREST or Storage",
                action: "Verify the key type, row-level policies, and Storage bucket policies needed for the target operation. Table reads/writes and Storage object mutations are authorized independently.",
            },
        ],
        rerun_commands: vec![
            "scripts/e2e/supabase_connector_verification.sh",
            "fwc manifest fix connectors/supabase/manifest.toml --check --json",
            "rch exec -- cargo test -p fcp-supabase --test integration -- --nocapture",
            "rch exec -- cargo clippy -p fcp-supabase --all-targets -- -D warnings",
        ],
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

#[derive(Debug)]
pub struct SupabaseConnector {
    base: BaseConnector,
    config: Option<SupabaseConfig>,
    client: Option<SupabaseClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl SupabaseConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.supabase")),
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

    #[allow(dead_code)]
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

    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self
            .config
            .as_ref()
            .map(SupabaseConfig::provisioning_readiness);
        let handshaken = self.base.handshaken.load(Ordering::Acquire);
        let mut checks = vec![
            DoctorCheck {
                name: "configuration".into(),
                passed: self.config.is_some(),
                message: if self.config.is_some() {
                    None
                } else {
                    Some("Not configured; run configure before handshake or invoke".into())
                },
                critical: true,
            },
            DoctorCheck {
                name: "client_initialized".into(),
                passed: self.client.is_some(),
                message: if self.client.is_some() {
                    None
                } else {
                    Some("Supabase HTTP client not initialized; re-run configure".into())
                },
                critical: true,
            },
            DoctorCheck {
                name: "runtime_initialized".into(),
                passed: self.runtime.is_some(),
                message: if self.runtime.is_some() {
                    None
                } else {
                    Some("ConnectorRuntime not initialized; re-run configure".into())
                },
                critical: true,
            },
            DoctorCheck {
                name: "handshake".into(),
                passed: handshaken,
                message: if handshaken {
                    None
                } else {
                    Some("Handshake not completed".into())
                },
                critical: false,
            },
        ];
        if let Some(readiness) = &provisioning {
            let limited_scope = readiness.key_classification == "publishable"
                || readiness.key_role_hint.as_deref() == Some("anon");
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: readiness.network_ok,
                message: Some(readiness.network_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "project_ref_alignment".into(),
                passed: readiness.project_ref_matches_token != Some(false),
                message: Some(match readiness.project_ref_matches_token {
                    Some(true) => format!(
                        "project_url ref {} matches token ref {}",
                        readiness.project_ref.as_deref().unwrap_or("unknown"),
                        readiness.token_project_ref.as_deref().unwrap_or("unknown")
                    ),
                    Some(false) => format!(
                        "project_url ref {} does not match token ref {}",
                        readiness.project_ref.as_deref().unwrap_or("unknown"),
                        readiness.token_project_ref.as_deref().unwrap_or("unknown")
                    ),
                    None => "No JWT project ref claim available for preflight matching".into(),
                }),
                critical: readiness.project_ref_matches_token.is_some(),
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!(
                    "Auth mode: {} ({})",
                    readiness.auth_mode, readiness.key_classification
                )),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "secret_material".into(),
                passed: readiness.secret_material_configured,
                message: Some(if readiness.secret_material_configured {
                    "Secret material configured directly".into()
                } else {
                    "Secretless mode requires host-side credential injection before live verification"
                        .into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "permission_model".into(),
                passed: !limited_scope,
                message: Some(readiness.permissions_guidance.clone()),
                critical: false,
            });
        }
        let result = DoctorResult::from_checks(checks, provisioning);
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "supabase.provisioning.doctor",
            status = result.status_label(),
            check_count = result.checks.len(),
            failed_checks,
            "Supabase doctor checks completed"
        );
        result
    }

    fn attach_self_check_details(
        mut report: SelfCheckReport,
        provisioning: Option<ProvisioningReadiness>,
        live_probe: Option<serde_json::Value>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "provisioning": provisioning,
            "live_probe": live_probe,
            "operator_guidance": operator_guidance(),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
        }));
        report
    }
}

impl Default for SupabaseConnector {
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
            id: OperationId::from_static(OP_QUERY),
            summary: "Query a Supabase table or view through PostgREST".into(),
            description: None,
            input_schema: json!({"type":"object","required":["table"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Read rows from a PostgREST table or view",
                vec!["Forgetting to add a limit for wide tables".into()],
                vec![],
                vec![CAP_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_INSERT),
            summary: "Insert rows into a Supabase table".into(),
            description: None,
            input_schema: json!({"type":"object","required":["table","rows"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Create new rows via PostgREST",
                vec!["Sending an empty rows array".into()],
                vec![],
                vec![CAP_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_UPDATE),
            summary: "Update rows in a Supabase table".into(),
            description: None,
            input_schema: json!({"type":"object","required":["table","values","filters"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Patch rows matching explicit filters",
                vec!["Omitting filters broadens the mutation surface".into()],
                vec![],
                vec![CAP_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_UPSERT),
            summary: "Upsert rows in a Supabase table".into(),
            description: None,
            input_schema: json!({"type":"object","required":["table","rows"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Merge rows using conflict resolution",
                vec!["Forgetting on_conflict for non-primary-key merges".into()],
                vec![],
                vec![CAP_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DELETE),
            summary: "Delete rows from a Supabase table".into(),
            description: None,
            input_schema: json!({"type":"object","required":["table","filters"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Hard-delete rows (irreversible)",
                vec!["Running delete without a narrow filter".into()],
                vec![],
                vec![CAP_WRITE],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RPC),
            summary: "Invoke a Supabase Postgres function through PostgREST RPC".into(),
            description: None,
            input_schema: json!({"type":"object","required":["function"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: hint(
                "Call a server-side Postgres function via /rpc",
                vec!["Assuming RPC is read-only without checking function semantics".into()],
                vec![],
                vec![CAP_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_SCHEMA_TABLES),
            summary: "List exposed PostgREST table and view resources".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Inspect what relations the PostgREST surface exposes",
                vec!["Assuming system tables will appear".into()],
                vec![],
                vec![CAP_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_UPLOAD),
            summary: "Upload a file into Supabase Storage".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","path","content_base64"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: hint(
                "Upload an object into a Storage bucket",
                vec!["Sending raw bytes instead of base64".into()],
                vec![],
                vec![CAP_STORAGE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_DOWNLOAD),
            summary: "Download a file from Supabase Storage".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","path"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Retrieve a stored object from Supabase Storage",
                vec!["Using the public path for a private bucket".into()],
                vec![],
                vec![CAP_STORAGE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_DELETE),
            summary: "Delete a file from Supabase Storage".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","path"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently remove a Storage object (irreversible)",
                vec!["Deleting wrong path due to missing folder segments".into()],
                vec![],
                vec![CAP_STORAGE],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check Supabase PostgREST reachability".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Verify that the Supabase REST surface is reachable",
                vec!["Assuming health proves every table policy is correct".into()],
                vec![],
                vec![CAP_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

fn json_response(key: &str, response: crate::types::JsonHttpResponse) -> serde_json::Value {
    let count = response
        .content_range
        .as_deref()
        .and_then(parse_content_range_total);

    let mut output = json!({
        key: response.data,
        "status_code": response.status_code,
    });
    if let Some(content_range) = response.content_range {
        output["content_range"] = json!(content_range);
    }
    if let Some(content_type) = response.content_type {
        output["content_type"] = json!(content_type);
    }
    if let Some(count) = count {
        output["count"] = json!(count);
    }
    output
}

fn parse_content_range_total(content_range: &str) -> Option<u64> {
    content_range.split('/').nth(1)?.parse::<u64>().ok()
}

#[async_trait]
impl FcpConnector for SupabaseConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = SupabaseConfig::from_value(config)?;
        let readiness = cfg.provisioning_readiness();
        let auth = cfg.auth();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        ));
        let client =
            SupabaseClient::new(auth, &cfg.project_url, &cfg.schema, cfg.request_timeout_ms)
                .map_err(|e| FcpError::Internal {
                    message: format!("Client init: {e}"),
                })?;
        self.client = Some(client);
        self.config = Some(cfg);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!(
            event = "supabase.configure",
            auth_mode = readiness.auth_mode,
            key_classification = %readiness.key_classification,
            network_ok = readiness.network_ok,
            project_url = %readiness.project_url,
            "Configured Supabase connector"
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
            .map(SupabaseConfig::provisioning_readiness);
        let handshaken = self.base.handshaken.load(Ordering::Acquire);
        let mut snap = match &provisioning {
            Some(readiness)
                if !readiness.network_ok || readiness.project_ref_matches_token == Some(false) =>
            {
                HealthSnapshot::error("Supabase provisioning is not ready")
            }
            Some(readiness)
                if readiness.requires_credential_injection
                    || readiness.key_classification == "publishable"
                    || readiness.key_role_hint.as_deref() == Some("anon") =>
            {
                HealthSnapshot::degraded(
                    "Supabase is reachable but not fully ready for all operations",
                )
            }
            Some(_) => HealthSnapshot::ready(),
            None => HealthSnapshot::degraded("not configured"),
        };
        snap.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snap.details = Some(json!({
            "configured": self.config.is_some(),
            "handshaken": handshaken,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
        }));
        snap
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
                None,
            ));
        };
        let readiness = config.provisioning_readiness();
        let Some(client) = &self.client else {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "client_missing",
                    "Supabase HTTP client not initialized; re-run configure",
                ),
                Some(readiness),
                None,
            ));
        };

        if !readiness.network_ok {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "network_constraints_invalid",
                    readiness.network_message.clone(),
                ),
                Some(readiness),
                None,
            ));
        }
        if readiness.project_ref_matches_token == Some(false) {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "project_ref_mismatch",
                    format!(
                        "project_url ref {} does not match token ref {}",
                        readiness.project_ref.as_deref().unwrap_or("unknown"),
                        readiness.token_project_ref.as_deref().unwrap_or("unknown")
                    ),
                ),
                Some(readiness),
                None,
            ));
        }
        if readiness.requires_credential_injection {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::degraded(
                    "credential_injection_required",
                    "No API key configured; egress proxy must inject credentials before live verification",
                ),
                Some(readiness),
                None,
            ));
        }

        match client.health().await {
            Ok(v) if v.get("status").and_then(|s| s.as_str()) == Some("ok") => {
                let classification = match &config.auth() {
                    SupabaseAuth::ApiKey(key) => classify_api_key(key),
                    SupabaseAuth::Secretless => ApiKeyClassification::Opaque,
                };
                let report = if classification.implies_limited_scope() {
                    SelfCheckReport::degraded(
                        "limited_key_scope",
                        "Supabase REST root is reachable, but publishable/anon keys may still fail writes, RPCs, or Storage mutations under RLS and bucket policies",
                    )
                } else {
                    SelfCheckReport::ok()
                };
                Ok(Self::attach_self_check_details(
                    report,
                    Some(readiness),
                    Some(v),
                ))
            }
            Ok(v) => Ok(Self::attach_self_check_details(
                SelfCheckReport::degraded(
                    "health_unknown",
                    "PostgREST responded but health status is unclear",
                ),
                Some(readiness),
                Some(v),
            )),
            Err(error @ crate::error::SupabaseError::Auth(_)) => {
                Ok(Self::attach_self_check_details(
                    SelfCheckReport::failed("auth_invalid", error.to_string()),
                    Some(readiness),
                    None,
                ))
            }
            Err(error @ crate::error::SupabaseError::PermissionDenied(_)) => {
                Ok(Self::attach_self_check_details(
                    SelfCheckReport::failed("permissions_insufficient", error.to_string()),
                    Some(readiness),
                    None,
                ))
            }
            Err(error) if error.is_retryable() => Ok(Self::attach_self_check_details(
                SelfCheckReport::degraded("self_check_retryable", error.to_string()),
                Some(readiness),
                None,
            )),
            Err(error) => Ok(Self::attach_self_check_details(
                SelfCheckReport::failed("self_check_failed", error.to_string()),
                Some(readiness),
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
        if let Some(client) = &self.client {
            client.shutdown();
        }
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

impl SupabaseConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_QUERY | OP_SCHEMA_TABLES | OP_HEALTH => CapabilityId::from_static(CAP_READ),
                OP_INSERT | OP_UPDATE | OP_UPSERT | OP_DELETE | OP_RPC => {
                    CapabilityId::from_static(CAP_WRITE)
                }
                OP_STORAGE_UPLOAD | OP_STORAGE_DOWNLOAD | OP_STORAGE_DELETE => {
                    CapabilityId::from_static(CAP_STORAGE)
                }
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            };
            verifier.verify(req.capability_token, &cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        }

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Supabase client".into(),
        })?;

        let output =
            match operation {
                OP_QUERY => {
                    let request: TableQueryRequest = serde_json::from_value(req.input.clone())
                        .map_err(|e| FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid query input: {e}"),
                        })?;
                    let result = client.query(&request).await.map_err(|e| e.to_fcp_error())?;
                    json_response("data", result)
                }
                OP_INSERT => {
                    let request: InsertRequest = serde_json::from_value(req.input.clone())
                        .map_err(|e| FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid insert input: {e}"),
                        })?;
                    let result = client
                        .insert(&request)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    json_response("data", result)
                }
                OP_UPDATE => {
                    let request: UpdateRequest = serde_json::from_value(req.input.clone())
                        .map_err(|e| FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid update input: {e}"),
                        })?;
                    let result = client
                        .update(&request)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    json_response("data", result)
                }
                OP_UPSERT => {
                    let request: UpsertRequest = serde_json::from_value(req.input.clone())
                        .map_err(|e| FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid upsert input: {e}"),
                        })?;
                    let result = client
                        .upsert(&request)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    json_response("data", result)
                }
                OP_DELETE => {
                    let request: DeleteRequest = serde_json::from_value(req.input.clone())
                        .map_err(|e| FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid delete input: {e}"),
                        })?;
                    let result = client
                        .delete(&request)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    json_response("data", result)
                }
                OP_RPC => {
                    let request: RpcRequest =
                        serde_json::from_value(req.input.clone()).map_err(|e| {
                            FcpError::InvalidRequest {
                                code: 1005,
                                message: format!("Invalid RPC input: {e}"),
                            }
                        })?;
                    let result = client.rpc(&request).await.map_err(|e| e.to_fcp_error())?;
                    json_response("data", result)
                }
                OP_SCHEMA_TABLES => {
                    let request: SchemaTablesRequest = serde_json::from_value(req.input.clone())
                        .map_err(|e| FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid schema_tables input: {e}"),
                        })?;
                    let result = client
                        .schema_tables(&request)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    serde_json::to_value(result).unwrap_or(json!({"tables": []}))
                }
                OP_STORAGE_UPLOAD => {
                    let request: StorageUploadRequest = serde_json::from_value(req.input.clone())
                        .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid storage_upload input: {e}"),
                    })?;
                    let result = client
                        .storage_upload(&request)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    json_response("object", result)
                }
                OP_STORAGE_DOWNLOAD => {
                    let request: StorageDownloadRequest = serde_json::from_value(req.input.clone())
                        .map_err(|e| FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid storage_download input: {e}"),
                        })?;
                    let result = client
                        .storage_download(&request)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    serde_json::to_value(result).unwrap_or(json!({}))
                }
                OP_STORAGE_DELETE => {
                    let request: StorageDeleteRequest = serde_json::from_value(req.input.clone())
                        .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid storage_delete input: {e}"),
                    })?;
                    let result = client
                        .storage_delete(&request)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    json_response("result", result)
                }
                OP_HEALTH => {
                    let health = client.health().await.map_err(|e| e.to_fcp_error())?;
                    json!({ "health": health })
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
        json!({"api_key": "sb-test-key", "project_url": "https://demo.supabase.co"})
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
                CapabilityId::from_static(CAP_STORAGE),
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
            connector_id: ConnectorId::from_static("fcp.supabase"),
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
        assert!(SupabaseConnector::new().config.is_none());
    }

    #[test]
    fn default_ok() {
        assert!(SupabaseConnector::default().config.is_none());
    }

    #[test]
    fn manifest_hash_stable() {
        assert_eq!(
            SupabaseConnector::manifest_hash(),
            SupabaseConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = SupabaseConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_no_key_succeeds() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = SupabaseConnector::new();
                c.configure(json!({"project_url": "https://demo.supabase.co"}))
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
                let mut c = SupabaseConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn introspect_ops() {
        assert_eq!(SupabaseConnector::new().introspect().operations.len(), 11);
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
                let mut c = SupabaseConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("supabase.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_table() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = SupabaseConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_QUERY, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            SupabaseConnector::new()
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.supabase"),
                    OperationId::from_static(OP_QUERY),
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
                SupabaseConnector::new()
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
            let mut c = SupabaseConnector::new();
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
            let mut c = SupabaseConnector::new();
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
            SupabaseConnector::require_str(&json!({"k": "v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(SupabaseConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn require_str_empty() {
        assert!(SupabaseConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(SupabaseConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }

    #[test]
    fn health_unconfigured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            SupabaseConnector::new().health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = SupabaseConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
    }

    #[test]
    fn config_debug_redacts_api_key() {
        let config = SupabaseConfig::from_value(tc()).unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("sb-test-key"));
    }

    #[test]
    fn parse_content_range_total_works() {
        assert_eq!(parse_content_range_total("0-9/100"), Some(100));
        assert_eq!(parse_content_range_total("0-9/*"), None);
        assert_eq!(parse_content_range_total("*/42"), Some(42));
    }

    #[test]
    fn parse_content_range_total_empty() {
        assert_eq!(parse_content_range_total(""), None);
    }

    #[test]
    fn operations_match_v3_contract() {
        let ops = operations_info();

        let find = |id: &str| ops.iter().find(|o| o.id.as_str() == id).unwrap();

        let query = find(OP_QUERY);
        assert_eq!(query.safety_tier, SafetyTier::Safe);
        assert_eq!(query.risk_level, RiskLevel::Low);
        assert_eq!(query.idempotency, IdempotencyClass::Strict);

        let insert = find(OP_INSERT);
        assert_eq!(insert.safety_tier, SafetyTier::Risky);
        assert_eq!(insert.risk_level, RiskLevel::Medium);

        let delete = find(OP_DELETE);
        assert_eq!(delete.safety_tier, SafetyTier::Dangerous);
        assert_eq!(delete.risk_level, RiskLevel::High);
        assert!(delete.requires_approval.is_some());

        let rpc = find(OP_RPC);
        assert_eq!(rpc.idempotency, IdempotencyClass::BestEffort);

        let download = find(OP_STORAGE_DOWNLOAD);
        assert_eq!(download.idempotency, IdempotencyClass::None);

        let upload = find(OP_STORAGE_UPLOAD);
        assert_eq!(upload.idempotency, IdempotencyClass::BestEffort);

        let storage_delete = find(OP_STORAGE_DELETE);
        assert_eq!(storage_delete.safety_tier, SafetyTier::Dangerous);
        assert!(storage_delete.requires_approval.is_some());
    }

    #[test]
    fn event_caps_disabled() {
        let intro = SupabaseConnector::new().introspect();
        let caps = intro.event_caps.unwrap();
        assert!(!caps.streaming);
        assert!(!caps.replay);
    }

    #[test]
    fn connector_id_correct() {
        let c = SupabaseConnector::new();
        assert_eq!(c.id().as_str(), "fcp.supabase");
    }

    #[test]
    fn project_url_policy_accepts_supabase_host() {
        let (ok, message, project_ref) = project_url_policy("https://demo-ref.supabase.co");
        assert!(ok);
        assert!(message.contains("accepted"));
        assert_eq!(project_ref.as_deref(), Some("demo-ref"));
    }

    #[test]
    fn project_url_policy_accepts_localhost() {
        let (ok, _message, project_ref) = project_url_policy("http://localhost:54321");
        assert!(ok);
        assert_eq!(project_ref, None);
    }

    #[test]
    fn project_url_policy_rejects_external_http() {
        let (ok, message, _project_ref) = project_url_policy("http://example.com/api");
        assert!(!ok);
        assert!(message.contains("scheme must be https"));
        assert!(message.contains("host must end with"));
    }

    #[test]
    fn classify_api_key_prefixes() {
        assert_eq!(
            classify_api_key("sb_secret_123"),
            ApiKeyClassification::Secret
        );
        assert_eq!(
            classify_api_key("sb_publishable_123"),
            ApiKeyClassification::Publishable
        );
    }

    #[test]
    fn classify_api_key_service_role_jwt() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"role":"service_role","ref":"projref"}"#);
        let token = format!("{header}.{payload}.sig");
        assert_eq!(
            classify_api_key(&token),
            ApiKeyClassification::JwtRole("service_role".into())
        );
        assert_eq!(decode_jwt_claim(&token, "ref").as_deref(), Some("projref"));
    }

    #[test]
    fn provisioning_readiness_detects_project_ref_mismatch() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"role":"anon","ref":"other-ref"}"#);
        let token = format!("{header}.{payload}.sig");
        let config = SupabaseConfig::from_value(json!({
            "api_key": token,
            "project_url": "https://demo-ref.supabase.co",
            "schema": "public"
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.project_ref_matches_token, Some(false));
        assert_eq!(readiness.key_role_hint.as_deref(), Some("anon"));
    }

    #[test]
    fn doctor_unconfigured_contains_operator_guidance() {
        let doctor = serde_json::to_value(SupabaseConnector::new().doctor()).unwrap();
        assert_eq!(doctor["status"], "unhealthy");
        assert_eq!(
            doctor["verification_script"],
            "scripts/e2e/supabase_connector_verification.sh"
        );
        assert_eq!(
            doctor["operator_guidance"]["artifact_root_hint"],
            "artifacts/e2e/supabase_connector/<timestamp>"
        );
    }
}
