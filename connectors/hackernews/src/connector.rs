//! Hacker News connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, ResourceTypeInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::HackerNewsClient;
use crate::error::HackerNewsError;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const DEFAULT_BASE_URL: &str = "https://hacker-news.firebaseio.com/v0";

// Operation IDs
const OP_ITEM_GET: &str = "hackernews.item.get";
const OP_USER_GET: &str = "hackernews.user.get";
const OP_TOP_STORIES: &str = "hackernews.top_stories";
const OP_NEW_STORIES: &str = "hackernews.new_stories";
const OP_BEST_STORIES: &str = "hackernews.best_stories";
const OP_ASK_STORIES: &str = "hackernews.ask_stories";
const OP_SHOW_STORIES: &str = "hackernews.show_stories";
const OP_JOB_STORIES: &str = "hackernews.job_stories";
const OP_HEALTH: &str = "hackernews.health";

// Capability IDs
const CAP_READ: &str = "hackernews.read";
const HN_PUBLIC_API_BOUNDARY: &str = "This connector only exposes public Firebase Hacker News reads; there is no Algolia search, authenticated account action, moderation, or streaming surface in the first slice.";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/hackernews_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/hackernews_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 11] = [
    "scripts/e2e/hackernews_connector_verification.sh",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo run -q -p fwc -- manifest fix connectors/hackernews/manifest.toml --check --json",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo fmt --manifest-path connectors/hackernews/Cargo.toml --check",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo check -p fcp-hackernews --all-targets",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration health_unconfigured_includes_guidance -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration self_check_ready_with_public_probe_and_evidence -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration self_check_retryable_api_failure_reports_degraded -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration invoke_item_get_preserves_public_item_evidence -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration introspection_emits_v3_compliance_evidence -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo clippy -p fcp-hackernews --all-targets -- -D warnings",
];

/// Hacker News connector configuration.
/// Auth is optional since HN API is entirely public.
#[derive(Clone, Deserialize)]
struct HackerNewsConfig {
    /// Optional custom base URL (defaults to Firebase HN API).
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for HackerNewsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HackerNewsConfig")
            .field("base_url", &self.base_url)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

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
    request_timeout_ms: u64,
    retry: RetryReadiness,
    item_lookup: bool,
    user_lookup: bool,
    feed_snapshots: Vec<&'static str>,
    search_supported: bool,
    write_supported: bool,
    streaming_supported: bool,
    comment_tree_expansion_supported: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
}

// Doctor types
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
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
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

/// Hacker News connector state.
#[derive(Debug)]
pub struct HackerNewsConnector {
    base: BaseConnector,
    config: Option<HackerNewsConfig>,
    client: Option<HackerNewsClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl HackerNewsConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.hackernews")),
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

    fn resolved_base_url(&self) -> Option<String> {
        self.client
            .as_ref()
            .map(|client| client.base_url().to_string())
            .or_else(|| {
                self.config.as_ref().map(|config| {
                    config
                        .base_url
                        .as_deref()
                        .unwrap_or(DEFAULT_BASE_URL)
                        .trim_end_matches('/')
                        .to_string()
                })
            })
    }

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.config.as_ref().map(|config| ProvisioningReadiness {
            provider: "hacker_news_firebase",
            base_url: self
                .resolved_base_url()
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
            auth_mode: "anonymous_public_api",
            request_timeout_ms: config.request_timeout_ms,
            retry: RetryReadiness {
                max_retries: config.retry.max_retries,
                initial_delay_ms: config.retry.initial_delay_ms,
                max_delay_ms: config.retry.max_delay_ms,
                jitter_enabled: config.retry.jitter_enabled,
            },
            item_lookup: true,
            user_lookup: true,
            feed_snapshots: vec!["top", "new", "best", "ask", "show", "job"],
            search_supported: false,
            write_supported: false,
            streaming_supported: false,
            comment_tree_expansion_supported: false,
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

    fn health_probe_details(
        client: &HackerNewsClient,
        retryable: bool,
        error: Option<&str>,
        retry_after_ms: Option<u64>,
    ) -> serde_json::Value {
        let base_url = client.base_url();
        json!({
            "base_url": base_url,
            "health_endpoint": format!("{base_url}/topstories.json"),
            "auth_mode": "anonymous_public_api",
            "surface_mode": "public_read_only",
            "search_supported": false,
            "write_supported": false,
            "retryable": retryable,
            "error": error,
            "retry_after_ms": retry_after_ms,
        })
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self.provisioning_readiness();
        let mut checks = Vec::new();

        // Configuration is always "passed" since HN has no required auth
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

        checks.push(DoctorCheck {
            name: "auth".into(),
            passed: true,
            message: Some("No authentication required (public API)".into()),
            critical: false,
        });

        if let Some(client) = &self.client {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: true,
                message: Some(format!("Base URL: {}", client.base_url())),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "read_only_surface".into(),
                passed: true,
                message: Some(
                    "Public read-only surface: items, users, ranked feeds, and health".into(),
                ),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "search_surface".into(),
                passed: true,
                message: Some(
                    "Algolia search is intentionally unsupported in the first slice".into(),
                ),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "write_surface".into(),
                passed: true,
                message: Some("No authenticated write or moderation surface is exposed".into()),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for HackerNewsConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use the public Firebase Hacker News API or a localhost mock override for verification.",
            "Treat this connector as read-only: item reads, user reads, feed snapshots, and health only.",
            "If you override base_url during verification, capture the override in the evidence bundle and keep it on the Firebase host or localhost.",
        ],
        dedicated_environment: "Prefer public HN data or a disposable localhost mock server. No authenticated YC or moderator environment is required.",
        redaction_rules: vec![
            "If verification uses a private mirror, redact the override hostname before sharing artifacts.",
            "Avoid publishing unnecessary raw user `about` fields or copied item text outside the owning team.",
            "Do not attach unrelated request traces from shared verification environments.",
        ],
        limitations: vec![
            "Algolia search is intentionally unsupported in the first slice.",
            "No submit, vote, favorite, reply, login, moderation, or admin workflows are exposed.",
            "Comments are only reachable through item.get; recursive thread expansion and live subscriptions are out of scope.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "health or self_check reports that the connector is not configured",
                action: "Configure base_url only if needed, plus timeout and retry settings, then rerun self_check.",
            },
            RemediationHint {
                code: "runtime_missing",
                symptom: "self_check reports that the connector runtime is not initialized",
                action: "Re-run configure so ConnectorRuntime and the HTTP client are both initialized before verification.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "public API probe failed with rate limiting, timeout, or transient 5xx",
                action: "Wait for the upstream to recover or relax retry and timeout settings, then rerun the verification script.",
            },
            RemediationHint {
                code: "self_check_failed",
                symptom: "self_check reports a non-retryable API or deserialization failure",
                action: "Verify the base_url still points at a Firebase-compatible Hacker News endpoint and inspect the captured live_probe error details.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn hackernews_resource_types() -> Vec<ResourceTypeInfo> {
    vec![
        ResourceTypeInfo {
            name: "hackernews.item".into(),
            uri_pattern: "hackernews://items/{item_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["id", "type"],
                "properties": {
                    "id": {"type": "integer"},
                    "type": {"type": "string"},
                    "by": {"type": "string"},
                    "time": {"type": "integer"},
                    "title": {"type": "string"},
                    "text": {"type": "string"},
                    "url": {"type": "string"},
                    "score": {"type": "integer"},
                    "parent": {"type": "integer"},
                    "kids": {"type": "array", "items": {"type": "integer"}},
                    "descendants": {"type": "integer"},
                    "deleted": {"type": "boolean"},
                    "dead": {"type": "boolean"}
                }
            }),
        },
        ResourceTypeInfo {
            name: "hackernews.user".into(),
            uri_pattern: "hackernews://users/{username}".into(),
            schema: json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": {"type": "string"},
                    "created": {"type": "integer"},
                    "karma": {"type": "integer"},
                    "about": {"type": "string"},
                    "submitted": {"type": "array", "items": {"type": "integer"}}
                }
            }),
        },
        ResourceTypeInfo {
            name: "hackernews.feed_snapshot".into(),
            uri_pattern: "hackernews://feeds/{feed_name}".into(),
            schema: json!({
                "type": "object",
                "required": ["feed", "item_ids"],
                "properties": {
                    "feed": {
                        "type": "string",
                        "enum": ["top", "new", "best", "ask", "show", "job"]
                    },
                    "item_ids": {"type": "array", "items": {"type": "integer"}}
                }
            }),
        },
    ]
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_ITEM_GET),
            summary: "Get an item by ID".into(),
            description: Some("Retrieves one public Firebase item by numeric ID. Covers stories, comments, jobs, polls, and poll options, but does not recursively expand comment trees or enrich feed snapshots.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "integer", "description": "Item ID" }
                }
            }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to fetch a specific HN story, comment, job, or poll by its numeric ID".into(),
                common_mistakes: vec![
                    "Item IDs are numeric, not string usernames".into(),
                    "Deleted or dead items may return partial data".into(),
                    "Search, batching, and recursive thread expansion are explicit non-goals for this first slice".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_USER_GET),
            summary: "Get a user by username".into(),
            description: Some("Retrieves one public Hacker News user profile by case-sensitive username. No login, private account state, or authenticated actor context is exposed.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["username"],
                "properties": {
                    "username": { "type": "string", "description": "HN username (case-sensitive)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "created": { "type": "integer" },
                    "karma": { "type": "integer" },
                    "about": { "type": "string" },
                    "submitted": { "type": "array", "items": { "type": "integer" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to look up a Hacker News user's profile by username".into(),
                common_mistakes: vec![
                    "Usernames are case-sensitive".into(),
                    "This connector does not expose authenticated user actions or private profile data".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_TOP_STORIES),
            summary: "Get top story IDs".into(),
            description: Some("Returns a top-stories snapshot as numeric item IDs only. Use item.get to expand stories; there is no automatic hydration or search surface.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Limit number of IDs returned" }
                }
            }),
            output_schema: json!({
                "type": "array",
                "items": { "type": "integer" }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need the current top/front page stories on HN".into(),
                common_mistakes: vec![
                    "Returns only IDs - use item.get to fetch full story details".into(),
                    HN_PUBLIC_API_BOUNDARY.into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_NEW_STORIES),
            summary: "Get new story IDs".into(),
            description: Some("Returns a newest-stories snapshot as numeric item IDs only. This is a feed snapshot, not a write, search, or live-streaming API.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Limit number of IDs returned" }
                }
            }),
            output_schema: json!({
                "type": "array",
                "items": { "type": "integer" }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need the most recently submitted stories".into(),
                common_mistakes: vec![
                    "Returns only IDs - use item.get to fetch full story details".into(),
                    "This connector does not expose live subscriptions or polling cursors".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_BEST_STORIES),
            summary: "Get best story IDs".into(),
            description: Some("Returns a best-stories snapshot as numeric item IDs only. Upstream ranking semantics come from Hacker News; the connector does not re-rank or search.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Limit number of IDs returned" }
                }
            }),
            output_schema: json!({
                "type": "array",
                "items": { "type": "integer" }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need the highest-ranked stories over time".into(),
                common_mistakes: vec![
                    "Returns only IDs - use item.get to fetch full story details".into(),
                    "This is not an Algolia relevance-search endpoint".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ASK_STORIES),
            summary: "Get Ask HN story IDs".into(),
            description: Some("Returns an Ask HN feed snapshot as numeric item IDs only. There is no thread expansion or reply/write surface.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Limit number of IDs returned" }
                }
            }),
            output_schema: json!({
                "type": "array",
                "items": { "type": "integer" }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need Ask HN discussion threads".into(),
                common_mistakes: vec![
                    "Returns only IDs - use item.get to fetch full story details".into(),
                    "The connector does not recursively expand Ask HN comment trees".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SHOW_STORIES),
            summary: "Get Show HN story IDs".into(),
            description: Some("Returns a Show HN feed snapshot as numeric item IDs only. The connector does not auto-expand items or scrape extra metadata from news.ycombinator.com.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Limit number of IDs returned" }
                }
            }),
            output_schema: json!({
                "type": "array",
                "items": { "type": "integer" }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need Show HN project showcase threads".into(),
                common_mistakes: vec![
                    "Returns only IDs - use item.get to fetch full story details".into(),
                    "This connector does not scrape HTML pages for richer project metadata".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_JOB_STORIES),
            summary: "Get job story IDs".into(),
            description: Some("Returns a Jobs feed snapshot as numeric item IDs only. The connector does not submit jobs, favorite posts, or perform authenticated actions.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Limit number of IDs returned" }
                }
            }),
            output_schema: json!({
                "type": "array",
                "items": { "type": "integer" }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need current YC/HN job postings".into(),
                common_mistakes: vec![
                    "Returns only IDs - use item.get to fetch full story details".into(),
                    "There is no authenticated submit or moderation surface in this connector".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check HN API health".into(),
            description: Some("Verifies the public Firebase Hacker News API is reachable. This does not validate search, writes, or any authenticated surface because those are not in scope.".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to verify the HN API is reachable and operational".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(HackerNewsConnector);

#[async_trait]
impl FcpConnector for HackerNewsConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: HackerNewsConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid HackerNews config: {e}"),
            })?;

        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = HackerNewsClient::new(config.base_url.as_deref(), config.retry.clone())
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HN client: {e}"),
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
        let provisioning = self.provisioning_readiness();
        let mut snapshot = match &self.client {
            None if self.config.is_none() => HealthSnapshot::degraded("not configured"),
            None => HealthSnapshot::error("client not initialized"),
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
        if self.runtime.is_none() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed("runtime_missing", "Connector runtime is not initialized"),
                None,
            ));
        };

        match client.health_check().await {
            Ok(()) => {
                let live_probe = Self::health_probe_details(client, false, None, None);
                Ok(self.attach_self_check_details(SelfCheckReport::ok(), Some(&live_probe)))
            }
            Err(HackerNewsError::RateLimited { retry_after_ms }) => {
                let message = format!("Rate limited, retry after {retry_after_ms}ms");
                let live_probe =
                    Self::health_probe_details(client, true, Some(&message), Some(retry_after_ms));
                Ok(self.attach_self_check_details(
                    SelfCheckReport::degraded("self_check_retryable", message),
                    Some(&live_probe),
                ))
            }
            Err(error) if error.is_retryable() => {
                let error_text = error.to_string();
                let live_probe = Self::health_probe_details(client, true, Some(&error_text), None);
                Ok(self.attach_self_check_details(
                    SelfCheckReport::degraded("self_check_retryable", error_text),
                    Some(&live_probe),
                ))
            }
            Err(error) => {
                let error_text = error.to_string();
                let live_probe = Self::health_probe_details(client, false, Some(&error_text), None);
                Ok(self.attach_self_check_details(
                    SelfCheckReport::failed("self_check_failed", error_text),
                    Some(&live_probe),
                ))
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
            resource_types: hackernews_resource_types(),
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

impl HackerNewsConnector {
    /// Apply an optional limit to a list of IDs.
    fn apply_limit(ids: Vec<u64>, limit: Option<u64>) -> Vec<u64> {
        match limit {
            Some(n) => ids.into_iter().take(n as usize).collect(),
            None => ids,
        }
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        // All HN operations require the read capability
        let required_cap = match operation {
            OP_ITEM_GET | OP_USER_GET | OP_TOP_STORIES | OP_NEW_STORIES | OP_BEST_STORIES
            | OP_ASK_STORIES | OP_SHOW_STORIES | OP_JOB_STORIES | OP_HEALTH => {
                CapabilityId::from_static(CAP_READ)
            }
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
            message: "HN client missing after configure".into(),
        })?;

        let output = match operation {
            OP_ITEM_GET => {
                let id = req.input.get("id").and_then(|v| v.as_u64()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing or invalid 'id' field (must be integer)".into(),
                    },
                )?;
                let item = client
                    .get_item(runtime, id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(item).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize item: {e}"),
                })?
            }
            OP_USER_GET => {
                let username = req.input.get("username").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'username' field".into(),
                    },
                )?;
                let user = client
                    .get_user(runtime, username)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(user).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize user: {e}"),
                })?
            }
            OP_TOP_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .top_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
            }
            OP_NEW_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .new_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
            }
            OP_BEST_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .best_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
            }
            OP_ASK_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .ask_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
            }
            OP_SHOW_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .show_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
            }
            OP_JOB_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .job_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
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

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
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

    fn test_config() -> serde_json::Value {
        json!({})
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = HackerNewsConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_empty() {
        let mut connector = HackerNewsConnector::new();
        let result = connector.configure(test_config()).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_url() {
        let mut connector = HackerNewsConnector::new();
        let result = connector
            .configure(json!({
                "base_url": "http://localhost:8080/v0"
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = HackerNewsConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = HackerNewsConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        let report = connector.doctor();
        assert!(report.passed);
        // Verify auth check says no auth required
        let auth_check = report.checks.iter().find(|c| c.name == "auth").unwrap();
        assert!(auth_check.passed);
        assert!(
            auth_check
                .message
                .as_ref()
                .unwrap()
                .contains("No authentication")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = HackerNewsConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = HackerNewsConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_ITEM_GET),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = HackerNewsConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 9);
        for op_name in &[
            OP_ITEM_GET,
            OP_USER_GET,
            OP_TOP_STORIES,
            OP_NEW_STORIES,
            OP_BEST_STORIES,
            OP_ASK_STORIES,
            OP_SHOW_STORIES,
            OP_JOB_STORIES,
            OP_HEALTH,
        ] {
            assert!(
                intro.operations.iter().any(|op| op.id.as_str() == *op_name),
                "Missing operation: {op_name}"
            );
        }
    }

    #[test]
    fn test_introspection_resource_inventory() {
        let intro = HackerNewsConnector::new().introspect();
        let names: Vec<&str> = intro
            .resource_types
            .iter()
            .map(|resource| resource.name.as_str())
            .collect();
        assert!(names.contains(&"hackernews.item"));
        assert!(names.contains(&"hackernews.user"));
        assert!(names.contains(&"hackernews.feed_snapshot"));
    }

    #[test]
    fn test_introspection_keeps_auth_caps_none() {
        let intro = HackerNewsConnector::new().introspect();
        assert!(intro.auth_caps.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "hackernews.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = HackerNewsConnector::new();
        let req = base_invoke(connector.id(), OP_ITEM_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_id_field() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ITEM_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_username_field() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_USER_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 9);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_all_ops_are_safe() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.safety_tier,
                SafetyTier::Safe,
                "Op {} should be Safe",
                op.id.as_str()
            );
            assert_eq!(
                op.risk_level,
                RiskLevel::Low,
                "Op {} should be Low risk",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_item_get_is_strict_idempotent() {
        let ops = operations_info();
        let item_get = ops.iter().find(|op| op.id.as_str() == OP_ITEM_GET).unwrap();
        assert_eq!(item_get.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_user_get_is_strict_idempotent() {
        let ops = operations_info();
        let user_get = ops.iter().find(|op| op.id.as_str() == OP_USER_GET).unwrap();
        assert_eq!(user_get.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_story_lists_are_none_idempotent() {
        let ops = operations_info();
        for name in &[
            OP_TOP_STORIES,
            OP_NEW_STORIES,
            OP_BEST_STORIES,
            OP_ASK_STORIES,
            OP_SHOW_STORIES,
            OP_JOB_STORIES,
        ] {
            let op = ops
                .iter()
                .find(|o| o.id.as_str() == *name)
                .unwrap_or_else(|| panic!("Missing op: {name}"));
            assert_eq!(
                op.idempotency,
                IdempotencyClass::None,
                "Op {name} should be None idempotency"
            );
        }
    }

    #[test]
    fn test_health_is_strict_idempotent() {
        let ops = operations_info();
        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = HackerNewsConnector::manifest_hash();
        let hash2 = HackerNewsConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = HackerNewsConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
        assert!(intro.events.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector
            .invoke(base_invoke(connector.id(), OP_ITEM_GET))
            .await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[test]
    fn test_all_ops_use_read_capability() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.capability.as_str(),
                CAP_READ,
                "Op {} should use hackernews.read capability",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_no_approval_required() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.requires_approval,
                Some(ApprovalMode::None),
                "Op {} should not require approval",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_connector_id() {
        let connector = HackerNewsConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.hackernews");
    }

    #[test]
    fn test_default_impl() {
        let connector = HackerNewsConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.hackernews");
    }

    #[test]
    fn test_apply_limit() {
        let ids = vec![1, 2, 3, 4, 5];
        assert_eq!(
            HackerNewsConnector::apply_limit(ids.clone(), Some(3)),
            vec![1, 2, 3]
        );
        assert_eq!(
            HackerNewsConnector::apply_limit(ids.clone(), None),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(
            HackerNewsConnector::apply_limit(ids, Some(10)),
            vec![1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn test_apply_limit_zero() {
        let ids = vec![1, 2, 3];
        let result = HackerNewsConnector::apply_limit(ids, Some(0));
        assert!(result.is_empty());
    }
}
