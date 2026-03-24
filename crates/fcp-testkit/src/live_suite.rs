//! Live suite infrastructure for non-mock acceptance testing.
//!
//! Provides the shared secret, account provisioning, cost tracking, cleanup,
//! and environment-manifest layer required for connectors that cannot stop at
//! `local_non_mock` (Tiers B–E in live-suite-classification.md).
//!
//! # Environment Gating
//!
//! Live tests are gated by environment variables:
//! - `FCP_LIVE_SANDBOX=1`  — Tier B sandbox-required connectors
//! - `FCP_LIVE_READ=1`     — Tier D read-only public API connectors
//! - `FCP_LIVE_WRITE=1`    — Tier E write-required connectors
//! - `FCP_LIVE_DEVICE=1`   — Tier C device-required connectors
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::live_suite::*;
//!
//! #[test]
//! fn test_stripe_sandbox() {
//!     let gate = LiveGate::sandbox();
//!     if !gate.is_enabled() {
//!         eprintln!("Skipping: {}", gate.skip_reason());
//!         return;
//!     }
//!
//!     let env = LiveEnvironment::load("stripe").unwrap();
//!     let budget = env.cost_budget();
//!     let _cleanup = env.cleanup_guard();
//!
//!     // ... run live test with real Stripe test-mode keys ...
//!
//!     budget.record_api_call("payment_intents.create", 0.01);
//!     assert!(budget.within_limits());
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// Live Gate — Environment-variable-gated test enablement
// ─────────────────────────────────────────────────────────────────────────────

/// Which tier of live testing is being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveTier {
    /// Tier A: local fixtures only (no gate needed).
    LocalSufficient,
    /// Tier B: provider sandbox/test account required.
    SandboxRequired,
    /// Tier C: physical device or platform-specific runtime.
    DeviceRequired,
    /// Tier D: read-only access to real public APIs.
    LiveReadOnly,
    /// Tier E: write access with no sandbox available.
    LiveWriteRequired,
}

impl LiveTier {
    /// The environment variable that gates this tier.
    #[must_use]
    pub fn gate_env_var(self) -> &'static str {
        match self {
            Self::LocalSufficient => "FCP_LIVE_LOCAL",
            Self::SandboxRequired => "FCP_LIVE_SANDBOX",
            Self::DeviceRequired => "FCP_LIVE_DEVICE",
            Self::LiveReadOnly => "FCP_LIVE_READ",
            Self::LiveWriteRequired => "FCP_LIVE_WRITE",
        }
    }
}

impl fmt::Display for LiveTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalSufficient => write!(f, "local_sufficient"),
            Self::SandboxRequired => write!(f, "sandbox_required"),
            Self::DeviceRequired => write!(f, "device_required"),
            Self::LiveReadOnly => write!(f, "live_read_only"),
            Self::LiveWriteRequired => write!(f, "live_write_required"),
        }
    }
}

/// Controls whether a live test should run based on environment variables.
#[derive(Debug, Clone)]
pub struct LiveGate {
    tier: LiveTier,
    enabled: bool,
}

impl LiveGate {
    /// Create a gate for the given tier, checking the corresponding env var.
    #[must_use]
    pub fn for_tier(tier: LiveTier) -> Self {
        let enabled = match tier {
            LiveTier::LocalSufficient => true,
            _ => std::env::var(tier.gate_env_var())
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        };
        Self { tier, enabled }
    }

    /// Create a gate with an explicit enabled state (for testing).
    #[must_use]
    pub fn with_state(tier: LiveTier, enabled: bool) -> Self {
        Self { tier, enabled }
    }

    /// Convenience: Tier B sandbox gate.
    #[must_use]
    pub fn sandbox() -> Self {
        Self::for_tier(LiveTier::SandboxRequired)
    }

    /// Convenience: Tier D read-only gate.
    #[must_use]
    pub fn read_only() -> Self {
        Self::for_tier(LiveTier::LiveReadOnly)
    }

    /// Convenience: Tier E write gate.
    #[must_use]
    pub fn write() -> Self {
        Self::for_tier(LiveTier::LiveWriteRequired)
    }

    /// Convenience: Tier C device gate.
    #[must_use]
    pub fn device() -> Self {
        Self::for_tier(LiveTier::DeviceRequired)
    }

    /// Whether this gate allows the test to proceed.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The tier this gate checks.
    #[must_use]
    pub fn tier(&self) -> LiveTier {
        self.tier
    }

    /// Human-readable reason why the test was skipped.
    #[must_use]
    pub fn skip_reason(&self) -> String {
        format!(
            "Live tier '{}' not enabled. Set {}=1 to run.",
            self.tier,
            self.tier.gate_env_var()
        )
    }

    /// Skip the current test if the gate is not enabled. Returns `true` if
    /// the test should be skipped (caller should `return` early).
    #[must_use]
    pub fn skip_if_disabled(&self) -> bool {
        if !self.enabled {
            eprintln!("SKIP: {}", self.skip_reason());
            return true;
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Secret Provider — Centralized credential loading
// ─────────────────────────────────────────────────────────────────────────────

/// How a secret is sourced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretSource {
    /// Read from an environment variable.
    EnvVar(String),
    /// Read from a file path (for CI secrets mounted as files).
    File(String),
    /// Hardcoded test value (only for truly non-sensitive test-mode keys).
    TestDefault(String),
}

/// A single secret requirement for a live suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRequirement {
    /// Logical name (e.g., "api_key", "client_secret").
    pub name: String,
    /// Where to load the secret from.
    pub source: SecretSource,
    /// Whether the test can proceed without this secret.
    pub required: bool,
    /// Human-readable description of what this secret is for.
    pub description: String,
}

/// Loaded secrets for a live suite run.
#[derive(Clone)]
pub struct SecretBag {
    secrets: HashMap<String, String>,
    missing: Vec<String>,
}

impl SecretBag {
    /// Load secrets from the given requirements.
    #[must_use]
    pub fn load(requirements: &[SecretRequirement]) -> Self {
        let mut secrets = HashMap::new();
        let mut missing = Vec::new();

        for req in requirements {
            let value = match &req.source {
                SecretSource::EnvVar(var) => std::env::var(var).ok(),
                SecretSource::File(path) => std::fs::read_to_string(path).ok().map(|s| s.trim().to_owned()),
                SecretSource::TestDefault(val) => Some(val.clone()),
            };

            if let Some(val) = value {
                if !val.is_empty() {
                    secrets.insert(req.name.clone(), val);
                } else if req.required {
                    missing.push(req.name.clone());
                }
            } else if req.required {
                missing.push(req.name.clone());
            }
        }

        Self { secrets, missing }
    }

    /// Whether all required secrets are present.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// Names of missing required secrets.
    #[must_use]
    pub fn missing_secrets(&self) -> &[String] {
        &self.missing
    }

    /// Get a loaded secret by name. Returns `None` if not loaded.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.secrets.get(name).map(String::as_str)
    }

    /// Get a loaded secret, panicking with a clear message if missing.
    ///
    /// # Panics
    ///
    /// Panics if the secret is not loaded.
    #[must_use]
    pub fn require(&self, name: &str) -> &str {
        self.secrets.get(name).map(String::as_str).unwrap_or_else(|| {
            panic!("Required secret '{name}' not loaded. Check environment or secret configuration.")
        })
    }

    /// Number of loaded secrets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Whether no secrets were loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

impl fmt::Debug for SecretBag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBag")
            .field("loaded_count", &self.secrets.len())
            .field("loaded_keys", &self.secrets.keys().collect::<Vec<_>>())
            .field("missing", &self.missing)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cost Budget — Per-test-run spending limits
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks estimated cost of API calls during a live test run.
#[derive(Debug)]
pub struct CostBudget {
    /// Maximum allowed cost in USD cents (stored as integer for precision).
    max_cents: u64,
    /// Running total of estimated cost in hundredths of a cent.
    spent_hundredths: AtomicU64,
    /// Per-operation cost log.
    log: std::sync::Mutex<Vec<CostEntry>>,
}

/// A single cost entry.
#[derive(Debug, Clone, Serialize)]
pub struct CostEntry {
    /// Operation that incurred the cost (e.g., "payment_intents.create").
    pub operation: String,
    /// Estimated cost in USD.
    pub cost_usd: f64,
    /// Timestamp.
    pub timestamp: String,
}

impl CostBudget {
    /// Create a new budget with the given maximum in USD.
    #[must_use]
    pub fn new(max_usd: f64) -> Self {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let max_cents = (max_usd * 100.0) as u64;
        Self {
            max_cents,
            spent_hundredths: AtomicU64::new(0),
            log: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Default budget for nightly runs: $1.00 per connector.
    #[must_use]
    pub fn nightly_default() -> Self {
        Self::new(1.0)
    }

    /// Record an API call with estimated cost.
    pub fn record_api_call(&self, operation: &str, cost_usd: f64) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let hundredths = (cost_usd * 10_000.0) as u64;
        self.spent_hundredths.fetch_add(hundredths, Ordering::Relaxed);

        if let Ok(mut log) = self.log.lock() {
            log.push(CostEntry {
                operation: operation.to_owned(),
                cost_usd,
                timestamp: Utc::now().to_rfc3339(),
            });
        }
    }

    /// Whether current spending is within budget.
    #[must_use]
    pub fn within_limits(&self) -> bool {
        let spent = self.spent_hundredths.load(Ordering::Relaxed);
        spent <= self.max_cents * 100 // Compare hundredths to hundredths
    }

    /// Total spent in USD.
    #[must_use]
    pub fn total_spent_usd(&self) -> f64 {
        let hundredths = self.spent_hundredths.load(Ordering::Relaxed);
        #[allow(clippy::cast_precision_loss)]
        let usd = hundredths as f64 / 10_000.0;
        usd
    }

    /// Maximum budget in USD.
    #[must_use]
    pub fn max_usd(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let usd = self.max_cents as f64 / 100.0;
        usd
    }

    /// Remaining budget in USD.
    #[must_use]
    pub fn remaining_usd(&self) -> f64 {
        self.max_usd() - self.total_spent_usd()
    }

    /// Get the cost log entries.
    #[must_use]
    pub fn entries(&self) -> Vec<CostEntry> {
        self.log.lock().map(|l| l.clone()).unwrap_or_default()
    }

    /// Produce a summary suitable for JSONL evidence.
    #[must_use]
    pub fn summary(&self) -> Value {
        serde_json::json!({
            "budget_max_usd": self.max_usd(),
            "total_spent_usd": self.total_spent_usd(),
            "remaining_usd": self.remaining_usd(),
            "within_limits": self.within_limits(),
            "api_call_count": self.entries().len(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Synthetic Tenant Labeling — Test resource naming
// ─────────────────────────────────────────────────────────────────────────────

/// Generates deterministic, identifiable names for test resources.
///
/// All synthetic resources follow the pattern:
/// `fcp-test-{connector}-{suffix}-{date}`
///
/// This makes it easy to identify and clean up orphaned test resources.
#[derive(Debug, Clone)]
pub struct SyntheticTenant {
    connector: String,
    run_id: String,
    date: String,
}

impl SyntheticTenant {
    /// Create a new synthetic tenant for a connector.
    #[must_use]
    pub fn new(connector: &str) -> Self {
        let run_id = uuid::Uuid::new_v4().to_string()[..8].to_owned();
        let date = Utc::now().format("%Y%m%d").to_string();
        Self {
            connector: connector.to_owned(),
            run_id,
            date,
        }
    }

    /// Create with a fixed run ID (for deterministic tests).
    #[must_use]
    pub fn with_run_id(connector: &str, run_id: &str) -> Self {
        let date = Utc::now().format("%Y%m%d").to_string();
        Self {
            connector: connector.to_owned(),
            run_id: run_id.to_owned(),
            date,
        }
    }

    /// Generate a resource name with a suffix.
    #[must_use]
    pub fn resource_name(&self, suffix: &str) -> String {
        format!("fcp-test-{}-{}-{}-{}", self.connector, suffix, self.run_id, self.date)
    }

    /// Generate an email-safe identifier for sandbox accounts.
    #[must_use]
    pub fn email_alias(&self, domain: &str) -> String {
        format!("fcp-test-{}+{}@{domain}", self.connector, self.run_id)
    }

    /// The prefix that all resources for this connector share.
    #[must_use]
    pub fn prefix(&self) -> String {
        format!("fcp-test-{}", self.connector)
    }

    /// The run-specific prefix.
    #[must_use]
    pub fn run_prefix(&self) -> String {
        format!("fcp-test-{}-{}", self.connector, self.run_id)
    }

    /// Whether a resource name was created by this module.
    #[must_use]
    pub fn is_synthetic(name: &str) -> bool {
        name.starts_with("fcp-test-")
    }

    /// Whether a resource name belongs to this specific connector.
    #[must_use]
    pub fn belongs_to_connector(name: &str, connector: &str) -> bool {
        name.starts_with(&format!("fcp-test-{connector}-"))
    }

    /// Whether a resource name is from a run older than the given number of days.
    #[must_use]
    pub fn is_stale(name: &str, max_age_days: u32) -> bool {
        // Extract date suffix (last 8 chars should be YYYYMMDD)
        if name.len() < 8 {
            return false;
        }
        let date_part = &name[name.len() - 8..];
        let Ok(date) = chrono::NaiveDate::parse_from_str(date_part, "%Y%m%d") else {
            return false;
        };
        let today = Utc::now().date_naive();
        let age = today.signed_duration_since(date).num_days();
        age > i64::from(max_age_days)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cleanup Guard — Automated test resource cleanup
// ─────────────────────────────────────────────────────────────────────────────

/// A cleanup action to run during teardown.
pub type CleanupAction = Box<dyn FnOnce() + Send>;

/// Ensures test resources are cleaned up when a live test completes.
///
/// Register cleanup actions during the test; they execute in reverse order
/// when the guard is dropped or `run_cleanup()` is called explicitly.
pub struct CleanupGuard {
    actions: std::sync::Mutex<Vec<(String, CleanupAction)>>,
    results: std::sync::Mutex<Vec<CleanupResult>>,
}

/// Result of a single cleanup action.
#[derive(Debug, Clone, Serialize)]
pub struct CleanupResult {
    /// Description of what was cleaned up.
    pub description: String,
    /// Whether cleanup succeeded.
    pub success: bool,
    /// Error message if cleanup failed.
    pub error: Option<String>,
}

impl CleanupGuard {
    /// Create a new cleanup guard.
    #[must_use]
    pub fn new() -> Self {
        Self {
            actions: std::sync::Mutex::new(Vec::new()),
            results: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Register a cleanup action with a description.
    pub fn register(&self, description: &str, action: CleanupAction) {
        if let Ok(mut actions) = self.actions.lock() {
            actions.push((description.to_owned(), action));
        }
    }

    /// Run all cleanup actions in reverse order. Returns results.
    pub fn run_cleanup(&self) -> Vec<CleanupResult> {
        let actions: Vec<(String, CleanupAction)> = self
            .actions
            .lock()
            .map(|mut a| {
                let mut taken = Vec::new();
                std::mem::swap(&mut taken, &mut *a);
                taken
            })
            .unwrap_or_default();

        let mut results = Vec::new();

        // Run in reverse order (LIFO cleanup)
        for (desc, action) in actions.into_iter().rev() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
            let cleanup_result = match result {
                Ok(()) => CleanupResult {
                    description: desc,
                    success: true,
                    error: None,
                },
                Err(e) => {
                    let error_msg = if let Some(s) = e.downcast_ref::<&str>() {
                        (*s).to_owned()
                    } else if let Some(s) = e.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "Unknown panic during cleanup".to_owned()
                    };
                    CleanupResult {
                        description: desc,
                        success: false,
                        error: Some(error_msg),
                    }
                }
            };
            results.push(cleanup_result);
        }

        if let Ok(mut stored) = self.results.lock() {
            stored.extend(results.clone());
        }

        results
    }

    /// Get all cleanup results (from previous `run_cleanup` calls).
    #[must_use]
    pub fn results(&self) -> Vec<CleanupResult> {
        self.results.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Produce a summary suitable for JSONL evidence.
    #[must_use]
    pub fn summary(&self) -> Value {
        let results = self.results();
        let total = results.len();
        let succeeded = results.iter().filter(|r| r.success).count();
        let failed = total - succeeded;
        serde_json::json!({
            "cleanup_total": total,
            "cleanup_succeeded": succeeded,
            "cleanup_failed": failed,
            "failures": results.iter()
                .filter(|r| !r.success)
                .map(|r| serde_json::json!({
                    "description": r.description,
                    "error": r.error,
                }))
                .collect::<Vec<_>>(),
        })
    }
}

impl Default for CleanupGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        // Run any remaining cleanup actions on drop
        let remaining: Vec<(String, CleanupAction)> = self
            .actions
            .lock()
            .map(|mut a| {
                let mut taken = Vec::new();
                std::mem::swap(&mut taken, &mut *a);
                taken
            })
            .unwrap_or_default();

        for (desc, action) in remaining.into_iter().rev() {
            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
                eprintln!("Cleanup failed for '{desc}': {e:?}");
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Environment Manifest — Per-connector live suite declaration
// ─────────────────────────────────────────────────────────────────────────────

/// Machine-readable declaration of what a connector's live suite requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentManifest {
    /// Connector identifier (e.g., "stripe", "aws", "discord").
    pub connector: String,
    /// Live tier classification.
    pub tier: LiveTier,
    /// Human-readable provider name.
    pub provider: String,
    /// Required secrets.
    pub secrets: Vec<SecretRequirement>,
    /// Required environment variables beyond secrets.
    pub env_vars: Vec<EnvVarRequirement>,
    /// Sandbox/test account setup instructions.
    pub account_setup: String,
    /// Maximum budget per test run in USD.
    pub budget_usd: f64,
    /// Cleanup strategy.
    pub cleanup: CleanupStrategy,
    /// Rate limit configuration.
    pub rate_limits: Option<RateLimitConfig>,
    /// Additional metadata.
    #[serde(default)]
    pub metadata: HashMap<String, Value>,
}

/// A required environment variable (non-secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarRequirement {
    /// Variable name.
    pub name: String,
    /// Default value if not set.
    pub default: Option<String>,
    /// Description.
    pub description: String,
}

/// How test resources should be cleaned up.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStrategy {
    /// No cleanup needed (read-only tests).
    None,
    /// Delete resources matching the synthetic tenant prefix.
    PrefixDelete,
    /// Run a custom cleanup script.
    Script(String),
    /// Resources auto-expire (e.g., temporary Stripe test data).
    AutoExpire { ttl_hours: u32 },
}

/// Rate limit awareness for live tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per second.
    pub max_rps: f64,
    /// Minimum delay between requests in milliseconds.
    pub min_delay_ms: u64,
    /// Whether to use exponential backoff on 429 responses.
    pub backoff_on_429: bool,
}

impl EnvironmentManifest {
    /// Create a manifest for a Tier A (local-sufficient) connector.
    #[must_use]
    pub fn local(connector: &str) -> Self {
        Self {
            connector: connector.to_owned(),
            tier: LiveTier::LocalSufficient,
            provider: "local".to_owned(),
            secrets: Vec::new(),
            env_vars: Vec::new(),
            account_setup: "No setup required — uses local fixtures.".to_owned(),
            budget_usd: 0.0,
            cleanup: CleanupStrategy::None,
            rate_limits: None,
            metadata: HashMap::new(),
        }
    }

    /// Create a manifest for a Tier B (sandbox-required) connector.
    #[must_use]
    pub fn sandbox(connector: &str, provider: &str) -> Self {
        Self {
            connector: connector.to_owned(),
            tier: LiveTier::SandboxRequired,
            provider: provider.to_owned(),
            secrets: Vec::new(),
            env_vars: Vec::new(),
            account_setup: String::new(),
            budget_usd: 1.0,
            cleanup: CleanupStrategy::PrefixDelete,
            rate_limits: None,
            metadata: HashMap::new(),
        }
    }

    /// Add a secret requirement sourced from an environment variable.
    #[must_use]
    pub fn with_env_secret(mut self, name: &str, env_var: &str, description: &str) -> Self {
        self.secrets.push(SecretRequirement {
            name: name.to_owned(),
            source: SecretSource::EnvVar(env_var.to_owned()),
            required: true,
            description: description.to_owned(),
        });
        self
    }

    /// Add an optional secret with a test-mode default.
    #[must_use]
    pub fn with_test_default_secret(mut self, name: &str, env_var: &str, default: &str, description: &str) -> Self {
        self.secrets.push(SecretRequirement {
            name: name.to_owned(),
            source: if std::env::var(env_var).is_ok() {
                SecretSource::EnvVar(env_var.to_owned())
            } else {
                SecretSource::TestDefault(default.to_owned())
            },
            required: false,
            description: description.to_owned(),
        });
        self
    }

    /// Set account setup instructions.
    #[must_use]
    pub fn with_account_setup(mut self, instructions: &str) -> Self {
        self.account_setup = instructions.to_owned();
        self
    }

    /// Set cost budget.
    #[must_use]
    pub fn with_budget(mut self, budget_usd: f64) -> Self {
        self.budget_usd = budget_usd;
        self
    }

    /// Set cleanup strategy.
    #[must_use]
    pub fn with_cleanup(mut self, cleanup: CleanupStrategy) -> Self {
        self.cleanup = cleanup;
        self
    }

    /// Set rate limit configuration.
    #[must_use]
    pub fn with_rate_limits(mut self, max_rps: f64, backoff_on_429: bool) -> Self {
        self.rate_limits = Some(RateLimitConfig {
            max_rps,
            min_delay_ms: if max_rps > 0.0 {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let ms = (1000.0 / max_rps) as u64;
                ms
            } else {
                1000
            },
            backoff_on_429,
        });
        self
    }

    /// Load all secrets declared in this manifest.
    #[must_use]
    pub fn load_secrets(&self) -> SecretBag {
        SecretBag::load(&self.secrets)
    }

    /// Create a cost budget from this manifest's budget setting.
    #[must_use]
    pub fn cost_budget(&self) -> CostBudget {
        CostBudget::new(self.budget_usd)
    }

    /// Create a synthetic tenant for this connector.
    #[must_use]
    pub fn synthetic_tenant(&self) -> SyntheticTenant {
        SyntheticTenant::new(&self.connector)
    }

    /// Create a cleanup guard.
    #[must_use]
    pub fn cleanup_guard(&self) -> CleanupGuard {
        CleanupGuard::new()
    }

    /// Validate that this manifest is ready for a live run.
    /// Returns a list of problems (empty = ready).
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();

        // Check gate
        let gate = LiveGate::for_tier(self.tier);
        if !gate.is_enabled() {
            problems.push(gate.skip_reason());
        }

        // Check secrets
        let secrets = self.load_secrets();
        for missing in secrets.missing_secrets() {
            problems.push(format!("Missing required secret: {missing}"));
        }

        // Check budget
        if self.tier != LiveTier::LocalSufficient && self.budget_usd <= 0.0 {
            problems.push("Live suite requires a cost budget > $0".to_owned());
        }

        problems
    }

    /// Produce a summary suitable for JSONL evidence.
    #[must_use]
    pub fn evidence_summary(&self) -> Value {
        serde_json::json!({
            "connector": self.connector,
            "tier": self.tier.to_string(),
            "provider": self.provider,
            "secret_count": self.secrets.len(),
            "budget_usd": self.budget_usd,
            "cleanup_strategy": format!("{:?}", self.cleanup),
            "has_rate_limits": self.rate_limits.is_some(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Live Environment — Convenience wrapper combining all pieces
// ─────────────────────────────────────────────────────────────────────────────

/// A fully loaded live test environment with secrets, budget, naming, and cleanup.
pub struct LiveEnvironment {
    /// The manifest this environment was loaded from.
    pub manifest: EnvironmentManifest,
    /// Loaded secrets.
    pub secrets: SecretBag,
    /// Cost budget tracker.
    pub budget: Arc<CostBudget>,
    /// Synthetic tenant for resource naming.
    pub tenant: SyntheticTenant,
    /// Cleanup guard.
    pub cleanup: CleanupGuard,
}

impl LiveEnvironment {
    /// Load a live environment from a manifest.
    #[must_use]
    pub fn from_manifest(manifest: EnvironmentManifest) -> Self {
        let secrets = manifest.load_secrets();
        let budget = Arc::new(manifest.cost_budget());
        let tenant = manifest.synthetic_tenant();
        let cleanup = manifest.cleanup_guard();
        Self {
            manifest,
            secrets,
            budget,
            tenant,
            cleanup,
        }
    }

    /// Whether the environment is ready for a live run.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.secrets.is_complete()
            && LiveGate::for_tier(self.manifest.tier).is_enabled()
    }

    /// Problems preventing a live run (empty if ready).
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        self.manifest.validate()
    }

    /// Produce a full evidence summary.
    #[must_use]
    pub fn evidence_summary(&self) -> Value {
        serde_json::json!({
            "manifest": self.manifest.evidence_summary(),
            "secrets_loaded": self.secrets.len(),
            "secrets_missing": self.secrets.missing_secrets(),
            "budget": self.budget.summary(),
            "tenant_prefix": self.tenant.prefix(),
            "ready": self.is_ready(),
        })
    }
}

impl fmt::Debug for LiveEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveEnvironment")
            .field("connector", &self.manifest.connector)
            .field("tier", &self.manifest.tier)
            .field("ready", &self.is_ready())
            .field("secrets", &self.secrets)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── LiveTier ─────────────────────────────────────────────────────────

    #[test]
    fn tier_gate_env_vars_are_correct() {
        assert_eq!(LiveTier::LocalSufficient.gate_env_var(), "FCP_LIVE_LOCAL");
        assert_eq!(LiveTier::SandboxRequired.gate_env_var(), "FCP_LIVE_SANDBOX");
        assert_eq!(LiveTier::DeviceRequired.gate_env_var(), "FCP_LIVE_DEVICE");
        assert_eq!(LiveTier::LiveReadOnly.gate_env_var(), "FCP_LIVE_READ");
        assert_eq!(LiveTier::LiveWriteRequired.gate_env_var(), "FCP_LIVE_WRITE");
    }

    #[test]
    fn tier_display() {
        assert_eq!(LiveTier::SandboxRequired.to_string(), "sandbox_required");
        assert_eq!(LiveTier::LiveReadOnly.to_string(), "live_read_only");
        assert_eq!(LiveTier::LocalSufficient.to_string(), "local_sufficient");
        assert_eq!(LiveTier::DeviceRequired.to_string(), "device_required");
        assert_eq!(LiveTier::LiveWriteRequired.to_string(), "live_write_required");
    }

    // ── LiveGate ────────────────────────────────────────────────────────

    #[test]
    fn local_sufficient_gate_always_enabled() {
        let gate = LiveGate::for_tier(LiveTier::LocalSufficient);
        assert!(gate.is_enabled());
    }

    #[test]
    fn gate_with_state_enabled() {
        let gate = LiveGate::with_state(LiveTier::SandboxRequired, true);
        assert!(gate.is_enabled());
        assert!(!gate.skip_if_disabled());
        assert_eq!(gate.tier(), LiveTier::SandboxRequired);
    }

    #[test]
    fn gate_with_state_disabled() {
        let gate = LiveGate::with_state(LiveTier::SandboxRequired, false);
        assert!(!gate.is_enabled());
        assert!(gate.skip_if_disabled());
    }

    #[test]
    fn gate_skip_reason_contains_env_var() {
        let gate = LiveGate::with_state(LiveTier::LiveWriteRequired, false);
        let reason = gate.skip_reason();
        assert!(reason.contains("FCP_LIVE_WRITE"));
        assert!(reason.contains("live_write_required"));
    }

    #[test]
    fn gate_convenience_constructors() {
        // These check env vars (likely unset in CI), just verify they don't panic
        let _ = LiveGate::sandbox();
        let _ = LiveGate::read_only();
        let _ = LiveGate::write();
        let _ = LiveGate::device();
    }

    // ── SecretBag ───────────────────────────────────────────────────────

    #[test]
    fn secret_bag_loads_test_default() {
        let reqs = vec![SecretRequirement {
            name: "api_key".to_owned(),
            source: SecretSource::TestDefault("sk-test-123".to_owned()),
            required: true,
            description: "Test API key".to_owned(),
        }];
        let bag = SecretBag::load(&reqs);
        assert!(bag.is_complete());
        assert_eq!(bag.get("api_key"), Some("sk-test-123"));
        assert_eq!(bag.require("api_key"), "sk-test-123");
    }

    #[test]
    fn secret_bag_reports_missing_required_env_var() {
        // Use a var name that will never exist in test env
        let reqs = vec![SecretRequirement {
            name: "missing_key".to_owned(),
            source: SecretSource::EnvVar("FCP_TESTKIT_INTERNAL_NEVER_SET_9999".to_owned()),
            required: true,
            description: "Intentionally missing".to_owned(),
        }];
        let bag = SecretBag::load(&reqs);
        assert!(!bag.is_complete());
        assert_eq!(bag.missing_secrets(), &["missing_key"]);
        assert!(bag.get("missing_key").is_none());
    }

    #[test]
    fn secret_bag_optional_missing_is_ok() {
        let reqs = vec![SecretRequirement {
            name: "optional_key".to_owned(),
            source: SecretSource::EnvVar("FCP_TESTKIT_INTERNAL_NEVER_SET_8888".to_owned()),
            required: false,
            description: "Optional".to_owned(),
        }];
        let bag = SecretBag::load(&reqs);
        assert!(bag.is_complete()); // Optional missing = still complete
        assert!(bag.get("optional_key").is_none());
    }

    #[test]
    fn secret_bag_debug_does_not_leak_values() {
        let reqs = vec![SecretRequirement {
            name: "secret".to_owned(),
            source: SecretSource::TestDefault("super-secret-value".to_owned()),
            required: false,
            description: "A secret".to_owned(),
        }];
        let bag = SecretBag::load(&reqs);
        let debug_output = format!("{bag:?}");
        assert!(!debug_output.contains("super-secret-value"));
        assert!(debug_output.contains("loaded_count"));
    }

    #[test]
    fn secret_bag_len_and_is_empty() {
        let empty = SecretBag::load(&[]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let reqs = vec![SecretRequirement {
            name: "k".to_owned(),
            source: SecretSource::TestDefault("v".to_owned()),
            required: false,
            description: String::new(),
        }];
        let loaded = SecretBag::load(&reqs);
        assert!(!loaded.is_empty());
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn secret_bag_multiple_secrets() {
        let reqs = vec![
            SecretRequirement {
                name: "key1".to_owned(),
                source: SecretSource::TestDefault("val1".to_owned()),
                required: true,
                description: String::new(),
            },
            SecretRequirement {
                name: "key2".to_owned(),
                source: SecretSource::TestDefault("val2".to_owned()),
                required: true,
                description: String::new(),
            },
        ];
        let bag = SecretBag::load(&reqs);
        assert!(bag.is_complete());
        assert_eq!(bag.len(), 2);
        assert_eq!(bag.get("key1"), Some("val1"));
        assert_eq!(bag.get("key2"), Some("val2"));
    }

    #[test]
    #[should_panic(expected = "Required secret")]
    fn secret_bag_require_panics_on_missing() {
        let bag = SecretBag::load(&[]);
        bag.require("nonexistent");
    }

    // ── CostBudget ──────────────────────────────────────────────────────

    #[test]
    fn cost_budget_tracks_spending() {
        let budget = CostBudget::new(1.0);
        assert!(budget.within_limits());
        assert!((budget.max_usd() - 1.0).abs() < f64::EPSILON);

        budget.record_api_call("create", 0.25);
        budget.record_api_call("update", 0.50);

        assert!((budget.total_spent_usd() - 0.75).abs() < 0.001);
        assert!(budget.within_limits());
        assert!(budget.remaining_usd() > 0.24);
    }

    #[test]
    fn cost_budget_exceeds_limit() {
        let budget = CostBudget::new(0.10);
        budget.record_api_call("expensive", 0.15);
        assert!(!budget.within_limits());
    }

    #[test]
    fn cost_budget_nightly_default() {
        let budget = CostBudget::nightly_default();
        assert!((budget.max_usd() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cost_budget_summary_has_required_fields() {
        let budget = CostBudget::new(5.0);
        budget.record_api_call("test.op", 0.01);
        let summary = budget.summary();
        assert!(summary["budget_max_usd"].is_number());
        assert!(summary["total_spent_usd"].is_number());
        assert!(summary["within_limits"].is_boolean());
        assert!(summary["api_call_count"].is_number());
    }

    #[test]
    fn cost_budget_entries_recorded() {
        let budget = CostBudget::new(10.0);
        budget.record_api_call("op1", 0.01);
        budget.record_api_call("op2", 0.02);
        let entries = budget.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].operation, "op1");
        assert_eq!(entries[1].operation, "op2");
    }

    #[test]
    fn cost_budget_zero_spending() {
        let budget = CostBudget::new(1.0);
        assert!((budget.total_spent_usd() - 0.0).abs() < f64::EPSILON);
        assert!(budget.within_limits());
        assert!(budget.entries().is_empty());
    }

    // ── SyntheticTenant ─────────────────────────────────────────────────

    #[test]
    fn synthetic_tenant_resource_name_format() {
        let tenant = SyntheticTenant::with_run_id("stripe", "abc12345");
        let name = tenant.resource_name("customer");
        assert!(name.starts_with("fcp-test-stripe-customer-abc12345-"));
    }

    #[test]
    fn synthetic_tenant_email_alias() {
        let tenant = SyntheticTenant::with_run_id("discord", "xyz");
        let email = tenant.email_alias("test.example.com");
        assert_eq!(email, "fcp-test-discord+xyz@test.example.com");
    }

    #[test]
    fn synthetic_tenant_prefix() {
        let tenant = SyntheticTenant::new("aws");
        assert!(tenant.prefix().starts_with("fcp-test-aws"));
    }

    #[test]
    fn synthetic_tenant_run_prefix() {
        let tenant = SyntheticTenant::with_run_id("gcp", "run42");
        assert_eq!(tenant.run_prefix(), "fcp-test-gcp-run42");
    }

    #[test]
    fn synthetic_tenant_is_synthetic() {
        assert!(SyntheticTenant::is_synthetic("fcp-test-stripe-customer-abc-20260324"));
        assert!(!SyntheticTenant::is_synthetic("my-real-resource"));
        assert!(!SyntheticTenant::is_synthetic(""));
    }

    #[test]
    fn synthetic_tenant_belongs_to_connector() {
        assert!(SyntheticTenant::belongs_to_connector("fcp-test-stripe-customer-abc", "stripe"));
        assert!(!SyntheticTenant::belongs_to_connector("fcp-test-aws-bucket-xyz", "stripe"));
    }

    #[test]
    fn synthetic_tenant_staleness_detection() {
        // A date from 100 days ago should be stale
        let old_name = format!("fcp-test-stripe-customer-abc-{}",
            (Utc::now() - chrono::Duration::days(100)).format("%Y%m%d"));
        assert!(SyntheticTenant::is_stale(&old_name, 30));

        // Today's date should not be stale
        let fresh_name = format!("fcp-test-stripe-customer-abc-{}",
            Utc::now().format("%Y%m%d"));
        assert!(!SyntheticTenant::is_stale(&fresh_name, 30));
    }

    #[test]
    fn synthetic_tenant_staleness_bad_format() {
        // Non-date suffix should not be considered stale
        assert!(!SyntheticTenant::is_stale("fcp-test-stripe-customer-abc-notadate", 30));
        assert!(!SyntheticTenant::is_stale("short", 30));
    }

    // ── CleanupGuard ────────────────────────────────────────────────────

    #[test]
    fn cleanup_guard_runs_in_reverse_order() {
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let guard = CleanupGuard::new();

        let o1 = Arc::clone(&order);
        guard.register("first", Box::new(move || { o1.lock().unwrap().push(1); }));
        let o2 = Arc::clone(&order);
        guard.register("second", Box::new(move || { o2.lock().unwrap().push(2); }));
        let o3 = Arc::clone(&order);
        guard.register("third", Box::new(move || { o3.lock().unwrap().push(3); }));

        let results = guard.run_cleanup();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.success));

        let executed = order.lock().unwrap().clone();
        assert_eq!(executed, vec![3, 2, 1]); // Reverse order
    }

    #[test]
    fn cleanup_guard_catches_panics() {
        let guard = CleanupGuard::new();
        guard.register("panicky", Box::new(|| panic!("test panic")));
        guard.register("safe", Box::new(|| {}));

        let results = guard.run_cleanup();
        assert_eq!(results.len(), 2);
        // "safe" runs first (reverse order), then "panicky"
        assert!(results[0].success); // "safe"
        assert!(!results[1].success); // "panicky"
        assert!(results[1].error.as_ref().unwrap().contains("test panic"));
    }

    #[test]
    fn cleanup_guard_summary() {
        let guard = CleanupGuard::new();
        guard.register("ok", Box::new(|| {}));
        guard.run_cleanup();
        let summary = guard.summary();
        assert_eq!(summary["cleanup_total"], 1);
        assert_eq!(summary["cleanup_succeeded"], 1);
        assert_eq!(summary["cleanup_failed"], 0);
    }

    #[test]
    fn cleanup_guard_empty() {
        let guard = CleanupGuard::new();
        let results = guard.run_cleanup();
        assert!(results.is_empty());
        let summary = guard.summary();
        assert_eq!(summary["cleanup_total"], 0);
    }

    #[test]
    fn cleanup_guard_default_trait() {
        let guard = CleanupGuard::default();
        let results = guard.run_cleanup();
        assert!(results.is_empty());
    }

    // ── EnvironmentManifest ─────────────────────────────────────────────

    #[test]
    fn manifest_local_has_no_requirements() {
        let manifest = EnvironmentManifest::local("sqlite");
        assert_eq!(manifest.tier, LiveTier::LocalSufficient);
        assert!(manifest.secrets.is_empty());
        assert!((manifest.budget_usd - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn manifest_sandbox_builder() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_env_secret("api_key", "STRIPE_TEST_KEY", "Stripe test-mode API key")
            .with_budget(2.0)
            .with_rate_limits(10.0, true)
            .with_account_setup("Create a Stripe test-mode account at dashboard.stripe.com")
            .with_cleanup(CleanupStrategy::AutoExpire { ttl_hours: 24 });

        assert_eq!(manifest.connector, "stripe");
        assert_eq!(manifest.tier, LiveTier::SandboxRequired);
        assert_eq!(manifest.secrets.len(), 1);
        assert!((manifest.budget_usd - 2.0).abs() < f64::EPSILON);
        assert!(manifest.rate_limits.is_some());
        let rl = manifest.rate_limits.unwrap();
        assert!((rl.max_rps - 10.0).abs() < f64::EPSILON);
        assert!(rl.backoff_on_429);
        assert_eq!(rl.min_delay_ms, 100);
    }

    #[test]
    fn manifest_with_test_default_secret() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_test_default_secret("mode", "STRIPE_MODE", "test", "Mode selector");
        assert_eq!(manifest.secrets.len(), 1);
        // The secret should resolve to "test" default since STRIPE_MODE is not set
        let bag = manifest.load_secrets();
        assert_eq!(bag.get("mode"), Some("test"));
    }

    #[test]
    fn manifest_validate_reports_missing_gate_via_state() {
        // Test validation logic using a sandbox manifest: the gate check
        // reads the real env (FCP_LIVE_SANDBOX likely unset), so validation
        // should report the missing gate.
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_budget(1.0);
        let problems = manifest.validate();
        // In CI without FCP_LIVE_SANDBOX=1, this should have at least the gate problem
        assert!(problems.iter().any(|p| p.contains("FCP_LIVE_SANDBOX")));
    }

    #[test]
    fn manifest_validate_reports_missing_secrets() {
        // Use a never-set env var for the secret
        let manifest = EnvironmentManifest::local("sqlite")
            .with_env_secret("api_key", "FCP_TESTKIT_INTERNAL_NEVER_SET_7777", "key");
        let problems = manifest.validate();
        assert!(problems.iter().any(|p| p.contains("api_key")));
    }

    #[test]
    fn manifest_evidence_summary() {
        let manifest = EnvironmentManifest::sandbox("aws", "Amazon Web Services")
            .with_budget(5.0);
        let summary = manifest.evidence_summary();
        assert_eq!(summary["connector"], "aws");
        assert_eq!(summary["tier"], "sandbox_required");
        assert_eq!(summary["provider"], "Amazon Web Services");
    }

    #[test]
    fn manifest_cost_budget() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_budget(3.50);
        let budget = manifest.cost_budget();
        assert!((budget.max_usd() - 3.50).abs() < f64::EPSILON);
    }

    #[test]
    fn manifest_synthetic_tenant() {
        let manifest = EnvironmentManifest::sandbox("aws", "AWS");
        let tenant = manifest.synthetic_tenant();
        assert!(tenant.prefix().starts_with("fcp-test-aws"));
    }

    // ── LiveEnvironment ─────────────────────────────────────────────────

    #[test]
    fn live_environment_from_local_manifest() {
        let manifest = EnvironmentManifest::local("sqlite");
        let env = LiveEnvironment::from_manifest(manifest);
        assert!(env.is_ready());
        assert!(env.problems().is_empty());
    }

    #[test]
    fn live_environment_sandbox_not_ready_without_gate() {
        // FCP_LIVE_SANDBOX is not set in test env, so sandbox env is not ready
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_budget(1.0);
        let env = LiveEnvironment::from_manifest(manifest);
        assert!(!env.is_ready());
        assert!(!env.problems().is_empty());
    }

    #[test]
    fn live_environment_evidence_summary() {
        let manifest = EnvironmentManifest::local("duckdb");
        let env = LiveEnvironment::from_manifest(manifest);
        let summary = env.evidence_summary();
        assert!(summary["ready"].as_bool().unwrap());
        assert_eq!(summary["manifest"]["connector"], "duckdb");
        assert!(summary["budget"].is_object());
        assert!(summary["tenant_prefix"].is_string());
    }

    #[test]
    fn live_environment_debug_does_not_leak() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_env_secret("key", "FCP_STRIPE_TEST_KEY_NEVER", "test key");
        let env = LiveEnvironment::from_manifest(manifest);
        let debug = format!("{env:?}");
        assert!(!debug.contains("FCP_STRIPE_TEST_KEY_NEVER"));
        assert!(debug.contains("LiveEnvironment"));
    }

    // ── Serialization round-trips ───────────────────────────────────────

    #[test]
    fn live_tier_serialization_roundtrip() {
        for tier in [
            LiveTier::LocalSufficient,
            LiveTier::SandboxRequired,
            LiveTier::DeviceRequired,
            LiveTier::LiveReadOnly,
            LiveTier::LiveWriteRequired,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let parsed: LiveTier = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, tier);
        }
    }

    #[test]
    fn sandbox_required_serializes_correctly() {
        let json = serde_json::to_string(&LiveTier::SandboxRequired).unwrap();
        assert_eq!(json, "\"sandbox_required\"");
    }

    #[test]
    fn environment_manifest_serialization_roundtrip() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_env_secret("key", "STRIPE_KEY", "API key")
            .with_budget(2.5)
            .with_rate_limits(10.0, true);
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: EnvironmentManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector, "stripe");
        assert_eq!(parsed.tier, LiveTier::SandboxRequired);
        assert_eq!(parsed.secrets.len(), 1);
        assert!((parsed.budget_usd - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn cleanup_strategy_serialization() {
        let auto = CleanupStrategy::AutoExpire { ttl_hours: 24 };
        let json = serde_json::to_string(&auto).unwrap();
        assert!(json.contains("auto_expire"));
        assert!(json.contains("24"));

        let none_json = serde_json::to_string(&CleanupStrategy::None).unwrap();
        assert!(none_json.contains("none"));

        let prefix_json = serde_json::to_string(&CleanupStrategy::PrefixDelete).unwrap();
        assert!(prefix_json.contains("prefix_delete"));
    }

    #[test]
    fn secret_source_serialization() {
        let env = SecretSource::EnvVar("MY_KEY".to_owned());
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("MY_KEY"));

        let file = SecretSource::File("/tmp/secret".to_owned());
        let json = serde_json::to_string(&file).unwrap();
        assert!(json.contains("/tmp/secret"));

        let default = SecretSource::TestDefault("val".to_owned());
        let json = serde_json::to_string(&default).unwrap();
        assert!(json.contains("val"));
    }

    #[test]
    fn rate_limit_config_serialization() {
        let config = RateLimitConfig {
            max_rps: 5.0,
            min_delay_ms: 200,
            backoff_on_429: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert!((parsed.max_rps - 5.0).abs() < f64::EPSILON);
        assert_eq!(parsed.min_delay_ms, 200);
        assert!(parsed.backoff_on_429);
    }
}
