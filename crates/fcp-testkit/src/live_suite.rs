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
//!     let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
//!         .with_env_secret("api_key", "STRIPE_TEST_KEY", "Stripe test-mode API key")
//!         .with_account_setup("Use a dedicated Stripe test-mode account")
//!         .with_budget(1.0);
//!     let env = LiveEnvironment::from_manifest(manifest);
//!
//!     // ... run live test with real Stripe test-mode keys ...
//!
//!     env.budget.record_api_call("payment_intents.create", 0.01);
//!     assert!(env.budget.within_limits());
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
    pub const fn gate_env_var(self) -> &'static str {
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
                .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
        };
        Self { tier, enabled }
    }

    /// Create a gate with an explicit enabled state (for testing).
    #[must_use]
    pub const fn with_state(tier: LiveTier, enabled: bool) -> Self {
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
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The tier this gate checks.
    #[must_use]
    pub const fn tier(&self) -> LiveTier {
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
    /// Logical name (e.g., `api_key`, `client_secret`).
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
                SecretSource::File(path) => std::fs::read_to_string(path)
                    .ok()
                    .map(|s| s.trim().to_owned()),
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
        self.secrets.get(name).map_or_else(
            || {
                panic!(
                    "Required secret '{name}' not loaded. Check environment or secret configuration."
                )
            },
            String::as_str,
        )
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

/// Loaded non-secret environment variables for a live suite run.
#[derive(Clone)]
pub struct EnvVarBag {
    values: HashMap<String, String>,
    missing: Vec<String>,
    defaults_used: Vec<String>,
}

impl EnvVarBag {
    /// Load environment variables from the given requirements.
    #[must_use]
    pub fn load(requirements: &[EnvVarRequirement]) -> Self {
        let mut values = HashMap::new();
        let mut missing = Vec::new();
        let mut defaults_used = Vec::new();

        for req in requirements {
            match std::env::var(&req.name) {
                Ok(value) if !value.trim().is_empty() => {
                    values.insert(req.name.clone(), value);
                }
                _ => {
                    if let Some(default) = &req.default {
                        values.insert(req.name.clone(), default.clone());
                        defaults_used.push(req.name.clone());
                    } else {
                        missing.push(req.name.clone());
                    }
                }
            }
        }

        Self {
            values,
            missing,
            defaults_used,
        }
    }

    /// Whether all required environment variables are available.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// Names of missing required environment variables.
    #[must_use]
    pub fn missing_vars(&self) -> &[String] {
        &self.missing
    }

    /// Names of variables satisfied by defaults.
    #[must_use]
    pub fn defaults_used(&self) -> &[String] {
        &self.defaults_used
    }

    /// Get a loaded environment variable by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// Number of loaded environment variables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether no environment variables were loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Produce a redaction-safe summary suitable for JSONL evidence.
    #[must_use]
    pub fn summary(&self) -> Value {
        let mut loaded_keys: Vec<&str> = self.values.keys().map(String::as_str).collect();
        loaded_keys.sort_unstable();

        serde_json::json!({
            "loaded_count": self.values.len(),
            "loaded_keys": loaded_keys,
            "missing": self.missing,
            "defaults_used": self.defaults_used,
            "complete": self.is_complete(),
        })
    }
}

impl fmt::Debug for EnvVarBag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut loaded_keys: Vec<&str> = self.values.keys().map(String::as_str).collect();
        loaded_keys.sort_unstable();

        f.debug_struct("EnvVarBag")
            .field("loaded_count", &self.values.len())
            .field("loaded_keys", &loaded_keys)
            .field("missing", &self.missing)
            .field("defaults_used", &self.defaults_used)
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
    /// Operation that incurred the cost (e.g., `payment_intents.create`).
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
        self.spent_hundredths
            .fetch_add(hundredths, Ordering::Relaxed);

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

    /// Whether spending has exceeded the given percentage of the budget.
    /// For example, `exceeds_threshold(0.80)` returns true if more than 80%
    /// of the budget has been spent.
    #[must_use]
    pub fn exceeds_threshold(&self, fraction: f64) -> bool {
        let spent = self.total_spent_usd();
        spent > self.max_usd() * fraction
    }

    /// Check budget status and return a human-readable alert level.
    #[must_use]
    pub fn alert_level(&self) -> BudgetAlert {
        if !self.within_limits() {
            BudgetAlert::Exceeded
        } else if self.exceeds_threshold(0.90) {
            BudgetAlert::Critical
        } else if self.exceeds_threshold(0.75) {
            BudgetAlert::Warning
        } else {
            BudgetAlert::Ok
        }
    }

    /// Produce a summary suitable for JSONL evidence.
    #[must_use]
    pub fn summary(&self) -> Value {
        serde_json::json!({
            "budget_max_usd": self.max_usd(),
            "total_spent_usd": self.total_spent_usd(),
            "remaining_usd": self.remaining_usd(),
            "within_limits": self.within_limits(),
            "alert_level": self.alert_level().as_str(),
            "api_call_count": self.entries().len(),
        })
    }
}

/// Budget alert levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetAlert {
    /// Spending is within normal limits (< 75%).
    Ok,
    /// Spending is approaching the limit (75-90%).
    Warning,
    /// Spending is near the limit (> 90%).
    Critical,
    /// Budget has been exceeded.
    Exceeded,
}

impl BudgetAlert {
    /// String representation for evidence output.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Exceeded => "exceeded",
        }
    }

    /// Whether this alert level indicates a problem.
    #[must_use]
    pub const fn is_problem(&self) -> bool {
        matches!(self, Self::Warning | Self::Critical | Self::Exceeded)
    }
}

impl fmt::Display for BudgetAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
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
        format!(
            "fcp-test-{}-{}-{}-{}",
            self.connector, suffix, self.run_id, self.date
        )
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
                    let error_msg = e.downcast_ref::<&str>().map_or_else(
                        || {
                            e.downcast_ref::<String>().map_or_else(
                                || "Unknown panic during cleanup".to_owned(),
                                Clone::clone,
                            )
                        },
                        |s| (*s).to_owned(),
                    );
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

impl CleanupStrategy {
    /// Whether this cleanup strategy expects synthetic-tenant-scoped resources.
    #[must_use]
    pub const fn uses_synthetic_tenant(&self) -> bool {
        matches!(self, Self::PrefixDelete | Self::AutoExpire { .. })
    }

    /// Produce a structured summary suitable for JSONL evidence.
    #[must_use]
    pub fn summary(&self) -> Value {
        match self {
            Self::None => serde_json::json!({ "kind": "none" }),
            Self::PrefixDelete => serde_json::json!({
                "kind": "prefix_delete",
                "uses_synthetic_tenant": true,
            }),
            Self::Script(path) => serde_json::json!({
                "kind": "script",
                "script": path,
                "uses_synthetic_tenant": false,
            }),
            Self::AutoExpire { ttl_hours } => serde_json::json!({
                "kind": "auto_expire",
                "ttl_hours": ttl_hours,
                "uses_synthetic_tenant": true,
            }),
        }
    }
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

impl RateLimitConfig {
    /// Produce a structured summary suitable for JSONL evidence.
    #[must_use]
    pub fn summary(&self) -> Value {
        serde_json::json!({
            "max_rps": self.max_rps,
            "min_delay_ms": self.min_delay_ms,
            "backoff_on_429": self.backoff_on_429,
        })
    }
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

    /// Create a manifest for a Tier C (device-required) connector.
    #[must_use]
    pub fn device(connector: &str, provider: &str) -> Self {
        Self {
            connector: connector.to_owned(),
            tier: LiveTier::DeviceRequired,
            provider: provider.to_owned(),
            secrets: Vec::new(),
            env_vars: Vec::new(),
            account_setup: String::new(),
            budget_usd: 1.0,
            cleanup: CleanupStrategy::None,
            rate_limits: None,
            metadata: HashMap::new(),
        }
    }

    /// Create a manifest for a Tier D (live-read-only) connector.
    #[must_use]
    pub fn read_only(connector: &str, provider: &str) -> Self {
        Self {
            connector: connector.to_owned(),
            tier: LiveTier::LiveReadOnly,
            provider: provider.to_owned(),
            secrets: Vec::new(),
            env_vars: Vec::new(),
            account_setup: String::new(),
            budget_usd: 1.0,
            cleanup: CleanupStrategy::None,
            rate_limits: None,
            metadata: HashMap::new(),
        }
    }

    /// Create a manifest for a Tier E (live-write-required) connector.
    #[must_use]
    pub fn live_write(connector: &str, provider: &str) -> Self {
        Self {
            connector: connector.to_owned(),
            tier: LiveTier::LiveWriteRequired,
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
    pub fn with_test_default_secret(
        mut self,
        name: &str,
        env_var: &str,
        default: &str,
        description: &str,
    ) -> Self {
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

    /// Add a required non-secret environment variable.
    #[must_use]
    pub fn with_env_var(mut self, name: &str, description: &str) -> Self {
        self.env_vars.push(EnvVarRequirement {
            name: name.to_owned(),
            default: None,
            description: description.to_owned(),
        });
        self
    }

    /// Add a non-secret environment variable with a safe default.
    #[must_use]
    pub fn with_env_var_default(mut self, name: &str, default: &str, description: &str) -> Self {
        self.env_vars.push(EnvVarRequirement {
            name: name.to_owned(),
            default: Some(default.to_owned()),
            description: description.to_owned(),
        });
        self
    }

    /// Set account setup instructions.
    #[must_use]
    pub fn with_account_setup(mut self, instructions: &str) -> Self {
        instructions.clone_into(&mut self.account_setup);
        self
    }

    /// Set cost budget.
    #[must_use]
    pub const fn with_budget(mut self, budget_usd: f64) -> Self {
        self.budget_usd = budget_usd;
        self
    }

    /// Set cleanup strategy.
    #[must_use]
    pub fn with_cleanup(mut self, cleanup: CleanupStrategy) -> Self {
        self.cleanup = cleanup;
        self
    }

    /// Add arbitrary metadata to the manifest.
    #[must_use]
    pub fn with_metadata(mut self, key: &str, value: Value) -> Self {
        self.metadata.insert(key.to_owned(), value);
        self
    }

    /// Set rate limit configuration.
    #[must_use]
    pub fn with_rate_limits(mut self, max_rps: f64, backoff_on_429: bool) -> Self {
        self.rate_limits = Some(RateLimitConfig {
            max_rps,
            min_delay_ms: if max_rps > 0.0 {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let ms = (1000.0 / max_rps).ceil().max(1.0) as u64;
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

    /// Load all non-secret environment variables declared in this manifest.
    #[must_use]
    pub fn load_env_vars(&self) -> EnvVarBag {
        EnvVarBag::load(&self.env_vars)
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

        if self.connector.trim().is_empty() {
            problems.push("Environment manifest requires a non-empty connector id".to_owned());
        }

        if self.provider.trim().is_empty() {
            problems.push("Environment manifest requires a non-empty provider name".to_owned());
        }

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

        // Check non-secret environment variables
        let env_vars = self.load_env_vars();
        for missing in env_vars.missing_vars() {
            problems.push(format!("Missing required environment variable: {missing}"));
        }

        // Check budget
        if !self.budget_usd.is_finite() || self.budget_usd < 0.0 {
            problems.push("Live suite budget must be a finite, non-negative number".to_owned());
        } else if self.tier != LiveTier::LocalSufficient && self.budget_usd <= 0.0 {
            problems.push("Live suite requires a cost budget > $0".to_owned());
        }

        if self.tier != LiveTier::LocalSufficient && self.account_setup.trim().is_empty() {
            problems.push(
                "Live suite requires account setup guidance for sandbox, device, or live runs"
                    .to_owned(),
            );
        }

        match &self.cleanup {
            CleanupStrategy::None
                if matches!(
                    self.tier,
                    LiveTier::SandboxRequired | LiveTier::LiveWriteRequired
                ) =>
            {
                problems.push(
                    "Mutation-capable live suites must declare a cleanup strategy".to_owned(),
                );
            }
            CleanupStrategy::Script(path) if path.trim().is_empty() => {
                problems.push("Cleanup script path must not be empty".to_owned());
            }
            CleanupStrategy::AutoExpire { ttl_hours } if *ttl_hours == 0 => {
                problems.push("Auto-expire cleanup requires ttl_hours > 0".to_owned());
            }
            CleanupStrategy::None
            | CleanupStrategy::PrefixDelete
            | CleanupStrategy::Script(_)
            | CleanupStrategy::AutoExpire { .. } => {}
        }

        if let Some(rate_limits) = &self.rate_limits {
            if !rate_limits.max_rps.is_finite() || rate_limits.max_rps <= 0.0 {
                problems.push("Rate-limit max_rps must be a finite value > 0".to_owned());
            }
            if rate_limits.min_delay_ms == 0 {
                problems.push("Rate-limit min_delay_ms must be > 0".to_owned());
            }
        }

        problems
    }

    /// Produce a summary suitable for JSONL evidence.
    #[must_use]
    pub fn evidence_summary(&self) -> Value {
        let mut metadata_keys: Vec<&str> = self.metadata.keys().map(String::as_str).collect();
        metadata_keys.sort_unstable();

        let required_env_vars = self
            .env_vars
            .iter()
            .filter(|requirement| requirement.default.is_none())
            .count();
        let env_vars_with_defaults = self
            .env_vars
            .iter()
            .filter(|requirement| requirement.default.is_some())
            .count();

        serde_json::json!({
            "connector": self.connector,
            "tier": self.tier.to_string(),
            "provider": self.provider,
            "secret_count": self.secrets.len(),
            "env_var_count": self.env_vars.len(),
            "required_env_var_count": required_env_vars,
            "defaulted_env_var_count": env_vars_with_defaults,
            "account_setup_configured": !self.account_setup.trim().is_empty(),
            "budget_usd": self.budget_usd,
            "cleanup_strategy": self.cleanup.summary(),
            "rate_limits": self.rate_limits.as_ref().map(RateLimitConfig::summary),
            "synthetic_tenant_expected": self.cleanup.uses_synthetic_tenant(),
            "metadata_keys": metadata_keys,
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
    /// Loaded non-secret environment variables.
    pub env_vars: EnvVarBag,
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
        let env_vars = manifest.load_env_vars();
        let budget = Arc::new(manifest.cost_budget());
        let tenant = manifest.synthetic_tenant();
        let cleanup = manifest.cleanup_guard();
        Self {
            manifest,
            secrets,
            env_vars,
            budget,
            tenant,
            cleanup,
        }
    }

    /// Whether the environment is ready for a live run.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.secrets.is_complete()
            && self.env_vars.is_complete()
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
            "env_vars": self.env_vars.summary(),
            "budget": self.budget.summary(),
            "tenant_prefix": self.tenant.prefix(),
            "tenant_identity": self.tenant.run_prefix(),
            "cleanup_expectations": self.manifest.cleanup.summary(),
            "ready": self.is_ready(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stale Resource Scanner — Find orphaned synthetic test resources
// ─────────────────────────────────────────────────────────────────────────────

/// Result of scanning for stale synthetic test resources.
#[derive(Debug, Clone, Serialize)]
pub struct StaleResourceReport {
    /// Resources identified as stale.
    pub stale: Vec<StaleResource>,
    /// Total resources scanned.
    pub scanned: usize,
    /// Maximum age in days used for the scan.
    pub max_age_days: u32,
}

/// A single stale resource.
#[derive(Debug, Clone, Serialize)]
pub struct StaleResource {
    /// Resource name or identifier.
    pub name: String,
    /// Which connector created it.
    pub connector: Option<String>,
    /// Estimated age in days.
    pub age_days: Option<i64>,
}

impl StaleResourceReport {
    /// Scan a list of resource names for stale synthetic test resources.
    #[must_use]
    pub fn scan(resource_names: &[&str], max_age_days: u32) -> Self {
        let mut stale = Vec::new();
        for &name in resource_names {
            if !SyntheticTenant::is_synthetic(name) {
                continue;
            }
            if SyntheticTenant::is_stale(name, max_age_days) {
                // Extract connector name from "fcp-test-{connector}-..."
                let connector = name
                    .strip_prefix("fcp-test-")
                    .and_then(|rest| rest.split('-').next())
                    .map(str::to_owned);

                // Estimate age from date suffix
                let age_days = if name.len() >= 8 {
                    let date_part = &name[name.len() - 8..];
                    chrono::NaiveDate::parse_from_str(date_part, "%Y%m%d")
                        .ok()
                        .map(|date| {
                            Utc::now()
                                .date_naive()
                                .signed_duration_since(date)
                                .num_days()
                        })
                } else {
                    None
                };

                stale.push(StaleResource {
                    name: name.to_owned(),
                    connector,
                    age_days,
                });
            }
        }
        Self {
            scanned: resource_names.len(),
            max_age_days,
            stale,
        }
    }

    /// Whether any stale resources were found.
    #[must_use]
    pub fn has_stale(&self) -> bool {
        !self.stale.is_empty()
    }

    /// Produce a summary suitable for JSONL evidence.
    #[must_use]
    pub fn summary(&self) -> Value {
        serde_json::json!({
            "scanned": self.scanned,
            "max_age_days": self.max_age_days,
            "stale_count": self.stale.len(),
            "stale_resources": self.stale.iter().map(|s| serde_json::json!({
                "name": s.name,
                "connector": s.connector,
                "age_days": s.age_days,
            })).collect::<Vec<_>>(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest Loading — Load manifests from JSON files
// ─────────────────────────────────────────────────────────────────────────────

impl EnvironmentManifest {
    /// Load a manifest from a JSON file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_json_file(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse {} as JSON: {e}", path.display()))
    }

    /// Serialize this manifest to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("Manifest serialization error: {e}"))
    }

    /// Collect all prerequisite problems into a structured report.
    #[must_use]
    pub fn prerequisite_report(&self) -> PrerequisiteReport {
        let problems = self.validate();
        let secrets = self.load_secrets();
        let env_vars = self.load_env_vars();
        let gate = LiveGate::for_tier(self.tier);
        let mut metadata_keys: Vec<String> = self.metadata.keys().cloned().collect();
        metadata_keys.sort_unstable();

        let budget_configured = if !self.budget_usd.is_finite() || self.budget_usd < 0.0 {
            false
        } else {
            self.tier == LiveTier::LocalSufficient || self.budget_usd > 0.0
        };
        let cleanup_configured = match &self.cleanup {
            CleanupStrategy::None => !matches!(
                self.tier,
                LiveTier::SandboxRequired | LiveTier::LiveWriteRequired
            ),
            CleanupStrategy::PrefixDelete => true,
            CleanupStrategy::Script(path) => !path.trim().is_empty(),
            CleanupStrategy::AutoExpire { ttl_hours } => *ttl_hours > 0,
        };

        PrerequisiteReport {
            connector: self.connector.clone(),
            provider: self.provider.clone(),
            tier: self.tier,
            gate_enabled: gate.is_enabled(),
            gate_env_var: gate.tier().gate_env_var().to_owned(),
            secrets_complete: secrets.is_complete(),
            secrets_loaded: secrets.len(),
            secrets_missing: secrets.missing_secrets().to_vec(),
            env_vars_complete: env_vars.is_complete(),
            env_vars_loaded: env_vars.len(),
            env_vars_missing: env_vars.missing_vars().to_vec(),
            env_vars_defaults_used: env_vars.defaults_used().to_vec(),
            account_setup_configured: self.tier == LiveTier::LocalSufficient
                || !self.account_setup.trim().is_empty(),
            budget_configured,
            cleanup_configured,
            cleanup_strategy: self.cleanup.summary(),
            rate_limits: self.rate_limits.as_ref().map(RateLimitConfig::summary),
            synthetic_tenant_expected: self.cleanup.uses_synthetic_tenant(),
            metadata_keys,
            problems,
        }
    }
}

/// Structured report of all prerequisites for a live suite run.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct PrerequisiteReport {
    /// Connector identifier.
    pub connector: String,
    /// Human-readable provider name.
    pub provider: String,
    /// Live tier.
    pub tier: LiveTier,
    /// Whether the tier gate is enabled.
    pub gate_enabled: bool,
    /// Environment variable that enables this tier.
    pub gate_env_var: String,
    /// Whether all required secrets are present.
    pub secrets_complete: bool,
    /// Number of loaded secrets.
    pub secrets_loaded: usize,
    /// Names of missing required secrets.
    pub secrets_missing: Vec<String>,
    /// Whether all required env vars are present.
    pub env_vars_complete: bool,
    /// Number of loaded env vars.
    pub env_vars_loaded: usize,
    /// Names of missing required env vars.
    pub env_vars_missing: Vec<String>,
    /// Names of env vars satisfied by defaults.
    pub env_vars_defaults_used: Vec<String>,
    /// Whether account setup guidance is present for the tier.
    pub account_setup_configured: bool,
    /// Whether a valid budget is configured.
    pub budget_configured: bool,
    /// Whether a cleanup strategy is configured for mutation-capable tiers.
    pub cleanup_configured: bool,
    /// Structured cleanup strategy summary.
    pub cleanup_strategy: Value,
    /// Structured rate-limit summary, when declared.
    pub rate_limits: Option<Value>,
    /// Whether this suite expects synthetic-tenant scoping.
    pub synthetic_tenant_expected: bool,
    /// Sorted metadata keys included with the manifest.
    pub metadata_keys: Vec<String>,
    /// All validation problems.
    pub problems: Vec<String>,
}

impl PrerequisiteReport {
    /// Whether all prerequisites are met.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.problems.is_empty()
    }

    /// Produce a summary suitable for JSONL evidence.
    #[must_use]
    pub fn summary(&self) -> Value {
        serde_json::json!({
            "connector": self.connector,
            "provider": self.provider,
            "tier": self.tier.to_string(),
            "ready": self.is_ready(),
            "gate_enabled": self.gate_enabled,
            "gate_env_var": self.gate_env_var,
            "secrets_complete": self.secrets_complete,
            "secrets_loaded": self.secrets_loaded,
            "secrets_missing": self.secrets_missing,
            "env_vars_complete": self.env_vars_complete,
            "env_vars_loaded": self.env_vars_loaded,
            "env_vars_missing": self.env_vars_missing,
            "env_vars_defaults_used": self.env_vars_defaults_used,
            "account_setup_configured": self.account_setup_configured,
            "budget_configured": self.budget_configured,
            "cleanup_configured": self.cleanup_configured,
            "cleanup_strategy": self.cleanup_strategy,
            "rate_limits": self.rate_limits,
            "synthetic_tenant_expected": self.synthetic_tenant_expected,
            "metadata_keys": self.metadata_keys,
            "problem_count": self.problems.len(),
            "problems": self.problems,
        })
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for LiveEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveEnvironment")
            .field("connector", &self.manifest.connector)
            .field("tier", &self.manifest.tier)
            .field("ready", &self.is_ready())
            .field("secrets", &self.secrets)
            .field("env_vars", &self.env_vars)
            .finish_non_exhaustive()
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
        assert_eq!(
            LiveTier::LiveWriteRequired.to_string(),
            "live_write_required"
        );
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
        let _ = bag.require("nonexistent");
    }

    // ── EnvVarBag ──────────────────────────────────────────────────────

    #[test]
    fn env_var_bag_loads_default_when_missing() {
        let requirements = vec![EnvVarRequirement {
            name: "FCP_TESTKIT_OPTIONAL_REGION".to_owned(),
            default: Some("us-east-1".to_owned()),
            description: "Default test region".to_owned(),
        }];

        let bag = EnvVarBag::load(&requirements);
        assert!(bag.is_complete());
        assert_eq!(bag.get("FCP_TESTKIT_OPTIONAL_REGION"), Some("us-east-1"));
        assert_eq!(bag.defaults_used(), &["FCP_TESTKIT_OPTIONAL_REGION"]);
    }

    #[test]
    fn env_var_bag_reports_missing_required_var() {
        let requirements = vec![EnvVarRequirement {
            name: "FCP_TESTKIT_REQUIRED_REGION_4242".to_owned(),
            default: None,
            description: "Required region".to_owned(),
        }];

        let bag = EnvVarBag::load(&requirements);
        assert!(!bag.is_complete());
        assert_eq!(bag.missing_vars(), &["FCP_TESTKIT_REQUIRED_REGION_4242"]);
        assert!(bag.get("FCP_TESTKIT_REQUIRED_REGION_4242").is_none());
    }

    #[test]
    fn env_var_bag_debug_does_not_print_values() {
        let requirements = vec![EnvVarRequirement {
            name: "FCP_TESTKIT_DEFAULT_PROFILE".to_owned(),
            default: Some("sandbox".to_owned()),
            description: "Profile".to_owned(),
        }];

        let bag = EnvVarBag::load(&requirements);
        let debug_output = format!("{bag:?}");
        assert!(debug_output.contains("loaded_keys"));
        assert!(!debug_output.contains("sandbox"));
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
        assert!(SyntheticTenant::is_synthetic(
            "fcp-test-stripe-customer-abc-20260324"
        ));
        assert!(!SyntheticTenant::is_synthetic("my-real-resource"));
        assert!(!SyntheticTenant::is_synthetic(""));
    }

    #[test]
    fn synthetic_tenant_belongs_to_connector() {
        assert!(SyntheticTenant::belongs_to_connector(
            "fcp-test-stripe-customer-abc",
            "stripe"
        ));
        assert!(!SyntheticTenant::belongs_to_connector(
            "fcp-test-aws-bucket-xyz",
            "stripe"
        ));
    }

    #[test]
    fn synthetic_tenant_staleness_detection() {
        // A date from 100 days ago should be stale
        let old_name = format!(
            "fcp-test-stripe-customer-abc-{}",
            (Utc::now() - chrono::Duration::days(100)).format("%Y%m%d")
        );
        assert!(SyntheticTenant::is_stale(&old_name, 30));

        // Today's date should not be stale
        let fresh_name = format!(
            "fcp-test-stripe-customer-abc-{}",
            Utc::now().format("%Y%m%d")
        );
        assert!(!SyntheticTenant::is_stale(&fresh_name, 30));
    }

    #[test]
    fn synthetic_tenant_staleness_bad_format() {
        // Non-date suffix should not be considered stale
        assert!(!SyntheticTenant::is_stale(
            "fcp-test-stripe-customer-abc-notadate",
            30
        ));
        assert!(!SyntheticTenant::is_stale("short", 30));
    }

    // ── CleanupGuard ────────────────────────────────────────────────────

    #[test]
    fn cleanup_guard_runs_in_reverse_order() {
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let guard = CleanupGuard::new();

        let o1 = Arc::clone(&order);
        guard.register(
            "first",
            Box::new(move || {
                o1.lock().unwrap().push(1);
            }),
        );
        let o2 = Arc::clone(&order);
        guard.register(
            "second",
            Box::new(move || {
                o2.lock().unwrap().push(2);
            }),
        );
        let o3 = Arc::clone(&order);
        guard.register(
            "third",
            Box::new(move || {
                o3.lock().unwrap().push(3);
            }),
        );

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
            .with_env_var("STRIPE_ACCOUNT_ID", "Stripe account identifier")
            .with_budget(2.0)
            .with_rate_limits(10.0, true)
            .with_account_setup("Create a Stripe test-mode account at dashboard.stripe.com")
            .with_cleanup(CleanupStrategy::AutoExpire { ttl_hours: 24 })
            .with_metadata("suite_owner", Value::String("payments".to_owned()));

        assert_eq!(manifest.connector, "stripe");
        assert_eq!(manifest.tier, LiveTier::SandboxRequired);
        assert_eq!(manifest.secrets.len(), 1);
        assert_eq!(manifest.env_vars.len(), 1);
        assert!((manifest.budget_usd - 2.0).abs() < f64::EPSILON);
        assert!(manifest.rate_limits.is_some());
        let rl = manifest.rate_limits.unwrap();
        assert!((rl.max_rps - 10.0).abs() < f64::EPSILON);
        assert!(rl.backoff_on_429);
        assert_eq!(rl.min_delay_ms, 100);
        assert_eq!(
            manifest.metadata["suite_owner"],
            Value::String("payments".to_owned())
        );
    }

    #[test]
    fn manifest_device_builder_defaults() {
        let manifest = EnvironmentManifest::device("hue", "Philips Hue");
        assert_eq!(manifest.tier, LiveTier::DeviceRequired);
        assert_eq!(manifest.provider, "Philips Hue");
        assert!(matches!(manifest.cleanup, CleanupStrategy::None));
        assert!((manifest.budget_usd - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn manifest_read_only_builder_defaults() {
        let manifest = EnvironmentManifest::read_only("reddit", "Reddit");
        assert_eq!(manifest.tier, LiveTier::LiveReadOnly);
        assert_eq!(manifest.provider, "Reddit");
        assert!(matches!(manifest.cleanup, CleanupStrategy::None));
        assert!((manifest.budget_usd - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn manifest_live_write_builder_defaults() {
        let manifest = EnvironmentManifest::live_write("line", "LINE");
        assert_eq!(manifest.tier, LiveTier::LiveWriteRequired);
        assert_eq!(manifest.provider, "LINE");
        assert!(matches!(manifest.cleanup, CleanupStrategy::PrefixDelete));
        assert!((manifest.budget_usd - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn manifest_with_test_default_secret() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe").with_test_default_secret(
            "mode",
            "STRIPE_MODE",
            "test",
            "Mode selector",
        );
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
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe").with_budget(1.0);
        let problems = manifest.validate();
        // In CI without FCP_LIVE_SANDBOX=1, this should have at least the gate problem
        assert!(problems.iter().any(|p| p.contains("FCP_LIVE_SANDBOX")));
    }

    #[test]
    fn manifest_validate_reports_missing_required_env_var() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_env_var("FCP_TESTKIT_REQUIRED_REGION_5555", "Required region")
            .with_account_setup("Use a dedicated Stripe test-mode account")
            .with_budget(1.0);
        let problems = manifest.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.contains("FCP_TESTKIT_REQUIRED_REGION_5555"))
        );
    }

    #[test]
    fn manifest_validate_requires_account_setup_for_non_local_runs() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe").with_budget(1.0);
        let problems = manifest.validate();
        assert!(problems.iter().any(|p| p.contains("account setup")));
    }

    #[test]
    fn manifest_validate_requires_cleanup_for_mutation_capable_tiers() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_account_setup("Use a dedicated Stripe test-mode account")
            .with_budget(1.0)
            .with_cleanup(CleanupStrategy::None);
        let problems = manifest.validate();
        assert!(problems.iter().any(|p| p.contains("cleanup strategy")));
    }

    #[test]
    fn manifest_validate_rejects_invalid_rate_limits() {
        let mut manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_account_setup("Use a dedicated Stripe test-mode account")
            .with_budget(1.0);
        manifest.rate_limits = Some(RateLimitConfig {
            max_rps: 0.0,
            min_delay_ms: 0,
            backoff_on_429: true,
        });

        let problems = manifest.validate();
        assert!(problems.iter().any(|p| p.contains("max_rps")));
        assert!(problems.iter().any(|p| p.contains("min_delay_ms")));
    }

    #[test]
    fn manifest_with_rate_limits_clamps_min_delay_to_one_ms() {
        let manifest = EnvironmentManifest::read_only("reddit", "Reddit")
            .with_account_setup("Use a dedicated Reddit API test account")
            .with_rate_limits(5_000.0, true);

        let rate_limits = manifest.rate_limits.expect("rate limit config");
        assert!((rate_limits.max_rps - 5_000.0).abs() < f64::EPSILON);
        assert_eq!(rate_limits.min_delay_ms, 1);
    }

    #[test]
    fn manifest_validate_reports_missing_secrets() {
        // Use a never-set env var for the secret
        let manifest = EnvironmentManifest::local("sqlite").with_env_secret(
            "api_key",
            "FCP_TESTKIT_INTERNAL_NEVER_SET_7777",
            "key",
        );
        let problems = manifest.validate();
        assert!(problems.iter().any(|p| p.contains("api_key")));
    }

    #[test]
    fn manifest_evidence_summary() {
        let manifest = EnvironmentManifest::sandbox("aws", "Amazon Web Services")
            .with_budget(5.0)
            .with_account_setup("Use a dedicated AWS sandbox account")
            .with_env_var_default("AWS_REGION", "us-east-1", "AWS region");
        let summary = manifest.evidence_summary();
        assert_eq!(summary["connector"], "aws");
        assert_eq!(summary["tier"], "sandbox_required");
        assert_eq!(summary["provider"], "Amazon Web Services");
        assert_eq!(summary["env_var_count"], 1);
        assert_eq!(summary["account_setup_configured"], true);
        assert_eq!(summary["cleanup_strategy"]["kind"], "prefix_delete");
    }

    #[test]
    fn manifest_cost_budget() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe").with_budget(3.50);
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
            .with_account_setup("Use a dedicated Stripe test-mode account")
            .with_budget(1.0);
        let env = LiveEnvironment::from_manifest(manifest);
        assert!(!env.is_ready());
        assert!(!env.problems().is_empty());
    }

    #[test]
    fn live_environment_not_ready_without_required_env_var() {
        let manifest = EnvironmentManifest::local("sqlite")
            .with_env_var("FCP_TESTKIT_REQUIRED_REGION_6060", "Required region");
        let env = LiveEnvironment::from_manifest(manifest);
        assert!(!env.is_ready());
        assert!(!env.env_vars.is_complete());
        assert!(
            env.problems()
                .iter()
                .any(|problem| problem.contains("FCP_TESTKIT_REQUIRED_REGION_6060"))
        );
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
        assert!(summary["tenant_identity"].is_string());
        assert!(summary["env_vars"].is_object());
        assert!(summary["cleanup_expectations"].is_object());
    }

    #[test]
    fn live_environment_debug_does_not_leak() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe").with_env_secret(
            "key",
            "FCP_STRIPE_TEST_KEY_NEVER",
            "test key",
        );
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

    // ── BudgetAlert ───────────────────────────────────────────────────────

    #[test]
    fn budget_alert_ok_when_under_75_percent() {
        let budget = CostBudget::new(1.0);
        budget.record_api_call("op", 0.50); // 50%
        assert_eq!(budget.alert_level(), BudgetAlert::Ok);
        assert!(!budget.alert_level().is_problem());
    }

    #[test]
    fn budget_alert_warning_at_75_percent() {
        let budget = CostBudget::new(1.0);
        budget.record_api_call("op", 0.80); // 80%
        assert_eq!(budget.alert_level(), BudgetAlert::Warning);
        assert!(budget.alert_level().is_problem());
    }

    #[test]
    fn budget_alert_critical_at_90_percent() {
        let budget = CostBudget::new(1.0);
        budget.record_api_call("op", 0.95); // 95%
        assert_eq!(budget.alert_level(), BudgetAlert::Critical);
        assert!(budget.alert_level().is_problem());
    }

    #[test]
    fn budget_alert_exceeded_over_limit() {
        let budget = CostBudget::new(1.0);
        budget.record_api_call("op", 1.50); // 150%
        assert_eq!(budget.alert_level(), BudgetAlert::Exceeded);
        assert!(budget.alert_level().is_problem());
    }

    #[test]
    fn budget_alert_display() {
        assert_eq!(BudgetAlert::Ok.to_string(), "ok");
        assert_eq!(BudgetAlert::Warning.to_string(), "warning");
        assert_eq!(BudgetAlert::Critical.to_string(), "critical");
        assert_eq!(BudgetAlert::Exceeded.to_string(), "exceeded");
    }

    #[test]
    fn budget_exceeds_threshold() {
        let budget = CostBudget::new(10.0);
        budget.record_api_call("op", 8.0); // 80%
        assert!(budget.exceeds_threshold(0.75));
        assert!(!budget.exceeds_threshold(0.85));
    }

    #[test]
    fn budget_summary_includes_alert_level() {
        let budget = CostBudget::new(1.0);
        budget.record_api_call("op", 0.10);
        let summary = budget.summary();
        assert_eq!(summary["alert_level"], "ok");
    }

    // ── StaleResourceReport ──────────────────────────────────────────────

    #[test]
    fn stale_resource_scan_finds_old_resources() {
        let old_date = (Utc::now() - chrono::Duration::days(45)).format("%Y%m%d");
        let old_name = format!("fcp-test-stripe-customer-abc-{old_date}");
        let fresh_name = format!("fcp-test-stripe-order-xyz-{}", Utc::now().format("%Y%m%d"));
        let non_synthetic = "my-prod-resource";

        let names = [old_name.as_str(), fresh_name.as_str(), non_synthetic];
        let report = StaleResourceReport::scan(&names, 30);

        assert_eq!(report.scanned, 3);
        assert!(report.has_stale());
        assert_eq!(report.stale.len(), 1);
        assert_eq!(report.stale[0].name, old_name);
        assert_eq!(report.stale[0].connector.as_deref(), Some("stripe"));
        assert!(report.stale[0].age_days.unwrap() >= 44);
    }

    #[test]
    fn stale_resource_scan_empty_when_all_fresh() {
        let fresh = format!("fcp-test-aws-bucket-abc-{}", Utc::now().format("%Y%m%d"));
        let names = [fresh.as_str()];
        let report = StaleResourceReport::scan(&names, 30);
        assert!(!report.has_stale());
        assert_eq!(report.stale.len(), 0);
    }

    #[test]
    fn stale_resource_scan_ignores_non_synthetic() {
        let names = ["production-database", "staging-bucket", "test-server"];
        let report = StaleResourceReport::scan(&names, 1);
        assert!(!report.has_stale());
    }

    #[test]
    fn stale_resource_summary_structure() {
        let old_date = (Utc::now() - chrono::Duration::days(60)).format("%Y%m%d");
        let old_name = format!("fcp-test-gcp-vm-run1-{old_date}");
        let names = [old_name.as_str()];
        let report = StaleResourceReport::scan(&names, 30);
        let summary = report.summary();
        assert_eq!(summary["scanned"], 1);
        assert_eq!(summary["stale_count"], 1);
        assert!(summary["stale_resources"].is_array());
    }

    // ── PrerequisiteReport ───────────────────────────────────────────────

    #[test]
    fn prerequisite_report_local_is_ready() {
        let manifest = EnvironmentManifest::local("sqlite");
        let report = manifest.prerequisite_report();
        assert!(report.is_ready());
        assert!(report.gate_enabled);
        assert_eq!(report.gate_env_var, "FCP_LIVE_LOCAL");
        assert!(report.secrets_complete);
        assert!(report.env_vars_complete);
        assert!(report.account_setup_configured);
        assert!(report.budget_configured);
        assert!(report.cleanup_configured);
    }

    #[test]
    fn prerequisite_report_sandbox_missing_gate() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_account_setup("Use Stripe test mode")
            .with_budget(1.0);
        let report = manifest.prerequisite_report();
        // FCP_LIVE_SANDBOX is not set in test env
        assert!(!report.gate_enabled);
        assert!(!report.is_ready());
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.contains("FCP_LIVE_SANDBOX"))
        );
    }

    #[test]
    fn prerequisite_report_missing_secrets() {
        let manifest = EnvironmentManifest::local("test").with_env_secret(
            "api_key",
            "FCP_NEVER_SET_PREREQ_TEST",
            "key",
        );
        let report = manifest.prerequisite_report();
        assert!(!report.secrets_complete);
        assert_eq!(report.secrets_missing, vec!["api_key"]);
    }

    #[test]
    fn prerequisite_report_detects_missing_account_setup() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe").with_budget(1.0);
        let report = manifest.prerequisite_report();
        assert!(!report.account_setup_configured);
        assert!(
            report
                .problems
                .iter()
                .any(|problem| problem.contains("account setup"))
        );
    }

    #[test]
    fn prerequisite_report_detects_invalid_cleanup_configuration() {
        let manifest = EnvironmentManifest::local("sqlite")
            .with_cleanup(CleanupStrategy::Script("   ".to_owned()));
        let report = manifest.prerequisite_report();
        assert!(!report.cleanup_configured);
        assert!(
            report
                .problems
                .iter()
                .any(|problem| problem.contains("Cleanup script path"))
        );
    }

    #[test]
    fn prerequisite_report_summary_includes_contract_context() {
        let manifest = EnvironmentManifest::sandbox("aws", "AWS")
            .with_account_setup("Use a dedicated test account")
            .with_budget(5.0)
            .with_env_var_default("AWS_REGION", "us-east-1", "AWS region")
            .with_rate_limits(4.0, true)
            .with_metadata("suite_owner", Value::String("cloud".to_owned()));
        let summary = manifest.prerequisite_report().summary();
        assert_eq!(summary["provider"], "AWS");
        assert_eq!(summary["gate_env_var"], "FCP_LIVE_SANDBOX");
        assert_eq!(summary["env_vars_defaults_used"][0], "AWS_REGION");
        assert_eq!(summary["cleanup_strategy"]["kind"], "prefix_delete");
        assert_eq!(summary["rate_limits"]["max_rps"], 4.0);
        assert_eq!(summary["synthetic_tenant_expected"], true);
        assert_eq!(summary["metadata_keys"][0], "suite_owner");
    }

    #[test]
    fn prerequisite_report_summary_structure() {
        let manifest = EnvironmentManifest::local("sqlite");
        let report = manifest.prerequisite_report();
        let summary = report.summary();
        assert!(summary["ready"].as_bool().unwrap());
        assert_eq!(summary["connector"], "sqlite");
        assert_eq!(summary["provider"], "local");
        assert!(summary["gate_enabled"].as_bool().unwrap());
        assert_eq!(summary["gate_env_var"], "FCP_LIVE_LOCAL");
        assert!(summary["secrets_complete"].as_bool().unwrap());
        assert!(summary["env_vars_complete"].as_bool().unwrap());
        assert!(summary["account_setup_configured"].as_bool().unwrap());
        assert!(summary["budget_configured"].as_bool().unwrap());
        assert!(summary["cleanup_configured"].as_bool().unwrap());
        assert_eq!(summary["problem_count"], 0);
    }

    // ── Manifest JSON serialization ──────────────────────────────────────

    #[test]
    fn manifest_to_json_and_back() {
        let manifest = EnvironmentManifest::sandbox("aws", "AWS")
            .with_env_secret("access_key", "AWS_ACCESS_KEY_ID", "AWS access key")
            .with_env_var_default("AWS_REGION", "us-east-1", "AWS region")
            .with_budget(5.0)
            .with_account_setup("Use a dedicated test account")
            .with_rate_limits(10.0, true);

        let json = manifest.to_json().unwrap();
        let parsed: EnvironmentManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector, "aws");
        assert_eq!(parsed.tier, LiveTier::SandboxRequired);
        assert_eq!(parsed.secrets.len(), 1);
        assert_eq!(parsed.env_vars.len(), 1);
        assert!((parsed.budget_usd - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn manifest_from_json_file_nonexistent() {
        let result =
            EnvironmentManifest::from_json_file(std::path::Path::new("/nonexistent/manifest.json"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read"));
    }

    // ── CleanupStrategy helpers ──────────────────────────────────────────

    #[test]
    fn cleanup_strategy_uses_synthetic_tenant() {
        assert!(!CleanupStrategy::None.uses_synthetic_tenant());
        assert!(CleanupStrategy::PrefixDelete.uses_synthetic_tenant());
        assert!(!CleanupStrategy::Script("/bin/cleanup.sh".to_owned()).uses_synthetic_tenant());
        assert!(CleanupStrategy::AutoExpire { ttl_hours: 24 }.uses_synthetic_tenant());
    }

    #[test]
    fn cleanup_strategy_summary_shapes() {
        let none = CleanupStrategy::None.summary();
        assert_eq!(none["kind"], "none");

        let prefix = CleanupStrategy::PrefixDelete.summary();
        assert_eq!(prefix["kind"], "prefix_delete");
        assert!(prefix["uses_synthetic_tenant"].as_bool().unwrap());

        let script = CleanupStrategy::Script("/tmp/clean.sh".to_owned()).summary();
        assert_eq!(script["kind"], "script");
        assert_eq!(script["script"], "/tmp/clean.sh");

        let auto = CleanupStrategy::AutoExpire { ttl_hours: 48 }.summary();
        assert_eq!(auto["kind"], "auto_expire");
        assert_eq!(auto["ttl_hours"], 48);
    }

    // ── RateLimitConfig ──────────────────────────────────────────────────

    #[test]
    fn rate_limit_config_summary() {
        let config = RateLimitConfig {
            max_rps: 10.0,
            min_delay_ms: 100,
            backoff_on_429: true,
        };
        let summary = config.summary();
        assert_eq!(summary["max_rps"], 10.0);
        assert_eq!(summary["min_delay_ms"], 100);
        assert!(summary["backoff_on_429"].as_bool().unwrap());
    }

    // ── EnvVarBag extras ─────────────────────────────────────────────────

    #[test]
    fn env_var_bag_len_and_is_empty() {
        let empty = EnvVarBag::load(&[]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let requirements = vec![EnvVarRequirement {
            name: "X".to_owned(),
            default: Some("y".to_owned()),
            description: String::new(),
        }];
        let loaded = EnvVarBag::load(&requirements);
        assert!(!loaded.is_empty());
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn env_var_bag_summary_structure() {
        let requirements = vec![EnvVarRequirement {
            name: "FCP_TESTKIT_REGION_SUMM".to_owned(),
            default: Some("us-west-2".to_owned()),
            description: "Region".to_owned(),
        }];
        let bag = EnvVarBag::load(&requirements);
        let summary = bag.summary();
        assert!(summary["complete"].as_bool().unwrap());
        assert_eq!(summary["loaded_count"], 1);
        assert!(summary["loaded_keys"].is_array());
        assert_eq!(summary["defaults_used"][0], "FCP_TESTKIT_REGION_SUMM");
    }
}
