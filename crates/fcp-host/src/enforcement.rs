//! Security enforcement pipeline for validating every request before routing.
//!
//! Implements a staged pipeline of checks that each request must pass before
//! being forwarded to a connector. The pipeline runs checks in order and
//! short-circuits at the first denial.
//!
//! # Architecture
//!
//! The pipeline comprises 9 concrete checks executed in sequence:
//! 1. Canonical decode — validates request has required non-empty fields
//! 2. Zone membership — validates principal is allowed in the zone
//! 3. Capability verify — validates capability claims cover the operation
//! 4. Checkpoint freshness — validates checkpoint age is within window
//! 5. Revocation freshness — validates revocation list age is within window
//! 6. Taint approval — validates critical taints have approval tokens
//! 7. Policy ceiling — validates zone policy permits connector/operation
//! 8. Connector manifest — validates manifest includes the operation
//! 9. Rate limit — validates request is within rate quota

use std::collections::{HashMap, HashSet};
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Enforcement configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configurable thresholds for enforcement checks.
#[derive(Debug, Clone)]
pub struct EnforcementConfig {
    /// Maximum age in milliseconds before a checkpoint is considered stale.
    pub checkpoint_max_age_ms: u64,
    /// Maximum age in milliseconds before the revocation list is stale.
    pub revocation_max_age_ms: u64,
    /// Taint flags that require an explicit approval token.
    pub critical_taint_flags: Vec<String>,
    /// Per-principal allowed zone IDs. Principal → set of zone IDs.
    pub zone_memberships: HashMap<String, HashSet<String>>,
    /// Per-zone allowed connector IDs.
    pub zone_allowed_connectors: HashMap<String, HashSet<String>>,
    /// Per-zone allowed operation IDs.
    pub zone_allowed_operations: HashMap<String, HashSet<String>>,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            checkpoint_max_age_ms: 300_000,  // 5 minutes
            revocation_max_age_ms: 600_000,  // 10 minutes
            critical_taint_flags: vec![
                "pii".into(),
                "phi".into(),
                "classified".into(),
                "financial".into(),
            ],
            zone_memberships: HashMap::new(),
            zone_allowed_connectors: HashMap::new(),
            zone_allowed_operations: HashMap::new(),
        }
    }
}

impl EnforcementConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the checkpoint maximum age.
    #[must_use]
    pub const fn with_checkpoint_max_age_ms(mut self, ms: u64) -> Self {
        self.checkpoint_max_age_ms = ms;
        self
    }

    /// Set the revocation list maximum age.
    #[must_use]
    pub const fn with_revocation_max_age_ms(mut self, ms: u64) -> Self {
        self.revocation_max_age_ms = ms;
        self
    }

    /// Set the critical taint flags.
    #[must_use]
    pub fn with_critical_taint_flags(mut self, flags: Vec<String>) -> Self {
        self.critical_taint_flags = flags;
        self
    }

    /// Add a zone membership for a principal.
    pub fn add_zone_membership(&mut self, principal: &str, zone: &str) {
        self.zone_memberships
            .entry(principal.to_string())
            .or_default()
            .insert(zone.to_string());
    }

    /// Add an allowed connector to a zone.
    pub fn add_zone_connector(&mut self, zone: &str, connector: &str) {
        self.zone_allowed_connectors
            .entry(zone.to_string())
            .or_default()
            .insert(connector.to_string());
    }

    /// Add an allowed operation to a zone.
    pub fn add_zone_operation(&mut self, zone: &str, operation: &str) {
        self.zone_allowed_operations
            .entry(zone.to_string())
            .or_default()
            .insert(operation.to_string());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enforcement context
// ─────────────────────────────────────────────────────────────────────────────

/// Context for enforcement checks — carries the request plus resolver state.
///
/// Built via [`EnforcementContextBuilder`] for ergonomic construction.
#[derive(Debug, Clone)]
pub struct EnforcementContext {
    /// Unique identifier for this request.
    pub request_id: String,
    /// Target connector identifier.
    pub connector_id: String,
    /// Target operation name.
    pub operation: String,
    /// Zone under which the request executes.
    pub zone_id: String,
    /// Principal (agent/user) making the request.
    pub principal: String,
    /// Capability IDs from the presented token.
    pub capability_claims: Vec<String>,
    /// Active taint flags on the request.
    pub taint_flags: Vec<String>,
    /// Approval scopes presented with the request.
    pub approval_scopes: Vec<String>,
    /// Request timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
    /// Whether the capability holder proof has been verified.
    pub holder_verified: bool,
    /// Age of the latest checkpoint in milliseconds (None if unavailable).
    pub checkpoint_age_ms: Option<u64>,
    /// Age of the revocation list in milliseconds (None if unavailable).
    pub revocation_list_age_ms: Option<u64>,
    /// Budget used so far in the current window.
    pub budget_used: Option<u64>,
    /// Budget limit for the current window.
    pub budget_limit: Option<u64>,
    /// Number of requests in the current rate-limit window.
    pub rate_count: Option<u32>,
    /// Maximum requests allowed in the rate-limit window.
    pub rate_limit: Option<u32>,
    /// Operations the connector manifest declares as supported.
    pub manifest_allowed_operations: Vec<String>,
}

/// Builder for constructing an [`EnforcementContext`].
#[derive(Debug, Clone, Default)]
pub struct EnforcementContextBuilder {
    request_id: Option<String>,
    connector_id: Option<String>,
    operation: Option<String>,
    zone_id: Option<String>,
    principal: Option<String>,
    capability_claims: Vec<String>,
    taint_flags: Vec<String>,
    approval_scopes: Vec<String>,
    timestamp_ms: u64,
    holder_verified: bool,
    checkpoint_age_ms: Option<u64>,
    revocation_list_age_ms: Option<u64>,
    budget_used: Option<u64>,
    budget_limit: Option<u64>,
    rate_count: Option<u32>,
    rate_limit: Option<u32>,
    manifest_allowed_operations: Vec<String>,
}

impl EnforcementContextBuilder {
    /// Create a new builder with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the request ID.
    #[must_use]
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Set the connector ID.
    #[must_use]
    pub fn connector_id(mut self, id: impl Into<String>) -> Self {
        self.connector_id = Some(id.into());
        self
    }

    /// Set the operation name.
    #[must_use]
    pub fn operation(mut self, op: impl Into<String>) -> Self {
        self.operation = Some(op.into());
        self
    }

    /// Set the zone ID.
    #[must_use]
    pub fn zone_id(mut self, zone: impl Into<String>) -> Self {
        self.zone_id = Some(zone.into());
        self
    }

    /// Set the principal.
    #[must_use]
    pub fn principal(mut self, p: impl Into<String>) -> Self {
        self.principal = Some(p.into());
        self
    }

    /// Set the capability claims.
    #[must_use]
    pub fn capability_claims(mut self, claims: Vec<String>) -> Self {
        self.capability_claims = claims;
        self
    }

    /// Set the taint flags.
    #[must_use]
    pub fn taint_flags(mut self, flags: Vec<String>) -> Self {
        self.taint_flags = flags;
        self
    }

    /// Set the approval scopes.
    #[must_use]
    pub fn approval_scopes(mut self, scopes: Vec<String>) -> Self {
        self.approval_scopes = scopes;
        self
    }

    /// Set the request timestamp.
    #[must_use]
    pub const fn timestamp_ms(mut self, ts: u64) -> Self {
        self.timestamp_ms = ts;
        self
    }

    /// Set whether the holder proof is verified.
    #[must_use]
    pub const fn holder_verified(mut self, verified: bool) -> Self {
        self.holder_verified = verified;
        self
    }

    /// Set the checkpoint age.
    #[must_use]
    pub const fn checkpoint_age_ms(mut self, age: u64) -> Self {
        self.checkpoint_age_ms = Some(age);
        self
    }

    /// Set the revocation list age.
    #[must_use]
    pub const fn revocation_list_age_ms(mut self, age: u64) -> Self {
        self.revocation_list_age_ms = Some(age);
        self
    }

    /// Set the budget used.
    #[must_use]
    pub const fn budget_used(mut self, used: u64) -> Self {
        self.budget_used = Some(used);
        self
    }

    /// Set the budget limit.
    #[must_use]
    pub const fn budget_limit(mut self, limit: u64) -> Self {
        self.budget_limit = Some(limit);
        self
    }

    /// Set the rate count.
    #[must_use]
    pub const fn rate_count(mut self, count: u32) -> Self {
        self.rate_count = Some(count);
        self
    }

    /// Set the rate limit.
    #[must_use]
    pub const fn rate_limit(mut self, limit: u32) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    /// Set the manifest allowed operations.
    #[must_use]
    pub fn manifest_allowed_operations(mut self, ops: Vec<String>) -> Self {
        self.manifest_allowed_operations = ops;
        self
    }

    /// Build the enforcement context.
    ///
    /// Returns `None` if any of the required fields (`request_id`, `connector_id`,
    /// `operation`, `zone_id`, `principal`) are missing.
    #[must_use]
    pub fn build(self) -> Option<EnforcementContext> {
        Some(EnforcementContext {
            request_id: self.request_id?,
            connector_id: self.connector_id?,
            operation: self.operation?,
            zone_id: self.zone_id?,
            principal: self.principal?,
            capability_claims: self.capability_claims,
            taint_flags: self.taint_flags,
            approval_scopes: self.approval_scopes,
            timestamp_ms: self.timestamp_ms,
            holder_verified: self.holder_verified,
            checkpoint_age_ms: self.checkpoint_age_ms,
            revocation_list_age_ms: self.revocation_list_age_ms,
            budget_used: self.budget_used,
            budget_limit: self.budget_limit,
            rate_count: self.rate_count,
            rate_limit: self.rate_limit,
            manifest_allowed_operations: self.manifest_allowed_operations,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Check outcome types
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a single enforcement check.
#[derive(Debug, Clone)]
pub enum CheckOutcome {
    /// The check passed.
    Allow,
    /// The check failed with a reason and explanation.
    Deny {
        /// Machine-readable reason code.
        reason_code: String,
        /// Human-readable explanation.
        explanation: String,
    },
    /// The check was not applicable.
    Skip {
        /// Why the check was skipped.
        reason: String,
    },
}

impl CheckOutcome {
    /// Whether this outcome is an `Allow`.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether this outcome is a `Deny`.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Whether this outcome is a `Skip`.
    #[must_use]
    pub const fn is_skip(&self) -> bool {
        matches!(self, Self::Skip { .. })
    }
}

/// Record of a single check execution within the pipeline.
#[derive(Debug, Clone)]
pub struct CheckRecord {
    /// Name of the check.
    pub name: String,
    /// Outcome of the check.
    pub outcome: CheckOutcome,
    /// Wall-clock time in milliseconds for this check.
    pub elapsed_ms: f64,
}

/// Overall outcome of the enforcement pipeline.
#[derive(Debug, Clone)]
pub enum PipelineOutcome {
    /// All checks passed (or were skipped).
    Allow,
    /// A check denied the request.
    Deny {
        /// Name of the check that denied.
        check_name: String,
        /// Machine-readable reason code.
        reason_code: String,
        /// Human-readable explanation.
        explanation: String,
    },
}

impl PipelineOutcome {
    /// Whether the pipeline allowed the request.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether the pipeline denied the request.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Result of the full enforcement pipeline evaluation.
#[derive(Debug, Clone)]
pub struct EnforcementDecision {
    /// Overall outcome of the pipeline.
    pub outcome: PipelineOutcome,
    /// Records of each check that was executed.
    pub checks_run: Vec<CheckRecord>,
    /// Total wall-clock time in milliseconds for the pipeline.
    pub elapsed_ms: f64,
}

impl EnforcementDecision {
    /// Whether the decision allows the request.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.outcome.is_allow()
    }

    /// Number of checks that were executed.
    #[must_use]
    pub const fn checks_executed(&self) -> usize {
        self.checks_run.len()
    }

    /// Number of checks that returned `Allow`.
    #[must_use]
    pub fn allow_count(&self) -> usize {
        self.checks_run.iter().filter(|c| c.outcome.is_allow()).count()
    }

    /// Number of checks that were skipped.
    #[must_use]
    pub fn skip_count(&self) -> usize {
        self.checks_run.iter().filter(|c| c.outcome.is_skip()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enforcement check trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for individual enforcement checks.
///
/// Each check inspects the [`EnforcementContext`] and returns a
/// [`CheckOutcome`]. Checks may also use a shared [`EnforcementConfig`].
pub trait EnforcementCheck: Send + Sync {
    /// Human-readable name for this check.
    fn name(&self) -> &'static str;

    /// Evaluate the check against the given context and config.
    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome;
}

// ─────────────────────────────────────────────────────────────────────────────
// Concrete checks
// ─────────────────────────────────────────────────────────────────────────────

/// Validates that required request fields are present and non-empty.
pub struct CanonicalDecodeCheck;

impl EnforcementCheck for CanonicalDecodeCheck {
    fn name(&self) -> &'static str {
        "canonical_decode"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        if ctx.connector_id.trim().is_empty() {
            return CheckOutcome::Deny {
                reason_code: "MISSING_CONNECTOR_ID".into(),
                explanation: "connector_id is required and must be non-empty".into(),
            };
        }
        if ctx.operation.trim().is_empty() {
            return CheckOutcome::Deny {
                reason_code: "MISSING_OPERATION".into(),
                explanation: "operation is required and must be non-empty".into(),
            };
        }
        if ctx.zone_id.trim().is_empty() {
            return CheckOutcome::Deny {
                reason_code: "MISSING_ZONE_ID".into(),
                explanation: "zone_id is required and must be non-empty".into(),
            };
        }
        if ctx.principal.trim().is_empty() {
            return CheckOutcome::Deny {
                reason_code: "MISSING_PRINCIPAL".into(),
                explanation: "principal is required and must be non-empty".into(),
            };
        }
        if ctx.request_id.trim().is_empty() {
            return CheckOutcome::Deny {
                reason_code: "MISSING_REQUEST_ID".into(),
                explanation: "request_id is required and must be non-empty".into(),
            };
        }
        CheckOutcome::Allow
    }
}

/// Validates that the principal is a member of the requested zone.
pub struct ZoneMembershipCheck;

impl EnforcementCheck for ZoneMembershipCheck {
    fn name(&self) -> &'static str {
        "zone_membership"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        // If no zone memberships are configured, skip (open policy).
        if config.zone_memberships.is_empty() {
            return CheckOutcome::Skip {
                reason: "no zone membership rules configured".into(),
            };
        }

        match config.zone_memberships.get(&ctx.principal) {
            Some(zones) if zones.contains(&ctx.zone_id) => CheckOutcome::Allow,
            Some(_) => CheckOutcome::Deny {
                reason_code: "ZONE_MEMBERSHIP_DENIED".into(),
                explanation: format!(
                    "principal '{}' is not a member of zone '{}'",
                    ctx.principal, ctx.zone_id
                ),
            },
            None => CheckOutcome::Deny {
                reason_code: "PRINCIPAL_NOT_REGISTERED".into(),
                explanation: format!(
                    "principal '{}' has no zone memberships configured",
                    ctx.principal
                ),
            },
        }
    }
}

/// Validates that capability claims cover the requested operation.
pub struct CapabilityVerifyCheck;

impl EnforcementCheck for CapabilityVerifyCheck {
    fn name(&self) -> &'static str {
        "capability_verify"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        if ctx.capability_claims.is_empty() {
            return CheckOutcome::Deny {
                reason_code: "NO_CAPABILITY_CLAIMS".into(),
                explanation: "request has no capability claims".into(),
            };
        }

        // Check for wildcard capability.
        if ctx.capability_claims.iter().any(|c| c == "*") {
            return CheckOutcome::Allow;
        }

        // Check if any claim matches the operation directly or as a prefix.
        let op = &ctx.operation;
        let has_matching_claim = ctx.capability_claims.iter().any(|claim| {
            claim == op || op.starts_with(&format!("{claim}.")) || op.starts_with(&format!("{claim}/"))
        });

        if has_matching_claim {
            CheckOutcome::Allow
        } else {
            CheckOutcome::Deny {
                reason_code: "CAPABILITY_NOT_GRANTED".into(),
                explanation: format!(
                    "no capability claim covers operation '{op}'"
                ),
            }
        }
    }
}

/// Validates that the checkpoint is fresh enough.
pub struct CheckpointFreshnessCheck;

impl EnforcementCheck for CheckpointFreshnessCheck {
    fn name(&self) -> &'static str {
        "checkpoint_freshness"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        match ctx.checkpoint_age_ms {
            None => CheckOutcome::Skip {
                reason: "checkpoint age not available".into(),
            },
            Some(age) if age <= config.checkpoint_max_age_ms => CheckOutcome::Allow,
            Some(age) => CheckOutcome::Deny {
                reason_code: "CHECKPOINT_STALE".into(),
                explanation: format!(
                    "checkpoint age {age}ms exceeds maximum {}ms",
                    config.checkpoint_max_age_ms
                ),
            },
        }
    }
}

/// Validates that the revocation list is fresh enough.
pub struct RevocationFreshnessCheck;

impl EnforcementCheck for RevocationFreshnessCheck {
    fn name(&self) -> &'static str {
        "revocation_freshness"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        match ctx.revocation_list_age_ms {
            None => CheckOutcome::Skip {
                reason: "revocation list age not available".into(),
            },
            Some(age) if age <= config.revocation_max_age_ms => CheckOutcome::Allow,
            Some(age) => CheckOutcome::Deny {
                reason_code: "REVOCATION_LIST_STALE".into(),
                explanation: format!(
                    "revocation list age {age}ms exceeds maximum {}ms",
                    config.revocation_max_age_ms
                ),
            },
        }
    }
}

/// Validates that critical taint flags have matching approval tokens.
pub struct TaintApprovalCheck;

impl EnforcementCheck for TaintApprovalCheck {
    fn name(&self) -> &'static str {
        "taint_approval"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        if ctx.taint_flags.is_empty() {
            return CheckOutcome::Skip {
                reason: "no taint flags on request".into(),
            };
        }

        let approval_set: HashSet<&str> = ctx.approval_scopes.iter().map(String::as_str).collect();

        for flag in &ctx.taint_flags {
            if config.critical_taint_flags.contains(flag) && !approval_set.contains(flag.as_str()) {
                return CheckOutcome::Deny {
                    reason_code: "TAINT_APPROVAL_MISSING".into(),
                    explanation: format!(
                        "critical taint flag '{flag}' requires an approval token"
                    ),
                };
            }
        }

        CheckOutcome::Allow
    }
}

/// Validates that zone policy permits the connector and operation.
pub struct PolicyCeilingCheck;

impl EnforcementCheck for PolicyCeilingCheck {
    fn name(&self) -> &'static str {
        "policy_ceiling"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        // Check connector allow list for this zone.
        if let Some(allowed_connectors) = config.zone_allowed_connectors.get(&ctx.zone_id)
            && !allowed_connectors.contains(&ctx.connector_id)
        {
            return CheckOutcome::Deny {
                reason_code: "CONNECTOR_NOT_IN_ZONE_POLICY".into(),
                explanation: format!(
                    "connector '{}' is not allowed in zone '{}'",
                    ctx.connector_id, ctx.zone_id
                ),
            };
        }

        // Check operation allow list for this zone.
        if let Some(allowed_ops) = config.zone_allowed_operations.get(&ctx.zone_id)
            && !allowed_ops.contains(&ctx.operation)
        {
            return CheckOutcome::Deny {
                reason_code: "OPERATION_NOT_IN_ZONE_POLICY".into(),
                explanation: format!(
                    "operation '{}' is not allowed in zone '{}'",
                    ctx.operation, ctx.zone_id
                ),
            };
        }

        // No restrictions or all checks passed.
        CheckOutcome::Allow
    }
}

/// Validates that the connector manifest allows the requested operation.
pub struct ConnectorManifestCheck;

impl EnforcementCheck for ConnectorManifestCheck {
    fn name(&self) -> &'static str {
        "connector_manifest"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        if ctx.manifest_allowed_operations.is_empty() {
            return CheckOutcome::Skip {
                reason: "no manifest operations provided".into(),
            };
        }

        if ctx.manifest_allowed_operations.contains(&ctx.operation) {
            CheckOutcome::Allow
        } else {
            CheckOutcome::Deny {
                reason_code: "OPERATION_NOT_IN_MANIFEST".into(),
                explanation: format!(
                    "operation '{}' is not declared in the connector manifest",
                    ctx.operation
                ),
            }
        }
    }
}

/// Validates that the request is within the rate-limit quota.
pub struct RateLimitCheck;

impl EnforcementCheck for RateLimitCheck {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        match (ctx.rate_count, ctx.rate_limit) {
            (None, _) | (_, None) => CheckOutcome::Skip {
                reason: "rate limit data not available".into(),
            },
            (Some(count), Some(limit)) if count < limit => CheckOutcome::Allow,
            (Some(count), Some(limit)) => CheckOutcome::Deny {
                reason_code: "RATE_LIMIT_EXCEEDED".into(),
                explanation: format!(
                    "rate count {count} has reached limit {limit}"
                ),
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enforcement pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Ordered pipeline of enforcement checks.
///
/// Runs each check in sequence and short-circuits on the first denial.
/// Skipped checks are recorded but do not block.
pub struct EnforcementPipeline {
    checks: Vec<Box<dyn EnforcementCheck>>,
    config: EnforcementConfig,
}

impl EnforcementPipeline {
    /// Create a pipeline with the default 9 checks and default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checks: Self::default_checks(),
            config: EnforcementConfig::default(),
        }
    }

    /// Create a pipeline with custom checks and default config.
    #[must_use]
    pub fn with_checks(checks: Vec<Box<dyn EnforcementCheck>>) -> Self {
        Self {
            checks,
            config: EnforcementConfig::default(),
        }
    }

    /// Create a pipeline with default checks and a custom config.
    #[must_use]
    pub fn with_config(config: EnforcementConfig) -> Self {
        Self {
            checks: Self::default_checks(),
            config,
        }
    }

    /// Create a pipeline with custom checks and config.
    #[must_use]
    pub fn with_checks_and_config(
        checks: Vec<Box<dyn EnforcementCheck>>,
        config: EnforcementConfig,
    ) -> Self {
        Self { checks, config }
    }

    /// Number of checks in the pipeline.
    #[must_use]
    pub fn check_count(&self) -> usize {
        self.checks.len()
    }

    /// Reference to the pipeline's config.
    #[must_use]
    pub const fn config(&self) -> &EnforcementConfig {
        &self.config
    }

    /// Names of all checks in order.
    #[must_use]
    pub fn check_names(&self) -> Vec<&str> {
        self.checks.iter().map(|c| c.name()).collect()
    }

    /// Evaluate all checks against the given context, stopping at first denial.
    #[must_use]
    pub fn evaluate(&self, ctx: &EnforcementContext) -> EnforcementDecision {
        let pipeline_start = Instant::now();
        let mut records = Vec::with_capacity(self.checks.len());

        for check in &self.checks {
            let check_start = Instant::now();
            let outcome = check.check(ctx, &self.config);
            let elapsed_ms = check_start.elapsed().as_secs_f64() * 1000.0;
            let check_name = check.name();

            if let CheckOutcome::Deny {
                ref reason_code,
                ref explanation,
            } = outcome
            {
                let deny_outcome = PipelineOutcome::Deny {
                    check_name: check_name.to_string(),
                    reason_code: reason_code.clone(),
                    explanation: explanation.clone(),
                };
                records.push(CheckRecord {
                    name: check_name.to_string(),
                    outcome,
                    elapsed_ms,
                });
                return EnforcementDecision {
                    outcome: deny_outcome,
                    checks_run: records,
                    elapsed_ms: pipeline_start.elapsed().as_secs_f64() * 1000.0,
                };
            }

            records.push(CheckRecord {
                name: check_name.to_string(),
                outcome,
                elapsed_ms,
            });
        }

        EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: records,
            elapsed_ms: pipeline_start.elapsed().as_secs_f64() * 1000.0,
        }
    }

    /// The default set of 9 checks in canonical order.
    fn default_checks() -> Vec<Box<dyn EnforcementCheck>> {
        vec![
            Box::new(CanonicalDecodeCheck),
            Box::new(ZoneMembershipCheck),
            Box::new(CapabilityVerifyCheck),
            Box::new(CheckpointFreshnessCheck),
            Box::new(RevocationFreshnessCheck),
            Box::new(TaintApprovalCheck),
            Box::new(PolicyCeilingCheck),
            Box::new(ConnectorManifestCheck),
            Box::new(RateLimitCheck),
        ]
    }
}

impl Default for EnforcementPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EnforcementPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnforcementPipeline")
            .field("check_count", &self.checks.len())
            .field("check_names", &self.check_names())
            .field("config", &self.config)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build a valid context for testing
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience function to create a minimal valid context for testing.
#[cfg(test)]
fn test_context() -> EnforcementContext {
    EnforcementContext {
        request_id: "req-001".into(),
        connector_id: "slack:utility:1.0.0".into(),
        operation: "send_message".into(),
        zone_id: "zone-prod".into(),
        principal: "agent-alpha".into(),
        capability_claims: vec!["send_message".into()],
        taint_flags: Vec::new(),
        approval_scopes: Vec::new(),
        timestamp_ms: 1_700_000_000_000,
        holder_verified: true,
        checkpoint_age_ms: Some(10_000),
        revocation_list_age_ms: Some(20_000),
        budget_used: Some(50),
        budget_limit: Some(1000),
        rate_count: Some(5),
        rate_limit: Some(100),
        manifest_allowed_operations: vec!["send_message".into(), "list_channels".into()],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EnforcementConfig ──

    #[test]
    fn config_default_has_reasonable_values() {
        let config = EnforcementConfig::default();
        assert_eq!(config.checkpoint_max_age_ms, 300_000);
        assert_eq!(config.revocation_max_age_ms, 600_000);
        assert!(!config.critical_taint_flags.is_empty());
        assert!(config.critical_taint_flags.contains(&"pii".to_string()));
        assert!(config.critical_taint_flags.contains(&"phi".to_string()));
    }

    #[test]
    fn config_new_equals_default() {
        let a = EnforcementConfig::new();
        let b = EnforcementConfig::default();
        assert_eq!(a.checkpoint_max_age_ms, b.checkpoint_max_age_ms);
        assert_eq!(a.revocation_max_age_ms, b.revocation_max_age_ms);
        assert_eq!(a.critical_taint_flags.len(), b.critical_taint_flags.len());
    }

    #[test]
    fn config_builder_checkpoint_age() {
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(1000);
        assert_eq!(config.checkpoint_max_age_ms, 1000);
    }

    #[test]
    fn config_builder_revocation_age() {
        let config = EnforcementConfig::new().with_revocation_max_age_ms(2000);
        assert_eq!(config.revocation_max_age_ms, 2000);
    }

    #[test]
    fn config_builder_critical_taints() {
        let config = EnforcementConfig::new()
            .with_critical_taint_flags(vec!["custom".into()]);
        assert_eq!(config.critical_taint_flags, vec!["custom"]);
    }

    #[test]
    fn config_add_zone_membership() {
        let mut config = EnforcementConfig::new();
        config.add_zone_membership("alice", "zone-a");
        config.add_zone_membership("alice", "zone-b");
        config.add_zone_membership("bob", "zone-a");

        let alice_zones = config.zone_memberships.get("alice").unwrap();
        assert!(alice_zones.contains("zone-a"));
        assert!(alice_zones.contains("zone-b"));
        assert_eq!(alice_zones.len(), 2);

        let bob_zones = config.zone_memberships.get("bob").unwrap();
        assert_eq!(bob_zones.len(), 1);
    }

    #[test]
    fn config_add_zone_connector() {
        let mut config = EnforcementConfig::new();
        config.add_zone_connector("zone-a", "slack");
        config.add_zone_connector("zone-a", "github");

        let connectors = config.zone_allowed_connectors.get("zone-a").unwrap();
        assert!(connectors.contains("slack"));
        assert!(connectors.contains("github"));
    }

    #[test]
    fn config_add_zone_operation() {
        let mut config = EnforcementConfig::new();
        config.add_zone_operation("zone-a", "read");
        config.add_zone_operation("zone-a", "write");

        let ops = config.zone_allowed_operations.get("zone-a").unwrap();
        assert!(ops.contains("read"));
        assert!(ops.contains("write"));
    }

    #[test]
    fn config_clone() {
        let mut original = EnforcementConfig::new();
        original.add_zone_membership("alice", "zone-a");
        let cloned = original.clone();
        assert_eq!(
            cloned.zone_memberships.get("alice").unwrap().len(),
            original.zone_memberships.get("alice").unwrap().len()
        );
    }

    #[test]
    fn config_debug_format() {
        let config = EnforcementConfig::new();
        let debug = format!("{config:?}");
        assert!(debug.contains("EnforcementConfig"));
    }

    // ── EnforcementContextBuilder ──

    #[test]
    fn builder_complete_builds_context() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .build();
        assert!(ctx.is_some());
        let ctx = ctx.unwrap();
        assert_eq!(ctx.request_id, "r1");
        assert_eq!(ctx.connector_id, "c1");
        assert_eq!(ctx.operation, "op1");
        assert_eq!(ctx.zone_id, "z1");
        assert_eq!(ctx.principal, "p1");
    }

    #[test]
    fn builder_missing_request_id_returns_none() {
        let ctx = EnforcementContextBuilder::new()
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_missing_connector_id_returns_none() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_missing_operation_returns_none() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .zone_id("z1")
            .principal("p1")
            .build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_missing_zone_id_returns_none() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .principal("p1")
            .build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_missing_principal_returns_none() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_with_capability_claims() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .capability_claims(vec!["cap1".into(), "cap2".into()])
            .build()
            .unwrap();
        assert_eq!(ctx.capability_claims.len(), 2);
    }

    #[test]
    fn builder_with_taint_flags() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .taint_flags(vec!["pii".into()])
            .build()
            .unwrap();
        assert_eq!(ctx.taint_flags, vec!["pii"]);
    }

    #[test]
    fn builder_with_approval_scopes() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .approval_scopes(vec!["pii".into()])
            .build()
            .unwrap();
        assert_eq!(ctx.approval_scopes, vec!["pii"]);
    }

    #[test]
    fn builder_with_timestamp() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .timestamp_ms(42)
            .build()
            .unwrap();
        assert_eq!(ctx.timestamp_ms, 42);
    }

    #[test]
    fn builder_with_holder_verified() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .holder_verified(true)
            .build()
            .unwrap();
        assert!(ctx.holder_verified);
    }

    #[test]
    fn builder_with_checkpoint_age() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .checkpoint_age_ms(5000)
            .build()
            .unwrap();
        assert_eq!(ctx.checkpoint_age_ms, Some(5000));
    }

    #[test]
    fn builder_with_revocation_list_age() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .revocation_list_age_ms(10_000)
            .build()
            .unwrap();
        assert_eq!(ctx.revocation_list_age_ms, Some(10_000));
    }

    #[test]
    fn builder_with_budget() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .budget_used(100)
            .budget_limit(1000)
            .build()
            .unwrap();
        assert_eq!(ctx.budget_used, Some(100));
        assert_eq!(ctx.budget_limit, Some(1000));
    }

    #[test]
    fn builder_with_rate_limit() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .rate_count(10)
            .rate_limit(100)
            .build()
            .unwrap();
        assert_eq!(ctx.rate_count, Some(10));
        assert_eq!(ctx.rate_limit, Some(100));
    }

    #[test]
    fn builder_with_manifest_ops() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .manifest_allowed_operations(vec!["op1".into(), "op2".into()])
            .build()
            .unwrap();
        assert_eq!(ctx.manifest_allowed_operations.len(), 2);
    }

    #[test]
    fn builder_default_values() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .build()
            .unwrap();
        assert_eq!(ctx.timestamp_ms, 0);
        assert!(!ctx.holder_verified);
        assert!(ctx.checkpoint_age_ms.is_none());
        assert!(ctx.revocation_list_age_ms.is_none());
        assert!(ctx.budget_used.is_none());
        assert!(ctx.budget_limit.is_none());
        assert!(ctx.rate_count.is_none());
        assert!(ctx.rate_limit.is_none());
        assert!(ctx.manifest_allowed_operations.is_empty());
        assert!(ctx.capability_claims.is_empty());
        assert!(ctx.taint_flags.is_empty());
        assert!(ctx.approval_scopes.is_empty());
    }

    #[test]
    fn builder_clone() {
        let builder = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1");
        let cloned = builder.clone();
        // Use original after clone to prove both are valid.
        let ctx_original = builder.build().unwrap();
        let ctx_cloned = cloned.build().unwrap();
        assert_eq!(ctx_original.request_id, "r1");
        assert_eq!(ctx_cloned.request_id, "r1");
    }

    // ── CheckOutcome ──

    #[test]
    fn check_outcome_allow_predicates() {
        let o = CheckOutcome::Allow;
        assert!(o.is_allow());
        assert!(!o.is_deny());
        assert!(!o.is_skip());
    }

    #[test]
    fn check_outcome_deny_predicates() {
        let o = CheckOutcome::Deny {
            reason_code: "X".into(),
            explanation: "Y".into(),
        };
        assert!(!o.is_allow());
        assert!(o.is_deny());
        assert!(!o.is_skip());
    }

    #[test]
    fn check_outcome_skip_predicates() {
        let o = CheckOutcome::Skip {
            reason: "N/A".into(),
        };
        assert!(!o.is_allow());
        assert!(!o.is_deny());
        assert!(o.is_skip());
    }

    #[test]
    fn check_outcome_debug_format() {
        let o = CheckOutcome::Allow;
        assert!(format!("{o:?}").contains("Allow"));
    }

    #[test]
    fn check_outcome_deny_debug() {
        let o = CheckOutcome::Deny {
            reason_code: "CODE".into(),
            explanation: "explain".into(),
        };
        let debug = format!("{o:?}");
        assert!(debug.contains("CODE"));
        assert!(debug.contains("explain"));
    }

    #[test]
    fn check_outcome_clone() {
        let original = CheckOutcome::Deny {
            reason_code: "A".into(),
            explanation: "B".into(),
        };
        let cloned = original.clone();
        assert!(original.is_deny());
        assert!(cloned.is_deny());
    }

    // ── PipelineOutcome ──

    #[test]
    fn pipeline_outcome_allow_predicates() {
        let o = PipelineOutcome::Allow;
        assert!(o.is_allow());
        assert!(!o.is_deny());
    }

    #[test]
    fn pipeline_outcome_deny_predicates() {
        let o = PipelineOutcome::Deny {
            check_name: "c".into(),
            reason_code: "r".into(),
            explanation: "e".into(),
        };
        assert!(!o.is_allow());
        assert!(o.is_deny());
    }

    #[test]
    fn pipeline_outcome_debug() {
        let o = PipelineOutcome::Allow;
        assert!(format!("{o:?}").contains("Allow"));
    }

    // ── CanonicalDecodeCheck ──

    #[test]
    fn canonical_decode_name() {
        assert_eq!(CanonicalDecodeCheck.name(), "canonical_decode");
    }

    #[test]
    fn canonical_decode_allow_valid() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn canonical_decode_deny_empty_connector_id() {
        let mut ctx = test_context();
        ctx.connector_id = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_CONNECTOR_ID");
        }
    }

    #[test]
    fn canonical_decode_deny_whitespace_connector_id() {
        let mut ctx = test_context();
        ctx.connector_id = "   ".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_CONNECTOR_ID");
        }
    }

    #[test]
    fn canonical_decode_deny_empty_operation() {
        let mut ctx = test_context();
        ctx.operation = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_OPERATION");
        }
    }

    #[test]
    fn canonical_decode_deny_whitespace_operation() {
        let mut ctx = test_context();
        ctx.operation = "\t\n ".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn canonical_decode_deny_empty_zone_id() {
        let mut ctx = test_context();
        ctx.zone_id = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_ZONE_ID");
        }
    }

    #[test]
    fn canonical_decode_deny_empty_principal() {
        let mut ctx = test_context();
        ctx.principal = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_PRINCIPAL");
        }
    }

    #[test]
    fn canonical_decode_deny_empty_request_id() {
        let mut ctx = test_context();
        ctx.request_id = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_REQUEST_ID");
        }
    }

    #[test]
    fn canonical_decode_deny_whitespace_principal() {
        let mut ctx = test_context();
        ctx.principal = "  ".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn canonical_decode_deny_whitespace_zone_id() {
        let mut ctx = test_context();
        ctx.zone_id = " ".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    // ── ZoneMembershipCheck ──

    #[test]
    fn zone_membership_name() {
        assert_eq!(ZoneMembershipCheck.name(), "zone_membership");
    }

    #[test]
    fn zone_membership_skip_no_rules() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn zone_membership_allow_member() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_membership("agent-alpha", "zone-prod");
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn zone_membership_deny_not_member() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_membership("agent-alpha", "zone-staging");
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, explanation } = &outcome {
            assert_eq!(reason_code, "ZONE_MEMBERSHIP_DENIED");
            assert!(explanation.contains("agent-alpha"));
            assert!(explanation.contains("zone-prod"));
        }
    }

    #[test]
    fn zone_membership_deny_unknown_principal() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_membership("agent-beta", "zone-prod");
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "PRINCIPAL_NOT_REGISTERED");
        }
    }

    #[test]
    fn zone_membership_allow_multiple_zones() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_membership("agent-alpha", "zone-staging");
        config.add_zone_membership("agent-alpha", "zone-prod");
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── CapabilityVerifyCheck ──

    #[test]
    fn capability_verify_name() {
        assert_eq!(CapabilityVerifyCheck.name(), "capability_verify");
    }

    #[test]
    fn capability_verify_allow_exact_match() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_allow_wildcard() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["*".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_allow_prefix_dot() {
        let mut ctx = test_context();
        ctx.operation = "messages.send".into();
        ctx.capability_claims = vec!["messages".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_allow_prefix_slash() {
        let mut ctx = test_context();
        ctx.operation = "messages/send".into();
        ctx.capability_claims = vec!["messages".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_deny_no_claims() {
        let mut ctx = test_context();
        ctx.capability_claims = Vec::new();
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "NO_CAPABILITY_CLAIMS");
        }
    }

    #[test]
    fn capability_verify_deny_wrong_claim() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["list_channels".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, explanation } = &outcome {
            assert_eq!(reason_code, "CAPABILITY_NOT_GRANTED");
            assert!(explanation.contains("send_message"));
        }
    }

    #[test]
    fn capability_verify_multiple_claims_one_match() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["unrelated".into(), "send_message".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_prefix_does_not_partial_match() {
        let mut ctx = test_context();
        ctx.operation = "send_message_extended".into();
        ctx.capability_claims = vec!["send_message".into()];
        let config = EnforcementConfig::default();
        // "send_message" does not prefix-match "send_message_extended" (no . or / separator)
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    // ── CheckpointFreshnessCheck ──

    #[test]
    fn checkpoint_freshness_name() {
        assert_eq!(CheckpointFreshnessCheck.name(), "checkpoint_freshness");
    }

    #[test]
    fn checkpoint_freshness_allow_within_window() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn checkpoint_freshness_skip_no_data() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = None;
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn checkpoint_freshness_deny_stale() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(500_000);
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, explanation } = &outcome {
            assert_eq!(reason_code, "CHECKPOINT_STALE");
            assert!(explanation.contains("500000"));
            assert!(explanation.contains("300000"));
        }
    }

    #[test]
    fn checkpoint_freshness_allow_at_boundary() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(300_000);
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn checkpoint_freshness_deny_just_over() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(300_001);
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn checkpoint_freshness_custom_threshold() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(50);
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(100);
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn checkpoint_freshness_zero_age() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(0);
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── RevocationFreshnessCheck ──

    #[test]
    fn revocation_freshness_name() {
        assert_eq!(RevocationFreshnessCheck.name(), "revocation_freshness");
    }

    #[test]
    fn revocation_freshness_allow_within_window() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = RevocationFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn revocation_freshness_skip_no_data() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = None;
        let config = EnforcementConfig::default();
        let outcome = RevocationFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn revocation_freshness_deny_stale() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(700_000);
        let config = EnforcementConfig::default();
        let outcome = RevocationFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "REVOCATION_LIST_STALE");
        }
    }

    #[test]
    fn revocation_freshness_allow_at_boundary() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(600_000);
        let config = EnforcementConfig::default();
        let outcome = RevocationFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn revocation_freshness_deny_just_over() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(600_001);
        let config = EnforcementConfig::default();
        let outcome = RevocationFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn revocation_freshness_custom_threshold() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(200);
        let config = EnforcementConfig::new().with_revocation_max_age_ms(500);
        let outcome = RevocationFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── TaintApprovalCheck ──

    #[test]
    fn taint_approval_name() {
        assert_eq!(TaintApprovalCheck.name(), "taint_approval");
    }

    #[test]
    fn taint_approval_skip_no_flags() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn taint_approval_allow_non_critical() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["public".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_allow_with_approval() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        ctx.approval_scopes = vec!["pii".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_deny_missing_approval() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        ctx.approval_scopes = Vec::new();
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, explanation } = &outcome {
            assert_eq!(reason_code, "TAINT_APPROVAL_MISSING");
            assert!(explanation.contains("pii"));
        }
    }

    #[test]
    fn taint_approval_deny_wrong_approval() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        ctx.approval_scopes = vec!["phi".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn taint_approval_allow_multiple_flags_all_approved() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into(), "phi".into(), "financial".into()];
        ctx.approval_scopes = vec!["pii".into(), "phi".into(), "financial".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_deny_multiple_flags_one_missing() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into(), "phi".into()];
        ctx.approval_scopes = vec!["pii".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("phi"));
        }
    }

    #[test]
    fn taint_approval_custom_critical_flags() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["custom".into()];
        let config = EnforcementConfig::new()
            .with_critical_taint_flags(vec!["custom".into()]);
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn taint_approval_mixed_critical_and_non_critical() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["public".into(), "pii".into()];
        ctx.approval_scopes = vec!["pii".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── PolicyCeilingCheck ──

    #[test]
    fn policy_ceiling_name() {
        assert_eq!(PolicyCeilingCheck.name(), "policy_ceiling");
    }

    #[test]
    fn policy_ceiling_allow_no_restrictions() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_allow_connector_permitted() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_connector("zone-prod", "slack:utility:1.0.0");
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_deny_connector_not_allowed() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_connector("zone-prod", "github:utility:1.0.0");
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "CONNECTOR_NOT_IN_ZONE_POLICY");
        }
    }

    #[test]
    fn policy_ceiling_allow_operation_permitted() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_operation("zone-prod", "send_message");
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_deny_operation_not_allowed() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_operation("zone-prod", "list_channels");
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "OPERATION_NOT_IN_ZONE_POLICY");
        }
    }

    #[test]
    fn policy_ceiling_allow_both_permitted() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_connector("zone-prod", "slack:utility:1.0.0");
        config.add_zone_operation("zone-prod", "send_message");
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_deny_connector_blocks_before_operation() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_connector("zone-prod", "github:utility:1.0.0");
        config.add_zone_operation("zone-prod", "send_message");
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "CONNECTOR_NOT_IN_ZONE_POLICY");
        }
    }

    #[test]
    fn policy_ceiling_other_zone_rules_dont_affect() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_connector("zone-staging", "github:utility:1.0.0");
        // zone-prod has no rules, so allow.
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── ConnectorManifestCheck ──

    #[test]
    fn connector_manifest_name() {
        assert_eq!(ConnectorManifestCheck.name(), "connector_manifest");
    }

    #[test]
    fn connector_manifest_allow_in_list() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn connector_manifest_skip_no_manifest() {
        let mut ctx = test_context();
        ctx.manifest_allowed_operations = Vec::new();
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn connector_manifest_deny_not_in_list() {
        let mut ctx = test_context();
        ctx.operation = "delete_channel".into();
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, explanation } = &outcome {
            assert_eq!(reason_code, "OPERATION_NOT_IN_MANIFEST");
            assert!(explanation.contains("delete_channel"));
        }
    }

    #[test]
    fn connector_manifest_allow_second_op() {
        let mut ctx = test_context();
        ctx.operation = "list_channels".into();
        let config = EnforcementConfig::default();
        // test_context has both send_message and list_channels.
        ctx.capability_claims = vec!["list_channels".into()];
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── RateLimitCheck ──

    #[test]
    fn rate_limit_name() {
        assert_eq!(RateLimitCheck.name(), "rate_limit");
    }

    #[test]
    fn rate_limit_allow_under_limit() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn rate_limit_skip_no_count() {
        let mut ctx = test_context();
        ctx.rate_count = None;
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn rate_limit_skip_no_limit() {
        let mut ctx = test_context();
        ctx.rate_limit = None;
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn rate_limit_deny_at_limit() {
        let mut ctx = test_context();
        ctx.rate_count = Some(100);
        ctx.rate_limit = Some(100);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "RATE_LIMIT_EXCEEDED");
        }
    }

    #[test]
    fn rate_limit_deny_over_limit() {
        let mut ctx = test_context();
        ctx.rate_count = Some(150);
        ctx.rate_limit = Some(100);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn rate_limit_allow_just_under() {
        let mut ctx = test_context();
        ctx.rate_count = Some(99);
        ctx.rate_limit = Some(100);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn rate_limit_allow_zero_count() {
        let mut ctx = test_context();
        ctx.rate_count = Some(0);
        ctx.rate_limit = Some(100);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn rate_limit_deny_explanation_includes_numbers() {
        let mut ctx = test_context();
        ctx.rate_count = Some(50);
        ctx.rate_limit = Some(50);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("50"));
        }
    }

    // ── EnforcementPipeline ──

    #[test]
    fn pipeline_default_has_9_checks() {
        let pipeline = EnforcementPipeline::new();
        assert_eq!(pipeline.check_count(), 9);
    }

    #[test]
    fn pipeline_default_check_order() {
        let pipeline = EnforcementPipeline::new();
        let names = pipeline.check_names();
        assert_eq!(names[0], "canonical_decode");
        assert_eq!(names[1], "zone_membership");
        assert_eq!(names[2], "capability_verify");
        assert_eq!(names[3], "checkpoint_freshness");
        assert_eq!(names[4], "revocation_freshness");
        assert_eq!(names[5], "taint_approval");
        assert_eq!(names[6], "policy_ceiling");
        assert_eq!(names[7], "connector_manifest");
        assert_eq!(names[8], "rate_limit");
    }

    #[test]
    fn pipeline_with_checks_custom_count() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(CanonicalDecodeCheck),
            Box::new(RateLimitCheck),
        ]);
        assert_eq!(pipeline.check_count(), 2);
    }

    #[test]
    fn pipeline_empty() {
        let pipeline = EnforcementPipeline::with_checks(vec![]);
        assert_eq!(pipeline.check_count(), 0);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.checks_executed(), 0);
    }

    #[test]
    fn pipeline_evaluate_full_allow() {
        let pipeline = EnforcementPipeline::new();
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert!(decision.elapsed_ms >= 0.0);
        assert_eq!(decision.checks_executed(), 9);
    }

    #[test]
    fn pipeline_evaluate_deny_at_canonical_decode() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.connector_id = String::new();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        assert_eq!(decision.checks_executed(), 1);
        if let PipelineOutcome::Deny { check_name, reason_code, .. } = &decision.outcome {
            assert_eq!(check_name, "canonical_decode");
            assert_eq!(reason_code, "MISSING_CONNECTOR_ID");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_capability_verify() {
        let config = EnforcementConfig::default();
        let pipeline = EnforcementPipeline::with_config(config);
        let mut ctx = test_context();
        ctx.capability_claims = Vec::new();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "capability_verify");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_checkpoint_freshness() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(999_999);
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "checkpoint_freshness");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_revocation_freshness() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(999_999);
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "revocation_freshness");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_taint_approval() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        // no approval scopes.
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "taint_approval");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_policy_ceiling() {
        let mut config = EnforcementConfig::default();
        config.add_zone_connector("zone-prod", "github:utility:1.0.0");
        let pipeline = EnforcementPipeline::with_config(config);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "policy_ceiling");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_connector_manifest() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.operation = "nonexistent_op".into();
        ctx.capability_claims = vec!["nonexistent_op".into()];
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "connector_manifest");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_rate_limit() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.rate_count = Some(200);
        ctx.rate_limit = Some(100);
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "rate_limit");
        }
    }

    #[test]
    fn pipeline_skips_are_tracked() {
        let pipeline = EnforcementPipeline::new();
        let ctx = test_context();
        // zone_membership and taint_approval will skip with default config.
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.skip_count() >= 2);
    }

    #[test]
    fn pipeline_allow_count() {
        let pipeline = EnforcementPipeline::new();
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.allow_count() > 0);
        assert_eq!(
            decision.allow_count() + decision.skip_count(),
            decision.checks_executed()
        );
    }

    #[test]
    fn pipeline_elapsed_non_negative() {
        let pipeline = EnforcementPipeline::new();
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.elapsed_ms >= 0.0);
        for record in &decision.checks_run {
            assert!(record.elapsed_ms >= 0.0);
        }
    }

    #[test]
    fn pipeline_check_records_have_names() {
        let pipeline = EnforcementPipeline::new();
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        for record in &decision.checks_run {
            assert!(!record.name.is_empty());
        }
    }

    #[test]
    fn pipeline_with_config() {
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(100);
        let pipeline = EnforcementPipeline::with_config(config);
        assert_eq!(pipeline.config().checkpoint_max_age_ms, 100);
        assert_eq!(pipeline.check_count(), 9);
    }

    #[test]
    fn pipeline_with_checks_and_config() {
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(50);
        let pipeline = EnforcementPipeline::with_checks_and_config(
            vec![Box::new(CanonicalDecodeCheck)],
            config,
        );
        assert_eq!(pipeline.check_count(), 1);
        assert_eq!(pipeline.config().checkpoint_max_age_ms, 50);
    }

    #[test]
    fn pipeline_debug_format() {
        let pipeline = EnforcementPipeline::new();
        let debug = format!("{pipeline:?}");
        assert!(debug.contains("EnforcementPipeline"));
        assert!(debug.contains("check_count"));
    }

    #[test]
    fn pipeline_default_trait() {
        let pipeline = EnforcementPipeline::default();
        assert_eq!(pipeline.check_count(), 9);
    }

    // ── Custom check implementation ──

    struct AlwaysAllowCheck;
    impl EnforcementCheck for AlwaysAllowCheck {
        fn name(&self) -> &'static str { "always_allow" }
        fn check(&self, _ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
            CheckOutcome::Allow
        }
    }

    struct AlwaysDenyCheck {
        code: String,
    }
    impl EnforcementCheck for AlwaysDenyCheck {
        fn name(&self) -> &'static str { "always_deny" }
        fn check(&self, _ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
            CheckOutcome::Deny {
                reason_code: self.code.clone(),
                explanation: "always denied".into(),
            }
        }
    }

    struct AlwaysSkipCheck;
    impl EnforcementCheck for AlwaysSkipCheck {
        fn name(&self) -> &'static str { "always_skip" }
        fn check(&self, _ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
            CheckOutcome::Skip {
                reason: "always skipped".into(),
            }
        }
    }

    #[test]
    fn custom_check_all_allow() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysAllowCheck),
            Box::new(AlwaysAllowCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.checks_executed(), 2);
    }

    #[test]
    fn custom_check_deny_stops_pipeline() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysAllowCheck),
            Box::new(AlwaysDenyCheck { code: "CUSTOM".into() }),
            Box::new(AlwaysAllowCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        assert_eq!(decision.checks_executed(), 2);
        if let PipelineOutcome::Deny { check_name, reason_code, .. } = &decision.outcome {
            assert_eq!(check_name, "always_deny");
            assert_eq!(reason_code, "CUSTOM");
        }
    }

    #[test]
    fn custom_check_skip_does_not_block() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysAllowCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.skip_count(), 1);
        assert_eq!(decision.allow_count(), 1);
    }

    #[test]
    fn custom_check_all_skip() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysSkipCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.skip_count(), 3);
        assert_eq!(decision.allow_count(), 0);
    }

    #[test]
    fn custom_check_first_deny_recorded() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysDenyCheck { code: "FIRST".into() }),
            Box::new(AlwaysDenyCheck { code: "SECOND".into() }),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert_eq!(decision.checks_executed(), 1);
        if let PipelineOutcome::Deny { reason_code, .. } = &decision.outcome {
            assert_eq!(reason_code, "FIRST");
        }
    }

    // ── EnforcementDecision ──

    #[test]
    fn decision_is_allowed_true() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![],
            elapsed_ms: 0.0,
        };
        assert!(decision.is_allowed());
    }

    #[test]
    fn decision_is_allowed_false() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Deny {
                check_name: "x".into(),
                reason_code: "y".into(),
                explanation: "z".into(),
            },
            checks_run: vec![],
            elapsed_ms: 0.0,
        };
        assert!(!decision.is_allowed());
    }

    #[test]
    fn decision_checks_executed_count() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![
                CheckRecord { name: "a".into(), outcome: CheckOutcome::Allow, elapsed_ms: 0.1 },
                CheckRecord { name: "b".into(), outcome: CheckOutcome::Allow, elapsed_ms: 0.2 },
            ],
            elapsed_ms: 0.3,
        };
        assert_eq!(decision.checks_executed(), 2);
    }

    #[test]
    fn decision_allow_and_skip_counts() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![
                CheckRecord { name: "a".into(), outcome: CheckOutcome::Allow, elapsed_ms: 0.0 },
                CheckRecord {
                    name: "b".into(),
                    outcome: CheckOutcome::Skip { reason: "n/a".into() },
                    elapsed_ms: 0.0,
                },
                CheckRecord { name: "c".into(), outcome: CheckOutcome::Allow, elapsed_ms: 0.0 },
            ],
            elapsed_ms: 0.0,
        };
        assert_eq!(decision.allow_count(), 2);
        assert_eq!(decision.skip_count(), 1);
    }

    #[test]
    fn decision_debug_format() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![],
            elapsed_ms: 1.5,
        };
        let debug = format!("{decision:?}");
        assert!(debug.contains("Allow"));
        assert!(debug.contains("1.5"));
    }

    // ── Context clone and debug ──

    #[test]
    fn context_clone() {
        let ctx = test_context();
        let cloned = ctx.clone();
        assert_eq!(ctx.request_id, cloned.request_id);
        assert_eq!(ctx.connector_id, cloned.connector_id);
        assert_eq!(ctx.operation, cloned.operation);
    }

    #[test]
    fn context_debug() {
        let ctx = test_context();
        let debug = format!("{ctx:?}");
        assert!(debug.contains("EnforcementContext"));
        assert!(debug.contains("req-001"));
    }

    // ── Edge cases ──

    #[test]
    fn zone_membership_check_with_many_zones() {
        let mut ctx = test_context();
        ctx.zone_id = "zone-99".into();
        let mut config = EnforcementConfig::default();
        for i in 0..100 {
            config.add_zone_membership("agent-alpha", &format!("zone-{i}"));
        }
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_many_claims() {
        let mut ctx = test_context();
        ctx.capability_claims = (0..50).map(|i| format!("cap_{i}")).collect();
        ctx.operation = "cap_25".into();
        ctx.manifest_allowed_operations.push("cap_25".into());
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn rate_limit_zero_limit() {
        let mut ctx = test_context();
        ctx.rate_count = Some(0);
        ctx.rate_limit = Some(0);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn taint_approval_empty_critical_flags_config() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        let config = EnforcementConfig::new()
            .with_critical_taint_flags(vec![]);
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        // No critical flags configured, so all taints are non-critical → allow.
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_multiple_connectors_in_zone() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_connector("zone-prod", "github:utility:1.0.0");
        config.add_zone_connector("zone-prod", "slack:utility:1.0.0");
        config.add_zone_connector("zone-prod", "jira:utility:1.0.0");
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn connector_manifest_single_op_match() {
        let mut ctx = test_context();
        ctx.manifest_allowed_operations = vec!["send_message".into()];
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn connector_manifest_single_op_no_match() {
        let mut ctx = test_context();
        ctx.manifest_allowed_operations = vec!["other_op".into()];
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn pipeline_short_circuits_preserves_timing() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.connector_id = String::new();
        let decision = pipeline.evaluate(&ctx);
        // Only ran one check.
        assert_eq!(decision.checks_executed(), 1);
        assert!(decision.checks_run[0].elapsed_ms >= 0.0);
        assert!(decision.elapsed_ms >= 0.0);
    }

    #[test]
    fn check_record_debug() {
        let record = CheckRecord {
            name: "test_check".into(),
            outcome: CheckOutcome::Allow,
            elapsed_ms: 0.42,
        };
        let debug = format!("{record:?}");
        assert!(debug.contains("test_check"));
        assert!(debug.contains("0.42"));
    }

    #[test]
    fn canonical_decode_checks_order_connector_first() {
        // When multiple fields are empty, connector_id is checked first.
        let mut ctx = test_context();
        ctx.connector_id = String::new();
        ctx.operation = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_CONNECTOR_ID");
        }
    }

    #[test]
    fn pipeline_zone_membership_configured_allow_passes_through() {
        let mut config = EnforcementConfig::default();
        config.add_zone_membership("agent-alpha", "zone-prod");
        config.add_zone_connector("zone-prod", "slack:utility:1.0.0");
        config.add_zone_operation("zone-prod", "send_message");
        let pipeline = EnforcementPipeline::with_config(config);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
    }

    #[test]
    fn pipeline_fully_configured_deny_zone_membership() {
        let mut config = EnforcementConfig::default();
        config.add_zone_membership("agent-alpha", "zone-staging");
        let pipeline = EnforcementPipeline::with_config(config);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "zone_membership");
        }
    }

    #[test]
    fn check_names_returns_correct_order() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(RateLimitCheck),
            Box::new(CanonicalDecodeCheck),
        ]);
        let names = pipeline.check_names();
        assert_eq!(names, vec!["rate_limit", "canonical_decode"]);
    }

    #[test]
    fn enforcement_decision_clone() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![
                CheckRecord { name: "a".into(), outcome: CheckOutcome::Allow, elapsed_ms: 0.1 },
            ],
            elapsed_ms: 0.1,
        };
        let cloned = decision.clone();
        assert!(decision.is_allowed());
        assert!(cloned.is_allowed());
        assert_eq!(cloned.checks_executed(), 1);
    }

    #[test]
    fn capability_verify_wildcard_with_other_claims() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["unrelated".into(), "*".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_duplicate_flags() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into(), "pii".into()];
        ctx.approval_scopes = vec!["pii".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── Additional edge-case and boundary tests ──

    // ── Config builder chaining ──

    #[test]
    fn config_builder_chained_all_setters() {
        let config = EnforcementConfig::new()
            .with_checkpoint_max_age_ms(111)
            .with_revocation_max_age_ms(222)
            .with_critical_taint_flags(vec!["secret".into()]);
        assert_eq!(config.checkpoint_max_age_ms, 111);
        assert_eq!(config.revocation_max_age_ms, 222);
        assert_eq!(config.critical_taint_flags, vec!["secret"]);
    }

    #[test]
    fn config_zero_thresholds() {
        let config = EnforcementConfig::new()
            .with_checkpoint_max_age_ms(0)
            .with_revocation_max_age_ms(0);
        assert_eq!(config.checkpoint_max_age_ms, 0);
        assert_eq!(config.revocation_max_age_ms, 0);
    }

    #[test]
    fn config_max_u64_thresholds() {
        let config = EnforcementConfig::new()
            .with_checkpoint_max_age_ms(u64::MAX)
            .with_revocation_max_age_ms(u64::MAX);
        assert_eq!(config.checkpoint_max_age_ms, u64::MAX);
        assert_eq!(config.revocation_max_age_ms, u64::MAX);
    }

    #[test]
    fn config_add_duplicate_zone_membership_is_idempotent() {
        let mut config = EnforcementConfig::new();
        config.add_zone_membership("alice", "zone-a");
        config.add_zone_membership("alice", "zone-a");
        let zones = config.zone_memberships.get("alice").unwrap();
        assert_eq!(zones.len(), 1);
    }

    #[test]
    fn config_add_duplicate_zone_connector_is_idempotent() {
        let mut config = EnforcementConfig::new();
        config.add_zone_connector("zone-a", "slack");
        config.add_zone_connector("zone-a", "slack");
        let connectors = config.zone_allowed_connectors.get("zone-a").unwrap();
        assert_eq!(connectors.len(), 1);
    }

    #[test]
    fn config_add_duplicate_zone_operation_is_idempotent() {
        let mut config = EnforcementConfig::new();
        config.add_zone_operation("zone-a", "read");
        config.add_zone_operation("zone-a", "read");
        let ops = config.zone_allowed_operations.get("zone-a").unwrap();
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn config_default_has_all_four_critical_flags() {
        let config = EnforcementConfig::default();
        assert!(config.critical_taint_flags.contains(&"pii".to_string()));
        assert!(config.critical_taint_flags.contains(&"phi".to_string()));
        assert!(config.critical_taint_flags.contains(&"classified".to_string()));
        assert!(config.critical_taint_flags.contains(&"financial".to_string()));
        assert_eq!(config.critical_taint_flags.len(), 4);
    }

    // ── Builder edge cases ──

    #[test]
    fn builder_empty_build_returns_none() {
        let ctx = EnforcementContextBuilder::new().build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_debug_format() {
        let builder = EnforcementContextBuilder::new().request_id("r1");
        let debug = format!("{builder:?}");
        assert!(debug.contains("EnforcementContextBuilder"));
        assert!(debug.contains("r1"));
    }

    #[test]
    fn builder_empty_strings_still_build() {
        // Builder accepts empty strings — canonical_decode catches them later
        let ctx = EnforcementContextBuilder::new()
            .request_id("")
            .connector_id("")
            .operation("")
            .zone_id("")
            .principal("")
            .build();
        assert!(ctx.is_some());
        let ctx = ctx.unwrap();
        assert!(ctx.request_id.is_empty());
    }

    #[test]
    fn builder_all_optional_fields_set() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .capability_claims(vec!["cap".into()])
            .taint_flags(vec!["pii".into()])
            .approval_scopes(vec!["pii".into()])
            .timestamp_ms(12345)
            .holder_verified(true)
            .checkpoint_age_ms(100)
            .revocation_list_age_ms(200)
            .budget_used(50)
            .budget_limit(500)
            .rate_count(3)
            .rate_limit(10)
            .manifest_allowed_operations(vec!["op1".into()])
            .build()
            .unwrap();
        assert_eq!(ctx.timestamp_ms, 12345);
        assert!(ctx.holder_verified);
        assert_eq!(ctx.checkpoint_age_ms, Some(100));
        assert_eq!(ctx.revocation_list_age_ms, Some(200));
        assert_eq!(ctx.budget_used, Some(50));
        assert_eq!(ctx.budget_limit, Some(500));
        assert_eq!(ctx.rate_count, Some(3));
        assert_eq!(ctx.rate_limit, Some(10));
    }

    // ── CanonicalDecodeCheck ordering ──

    #[test]
    fn canonical_decode_checks_operation_before_zone() {
        let mut ctx = test_context();
        ctx.operation = String::new();
        ctx.zone_id = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_OPERATION");
        }
    }

    #[test]
    fn canonical_decode_checks_zone_before_principal() {
        let mut ctx = test_context();
        ctx.zone_id = String::new();
        ctx.principal = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_ZONE_ID");
        }
    }

    #[test]
    fn canonical_decode_checks_principal_before_request_id() {
        let mut ctx = test_context();
        ctx.principal = String::new();
        ctx.request_id = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_PRINCIPAL");
        }
    }

    #[test]
    fn canonical_decode_deny_whitespace_request_id() {
        let mut ctx = test_context();
        ctx.request_id = " \t ".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_REQUEST_ID");
        }
    }

    // ── CapabilityVerifyCheck edge cases ──

    #[test]
    fn capability_verify_nested_prefix_dot() {
        let mut ctx = test_context();
        ctx.operation = "messages.channels.send".into();
        ctx.capability_claims = vec!["messages.channels".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_nested_prefix_slash() {
        let mut ctx = test_context();
        ctx.operation = "api/v2/list".into();
        ctx.capability_claims = vec!["api/v2".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_no_partial_match_without_separator() {
        // "send" should NOT match "send_extended" (no dot/slash)
        let mut ctx = test_context();
        ctx.operation = "send_extended".into();
        ctx.capability_claims = vec!["send".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn capability_verify_exact_match_with_dots() {
        let mut ctx = test_context();
        ctx.operation = "a.b.c".into();
        ctx.capability_claims = vec!["a.b.c".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_wildcard_alone() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["*".into()];
        ctx.operation = "any.random.operation".into();
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── CheckpointFreshnessCheck boundary ──

    #[test]
    fn checkpoint_freshness_deny_at_max_u64() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(u64::MAX);
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn checkpoint_freshness_allow_zero_threshold() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(0);
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(0);
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn checkpoint_freshness_deny_one_over_zero_threshold() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(1);
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(0);
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    // ── RevocationFreshnessCheck boundary ──

    #[test]
    fn revocation_freshness_deny_at_max_u64() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(u64::MAX);
        let config = EnforcementConfig::default();
        let outcome = RevocationFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn revocation_freshness_allow_zero_threshold() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(0);
        let config = EnforcementConfig::new().with_revocation_max_age_ms(0);
        let outcome = RevocationFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn revocation_freshness_zero_age() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(0);
        let config = EnforcementConfig::default();
        let outcome = RevocationFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── TaintApprovalCheck edge cases ──

    #[test]
    fn taint_approval_deny_classified_without_approval() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["classified".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("classified"));
        }
    }

    #[test]
    fn taint_approval_deny_financial_without_approval() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["financial".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("financial"));
        }
    }

    #[test]
    fn taint_approval_superset_approvals_ok() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        ctx.approval_scopes = vec!["pii".into(), "phi".into(), "classified".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_all_four_defaults_approved() {
        let mut ctx = test_context();
        ctx.taint_flags = vec![
            "pii".into(), "phi".into(), "classified".into(), "financial".into(),
        ];
        ctx.approval_scopes = vec![
            "pii".into(), "phi".into(), "classified".into(), "financial".into(),
        ];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_all_four_defaults_one_missing() {
        let mut ctx = test_context();
        ctx.taint_flags = vec![
            "pii".into(), "phi".into(), "classified".into(), "financial".into(),
        ];
        ctx.approval_scopes = vec!["pii".into(), "phi".into(), "financial".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("classified"));
        }
    }

    // ── PolicyCeilingCheck edge cases ──

    #[test]
    fn policy_ceiling_connector_allowed_operation_denied() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_connector("zone-prod", "slack:utility:1.0.0");
        config.add_zone_operation("zone-prod", "list_channels");
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "OPERATION_NOT_IN_ZONE_POLICY");
        }
    }

    #[test]
    fn policy_ceiling_no_connector_rules_but_operation_rules_deny() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        // No connector rules for zone-prod, but operation rules exist
        config.add_zone_operation("zone-prod", "list_channels");
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "OPERATION_NOT_IN_ZONE_POLICY");
        }
    }

    #[test]
    fn policy_ceiling_rules_for_other_zone_only() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_connector("zone-dev", "slack:utility:1.0.0");
        config.add_zone_operation("zone-dev", "send_message");
        // zone-prod has no rules → allow
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── RateLimitCheck edge cases ──

    #[test]
    fn rate_limit_both_none() {
        let mut ctx = test_context();
        ctx.rate_count = None;
        ctx.rate_limit = None;
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn rate_limit_max_u32_under_limit() {
        let mut ctx = test_context();
        ctx.rate_count = Some(u32::MAX - 1);
        ctx.rate_limit = Some(u32::MAX);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn rate_limit_max_u32_at_limit() {
        let mut ctx = test_context();
        ctx.rate_count = Some(u32::MAX);
        ctx.rate_limit = Some(u32::MAX);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn rate_limit_one_of_one() {
        let mut ctx = test_context();
        ctx.rate_count = Some(1);
        ctx.rate_limit = Some(1);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    // ── ConnectorManifestCheck edge cases ──

    #[test]
    fn connector_manifest_many_ops_last_matches() {
        let mut ctx = test_context();
        let mut ops: Vec<String> = (0..99).map(|i| format!("op_{i}")).collect();
        ops.push("send_message".into());
        ctx.manifest_allowed_operations = ops;
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn connector_manifest_many_ops_none_match() {
        let mut ctx = test_context();
        ctx.manifest_allowed_operations = (0..100).map(|i| format!("op_{i}")).collect();
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    // ── Pipeline integration edge cases ──

    #[test]
    fn pipeline_single_allow_check() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysAllowCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.checks_executed(), 1);
        assert_eq!(decision.allow_count(), 1);
        assert_eq!(decision.skip_count(), 0);
    }

    #[test]
    fn pipeline_single_deny_check() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysDenyCheck { code: "SOLO".into() }),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        assert_eq!(decision.checks_executed(), 1);
        if let PipelineOutcome::Deny { reason_code, .. } = &decision.outcome {
            assert_eq!(reason_code, "SOLO");
        }
    }

    #[test]
    fn pipeline_single_skip_check() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysSkipCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.skip_count(), 1);
        assert_eq!(decision.allow_count(), 0);
    }

    #[test]
    fn pipeline_deny_after_many_skips() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysDenyCheck { code: "LATE".into() }),
            Box::new(AlwaysAllowCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        assert_eq!(decision.checks_executed(), 4);
        assert_eq!(decision.skip_count(), 3);
    }

    #[test]
    fn pipeline_check_names_empty() {
        let pipeline = EnforcementPipeline::with_checks(vec![]);
        assert!(pipeline.check_names().is_empty());
    }

    // ── PipelineOutcome clone ──

    #[test]
    fn pipeline_outcome_clone_allow() {
        let o = PipelineOutcome::Allow;
        let cloned = o.clone();
        assert!(o.is_allow());
        assert!(cloned.is_allow());
    }

    #[test]
    fn pipeline_outcome_clone_deny() {
        let o = PipelineOutcome::Deny {
            check_name: "check".into(),
            reason_code: "code".into(),
            explanation: "detail".into(),
        };
        let cloned = o.clone();
        assert!(o.is_deny());
        assert!(cloned.is_deny());
        if let PipelineOutcome::Deny { check_name, reason_code, explanation } = &cloned {
            assert_eq!(check_name, "check");
            assert_eq!(reason_code, "code");
            assert_eq!(explanation, "detail");
        }
    }

    #[test]
    fn pipeline_outcome_deny_debug_contains_fields() {
        let o = PipelineOutcome::Deny {
            check_name: "mycheck".into(),
            reason_code: "MYCODE".into(),
            explanation: "mydetail".into(),
        };
        let debug = format!("{o:?}");
        assert!(debug.contains("mycheck"));
        assert!(debug.contains("MYCODE"));
        assert!(debug.contains("mydetail"));
    }

    // ── CheckOutcome skip debug ──

    #[test]
    fn check_outcome_skip_debug_contains_reason() {
        let o = CheckOutcome::Skip {
            reason: "not applicable".into(),
        };
        let debug = format!("{o:?}");
        assert!(debug.contains("not applicable"));
    }

    // ── CheckRecord clone ──

    #[test]
    fn check_record_clone() {
        let record = CheckRecord {
            name: "test".into(),
            outcome: CheckOutcome::Allow,
            elapsed_ms: 1.5,
        };
        let cloned = record.clone();
        assert_eq!(record.name, cloned.name);
        assert!(cloned.outcome.is_allow());
        assert!((cloned.elapsed_ms - 1.5).abs() < f64::EPSILON);
    }

    // ── Decision with deny outcome ──

    #[test]
    fn enforcement_decision_clone_deny() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Deny {
                check_name: "x".into(),
                reason_code: "y".into(),
                explanation: "z".into(),
            },
            checks_run: vec![
                CheckRecord {
                    name: "x".into(),
                    outcome: CheckOutcome::Deny {
                        reason_code: "y".into(),
                        explanation: "z".into(),
                    },
                    elapsed_ms: 0.5,
                },
            ],
            elapsed_ms: 0.5,
        };
        let cloned = decision.clone();
        assert!(!decision.is_allowed());
        assert!(!cloned.is_allowed());
        assert_eq!(cloned.checks_executed(), 1);
    }

    #[test]
    fn enforcement_decision_debug_deny() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Deny {
                check_name: "check_abc".into(),
                reason_code: "CODE_XYZ".into(),
                explanation: "details here".into(),
            },
            checks_run: vec![],
            elapsed_ms: 2.0,
        };
        let debug = format!("{decision:?}");
        assert!(debug.contains("check_abc"));
        assert!(debug.contains("CODE_XYZ"));
    }

    // ── Context field verification ──

    #[test]
    fn context_clone_preserves_all_fields() {
        let ctx = test_context();
        let cloned = ctx.clone();
        assert_eq!(ctx.request_id, cloned.request_id);
        assert_eq!(ctx.connector_id, cloned.connector_id);
        assert_eq!(ctx.operation, cloned.operation);
        assert_eq!(ctx.zone_id, cloned.zone_id);
        assert_eq!(ctx.principal, cloned.principal);
        assert_eq!(ctx.capability_claims, cloned.capability_claims);
        assert_eq!(ctx.taint_flags, cloned.taint_flags);
        assert_eq!(ctx.approval_scopes, cloned.approval_scopes);
        assert_eq!(ctx.timestamp_ms, cloned.timestamp_ms);
        assert_eq!(ctx.holder_verified, cloned.holder_verified);
        assert_eq!(ctx.checkpoint_age_ms, cloned.checkpoint_age_ms);
        assert_eq!(ctx.revocation_list_age_ms, cloned.revocation_list_age_ms);
        assert_eq!(ctx.budget_used, cloned.budget_used);
        assert_eq!(ctx.budget_limit, cloned.budget_limit);
        assert_eq!(ctx.rate_count, cloned.rate_count);
        assert_eq!(ctx.rate_limit, cloned.rate_limit);
        assert_eq!(ctx.manifest_allowed_operations, cloned.manifest_allowed_operations);
    }

    // ── Pipeline with fully configured config passes all checks ──

    #[test]
    fn pipeline_fully_configured_all_allow() {
        let mut config = EnforcementConfig::new()
            .with_checkpoint_max_age_ms(100_000)
            .with_revocation_max_age_ms(200_000);
        config.add_zone_membership("agent-alpha", "zone-prod");
        config.add_zone_connector("zone-prod", "slack:utility:1.0.0");
        config.add_zone_operation("zone-prod", "send_message");

        let pipeline = EnforcementPipeline::with_config(config);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.checks_executed(), 9);
        // With zone membership configured, it should be allow not skip
        let zone_check = &decision.checks_run[1];
        assert_eq!(zone_check.name, "zone_membership");
        assert!(zone_check.outcome.is_allow());
    }

    #[test]
    fn pipeline_deny_zone_membership_before_capability() {
        let mut config = EnforcementConfig::default();
        config.add_zone_membership("agent-alpha", "zone-staging");
        let pipeline = EnforcementPipeline::with_config(config);
        let mut ctx = test_context();
        ctx.capability_claims = Vec::new(); // would also fail
        let decision = pipeline.evaluate(&ctx);
        // zone_membership is checked before capability_verify
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "zone_membership");
        }
    }
}
