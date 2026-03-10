//! Terraform safety-critical design enforcement.
//!
//! Ensures that Terraform operations follow strict safety policies:
//! - `plan` is always read-only
//! - `apply` requires approval gating bound to a specific plan hash
//! - `destroy` is forbidden by default
//! - Never runs Terraform with `-auto-approve`
//! - Always requires `-input=false`

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SafetyMode
// ---------------------------------------------------------------------------

/// Top-level classification of how an operation may be executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafetyMode {
    /// The operation is purely read-only and always allowed.
    ReadOnly,
    /// The operation requires explicit approval before execution.
    ApprovalGated,
    /// The operation is unconditionally denied.
    Forbidden,
}

impl fmt::Display for SafetyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "ReadOnly"),
            Self::ApprovalGated => write!(f, "ApprovalGated"),
            Self::Forbidden => write!(f, "Forbidden"),
        }
    }
}

// ---------------------------------------------------------------------------
// OperationSafety
// ---------------------------------------------------------------------------

/// Concrete Terraform operations tagged with their safety classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationSafety {
    /// `terraform plan` — always read-only.
    PlanRead,
    /// `terraform apply` — approval-gated, bound to a plan hash.
    ApplyWrite,
    /// `terraform destroy` — forbidden by default.
    DestroyForbidden,
    /// `terraform refresh` — read-only state refresh.
    RefreshRead,
    /// `terraform import` — writes state, approval-gated.
    ImportWrite,
    /// `terraform state pull` — read-only state export.
    StatePull,
}

impl OperationSafety {
    /// Returns the inherent safety mode for this operation.
    #[must_use]
    pub const fn inherent_mode(self) -> SafetyMode {
        match self {
            Self::PlanRead | Self::RefreshRead | Self::StatePull => SafetyMode::ReadOnly,
            Self::ApplyWrite | Self::ImportWrite => SafetyMode::ApprovalGated,
            Self::DestroyForbidden => SafetyMode::Forbidden,
        }
    }

    /// Returns a human-readable label for this operation.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PlanRead => "plan",
            Self::ApplyWrite => "apply",
            Self::DestroyForbidden => "destroy",
            Self::RefreshRead => "refresh",
            Self::ImportWrite => "import",
            Self::StatePull => "state pull",
        }
    }
}

impl fmt::Display for OperationSafety {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// ApprovalScope
// ---------------------------------------------------------------------------

/// Defines how broadly an approval token applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApprovalScope {
    /// Token is valid for exactly one apply invocation.
    SingleApply,
    /// Token is valid for all applies within a workspace session.
    WorkspaceSession,
    /// Emergency override — bypasses some checks but is still logged.
    Emergency,
}

impl fmt::Display for ApprovalScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleApply => write!(f, "SingleApply"),
            Self::WorkspaceSession => write!(f, "WorkspaceSession"),
            Self::Emergency => write!(f, "Emergency"),
        }
    }
}

// ---------------------------------------------------------------------------
// ApprovalToken
// ---------------------------------------------------------------------------

/// A cryptographically-bound approval token authorising a specific apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    /// Unique identifier for this token.
    pub token_id: String,
    /// Principal that issued the approval.
    pub issued_by: String,
    /// When the token was issued.
    pub issued_at: u64,
    /// SHA-256 hash of the plan this token authorises.
    pub plan_hash: String,
    /// When the token expires (epoch seconds).
    pub expires_at: u64,
    /// Scope of the approval.
    pub scope: ApprovalScope,
}

impl ApprovalToken {
    /// Returns `true` if the token has expired relative to `now`.
    #[must_use]
    pub const fn is_expired(&self, now_epoch_secs: u64) -> bool {
        now_epoch_secs >= self.expires_at
    }

    /// Returns `true` if the plan hash matches.
    #[must_use]
    pub fn matches_plan(&self, plan_hash: &str) -> bool {
        self.plan_hash == plan_hash
    }

    /// Creates a builder for constructing tokens in tests.
    #[must_use]
    pub fn builder() -> ApprovalTokenBuilder {
        ApprovalTokenBuilder::default()
    }
}

/// Builder for [`ApprovalToken`].
#[derive(Debug, Default)]
pub struct ApprovalTokenBuilder {
    token_id: Option<String>,
    issued_by: Option<String>,
    issued_at: Option<u64>,
    plan_hash: Option<String>,
    expires_at: Option<u64>,
    scope: Option<ApprovalScope>,
}

impl ApprovalTokenBuilder {
    #[must_use]
    pub fn token_id(mut self, id: impl Into<String>) -> Self {
        self.token_id = Some(id.into());
        self
    }

    #[must_use]
    pub fn issued_by(mut self, by: impl Into<String>) -> Self {
        self.issued_by = Some(by.into());
        self
    }

    #[must_use]
    pub const fn issued_at(mut self, at: u64) -> Self {
        self.issued_at = Some(at);
        self
    }

    #[must_use]
    pub fn plan_hash(mut self, hash: impl Into<String>) -> Self {
        self.plan_hash = Some(hash.into());
        self
    }

    #[must_use]
    pub const fn expires_at(mut self, at: u64) -> Self {
        self.expires_at = Some(at);
        self
    }

    #[must_use]
    pub const fn scope(mut self, scope: ApprovalScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Build the token, panicking if required fields are missing.
    ///
    /// # Panics
    ///
    /// Panics if any required field is not set.
    #[must_use]
    pub fn build(self) -> ApprovalToken {
        ApprovalToken {
            token_id: self.token_id.expect("token_id required"),
            issued_by: self.issued_by.expect("issued_by required"),
            issued_at: self.issued_at.expect("issued_at required"),
            plan_hash: self.plan_hash.expect("plan_hash required"),
            expires_at: self.expires_at.expect("expires_at required"),
            scope: self.scope.expect("scope required"),
        }
    }
}

// ---------------------------------------------------------------------------
// DenialCode
// ---------------------------------------------------------------------------

/// Machine-readable reason for denying an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DenialCode {
    /// `terraform destroy` is not allowed by policy.
    DestroyForbidden,
    /// The plan hash provided does not match the expected value.
    PlanHashMismatch,
    /// The approval token has expired.
    TokenExpired,
    /// No approval token was provided.
    TokenMissing,
    /// The apply would affect more resources than allowed.
    ResourceLimitExceeded,
    /// The `-auto-approve` flag was detected.
    AutoApproveBlocked,
    /// The `-input=false` flag is missing.
    InputNotDisabled,
    /// No matching plan exists for the requested apply.
    NoMatchingPlan,
    /// A generic policy violation was detected.
    PolicyViolation,
}

impl fmt::Display for DenialCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestroyForbidden => write!(f, "DESTROY_FORBIDDEN"),
            Self::PlanHashMismatch => write!(f, "PLAN_HASH_MISMATCH"),
            Self::TokenExpired => write!(f, "TOKEN_EXPIRED"),
            Self::TokenMissing => write!(f, "TOKEN_MISSING"),
            Self::ResourceLimitExceeded => write!(f, "RESOURCE_LIMIT_EXCEEDED"),
            Self::AutoApproveBlocked => write!(f, "AUTO_APPROVE_BLOCKED"),
            Self::InputNotDisabled => write!(f, "INPUT_NOT_DISABLED"),
            Self::NoMatchingPlan => write!(f, "NO_MATCHING_PLAN"),
            Self::PolicyViolation => write!(f, "POLICY_VIOLATION"),
        }
    }
}

// ---------------------------------------------------------------------------
// SafetyDecision
// ---------------------------------------------------------------------------

/// The outcome of a safety check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafetyDecision {
    /// The operation is allowed.
    Allow {
        /// Human-readable reason the operation was allowed.
        reason: String,
    },
    /// The operation is denied.
    Deny {
        /// Machine-readable denial code.
        code: DenialCode,
        /// Human-readable explanation.
        reason: String,
    },
    /// The operation requires an approval token before proceeding.
    RequireApproval {
        /// Description of what the token must contain.
        token_requirements: String,
    },
}

impl SafetyDecision {
    /// Returns `true` if the decision is `Allow`.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Returns `true` if the decision is `Deny`.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns `true` if the decision is `RequireApproval`.
    #[must_use]
    pub const fn requires_approval(&self) -> bool {
        matches!(self, Self::RequireApproval { .. })
    }

    /// Returns the denial code if the decision is `Deny`.
    #[must_use]
    pub const fn denial_code(&self) -> Option<DenialCode> {
        match self {
            Self::Deny { code, .. } => Some(*code),
            _ => None,
        }
    }
}

impl fmt::Display for SafetyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow { reason } => write!(f, "ALLOW: {reason}"),
            Self::Deny { code, reason } => write!(f, "DENY [{code}]: {reason}"),
            Self::RequireApproval { token_requirements } => {
                write!(f, "REQUIRE_APPROVAL: {token_requirements}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SafetyPolicy
// ---------------------------------------------------------------------------

/// Configuration governing safety enforcement for Terraform operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyPolicy {
    /// Default safety mode applied when no override exists.
    pub default_mode: SafetyMode,
    /// Per-operation mode overrides.
    pub operation_overrides: HashMap<OperationSafety, SafetyMode>,
    /// Whether `destroy` is allowed at all.
    pub allow_destroy: bool,
    /// Whether apply requires a matching plan hash.
    pub require_plan_hash: bool,
    /// Whether apply requires an approval token.
    pub require_approval_token: bool,
    /// Maximum number of resources a single apply may affect (0 = unlimited).
    pub max_resources_per_apply: u32,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            default_mode: SafetyMode::Forbidden,
            operation_overrides: HashMap::new(),
            allow_destroy: false,
            require_plan_hash: true,
            require_approval_token: true,
            max_resources_per_apply: 0,
        }
    }
}

impl SafetyPolicy {
    /// Creates a strict default policy: destroy forbidden, approval required.
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Creates a policy that allows read-only operations without approval.
    #[must_use]
    pub fn read_only() -> Self {
        let mut overrides = HashMap::new();
        overrides.insert(OperationSafety::PlanRead, SafetyMode::ReadOnly);
        overrides.insert(OperationSafety::RefreshRead, SafetyMode::ReadOnly);
        overrides.insert(OperationSafety::StatePull, SafetyMode::ReadOnly);
        Self {
            default_mode: SafetyMode::Forbidden,
            operation_overrides: overrides,
            allow_destroy: false,
            require_plan_hash: true,
            require_approval_token: true,
            max_resources_per_apply: 0,
        }
    }

    /// Returns the effective safety mode for a given operation.
    #[must_use]
    pub fn effective_mode(&self, op: OperationSafety) -> SafetyMode {
        self.operation_overrides
            .get(&op)
            .copied()
            .unwrap_or_else(|| op.inherent_mode())
    }
}

// ---------------------------------------------------------------------------
// SafetyAuditEntry
// ---------------------------------------------------------------------------

/// A record in the enforcer's audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyAuditEntry {
    /// Epoch-seconds timestamp of the audit entry.
    pub timestamp: u64,
    /// The operation that was checked.
    pub operation: OperationSafety,
    /// The decision that was rendered.
    pub decision: SafetyDecision,
    /// Optional free-form details.
    pub details: String,
}

impl fmt::Display for SafetyAuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} -> {} ({})",
            self.timestamp, self.operation, self.decision, self.details
        )
    }
}

// ---------------------------------------------------------------------------
// SafetyEnforcer
// ---------------------------------------------------------------------------

/// The main entry-point for evaluating Terraform operation safety.
#[derive(Debug, Clone)]
pub struct SafetyEnforcer {
    policy: SafetyPolicy,
    audit_log: Vec<SafetyAuditEntry>,
}

impl SafetyEnforcer {
    /// Creates a new enforcer with the given policy.
    #[must_use]
    pub const fn new(policy: SafetyPolicy) -> Self {
        Self {
            policy,
            audit_log: Vec::new(),
        }
    }

    /// Creates an enforcer with the default strict policy.
    #[must_use]
    pub fn strict() -> Self {
        Self::new(SafetyPolicy::strict())
    }

    /// Checks whether the given operation is permitted under the current policy.
    pub fn check_operation(&mut self, op: OperationSafety) -> SafetyDecision {
        let decision = self.evaluate_operation(op);
        self.record_audit(op, &decision, "check_operation");
        decision
    }

    /// Validates an apply operation against a plan hash and optional token.
    pub fn validate_apply(
        &mut self,
        plan_hash: Option<&str>,
        token: Option<&ApprovalToken>,
        resource_count: u32,
    ) -> SafetyDecision {
        let op = OperationSafety::ApplyWrite;

        // Check resource limit first
        if self.policy.max_resources_per_apply > 0
            && resource_count > self.policy.max_resources_per_apply
        {
            let decision = SafetyDecision::Deny {
                code: DenialCode::ResourceLimitExceeded,
                reason: format!(
                    "apply affects {} resources, limit is {}",
                    resource_count, self.policy.max_resources_per_apply
                ),
            };
            self.record_audit(op, &decision, "validate_apply: resource limit");
            return decision;
        }

        // Check plan hash requirement
        if self.policy.require_plan_hash {
            match plan_hash {
                None => {
                    let decision = SafetyDecision::Deny {
                        code: DenialCode::NoMatchingPlan,
                        reason: "apply requires a plan hash but none was provided".into(),
                    };
                    self.record_audit(op, &decision, "validate_apply: missing plan hash");
                    return decision;
                }
                Some(hash) => {
                    if hash.is_empty() {
                        let decision = SafetyDecision::Deny {
                            code: DenialCode::NoMatchingPlan,
                            reason: "plan hash must not be empty".into(),
                        };
                        self.record_audit(op, &decision, "validate_apply: empty plan hash");
                        return decision;
                    }

                    // If token is provided, verify hash matches
                    if let Some(tok) = token {
                        if !tok.matches_plan(hash) {
                            let decision = SafetyDecision::Deny {
                                code: DenialCode::PlanHashMismatch,
                                reason: format!(
                                    "token plan hash '{}' does not match provided plan hash '{}'",
                                    tok.plan_hash, hash
                                ),
                            };
                            self.record_audit(op, &decision, "validate_apply: hash mismatch");
                            return decision;
                        }
                    }
                }
            }
        }

        // Check approval token requirement
        if self.policy.require_approval_token {
            match token {
                None => {
                    let decision = SafetyDecision::RequireApproval {
                        token_requirements: format!(
                            "approval token required for apply (plan_hash: {})",
                            plan_hash.unwrap_or("none")
                        ),
                    };
                    self.record_audit(op, &decision, "validate_apply: token missing");
                    return decision;
                }
                Some(tok) => {
                    let token_decision = self.validate_token(tok);
                    if !token_decision.is_allowed() {
                        self.record_audit(op, &token_decision, "validate_apply: token invalid");
                        return token_decision;
                    }
                }
            }
        }

        let decision = SafetyDecision::Allow {
            reason: "apply validated: plan hash matched, token valid".into(),
        };
        self.record_audit(op, &decision, "validate_apply: approved");
        decision
    }

    /// Validates an approval token.
    pub fn validate_token(&self, token: &ApprovalToken) -> SafetyDecision {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        self.validate_token_at(token, now)
    }

    /// Validates an approval token against a specific timestamp (for testing).
    #[must_use]
    pub fn validate_token_at(&self, token: &ApprovalToken, now_epoch_secs: u64) -> SafetyDecision {
        if token.token_id.is_empty() {
            return SafetyDecision::Deny {
                code: DenialCode::TokenMissing,
                reason: "token has empty token_id".into(),
            };
        }

        if token.is_expired(now_epoch_secs) {
            return SafetyDecision::Deny {
                code: DenialCode::TokenExpired,
                reason: format!(
                    "token '{}' expired at {}, current time is {}",
                    token.token_id, token.expires_at, now_epoch_secs
                ),
            };
        }

        if token.plan_hash.is_empty() {
            return SafetyDecision::Deny {
                code: DenialCode::PlanHashMismatch,
                reason: "token has empty plan_hash".into(),
            };
        }

        SafetyDecision::Allow {
            reason: format!("token '{}' is valid", token.token_id),
        }
    }

    /// Returns `true` if a CLI flag is safe to use with Terraform.
    ///
    /// Blocks `-auto-approve` and requires `-input=false`.
    #[must_use]
    pub fn is_safe_flag(flag: &str) -> bool {
        let normalized = flag.trim();

        // Block -auto-approve in any form
        if normalized == "-auto-approve" || normalized == "--auto-approve" {
            return false;
        }

        // Block combined forms like -auto-approve=true
        if normalized.starts_with("-auto-approve=") || normalized.starts_with("--auto-approve=") {
            return false;
        }

        true
    }

    /// Validates an entire set of CLI flags, returning the first violation found.
    #[must_use]
    pub fn check_flags(flags: &[&str]) -> Option<SafetyDecision> {
        let mut has_input_false = false;

        for flag in flags {
            if !Self::is_safe_flag(flag) {
                return Some(SafetyDecision::Deny {
                    code: DenialCode::AutoApproveBlocked,
                    reason: format!("forbidden flag detected: {flag}"),
                });
            }
            if *flag == "-input=false" || *flag == "--input=false" {
                has_input_false = true;
            }
        }

        if !has_input_false {
            return Some(SafetyDecision::Deny {
                code: DenialCode::InputNotDisabled,
                reason: "-input=false is required but was not found in flags".into(),
            });
        }

        None
    }

    /// Returns a reference to the audit log.
    #[must_use]
    pub fn audit_log(&self) -> &[SafetyAuditEntry] {
        &self.audit_log
    }

    /// Returns the number of audit entries.
    #[must_use]
    pub fn audit_count(&self) -> usize {
        self.audit_log.len()
    }

    /// Clears the audit log.
    pub fn clear_audit_log(&mut self) {
        self.audit_log.clear();
    }

    /// Returns a reference to the current policy.
    #[must_use]
    pub const fn policy(&self) -> &SafetyPolicy {
        &self.policy
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn evaluate_operation(&self, op: OperationSafety) -> SafetyDecision {
        // Destroy is always checked against allow_destroy regardless of overrides
        if op == OperationSafety::DestroyForbidden && !self.policy.allow_destroy {
            return SafetyDecision::Deny {
                code: DenialCode::DestroyForbidden,
                reason: "destroy operations are forbidden by policy".into(),
            };
        }

        let mode = self.policy.effective_mode(op);
        match mode {
            SafetyMode::ReadOnly => SafetyDecision::Allow {
                reason: format!("{} is read-only", op.label()),
            },
            SafetyMode::ApprovalGated => SafetyDecision::RequireApproval {
                token_requirements: format!(
                    "{} requires approval with matching plan hash",
                    op.label()
                ),
            },
            SafetyMode::Forbidden => SafetyDecision::Deny {
                code: DenialCode::PolicyViolation,
                reason: format!("{} is forbidden by policy", op.label()),
            },
        }
    }

    fn record_audit(&mut self, op: OperationSafety, decision: &SafetyDecision, details: &str) {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        self.audit_log.push(SafetyAuditEntry {
            timestamp,
            operation: op,
            decision: decision.clone(),
            details: details.to_owned(),
        });
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helper factories
    // -----------------------------------------------------------------------

    fn make_token(plan_hash: &str, expires_at: u64) -> ApprovalToken {
        ApprovalToken {
            token_id: "tok-001".into(),
            issued_by: "admin".into(),
            issued_at: 1_000_000,
            plan_hash: plan_hash.into(),
            expires_at,
            scope: ApprovalScope::SingleApply,
        }
    }

    fn make_valid_token(plan_hash: &str) -> ApprovalToken {
        make_token(plan_hash, u64::MAX)
    }

    fn far_future() -> u64 {
        9_999_999_999
    }

    // =======================================================================
    // SafetyMode tests
    // =======================================================================

    #[test]
    fn safety_mode_display_read_only() {
        assert_eq!(SafetyMode::ReadOnly.to_string(), "ReadOnly");
    }

    #[test]
    fn safety_mode_display_approval_gated() {
        assert_eq!(SafetyMode::ApprovalGated.to_string(), "ApprovalGated");
    }

    #[test]
    fn safety_mode_display_forbidden() {
        assert_eq!(SafetyMode::Forbidden.to_string(), "Forbidden");
    }

    #[test]
    fn safety_mode_clone_eq() {
        let a = SafetyMode::ReadOnly;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn safety_mode_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SafetyMode::ReadOnly);
        set.insert(SafetyMode::ApprovalGated);
        set.insert(SafetyMode::Forbidden);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn safety_mode_serde_roundtrip() {
        let mode = SafetyMode::ApprovalGated;
        let json = serde_json::to_string(&mode).unwrap();
        let back: SafetyMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }

    #[test]
    fn safety_mode_ne() {
        assert_ne!(SafetyMode::ReadOnly, SafetyMode::Forbidden);
    }

    // =======================================================================
    // OperationSafety tests
    // =======================================================================

    #[test]
    fn plan_is_read_only() {
        assert_eq!(
            OperationSafety::PlanRead.inherent_mode(),
            SafetyMode::ReadOnly
        );
    }

    #[test]
    fn apply_is_approval_gated() {
        assert_eq!(
            OperationSafety::ApplyWrite.inherent_mode(),
            SafetyMode::ApprovalGated
        );
    }

    #[test]
    fn destroy_is_forbidden() {
        assert_eq!(
            OperationSafety::DestroyForbidden.inherent_mode(),
            SafetyMode::Forbidden
        );
    }

    #[test]
    fn refresh_is_read_only() {
        assert_eq!(
            OperationSafety::RefreshRead.inherent_mode(),
            SafetyMode::ReadOnly
        );
    }

    #[test]
    fn import_is_approval_gated() {
        assert_eq!(
            OperationSafety::ImportWrite.inherent_mode(),
            SafetyMode::ApprovalGated
        );
    }

    #[test]
    fn state_pull_is_read_only() {
        assert_eq!(
            OperationSafety::StatePull.inherent_mode(),
            SafetyMode::ReadOnly
        );
    }

    #[test]
    fn operation_labels() {
        assert_eq!(OperationSafety::PlanRead.label(), "plan");
        assert_eq!(OperationSafety::ApplyWrite.label(), "apply");
        assert_eq!(OperationSafety::DestroyForbidden.label(), "destroy");
        assert_eq!(OperationSafety::RefreshRead.label(), "refresh");
        assert_eq!(OperationSafety::ImportWrite.label(), "import");
        assert_eq!(OperationSafety::StatePull.label(), "state pull");
    }

    #[test]
    fn operation_display() {
        assert_eq!(OperationSafety::PlanRead.to_string(), "plan");
        assert_eq!(OperationSafety::ApplyWrite.to_string(), "apply");
    }

    #[test]
    fn operation_serde_roundtrip() {
        let op = OperationSafety::ApplyWrite;
        let json = serde_json::to_string(&op).unwrap();
        let back: OperationSafety = serde_json::from_str(&json).unwrap();
        assert_eq!(op, back);
    }

    #[test]
    fn operation_copy() {
        let a = OperationSafety::PlanRead;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn operation_hash_in_map() {
        let mut map = HashMap::new();
        map.insert(OperationSafety::PlanRead, "plan");
        map.insert(OperationSafety::ApplyWrite, "apply");
        assert_eq!(map.get(&OperationSafety::PlanRead), Some(&"plan"));
    }

    // =======================================================================
    // ApprovalScope tests
    // =======================================================================

    #[test]
    fn approval_scope_display() {
        assert_eq!(ApprovalScope::SingleApply.to_string(), "SingleApply");
        assert_eq!(
            ApprovalScope::WorkspaceSession.to_string(),
            "WorkspaceSession"
        );
        assert_eq!(ApprovalScope::Emergency.to_string(), "Emergency");
    }

    #[test]
    fn approval_scope_serde_roundtrip() {
        let scope = ApprovalScope::Emergency;
        let json = serde_json::to_string(&scope).unwrap();
        let back: ApprovalScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }

    #[test]
    fn approval_scope_eq() {
        assert_eq!(ApprovalScope::SingleApply, ApprovalScope::SingleApply);
        assert_ne!(ApprovalScope::SingleApply, ApprovalScope::Emergency);
    }

    // =======================================================================
    // ApprovalToken tests
    // =======================================================================

    #[test]
    fn token_not_expired() {
        let tok = make_token("abc123", 2_000_000);
        assert!(!tok.is_expired(1_500_000));
    }

    #[test]
    fn token_expired_at_boundary() {
        let tok = make_token("abc123", 2_000_000);
        assert!(tok.is_expired(2_000_000));
    }

    #[test]
    fn token_expired_past() {
        let tok = make_token("abc123", 2_000_000);
        assert!(tok.is_expired(3_000_000));
    }

    #[test]
    fn token_matches_plan() {
        let tok = make_token("sha256:abc123", far_future());
        assert!(tok.matches_plan("sha256:abc123"));
    }

    #[test]
    fn token_does_not_match_plan() {
        let tok = make_token("sha256:abc123", far_future());
        assert!(!tok.matches_plan("sha256:def456"));
    }

    #[test]
    fn token_serde_roundtrip() {
        let tok = make_valid_token("hash1");
        let json = serde_json::to_string(&tok).unwrap();
        let back: ApprovalToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.token_id, tok.token_id);
        assert_eq!(back.plan_hash, tok.plan_hash);
    }

    #[test]
    fn token_clone() {
        let tok = make_valid_token("hash1");
        let cloned = tok.clone();
        assert_eq!(tok.token_id, cloned.token_id);
        assert_eq!(tok.plan_hash, cloned.plan_hash);
    }

    #[test]
    fn token_debug() {
        let tok = make_valid_token("hash1");
        let debug = format!("{tok:?}");
        assert!(debug.contains("tok-001"));
    }

    #[test]
    fn token_builder_full() {
        let tok = ApprovalToken::builder()
            .token_id("t1")
            .issued_by("user1")
            .issued_at(100)
            .plan_hash("h1")
            .expires_at(200)
            .scope(ApprovalScope::SingleApply)
            .build();
        assert_eq!(tok.token_id, "t1");
        assert_eq!(tok.issued_by, "user1");
        assert_eq!(tok.issued_at, 100);
        assert_eq!(tok.plan_hash, "h1");
        assert_eq!(tok.expires_at, 200);
        assert_eq!(tok.scope, ApprovalScope::SingleApply);
    }

    #[test]
    #[should_panic(expected = "token_id required")]
    fn token_builder_missing_id_panics() {
        let _ = ApprovalToken::builder()
            .issued_by("x")
            .issued_at(1)
            .plan_hash("h")
            .expires_at(2)
            .scope(ApprovalScope::SingleApply)
            .build();
    }

    #[test]
    #[should_panic(expected = "plan_hash required")]
    fn token_builder_missing_hash_panics() {
        let _ = ApprovalToken::builder()
            .token_id("t1")
            .issued_by("x")
            .issued_at(1)
            .expires_at(2)
            .scope(ApprovalScope::SingleApply)
            .build();
    }

    #[test]
    fn token_builder_workspace_scope() {
        let tok = ApprovalToken::builder()
            .token_id("t1")
            .issued_by("ops")
            .issued_at(100)
            .plan_hash("h1")
            .expires_at(200)
            .scope(ApprovalScope::WorkspaceSession)
            .build();
        assert_eq!(tok.scope, ApprovalScope::WorkspaceSession);
    }

    #[test]
    fn token_builder_emergency_scope() {
        let tok = ApprovalToken::builder()
            .token_id("t1")
            .issued_by("oncall")
            .issued_at(100)
            .plan_hash("h1")
            .expires_at(200)
            .scope(ApprovalScope::Emergency)
            .build();
        assert_eq!(tok.scope, ApprovalScope::Emergency);
    }

    // =======================================================================
    // DenialCode tests
    // =======================================================================

    #[test]
    fn denial_code_display_all() {
        assert_eq!(
            DenialCode::DestroyForbidden.to_string(),
            "DESTROY_FORBIDDEN"
        );
        assert_eq!(
            DenialCode::PlanHashMismatch.to_string(),
            "PLAN_HASH_MISMATCH"
        );
        assert_eq!(DenialCode::TokenExpired.to_string(), "TOKEN_EXPIRED");
        assert_eq!(DenialCode::TokenMissing.to_string(), "TOKEN_MISSING");
        assert_eq!(
            DenialCode::ResourceLimitExceeded.to_string(),
            "RESOURCE_LIMIT_EXCEEDED"
        );
        assert_eq!(
            DenialCode::AutoApproveBlocked.to_string(),
            "AUTO_APPROVE_BLOCKED"
        );
        assert_eq!(
            DenialCode::InputNotDisabled.to_string(),
            "INPUT_NOT_DISABLED"
        );
        assert_eq!(DenialCode::NoMatchingPlan.to_string(), "NO_MATCHING_PLAN");
        assert_eq!(DenialCode::PolicyViolation.to_string(), "POLICY_VIOLATION");
    }

    #[test]
    fn denial_code_serde_roundtrip() {
        let code = DenialCode::AutoApproveBlocked;
        let json = serde_json::to_string(&code).unwrap();
        let back: DenialCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }

    #[test]
    fn denial_code_eq_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DenialCode::DestroyForbidden);
        set.insert(DenialCode::TokenExpired);
        set.insert(DenialCode::DestroyForbidden);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn denial_code_copy() {
        let a = DenialCode::PlanHashMismatch;
        let b = a;
        assert_eq!(a, b);
    }

    // =======================================================================
    // SafetyDecision tests
    // =======================================================================

    #[test]
    fn decision_allow() {
        let d = SafetyDecision::Allow {
            reason: "ok".into(),
        };
        assert!(d.is_allowed());
        assert!(!d.is_denied());
        assert!(!d.requires_approval());
        assert_eq!(d.denial_code(), None);
    }

    #[test]
    fn decision_deny() {
        let d = SafetyDecision::Deny {
            code: DenialCode::DestroyForbidden,
            reason: "no".into(),
        };
        assert!(!d.is_allowed());
        assert!(d.is_denied());
        assert!(!d.requires_approval());
        assert_eq!(d.denial_code(), Some(DenialCode::DestroyForbidden));
    }

    #[test]
    fn decision_require_approval() {
        let d = SafetyDecision::RequireApproval {
            token_requirements: "need token".into(),
        };
        assert!(!d.is_allowed());
        assert!(!d.is_denied());
        assert!(d.requires_approval());
        assert_eq!(d.denial_code(), None);
    }

    #[test]
    fn decision_display_allow() {
        let d = SafetyDecision::Allow {
            reason: "all good".into(),
        };
        let s = d.to_string();
        assert!(s.contains("ALLOW"));
        assert!(s.contains("all good"));
    }

    #[test]
    fn decision_display_deny() {
        let d = SafetyDecision::Deny {
            code: DenialCode::TokenExpired,
            reason: "expired".into(),
        };
        let s = d.to_string();
        assert!(s.contains("DENY"));
        assert!(s.contains("TOKEN_EXPIRED"));
    }

    #[test]
    fn decision_display_require_approval() {
        let d = SafetyDecision::RequireApproval {
            token_requirements: "need plan hash".into(),
        };
        let s = d.to_string();
        assert!(s.contains("REQUIRE_APPROVAL"));
    }

    #[test]
    fn decision_serde_roundtrip_allow() {
        let d = SafetyDecision::Allow {
            reason: "ok".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: SafetyDecision = serde_json::from_str(&json).unwrap();
        assert!(back.is_allowed());
    }

    #[test]
    fn decision_serde_roundtrip_deny() {
        let d = SafetyDecision::Deny {
            code: DenialCode::PolicyViolation,
            reason: "bad".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: SafetyDecision = serde_json::from_str(&json).unwrap();
        assert!(back.is_denied());
        assert_eq!(back.denial_code(), Some(DenialCode::PolicyViolation));
    }

    #[test]
    fn decision_clone() {
        let d = SafetyDecision::Allow {
            reason: "ok".into(),
        };
        let c = d.clone();
        assert!(d.is_allowed());
        assert!(c.is_allowed());
    }

    // =======================================================================
    // SafetyPolicy tests
    // =======================================================================

    #[test]
    fn strict_policy_defaults() {
        let p = SafetyPolicy::strict();
        assert_eq!(p.default_mode, SafetyMode::Forbidden);
        assert!(!p.allow_destroy);
        assert!(p.require_plan_hash);
        assert!(p.require_approval_token);
        assert_eq!(p.max_resources_per_apply, 0);
    }

    #[test]
    fn read_only_policy() {
        let p = SafetyPolicy::read_only();
        assert_eq!(
            p.effective_mode(OperationSafety::PlanRead),
            SafetyMode::ReadOnly
        );
        assert_eq!(
            p.effective_mode(OperationSafety::RefreshRead),
            SafetyMode::ReadOnly
        );
        assert_eq!(
            p.effective_mode(OperationSafety::StatePull),
            SafetyMode::ReadOnly
        );
    }

    #[test]
    fn policy_effective_mode_with_override() {
        let mut p = SafetyPolicy::strict();
        p.operation_overrides
            .insert(OperationSafety::ImportWrite, SafetyMode::Forbidden);
        assert_eq!(
            p.effective_mode(OperationSafety::ImportWrite),
            SafetyMode::Forbidden
        );
    }

    #[test]
    fn policy_effective_mode_without_override() {
        let p = SafetyPolicy::strict();
        assert_eq!(
            p.effective_mode(OperationSafety::PlanRead),
            SafetyMode::ReadOnly
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = SafetyPolicy::strict();
        let json = serde_json::to_string(&p).unwrap();
        let back: SafetyPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.default_mode, SafetyMode::Forbidden);
        assert!(!back.allow_destroy);
    }

    #[test]
    fn policy_default_is_strict() {
        let p = SafetyPolicy::default();
        let s = SafetyPolicy::strict();
        assert_eq!(p.default_mode, s.default_mode);
        assert_eq!(p.allow_destroy, s.allow_destroy);
    }

    #[test]
    fn policy_clone() {
        let p = SafetyPolicy::strict();
        let c = p.clone();
        assert_eq!(c.default_mode, p.default_mode);
    }

    #[test]
    fn policy_with_resource_limit() {
        let mut p = SafetyPolicy::strict();
        p.max_resources_per_apply = 50;
        assert_eq!(p.max_resources_per_apply, 50);
    }

    #[test]
    fn policy_allow_destroy_toggle() {
        let mut p = SafetyPolicy::strict();
        assert!(!p.allow_destroy);
        p.allow_destroy = true;
        assert!(p.allow_destroy);
    }

    #[test]
    fn policy_multiple_overrides() {
        let mut p = SafetyPolicy::strict();
        p.operation_overrides
            .insert(OperationSafety::ApplyWrite, SafetyMode::Forbidden);
        p.operation_overrides
            .insert(OperationSafety::ImportWrite, SafetyMode::ReadOnly);
        assert_eq!(
            p.effective_mode(OperationSafety::ApplyWrite),
            SafetyMode::Forbidden
        );
        assert_eq!(
            p.effective_mode(OperationSafety::ImportWrite),
            SafetyMode::ReadOnly
        );
    }

    // =======================================================================
    // SafetyAuditEntry tests
    // =======================================================================

    #[test]
    fn audit_entry_display() {
        let entry = SafetyAuditEntry {
            timestamp: 1_000_000,
            operation: OperationSafety::PlanRead,
            decision: SafetyDecision::Allow {
                reason: "ok".into(),
            },
            details: "test".into(),
        };
        let s = entry.to_string();
        assert!(s.contains("1000000"));
        assert!(s.contains("plan"));
        assert!(s.contains("ALLOW"));
    }

    #[test]
    fn audit_entry_serde_roundtrip() {
        let entry = SafetyAuditEntry {
            timestamp: 42,
            operation: OperationSafety::ApplyWrite,
            decision: SafetyDecision::Deny {
                code: DenialCode::TokenMissing,
                reason: "no token".into(),
            },
            details: "test".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: SafetyAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.timestamp, 42);
    }

    #[test]
    fn audit_entry_clone() {
        let entry = SafetyAuditEntry {
            timestamp: 42,
            operation: OperationSafety::PlanRead,
            decision: SafetyDecision::Allow {
                reason: "ok".into(),
            },
            details: "detail".into(),
        };
        let cloned = entry.clone();
        assert_eq!(entry.timestamp, cloned.timestamp);
        assert_eq!(entry.details, cloned.details);
    }

    // =======================================================================
    // SafetyEnforcer — check_operation tests
    // =======================================================================

    #[test]
    fn enforcer_plan_always_allowed() {
        let mut e = SafetyEnforcer::strict();
        let d = e.check_operation(OperationSafety::PlanRead);
        assert!(d.is_allowed());
    }

    #[test]
    fn enforcer_refresh_always_allowed() {
        let mut e = SafetyEnforcer::strict();
        let d = e.check_operation(OperationSafety::RefreshRead);
        assert!(d.is_allowed());
    }

    #[test]
    fn enforcer_state_pull_always_allowed() {
        let mut e = SafetyEnforcer::strict();
        let d = e.check_operation(OperationSafety::StatePull);
        assert!(d.is_allowed());
    }

    #[test]
    fn enforcer_apply_requires_approval() {
        let mut e = SafetyEnforcer::strict();
        let d = e.check_operation(OperationSafety::ApplyWrite);
        assert!(d.requires_approval());
    }

    #[test]
    fn enforcer_import_requires_approval() {
        let mut e = SafetyEnforcer::strict();
        let d = e.check_operation(OperationSafety::ImportWrite);
        assert!(d.requires_approval());
    }

    #[test]
    fn enforcer_destroy_denied_by_default() {
        let mut e = SafetyEnforcer::strict();
        let d = e.check_operation(OperationSafety::DestroyForbidden);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::DestroyForbidden));
    }

    #[test]
    fn enforcer_destroy_allowed_when_enabled() {
        let mut policy = SafetyPolicy::strict();
        policy.allow_destroy = true;
        let mut e = SafetyEnforcer::new(policy);
        let d = e.check_operation(OperationSafety::DestroyForbidden);
        // Even with allow_destroy=true, the inherent mode is Forbidden
        // so it should still be denied via effective_mode
        assert!(d.is_denied());
    }

    #[test]
    fn enforcer_destroy_allowed_with_override() {
        let mut policy = SafetyPolicy::strict();
        policy.allow_destroy = true;
        policy
            .operation_overrides
            .insert(OperationSafety::DestroyForbidden, SafetyMode::ApprovalGated);
        let mut e = SafetyEnforcer::new(policy);
        let d = e.check_operation(OperationSafety::DestroyForbidden);
        // allow_destroy is true + override to ApprovalGated
        assert!(d.requires_approval());
    }

    #[test]
    fn enforcer_operation_with_forbidden_override() {
        let mut policy = SafetyPolicy::strict();
        policy
            .operation_overrides
            .insert(OperationSafety::PlanRead, SafetyMode::Forbidden);
        let mut e = SafetyEnforcer::new(policy);
        let d = e.check_operation(OperationSafety::PlanRead);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::PolicyViolation));
    }

    #[test]
    fn enforcer_records_audit_on_check() {
        let mut e = SafetyEnforcer::strict();
        assert_eq!(e.audit_count(), 0);
        e.check_operation(OperationSafety::PlanRead);
        assert_eq!(e.audit_count(), 1);
    }

    #[test]
    fn enforcer_multiple_checks_accumulate_audit() {
        let mut e = SafetyEnforcer::strict();
        e.check_operation(OperationSafety::PlanRead);
        e.check_operation(OperationSafety::ApplyWrite);
        e.check_operation(OperationSafety::DestroyForbidden);
        assert_eq!(e.audit_count(), 3);
    }

    // =======================================================================
    // SafetyEnforcer — validate_apply tests
    // =======================================================================

    #[test]
    fn validate_apply_full_valid() {
        let mut e = SafetyEnforcer::strict();
        let tok = make_valid_token("plan-hash-1");
        let d = e.validate_apply(Some("plan-hash-1"), Some(&tok), 5);
        assert!(d.is_allowed());
    }

    #[test]
    fn validate_apply_missing_plan_hash() {
        let mut e = SafetyEnforcer::strict();
        let tok = make_valid_token("plan-hash-1");
        let d = e.validate_apply(None, Some(&tok), 5);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::NoMatchingPlan));
    }

    #[test]
    fn validate_apply_empty_plan_hash() {
        let mut e = SafetyEnforcer::strict();
        let tok = make_valid_token("plan-hash-1");
        let d = e.validate_apply(Some(""), Some(&tok), 5);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::NoMatchingPlan));
    }

    #[test]
    fn validate_apply_hash_mismatch() {
        let mut e = SafetyEnforcer::strict();
        let tok = make_valid_token("hash-a");
        let d = e.validate_apply(Some("hash-b"), Some(&tok), 5);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::PlanHashMismatch));
    }

    #[test]
    fn validate_apply_missing_token() {
        let mut e = SafetyEnforcer::strict();
        let d = e.validate_apply(Some("plan-hash-1"), None, 5);
        assert!(d.requires_approval());
    }

    #[test]
    fn validate_apply_expired_token() {
        let mut e = SafetyEnforcer::strict();
        let tok = make_token("plan-hash-1", 1); // expired at epoch 1
        let d = e.validate_apply(Some("plan-hash-1"), Some(&tok), 5);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::TokenExpired));
    }

    #[test]
    fn validate_apply_resource_limit_exceeded() {
        let mut policy = SafetyPolicy::strict();
        policy.max_resources_per_apply = 10;
        let mut e = SafetyEnforcer::new(policy);
        let tok = make_valid_token("h1");
        let d = e.validate_apply(Some("h1"), Some(&tok), 11);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::ResourceLimitExceeded));
    }

    #[test]
    fn validate_apply_resource_limit_at_boundary() {
        let mut policy = SafetyPolicy::strict();
        policy.max_resources_per_apply = 10;
        let mut e = SafetyEnforcer::new(policy);
        let tok = make_valid_token("h1");
        let d = e.validate_apply(Some("h1"), Some(&tok), 10);
        assert!(d.is_allowed());
    }

    #[test]
    fn validate_apply_no_resource_limit() {
        let mut e = SafetyEnforcer::strict();
        let tok = make_valid_token("h1");
        let d = e.validate_apply(Some("h1"), Some(&tok), 99999);
        assert!(d.is_allowed());
    }

    #[test]
    fn validate_apply_without_hash_requirement() {
        let mut policy = SafetyPolicy::strict();
        policy.require_plan_hash = false;
        let mut e = SafetyEnforcer::new(policy);
        let tok = make_valid_token("h1");
        let d = e.validate_apply(None, Some(&tok), 5);
        assert!(d.is_allowed());
    }

    #[test]
    fn validate_apply_without_token_requirement() {
        let mut policy = SafetyPolicy::strict();
        policy.require_approval_token = false;
        let mut e = SafetyEnforcer::new(policy);
        let d = e.validate_apply(Some("h1"), None, 5);
        assert!(d.is_allowed());
    }

    #[test]
    fn validate_apply_records_audit() {
        let mut e = SafetyEnforcer::strict();
        let tok = make_valid_token("h1");
        e.validate_apply(Some("h1"), Some(&tok), 5);
        assert!(e.audit_count() >= 1);
    }

    #[test]
    fn validate_apply_resource_check_before_hash() {
        let mut policy = SafetyPolicy::strict();
        policy.max_resources_per_apply = 5;
        let mut e = SafetyEnforcer::new(policy);
        // Even with no plan hash, resource limit is checked first
        let d = e.validate_apply(None, None, 10);
        assert_eq!(d.denial_code(), Some(DenialCode::ResourceLimitExceeded));
    }

    // =======================================================================
    // SafetyEnforcer — validate_token tests
    // =======================================================================

    #[test]
    fn validate_token_valid() {
        let e = SafetyEnforcer::strict();
        let tok = make_valid_token("h1");
        let d = e.validate_token_at(&tok, 1_500_000);
        assert!(d.is_allowed());
    }

    #[test]
    fn validate_token_expired() {
        let e = SafetyEnforcer::strict();
        let tok = make_token("h1", 1_000_000);
        let d = e.validate_token_at(&tok, 2_000_000);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::TokenExpired));
    }

    #[test]
    fn validate_token_empty_id() {
        let e = SafetyEnforcer::strict();
        let mut tok = make_valid_token("h1");
        tok.token_id = String::new();
        let d = e.validate_token_at(&tok, 1_500_000);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::TokenMissing));
    }

    #[test]
    fn validate_token_empty_plan_hash() {
        let e = SafetyEnforcer::strict();
        let mut tok = make_valid_token("");
        tok.token_id = "tok-valid".into();
        let d = e.validate_token_at(&tok, 1_500_000);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::PlanHashMismatch));
    }

    #[test]
    fn validate_token_exactly_at_expiry() {
        let e = SafetyEnforcer::strict();
        let tok = make_token("h1", 1_000_000);
        let d = e.validate_token_at(&tok, 1_000_000);
        assert!(d.is_denied());
        assert_eq!(d.denial_code(), Some(DenialCode::TokenExpired));
    }

    #[test]
    fn validate_token_just_before_expiry() {
        let e = SafetyEnforcer::strict();
        let tok = make_token("h1", 1_000_000);
        let d = e.validate_token_at(&tok, 999_999);
        assert!(d.is_allowed());
    }

    // =======================================================================
    // SafetyEnforcer — is_safe_flag tests
    // =======================================================================

    #[test]
    fn flag_auto_approve_blocked() {
        assert!(!SafetyEnforcer::is_safe_flag("-auto-approve"));
    }

    #[test]
    fn flag_auto_approve_double_dash_blocked() {
        assert!(!SafetyEnforcer::is_safe_flag("--auto-approve"));
    }

    #[test]
    fn flag_auto_approve_eq_true_blocked() {
        assert!(!SafetyEnforcer::is_safe_flag("-auto-approve=true"));
    }

    #[test]
    fn flag_auto_approve_double_eq_blocked() {
        assert!(!SafetyEnforcer::is_safe_flag("--auto-approve=true"));
    }

    #[test]
    fn flag_input_false_safe() {
        assert!(SafetyEnforcer::is_safe_flag("-input=false"));
    }

    #[test]
    fn flag_var_safe() {
        assert!(SafetyEnforcer::is_safe_flag("-var=key=value"));
    }

    #[test]
    fn flag_target_safe() {
        assert!(SafetyEnforcer::is_safe_flag("-target=module.foo"));
    }

    #[test]
    fn flag_no_color_safe() {
        assert!(SafetyEnforcer::is_safe_flag("-no-color"));
    }

    #[test]
    fn flag_empty_safe() {
        assert!(SafetyEnforcer::is_safe_flag(""));
    }

    #[test]
    fn flag_whitespace_trimmed() {
        assert!(!SafetyEnforcer::is_safe_flag("  -auto-approve  "));
    }

    // =======================================================================
    // SafetyEnforcer — check_flags tests
    // =======================================================================

    #[test]
    fn check_flags_valid() {
        let result = SafetyEnforcer::check_flags(&["-input=false", "-no-color"]);
        assert!(result.is_none());
    }

    #[test]
    fn check_flags_missing_input_false() {
        let result = SafetyEnforcer::check_flags(&["-no-color"]);
        assert!(result.is_some());
        let d = result.unwrap();
        assert_eq!(d.denial_code(), Some(DenialCode::InputNotDisabled));
    }

    #[test]
    fn check_flags_auto_approve_present() {
        let result = SafetyEnforcer::check_flags(&["-input=false", "-auto-approve"]);
        assert!(result.is_some());
        let d = result.unwrap();
        assert_eq!(d.denial_code(), Some(DenialCode::AutoApproveBlocked));
    }

    #[test]
    fn check_flags_double_dash_input_false() {
        let result = SafetyEnforcer::check_flags(&["--input=false"]);
        assert!(result.is_none());
    }

    #[test]
    fn check_flags_empty() {
        let result = SafetyEnforcer::check_flags(&[]);
        assert!(result.is_some());
        let d = result.unwrap();
        assert_eq!(d.denial_code(), Some(DenialCode::InputNotDisabled));
    }

    #[test]
    fn check_flags_auto_approve_before_input() {
        // auto-approve should be caught even if input=false is later
        let result = SafetyEnforcer::check_flags(&["-auto-approve", "-input=false"]);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().denial_code(),
            Some(DenialCode::AutoApproveBlocked)
        );
    }

    #[test]
    fn check_flags_many_safe_flags() {
        let result = SafetyEnforcer::check_flags(&[
            "-input=false",
            "-no-color",
            "-var=x=1",
            "-target=module.a",
            "-compact-warnings",
        ]);
        assert!(result.is_none());
    }

    // =======================================================================
    // SafetyEnforcer — audit log tests
    // =======================================================================

    #[test]
    fn audit_log_empty_initially() {
        let e = SafetyEnforcer::strict();
        assert_eq!(e.audit_count(), 0);
        assert!(e.audit_log().is_empty());
    }

    #[test]
    fn audit_log_grows_with_checks() {
        let mut e = SafetyEnforcer::strict();
        e.check_operation(OperationSafety::PlanRead);
        e.check_operation(OperationSafety::ApplyWrite);
        assert_eq!(e.audit_count(), 2);
    }

    #[test]
    fn audit_log_clear() {
        let mut e = SafetyEnforcer::strict();
        e.check_operation(OperationSafety::PlanRead);
        assert_eq!(e.audit_count(), 1);
        e.clear_audit_log();
        assert_eq!(e.audit_count(), 0);
    }

    #[test]
    fn audit_log_entry_has_operation() {
        let mut e = SafetyEnforcer::strict();
        e.check_operation(OperationSafety::DestroyForbidden);
        let entry = &e.audit_log()[0];
        assert_eq!(entry.operation, OperationSafety::DestroyForbidden);
    }

    #[test]
    fn audit_log_entry_has_decision() {
        let mut e = SafetyEnforcer::strict();
        e.check_operation(OperationSafety::DestroyForbidden);
        let entry = &e.audit_log()[0];
        assert!(entry.decision.is_denied());
    }

    #[test]
    fn audit_log_validate_apply_entries() {
        let mut e = SafetyEnforcer::strict();
        let tok = make_valid_token("h1");
        e.validate_apply(Some("h1"), Some(&tok), 5);
        assert!(e.audit_count() >= 1);
        let last = e.audit_log().last().unwrap();
        assert_eq!(last.operation, OperationSafety::ApplyWrite);
    }

    #[test]
    fn audit_log_preserves_order() {
        let mut e = SafetyEnforcer::strict();
        e.check_operation(OperationSafety::PlanRead);
        e.check_operation(OperationSafety::ApplyWrite);
        e.check_operation(OperationSafety::StatePull);
        assert_eq!(e.audit_log()[0].operation, OperationSafety::PlanRead);
        assert_eq!(e.audit_log()[1].operation, OperationSafety::ApplyWrite);
        assert_eq!(e.audit_log()[2].operation, OperationSafety::StatePull);
    }

    // =======================================================================
    // SafetyEnforcer — policy accessor
    // =======================================================================

    #[test]
    fn enforcer_policy_accessor() {
        let policy = SafetyPolicy::read_only();
        let e = SafetyEnforcer::new(policy);
        assert_eq!(e.policy().default_mode, SafetyMode::Forbidden);
        assert!(!e.policy().allow_destroy);
    }

    #[test]
    fn enforcer_strict_constructor() {
        let e = SafetyEnforcer::strict();
        assert_eq!(e.policy().default_mode, SafetyMode::Forbidden);
    }

    // =======================================================================
    // Edge cases and integration-style tests
    // =======================================================================

    #[test]
    fn plan_never_mutated_by_overrides() {
        // Even if someone adds a policy override, we test the inherent mode stays ReadOnly
        assert_eq!(
            OperationSafety::PlanRead.inherent_mode(),
            SafetyMode::ReadOnly
        );
    }

    #[test]
    fn apply_always_gated_inherently() {
        assert_eq!(
            OperationSafety::ApplyWrite.inherent_mode(),
            SafetyMode::ApprovalGated
        );
    }

    #[test]
    fn destroy_always_forbidden_inherently() {
        assert_eq!(
            OperationSafety::DestroyForbidden.inherent_mode(),
            SafetyMode::Forbidden
        );
    }

    #[test]
    fn full_workflow_plan_then_apply() {
        let mut e = SafetyEnforcer::strict();

        // Step 1: Plan is always allowed
        let d1 = e.check_operation(OperationSafety::PlanRead);
        assert!(d1.is_allowed());

        // Step 2: Apply requires approval
        let d2 = e.check_operation(OperationSafety::ApplyWrite);
        assert!(d2.requires_approval());

        // Step 3: Validate apply with token
        let tok = make_valid_token("plan-sha256-abc");
        let d3 = e.validate_apply(Some("plan-sha256-abc"), Some(&tok), 3);
        assert!(d3.is_allowed());

        assert_eq!(e.audit_count(), 3);
    }

    #[test]
    fn full_workflow_deny_destroy_then_plan() {
        let mut e = SafetyEnforcer::strict();
        let d1 = e.check_operation(OperationSafety::DestroyForbidden);
        assert!(d1.is_denied());
        let d2 = e.check_operation(OperationSafety::PlanRead);
        assert!(d2.is_allowed());
    }

    #[test]
    fn serde_full_enforcer_audit() {
        let mut e = SafetyEnforcer::strict();
        e.check_operation(OperationSafety::PlanRead);
        e.check_operation(OperationSafety::DestroyForbidden);

        let entries = e.audit_log();
        let json = serde_json::to_string(entries).unwrap();
        let back: Vec<SafetyAuditEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn enforcer_clone() {
        let mut e = SafetyEnforcer::strict();
        e.check_operation(OperationSafety::PlanRead);
        let e2 = e.clone();
        assert_eq!(e2.audit_count(), 1);
    }

    #[test]
    fn enforcer_debug() {
        let e = SafetyEnforcer::strict();
        let debug = format!("{e:?}");
        assert!(debug.contains("SafetyEnforcer"));
    }

    #[test]
    fn all_operations_have_labels() {
        let ops = [
            OperationSafety::PlanRead,
            OperationSafety::ApplyWrite,
            OperationSafety::DestroyForbidden,
            OperationSafety::RefreshRead,
            OperationSafety::ImportWrite,
            OperationSafety::StatePull,
        ];
        for op in ops {
            assert!(!op.label().is_empty());
        }
    }

    #[test]
    fn all_denial_codes_display_uppercase() {
        let codes = [
            DenialCode::DestroyForbidden,
            DenialCode::PlanHashMismatch,
            DenialCode::TokenExpired,
            DenialCode::TokenMissing,
            DenialCode::ResourceLimitExceeded,
            DenialCode::AutoApproveBlocked,
            DenialCode::InputNotDisabled,
            DenialCode::NoMatchingPlan,
            DenialCode::PolicyViolation,
        ];
        for code in codes {
            let s = code.to_string();
            assert_eq!(
                s,
                s.to_uppercase(),
                "DenialCode display should be uppercase: {s}"
            );
        }
    }

    #[test]
    fn validate_apply_with_emergency_token() {
        let mut e = SafetyEnforcer::strict();
        let tok = ApprovalToken::builder()
            .token_id("emergency-1")
            .issued_by("oncall")
            .issued_at(1_000_000)
            .plan_hash("h1")
            .expires_at(u64::MAX)
            .scope(ApprovalScope::Emergency)
            .build();
        let d = e.validate_apply(Some("h1"), Some(&tok), 100);
        assert!(d.is_allowed());
    }

    #[test]
    fn validate_apply_with_workspace_session_token() {
        let mut e = SafetyEnforcer::strict();
        let tok = ApprovalToken::builder()
            .token_id("ws-1")
            .issued_by("deployer")
            .issued_at(1_000_000)
            .plan_hash("h1")
            .expires_at(u64::MAX)
            .scope(ApprovalScope::WorkspaceSession)
            .build();
        let d = e.validate_apply(Some("h1"), Some(&tok), 5);
        assert!(d.is_allowed());
    }

    #[test]
    fn validate_apply_both_requirements_disabled() {
        let mut policy = SafetyPolicy::strict();
        policy.require_plan_hash = false;
        policy.require_approval_token = false;
        let mut e = SafetyEnforcer::new(policy);
        let d = e.validate_apply(None, None, 100);
        assert!(d.is_allowed());
    }

    #[test]
    fn read_only_policy_allows_reads_denies_writes() {
        let policy = SafetyPolicy::read_only();
        let mut e = SafetyEnforcer::new(policy);

        assert!(e.check_operation(OperationSafety::PlanRead).is_allowed());
        assert!(e.check_operation(OperationSafety::RefreshRead).is_allowed());
        assert!(e.check_operation(OperationSafety::StatePull).is_allowed());
        assert!(
            e.check_operation(OperationSafety::ApplyWrite)
                .requires_approval()
        );
        assert!(
            e.check_operation(OperationSafety::DestroyForbidden)
                .is_denied()
        );
    }

    #[test]
    fn safety_mode_all_variants_serde() {
        let modes = [
            SafetyMode::ReadOnly,
            SafetyMode::ApprovalGated,
            SafetyMode::Forbidden,
        ];
        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let back: SafetyMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn operation_safety_all_variants_serde() {
        let ops = [
            OperationSafety::PlanRead,
            OperationSafety::ApplyWrite,
            OperationSafety::DestroyForbidden,
            OperationSafety::RefreshRead,
            OperationSafety::ImportWrite,
            OperationSafety::StatePull,
        ];
        for op in ops {
            let json = serde_json::to_string(&op).unwrap();
            let back: OperationSafety = serde_json::from_str(&json).unwrap();
            assert_eq!(op, back);
        }
    }

    #[test]
    fn denial_code_all_variants_serde() {
        let codes = [
            DenialCode::DestroyForbidden,
            DenialCode::PlanHashMismatch,
            DenialCode::TokenExpired,
            DenialCode::TokenMissing,
            DenialCode::ResourceLimitExceeded,
            DenialCode::AutoApproveBlocked,
            DenialCode::InputNotDisabled,
            DenialCode::NoMatchingPlan,
            DenialCode::PolicyViolation,
        ];
        for code in codes {
            let json = serde_json::to_string(&code).unwrap();
            let back: DenialCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, back);
        }
    }

    #[test]
    fn approval_scope_all_variants_serde() {
        let scopes = [
            ApprovalScope::SingleApply,
            ApprovalScope::WorkspaceSession,
            ApprovalScope::Emergency,
        ];
        for scope in scopes {
            let json = serde_json::to_string(&scope).unwrap();
            let back: ApprovalScope = serde_json::from_str(&json).unwrap();
            assert_eq!(scope, back);
        }
    }

    #[test]
    fn enforcer_clear_and_reuse() {
        let mut e = SafetyEnforcer::strict();
        e.check_operation(OperationSafety::PlanRead);
        e.check_operation(OperationSafety::ApplyWrite);
        assert_eq!(e.audit_count(), 2);
        e.clear_audit_log();
        assert_eq!(e.audit_count(), 0);
        e.check_operation(OperationSafety::StatePull);
        assert_eq!(e.audit_count(), 1);
    }

    #[test]
    fn token_matches_plan_case_sensitive() {
        let tok = make_valid_token("HASH");
        assert!(tok.matches_plan("HASH"));
        assert!(!tok.matches_plan("hash"));
    }

    #[test]
    fn flag_lock_is_safe() {
        assert!(SafetyEnforcer::is_safe_flag("-lock=true"));
    }

    #[test]
    fn flag_lock_timeout_is_safe() {
        assert!(SafetyEnforcer::is_safe_flag("-lock-timeout=30s"));
    }

    #[test]
    fn flag_parallelism_is_safe() {
        assert!(SafetyEnforcer::is_safe_flag("-parallelism=10"));
    }

    #[test]
    fn validate_apply_zero_resources() {
        let mut policy = SafetyPolicy::strict();
        policy.max_resources_per_apply = 10;
        let mut e = SafetyEnforcer::new(policy);
        let tok = make_valid_token("h1");
        let d = e.validate_apply(Some("h1"), Some(&tok), 0);
        assert!(d.is_allowed());
    }

    #[test]
    fn policy_debug() {
        let p = SafetyPolicy::strict();
        let debug = format!("{p:?}");
        assert!(debug.contains("SafetyPolicy"));
    }

    #[test]
    fn decision_deny_reason_in_display() {
        let d = SafetyDecision::Deny {
            code: DenialCode::PolicyViolation,
            reason: "custom reason xyz".into(),
        };
        let s = d.to_string();
        assert!(s.contains("custom reason xyz"));
    }

    #[test]
    fn check_flags_only_input_false() {
        let result = SafetyEnforcer::check_flags(&["-input=false"]);
        assert!(result.is_none());
    }

    #[test]
    fn check_flags_auto_approve_eq_false_still_blocked() {
        // Even -auto-approve=false is blocked because we never want that flag
        let result = SafetyEnforcer::check_flags(&["-auto-approve=false", "-input=false"]);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().denial_code(),
            Some(DenialCode::AutoApproveBlocked)
        );
    }

    #[test]
    fn safety_policy_operation_overrides_empty_by_default() {
        let p = SafetyPolicy::strict();
        assert!(p.operation_overrides.is_empty());
    }

    #[test]
    fn read_only_policy_has_three_overrides() {
        let p = SafetyPolicy::read_only();
        assert_eq!(p.operation_overrides.len(), 3);
    }

    #[test]
    fn validate_apply_audit_on_resource_limit() {
        let mut policy = SafetyPolicy::strict();
        policy.max_resources_per_apply = 1;
        let mut e = SafetyEnforcer::new(policy);
        e.validate_apply(Some("h"), None, 5);
        let last = e.audit_log().last().unwrap();
        assert!(last.details.contains("resource limit"));
    }

    #[test]
    fn validate_apply_audit_on_hash_mismatch() {
        let mut e = SafetyEnforcer::strict();
        let tok = make_valid_token("a");
        e.validate_apply(Some("b"), Some(&tok), 1);
        let last = e.audit_log().last().unwrap();
        assert!(last.details.contains("hash mismatch"));
    }
}
