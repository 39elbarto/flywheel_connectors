//! Access-planning command family for `fwc access`.
//!
//! Implements read-only access checks, planning, and side-effecting grant
//! requests with bundle management.  All output uses TOON formatting via
//! `Vec<String>` line collections.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Severity ─────────────────────────────────────────────────────────

/// Severity level for access blockers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    /// Informational — does not block access.
    Info,
    /// Warning — access allowed but flagged.
    Warning,
    /// Error — access denied until resolved.
    Error,
    /// Critical — requires immediate remediation.
    Critical,
}

impl BlockerSeverity {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    #[must_use]
    pub const fn icon(self) -> &'static str {
        match self {
            Self::Info => "i",
            Self::Warning => "!",
            Self::Error => "X",
            Self::Critical => "!!",
        }
    }

    /// Whether this severity blocks access.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Error | Self::Critical)
    }
}

impl fmt::Display for BlockerSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── BundleStatus ─────────────────────────────────────────────────────

/// Status of an access bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    /// Bundle is pending approval.
    Pending,
    /// Bundle is active (all grants approved).
    Active,
    /// Bundle has been revoked.
    Revoked,
    /// Bundle has expired.
    Expired,
    /// Bundle was denied.
    Denied,
    /// Bundle is partially approved (some grants active).
    Partial,
}

impl BundleStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Denied => "denied",
            Self::Partial => "partial",
        }
    }

    /// Whether grants in this bundle can be used.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Active | Self::Partial)
    }

    /// Whether this is a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::Expired | Self::Denied)
    }
}

impl fmt::Display for BundleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── GrantScope ───────────────────────────────────────────────────────

/// Scope of an access grant.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    /// Single operation on a single connector.
    Operation,
    /// All operations on a connector.
    Connector,
    /// All connectors in a zone.
    Zone,
    /// Mesh-wide grant.
    Global,
}

impl GrantScope {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Connector => "connector",
            Self::Zone => "zone",
            Self::Global => "global",
        }
    }
}

impl fmt::Display for GrantScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── AuditAction ──────────────────────────────────────────────────────

/// Action recorded in the audit trail.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Access was checked.
    Check,
    /// Access was requested.
    Request,
    /// Access was granted.
    Grant,
    /// Access was denied.
    Deny,
    /// Access was revoked.
    Revoke,
    /// Bundle was attached.
    Attach,
    /// Session was resumed.
    Resume,
    /// Grant expired naturally.
    Expire,
}

impl AuditAction {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Request => "request",
            Self::Grant => "grant",
            Self::Deny => "deny",
            Self::Revoke => "revoke",
            Self::Attach => "attach",
            Self::Resume => "resume",
            Self::Expire => "expire",
        }
    }
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Args types ───────────────────────────────────────────────────────

/// Arguments for `fwc access check`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessCheckArgs {
    /// Target connector identifier.
    pub connector: String,
    /// Target operation name.
    pub operation: String,
    /// Optional zone constraint.
    pub zone: Option<String>,
    /// Optional additional context key-value pairs.
    pub context: BTreeMap<String, String>,
}

impl AccessCheckArgs {
    pub fn new(connector: impl Into<String>, operation: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            operation: operation.into(),
            zone: None,
            context: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_zone(mut self, zone: impl Into<String>) -> Self {
        self.zone = Some(zone.into());
        self
    }

    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Validate arguments, returning errors if invalid.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.connector.is_empty() {
            errors.push("connector must not be empty".into());
        }
        if self.operation.is_empty() {
            errors.push("operation must not be empty".into());
        }
        if let Some(z) = &self.zone {
            if z.is_empty() {
                errors.push("zone must not be empty when specified".into());
            }
        }
        errors
    }
}

/// Arguments for `fwc access plan`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPlanArgs {
    /// Target connector identifier.
    pub connector: String,
    /// Target operation name.
    pub operation: String,
    /// Optional additional context key-value pairs.
    pub context: BTreeMap<String, String>,
    /// Whether to run in dry-run mode (no side effects).
    pub dry_run: bool,
}

impl AccessPlanArgs {
    pub fn new(connector: impl Into<String>, operation: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            operation: operation.into(),
            context: BTreeMap::new(),
            dry_run: false,
        }
    }

    #[must_use]
    pub const fn with_dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.connector.is_empty() {
            errors.push("connector must not be empty".into());
        }
        if self.operation.is_empty() {
            errors.push("operation must not be empty".into());
        }
        errors
    }
}

/// Arguments for `fwc access request`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessRequestArgs {
    /// Target connector identifier.
    pub connector: String,
    /// Target operation name.
    pub operation: String,
    /// Human-readable justification for the access request.
    pub justification: String,
}

impl AccessRequestArgs {
    pub fn new(
        connector: impl Into<String>,
        operation: impl Into<String>,
        justification: impl Into<String>,
    ) -> Self {
        Self {
            connector: connector.into(),
            operation: operation.into(),
            justification: justification.into(),
        }
    }

    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.connector.is_empty() {
            errors.push("connector must not be empty".into());
        }
        if self.operation.is_empty() {
            errors.push("operation must not be empty".into());
        }
        if self.justification.trim().is_empty() {
            errors.push("justification must not be empty".into());
        }
        errors
    }
}

/// Arguments for `fwc access attach`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessAttachArgs {
    /// A bundle handle or approval handle to attach.
    pub handle: String,
}

impl AccessAttachArgs {
    pub fn new(handle: impl Into<String>) -> Self {
        Self {
            handle: handle.into(),
        }
    }

    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.handle.is_empty() {
            errors.push("handle must not be empty".into());
        }
        if !is_valid_handle(&self.handle) {
            errors.push(format!("invalid handle format: {}", self.handle));
        }
        errors
    }
}

/// Arguments for `fwc access resume`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessResumeArgs {
    /// The resume handle from a previous session.
    pub handle: String,
}

impl AccessResumeArgs {
    pub fn new(handle: impl Into<String>) -> Self {
        Self {
            handle: handle.into(),
        }
    }

    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.handle.is_empty() {
            errors.push("handle must not be empty".into());
        }
        if !is_valid_handle(&self.handle) {
            errors.push(format!("invalid handle format: {}", self.handle));
        }
        errors
    }
}

/// Arguments for `fwc access inspect`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessInspectArgs {
    /// Target connector identifier.
    pub connector: String,
    /// Target operation name (optional — inspect all if absent).
    pub operation: Option<String>,
    /// Whether to include verbose detail (audit trail, grant metadata).
    pub verbose: bool,
}

impl AccessInspectArgs {
    pub fn new(connector: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            operation: None,
            verbose: false,
        }
    }

    #[must_use]
    pub fn with_operation(mut self, op: impl Into<String>) -> Self {
        self.operation = Some(op.into());
        self
    }

    #[must_use]
    pub const fn with_verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.connector.is_empty() {
            errors.push("connector must not be empty".into());
        }
        if let Some(op) = &self.operation {
            if op.is_empty() {
                errors.push("operation must not be empty when specified".into());
            }
        }
        errors
    }
}

// ── Result types ─────────────────────────────────────────────────────

/// A single blocker preventing or warning about access.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessBlocker {
    /// Machine-readable blocker code (e.g., `"missing_credential"`).
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// How severe this blocker is.
    pub severity: BlockerSeverity,
    /// Optional remediation hint.
    pub remediation: Option<String>,
}

impl AccessBlocker {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        severity: BlockerSeverity,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            severity,
            remediation: None,
        }
    }

    #[must_use]
    pub fn with_remediation(mut self, hint: impl Into<String>) -> Self {
        self.remediation = Some(hint.into());
        self
    }

    /// Whether this blocker actually prevents access.
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        self.severity.is_blocking()
    }
}

/// Result of an access check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessCheckResult {
    /// Whether access is allowed.
    pub allowed: bool,
    /// Any blockers or warnings found.
    pub blockers: Vec<AccessBlocker>,
    /// Diff of grants that would change if access were granted.
    pub grant_diff: Option<serde_json::Value>,
    /// Connector that was checked.
    pub connector: String,
    /// Operation that was checked.
    pub operation: String,
    /// When the check was performed.
    pub checked_at: DateTime<Utc>,
}

impl AccessCheckResult {
    /// Create an "allowed" result with no blockers.
    pub fn allowed(connector: impl Into<String>, operation: impl Into<String>) -> Self {
        Self {
            allowed: true,
            blockers: Vec::new(),
            grant_diff: None,
            connector: connector.into(),
            operation: operation.into(),
            checked_at: Utc::now(),
        }
    }

    /// Create a "blocked" result with the given blockers.
    pub fn blocked(
        connector: impl Into<String>,
        operation: impl Into<String>,
        blockers: Vec<AccessBlocker>,
    ) -> Self {
        Self {
            allowed: false,
            blockers,
            grant_diff: None,
            connector: connector.into(),
            operation: operation.into(),
            checked_at: Utc::now(),
        }
    }

    /// Number of blocking issues (error or critical severity).
    #[must_use]
    pub fn blocking_count(&self) -> usize {
        self.blockers.iter().filter(|b| b.is_blocking()).count()
    }

    /// Number of warnings (non-blocking).
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.blockers.iter().filter(|b| !b.is_blocking()).count()
    }

    /// Whether the result has any blockers at all.
    #[must_use]
    pub fn has_blockers(&self) -> bool {
        !self.blockers.is_empty()
    }
}

/// A single step in an access plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPlanStep {
    /// Human-readable action description.
    pub action: String,
    /// Target resource for this step.
    pub target: String,
    /// Whether this step requires manual approval.
    pub requires_approval: bool,
    /// Side effects this step may cause.
    pub side_effects: Vec<String>,
    /// Step ordering index (0-based).
    pub index: usize,
}

impl AccessPlanStep {
    pub fn new(action: impl Into<String>, target: impl Into<String>, index: usize) -> Self {
        Self {
            action: action.into(),
            target: target.into(),
            requires_approval: false,
            side_effects: Vec::new(),
            index,
        }
    }

    #[must_use]
    pub const fn with_approval(mut self) -> Self {
        self.requires_approval = true;
        self
    }

    #[must_use]
    pub fn with_side_effect(mut self, effect: impl Into<String>) -> Self {
        self.side_effects.push(effect.into());
        self
    }

    /// Whether this step has side effects.
    #[must_use]
    pub fn has_side_effects(&self) -> bool {
        !self.side_effects.is_empty()
    }
}

/// An access plan with ordered steps and metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPlan {
    /// Ordered steps to achieve access.
    pub steps: Vec<AccessPlanStep>,
    /// Estimated total duration.
    pub estimated_duration: Option<Duration>,
    /// Prerequisites that must be satisfied before the plan can execute.
    pub prerequisites: Vec<String>,
    /// Connector this plan is for.
    pub connector: String,
    /// Operation this plan is for.
    pub operation: String,
    /// Whether this is a dry-run plan.
    pub dry_run: bool,
}

impl AccessPlan {
    pub fn new(connector: impl Into<String>, operation: impl Into<String>) -> Self {
        Self {
            steps: Vec::new(),
            estimated_duration: None,
            prerequisites: Vec::new(),
            connector: connector.into(),
            operation: operation.into(),
            dry_run: false,
        }
    }

    #[must_use]
    pub fn with_step(mut self, step: AccessPlanStep) -> Self {
        self.steps.push(step);
        self
    }

    #[must_use]
    pub const fn with_estimated_duration(mut self, d: Duration) -> Self {
        self.estimated_duration = Some(d);
        self
    }

    #[must_use]
    pub fn with_prerequisite(mut self, prereq: impl Into<String>) -> Self {
        self.prerequisites.push(prereq.into());
        self
    }

    #[must_use]
    pub const fn with_dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Total number of steps.
    #[must_use]
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Number of steps requiring approval.
    #[must_use]
    pub fn approval_steps(&self) -> usize {
        self.steps.iter().filter(|s| s.requires_approval).count()
    }

    /// Whether the plan has unmet prerequisites.
    #[must_use]
    pub fn has_prerequisites(&self) -> bool {
        !self.prerequisites.is_empty()
    }

    /// Whether any step has side effects.
    pub fn has_side_effects(&self) -> bool {
        self.steps.iter().any(AccessPlanStep::has_side_effects)
    }

    /// Validate step ordering — indices must be sequential from 0.
    #[must_use]
    pub fn validate_step_order(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (i, step) in self.steps.iter().enumerate() {
            if step.index != i {
                errors.push(format!("step {i} has index {} (expected {i})", step.index));
            }
        }
        errors
    }
}

/// An individual access grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessGrant {
    /// Unique grant handle.
    pub handle: String,
    /// Connector the grant applies to.
    pub connector: String,
    /// Operation the grant applies to.
    pub operation: String,
    /// Scope of the grant.
    pub scope: GrantScope,
    /// When the grant expires.
    pub expires_at: DateTime<Utc>,
    /// Whether the grant can be revoked before expiry.
    pub revocable: bool,
}

impl AccessGrant {
    pub fn new(
        handle: impl Into<String>,
        connector: impl Into<String>,
        operation: impl Into<String>,
        scope: GrantScope,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            handle: handle.into(),
            connector: connector.into(),
            operation: operation.into(),
            scope,
            expires_at,
            revocable: true,
        }
    }

    #[must_use]
    pub const fn non_revocable(mut self) -> Self {
        self.revocable = false;
        self
    }

    /// Whether the grant has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Whether the grant is still active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.is_expired()
    }

    /// Remaining time until expiry. Returns zero if expired.
    #[must_use]
    pub fn remaining(&self) -> chrono::Duration {
        let now = Utc::now();
        if now >= self.expires_at {
            chrono::Duration::zero()
        } else {
            self.expires_at - now
        }
    }

    /// Human-readable remaining time.
    #[must_use]
    pub fn remaining_display(&self) -> String {
        let remaining = self.remaining();
        if remaining.is_zero() {
            return "expired".to_string();
        }
        let total_secs = remaining.num_seconds();
        if total_secs < 60 {
            format!("{total_secs}s")
        } else if total_secs < 3600 {
            format!("{}m {}s", total_secs / 60, total_secs % 60)
        } else {
            format!("{}h {}m", total_secs / 3600, (total_secs % 3600) / 60)
        }
    }
}

/// A bundle of related access grants.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessBundle {
    /// Unique bundle handle.
    pub handle: String,
    /// Grants in this bundle.
    pub grants: Vec<AccessGrant>,
    /// Current status.
    pub status: BundleStatus,
    /// Receipt or confirmation token.
    pub receipt: Option<String>,
    /// When the bundle was created.
    pub created_at: DateTime<Utc>,
    /// Justification provided at request time.
    pub justification: Option<String>,
}

impl AccessBundle {
    pub fn new(handle: impl Into<String>) -> Self {
        Self {
            handle: handle.into(),
            grants: Vec::new(),
            status: BundleStatus::Pending,
            receipt: None,
            created_at: Utc::now(),
            justification: None,
        }
    }

    #[must_use]
    pub fn with_grant(mut self, grant: AccessGrant) -> Self {
        self.grants.push(grant);
        self
    }

    #[must_use]
    pub const fn with_status(mut self, status: BundleStatus) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub fn with_receipt(mut self, receipt: impl Into<String>) -> Self {
        self.receipt = Some(receipt.into());
        self
    }

    #[must_use]
    pub fn with_justification(mut self, j: impl Into<String>) -> Self {
        self.justification = Some(j.into());
        self
    }

    /// Number of grants in the bundle.
    #[must_use]
    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    /// Number of active (non-expired) grants.
    #[must_use]
    pub fn active_grant_count(&self) -> usize {
        self.grants.iter().filter(|g| g.is_active()).count()
    }

    /// Whether the bundle is usable (active or partial).
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.status.is_usable()
    }

    /// Whether the bundle is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    /// Activate the bundle.
    pub const fn activate(&mut self) {
        self.status = BundleStatus::Active;
    }

    /// Revoke the bundle.
    pub const fn revoke(&mut self) {
        self.status = BundleStatus::Revoked;
    }

    /// Mark the bundle as expired.
    pub const fn expire(&mut self) {
        self.status = BundleStatus::Expired;
    }

    /// Mark the bundle as denied.
    pub const fn deny(&mut self) {
        self.status = BundleStatus::Denied;
    }

    /// Abandon the bundle (agent-initiated withdrawal).
    ///
    /// Sets the bundle to Denied status, effectively withdrawing the
    /// request before approval.  Only valid from Pending state.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundle is not pending.
    pub fn abandon(&mut self) -> Result<(), &'static str> {
        if self.status != BundleStatus::Pending {
            return Err("can only abandon a pending bundle");
        }
        self.status = BundleStatus::Denied;
        Ok(())
    }

    /// Check whether this bundle's context is stale.
    ///
    /// A bundle is stale when it was created too long ago (beyond the
    /// given max age) and is still pending.
    #[must_use]
    pub fn is_stale_context(&self, max_age: chrono::Duration) -> bool {
        self.status == BundleStatus::Pending
            && Utc::now().signed_duration_since(self.created_at) > max_age
    }

    /// Check whether a resume attempt is valid.
    ///
    /// Returns an error string if the bundle cannot be resumed.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundle is not active or partial.
    pub fn validate_resume(&self) -> Result<(), String> {
        match self.status {
            BundleStatus::Active | BundleStatus::Partial => Ok(()),
            BundleStatus::Pending => Err("bundle is still pending approval".into()),
            BundleStatus::Revoked => Err("bundle has been revoked — request a new one".into()),
            BundleStatus::Expired => Err("bundle has expired — request a new one".into()),
            BundleStatus::Denied => {
                Err("bundle was denied — request a new one with updated justification".into())
            }
        }
    }
}

/// An audit trail entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When the action occurred.
    pub timestamp: DateTime<Utc>,
    /// What action was taken.
    pub action: AuditAction,
    /// Who performed the action.
    pub actor: String,
    /// Target of the action.
    pub target: String,
    /// Additional details.
    pub details: Option<String>,
}

impl AuditEntry {
    pub fn new(action: AuditAction, actor: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            action,
            actor: actor.into(),
            target: target.into(),
            details: None,
        }
    }

    #[must_use]
    pub fn with_details(mut self, d: impl Into<String>) -> Self {
        self.details = Some(d.into());
        self
    }
}

/// An active session summary for inspection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveSession {
    /// Session identifier.
    pub session_id: String,
    /// Bundle handle this session uses.
    pub bundle_handle: String,
    /// When the session started.
    pub started_at: DateTime<Utc>,
    /// Last activity time.
    pub last_activity: DateTime<Utc>,
}

impl ActiveSession {
    pub fn new(session_id: impl Into<String>, bundle_handle: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            session_id: session_id.into(),
            bundle_handle: bundle_handle.into(),
            started_at: now,
            last_activity: now,
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }
}

/// Result of `fwc access inspect`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessInspection {
    /// Active grants.
    pub grants: Vec<AccessGrant>,
    /// Active sessions.
    pub active_sessions: Vec<ActiveSession>,
    /// Audit trail entries.
    pub audit_trail: Vec<AuditEntry>,
    /// Connector inspected.
    pub connector: String,
    /// Operation inspected (if scoped).
    pub operation: Option<String>,
}

impl AccessInspection {
    pub fn new(connector: impl Into<String>) -> Self {
        Self {
            grants: Vec::new(),
            active_sessions: Vec::new(),
            audit_trail: Vec::new(),
            connector: connector.into(),
            operation: None,
        }
    }

    #[must_use]
    pub fn with_operation(mut self, op: impl Into<String>) -> Self {
        self.operation = Some(op.into());
        self
    }

    #[must_use]
    pub fn with_grant(mut self, g: AccessGrant) -> Self {
        self.grants.push(g);
        self
    }

    #[must_use]
    pub fn with_session(mut self, s: ActiveSession) -> Self {
        self.active_sessions.push(s);
        self
    }

    #[must_use]
    pub fn with_audit_entry(mut self, e: AuditEntry) -> Self {
        self.audit_trail.push(e);
        self
    }

    /// Number of active grants.
    #[must_use]
    pub fn active_grant_count(&self) -> usize {
        self.grants.iter().filter(|g| g.is_active()).count()
    }

    /// Total audit entries.
    #[must_use]
    pub fn audit_count(&self) -> usize {
        self.audit_trail.len()
    }

    /// Whether there are any active sessions.
    #[must_use]
    pub fn has_active_sessions(&self) -> bool {
        !self.active_sessions.is_empty()
    }

    /// Whether there are any grants.
    #[must_use]
    pub fn has_grants(&self) -> bool {
        !self.grants.is_empty()
    }
}

// ── Handle validation ────────────────────────────────────────────────

/// Valid handle format: non-empty, ASCII alphanumeric plus `_`, `-`, `.`.
#[must_use]
pub fn is_valid_handle(handle: &str) -> bool {
    if handle.is_empty() {
        return false;
    }
    handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
}

/// Generate a deterministic handle from components.
#[must_use]
pub fn generate_handle(prefix: &str, connector: &str, operation: &str) -> String {
    let hash_input = format!(
        "{prefix}:{connector}:{operation}:{}",
        Utc::now().timestamp_millis()
    );
    let hash = blake3::hash(hash_input.as_bytes());
    let short = &hash.to_hex()[..12];
    format!("{prefix}-{short}")
}

/// File-backed access-bundle store.
pub struct AccessBundleStore {
    dir: PathBuf,
}

impl AccessBundleStore {
    /// Create a store at the default location.
    #[must_use]
    pub fn default_path() -> Self {
        if let Ok(dir) = std::env::var("FWC_ACCESS_BUNDLE_DIR")
            && !dir.trim().is_empty()
        {
            return Self {
                dir: PathBuf::from(dir),
            };
        }

        if let Some(override_dir) = std::env::var_os("FWC_STATE_DIR") {
            return Self {
                dir: PathBuf::from(override_dir).join("access").join("bundles"),
            };
        }

        #[cfg(test)]
        if let Some(tmpdir) = std::env::var_os("CARGO_TARGET_TMPDIR") {
            return Self {
                dir: PathBuf::from(tmpdir)
                    .join(format!("fwc-access-bundles-{}", std::process::id())),
            };
        }

        if let Some(state_home) = std::env::var_os("XDG_STATE_HOME") {
            return Self {
                dir: PathBuf::from(state_home)
                    .join("fwc")
                    .join("access")
                    .join("bundles"),
            };
        }

        if let Some(home) = std::env::var_os("HOME") {
            return Self {
                dir: PathBuf::from(home)
                    .join(".local")
                    .join("state")
                    .join("fwc")
                    .join("access")
                    .join("bundles"),
            };
        }

        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self {
            dir: cwd.join(".fwc-state").join("access").join("bundles"),
        }
    }

    /// Create a store at a custom path.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Save a bundle to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle directory cannot be created, the bundle
    /// cannot be serialized, or the bundle file cannot be written.
    pub fn save(&self, bundle: &AccessBundle) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|err| {
            format!(
                "failed to create access bundle store '{}': {err}",
                self.dir.display()
            )
        })?;
        let path = self.bundle_path(&bundle.handle);
        let json = serde_json::to_string_pretty(bundle).map_err(|err| {
            format!(
                "failed to serialize access bundle '{}': {err}",
                bundle.handle
            )
        })?;
        std::fs::write(&path, json).map_err(|err| {
            format!(
                "failed to write access bundle '{}' to '{}': {err}",
                bundle.handle,
                path.display()
            )
        })?;
        Ok(())
    }

    /// Load a bundle by handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle file cannot be read, cannot be parsed, or
    /// contains a handle that does not match the requested handle.
    pub fn load(&self, handle: &str) -> Result<Option<AccessBundle>, String> {
        let path = self.bundle_path(handle);
        if !path.exists() {
            return Ok(None);
        }

        let json = std::fs::read_to_string(&path).map_err(|err| {
            format!(
                "failed to read access bundle '{}' from '{}': {err}",
                handle,
                path.display()
            )
        })?;
        let bundle: AccessBundle = serde_json::from_str(&json).map_err(|err| {
            format!(
                "failed to parse access bundle '{}' from '{}': {err}",
                handle,
                path.display()
            )
        })?;
        if bundle.handle != handle {
            return Err(format!(
                "access bundle '{}' contained mismatched handle '{}'",
                path.display(),
                bundle.handle
            ));
        }

        Ok(Some(bundle))
    }

    /// The root directory used for persisted bundles.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn bundle_path(&self, handle: &str) -> PathBuf {
        self.dir.join(format!("{handle}.json"))
    }
}

// ── Core functions ───────────────────────────────────────────────────

/// Perform a read-only access check.
///
/// Returns an `AccessCheckResult` indicating whether the specified
/// operation is currently allowed and listing any blockers.
///
/// # Errors
///
/// Returns an error when the supplied arguments are invalid.
pub fn check_access(args: &AccessCheckArgs) -> Result<AccessCheckResult, String> {
    let errors = args.validate();
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }

    let mut blockers = Vec::new();
    let mut grant_diff = None;

    let zone = args.zone.as_deref().unwrap_or("z:unknown");
    if let Some(zone) = &args.zone {
        if !zone.starts_with("z:") {
            blockers.push(
                AccessBlocker::new(
                    "invalid_zone",
                    format!("'{zone}' is not a recognized FCP zone identifier"),
                    BlockerSeverity::Error,
                )
                .with_remediation("Use a zone identifier starting with 'z:' (for example, z:work)"),
            );
        }
    }

    let required_capabilities = parse_capability_context(args.context.get("required_capabilities"));
    if !required_capabilities.is_empty() {
        let existing_capabilities = parse_capability_context(
            args.context
                .get("granted_capabilities")
                .or_else(|| args.context.get("existing_capabilities")),
        );
        let ceiling_capabilities = parse_capability_context(args.context.get("capability_ceiling"));
        let ceiling = (!ceiling_capabilities.is_empty()).then_some(ceiling_capabilities.as_slice());
        let analysis = analyze_capability_gap(
            &args.connector,
            &args.operation,
            zone,
            &existing_capabilities,
            &required_capabilities,
            ceiling,
        );

        blockers.extend(analysis.blockers.iter().map(access_blocker_from_typed));
        if analysis.grant_diff.change_count() > 0 || analysis.grant_diff.has_alternatives() {
            grant_diff = serde_json::to_value(analysis.grant_diff).ok();
        }
    }

    if let Some(env) = args.context.get("environment") {
        if env == "production" {
            blockers.push(
                AccessBlocker::new(
                    "production_env",
                    "production environment requires elevated access",
                    BlockerSeverity::Warning,
                )
                .with_remediation("Use `fwc access request` with justification"),
            );
        }
    }

    let allowed = !blockers.iter().any(AccessBlocker::is_blocking);

    Ok(AccessCheckResult {
        allowed,
        blockers,
        grant_diff,
        connector: args.connector.clone(),
        operation: args.operation.clone(),
        checked_at: Utc::now(),
    })
}

fn parse_capability_context(value: Option<&String>) -> Vec<String> {
    value
        .map(|raw| {
            raw.split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
                .map(str::trim)
                .filter(|cap| !cap.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn access_blocker_from_typed(blocker: &TypedBlocker) -> AccessBlocker {
    let mut access_blocker = AccessBlocker::new(
        blocker.blocker_type.label(),
        blocker.message.clone(),
        blocker.severity,
    );
    if let Some(remediation) = blocker.remediation.first() {
        access_blocker = access_blocker.with_remediation(remediation.clone());
    }
    access_blocker
}

/// Create a read-only access plan.
///
/// Returns an `AccessPlan` describing the steps needed to gain access
/// to the specified operation.
///
/// # Errors
///
/// Returns an error when the supplied arguments are invalid.
pub fn plan_access(args: &AccessPlanArgs) -> Result<AccessPlan, String> {
    let errors = args.validate();
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }

    let mut plan = AccessPlan::new(&args.connector, &args.operation);
    if args.dry_run {
        plan = plan.with_dry_run();
    }

    // Build standard plan steps.
    plan = plan.with_step(AccessPlanStep::new(
        "Verify credentials",
        &args.connector,
        0,
    ));
    plan = plan.with_step(AccessPlanStep::new(
        "Check policy engine",
        &args.operation,
        1,
    ));
    plan = plan.with_step(
        AccessPlanStep::new("Request grant", &args.connector, 2)
            .with_approval()
            .with_side_effect("Creates access grant record"),
    );
    plan = plan.with_step(
        AccessPlanStep::new("Activate bundle", &args.connector, 3)
            .with_side_effect("Activates session"),
    );

    plan = plan.with_estimated_duration(Duration::from_secs(30));

    // Add prerequisites based on context.
    if args
        .context
        .get("environment")
        .is_some_and(|e| e == "production")
    {
        plan = plan.with_prerequisite("Manager approval required for production");
    }

    Ok(plan)
}

/// Request access (side-effecting) — returns a bundle handle.
///
/// # Errors
///
/// Returns an error when the request arguments are invalid or the bundle cannot
/// be persisted in the default store.
pub fn request_access(args: &AccessRequestArgs) -> Result<AccessBundle, String> {
    let store = AccessBundleStore::default_path();
    request_access_with_store(args, &store)
}

/// Request access and persist the resulting bundle in the provided store.
///
/// # Errors
///
/// Returns an error when the request arguments are invalid or the bundle cannot
/// be persisted in the provided store.
pub fn request_access_with_store(
    args: &AccessRequestArgs,
    store: &AccessBundleStore,
) -> Result<AccessBundle, String> {
    let errors = args.validate();
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }

    let handle = generate_handle("bnd", &args.connector, &args.operation);

    let grant = AccessGrant::new(
        generate_handle("grt", &args.connector, &args.operation),
        &args.connector,
        &args.operation,
        GrantScope::Operation,
        Utc::now() + chrono::Duration::hours(1),
    );

    let bundle = AccessBundle::new(&handle)
        .with_grant(grant)
        .with_status(BundleStatus::Pending)
        .with_justification(&args.justification);

    store.save(&bundle)?;
    Ok(bundle)
}

/// Attach a bundle or approval handle to the current session.
///
/// # Errors
///
/// Returns an error when the handle is invalid, missing from the default store,
/// or cannot be loaded from disk.
pub fn attach_bundle(args: &AccessAttachArgs) -> Result<AccessBundle, String> {
    let store = AccessBundleStore::default_path();
    attach_bundle_with_store(args, &store)
}

/// Attach a persisted bundle from the provided store.
///
/// # Errors
///
/// Returns an error when the handle is invalid, missing from the provided store,
/// or cannot be loaded from disk.
pub fn attach_bundle_with_store(
    args: &AccessAttachArgs,
    store: &AccessBundleStore,
) -> Result<AccessBundle, String> {
    let errors = args.validate();
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }

    store
        .load(&args.handle)?
        .ok_or_else(|| format!("unknown bundle handle: {}", args.handle))
}

/// Resume a previous access session from a handle.
///
/// # Errors
///
/// Returns an error when the handle is invalid or represents an expired session.
pub fn resume_access(args: &AccessResumeArgs) -> Result<AccessBundle, String> {
    let errors = args.validate();
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }

    // Check for expired handles (handles starting with "exp-" are treated as expired).
    if args.handle.starts_with("exp-") {
        return Err(format!("handle '{}' has expired", args.handle));
    }

    let bundle = AccessBundle::new(&args.handle)
        .with_status(BundleStatus::Active)
        .with_receipt(format!("resumed-{}", &args.handle));

    Ok(bundle)
}

/// Inspect access state for a connector.
///
/// # Errors
///
/// Returns an error when the supplied arguments are invalid.
pub fn inspect_access(args: &AccessInspectArgs) -> Result<AccessInspection, String> {
    let errors = args.validate();
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }

    let mut inspection = AccessInspection::new(&args.connector);
    if let Some(op) = &args.operation {
        inspection = inspection.with_operation(op);
    }

    Ok(inspection)
}

// ── TOON formatters ──────────────────────────────────────────────────

/// Format an access check result as TOON lines.
#[must_use]
pub fn format_check_toon(result: &AccessCheckResult) -> Vec<String> {
    let mut lines = Vec::new();

    let verdict = if result.allowed { "ALLOWED" } else { "DENIED" };
    lines.push(format!(
        "Access Check: {}.{} -> {}",
        result.connector, result.operation, verdict
    ));
    lines.push(format!("  Connector: {}", result.connector));
    lines.push(format!("  Operation: {}", result.operation));
    lines.push(format!(
        "  Checked:   {}",
        result.checked_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    if result.blockers.is_empty() {
        lines.push("  Blockers:  (none)".into());
    } else {
        lines.push(format!("  Blockers:  {}", result.blockers.len()));
        for b in &result.blockers {
            lines.push(format!(
                "    [{}] {} — {}",
                b.severity.icon(),
                b.code,
                b.message
            ));
            if let Some(r) = &b.remediation {
                lines.push(format!("           Remedy: {r}"));
            }
        }
    }

    if let Some(diff) = &result.grant_diff {
        lines.push(format!("  Grant diff: {diff}"));
    }

    lines
}

/// Format an access plan as TOON lines.
#[must_use]
pub fn format_plan_toon(plan: &AccessPlan) -> Vec<String> {
    let mut lines = Vec::new();

    let mode = if plan.dry_run { " (DRY-RUN)" } else { "" };
    lines.push(format!(
        "Access Plan: {}.{}{}",
        plan.connector, plan.operation, mode
    ));

    if !plan.prerequisites.is_empty() {
        lines.push("  Prerequisites:".into());
        for p in &plan.prerequisites {
            lines.push(format!("    - {p}"));
        }
    }

    if let Some(dur) = plan.estimated_duration {
        lines.push(format!("  Estimated duration: {:.1}s", dur.as_secs_f64()));
    }

    lines.push(format!("  Steps: {}", plan.steps.len()));
    for step in &plan.steps {
        let approval = if step.requires_approval {
            " [approval required]"
        } else {
            ""
        };
        lines.push(format!(
            "    {}. {} -> {}{}",
            step.index + 1,
            step.action,
            step.target,
            approval
        ));
        for effect in &step.side_effects {
            lines.push(format!("       Side-effect: {effect}"));
        }
    }

    lines
}

/// Format an access bundle as TOON lines.
#[must_use]
pub fn format_bundle_toon(bundle: &AccessBundle) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!("Access Bundle: {}", bundle.handle));
    lines.push(format!("  Status:  {}", bundle.status.label()));
    lines.push(format!("  Grants:  {}", bundle.grant_count()));
    lines.push(format!(
        "  Created: {}",
        bundle.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    if let Some(j) = &bundle.justification {
        lines.push(format!("  Justification: {j}"));
    }
    if let Some(r) = &bundle.receipt {
        lines.push(format!("  Receipt: {r}"));
    }

    for grant in &bundle.grants {
        lines.push(format!("  Grant: {}", grant.handle));
        lines.push(format!("    Connector: {}", grant.connector));
        lines.push(format!("    Operation: {}", grant.operation));
        lines.push(format!("    Scope:     {}", grant.scope.label()));
        lines.push(format!(
            "    Expires:   {}",
            grant.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        lines.push(format!("    Revocable: {}", grant.revocable));
    }

    lines
}

/// Format an access grant as TOON lines.
#[must_use]
pub fn format_grant_toon(grant: &AccessGrant) -> Vec<String> {
    let mut lines = Vec::new();

    let status = if grant.is_expired() {
        "EXPIRED"
    } else {
        "ACTIVE"
    };
    lines.push(format!("Grant: {} [{}]", grant.handle, status));
    lines.push(format!("  Connector: {}", grant.connector));
    lines.push(format!("  Operation: {}", grant.operation));
    lines.push(format!("  Scope:     {}", grant.scope.label()));
    lines.push(format!(
        "  Expires:   {}",
        grant.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    lines.push(format!("  Remaining: {}", grant.remaining_display()));
    lines.push(format!("  Revocable: {}", grant.revocable));

    lines
}

/// Format a blocker as TOON lines.
#[must_use]
pub fn format_blocker_toon(blocker: &AccessBlocker) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!(
        "[{}] {}: {}",
        blocker.severity.icon(),
        blocker.code,
        blocker.message
    ));
    if let Some(r) = &blocker.remediation {
        lines.push(format!("     Remedy: {r}"));
    }

    lines
}

/// Format an inspection as TOON lines.
#[must_use]
pub fn format_inspection_toon(inspection: &AccessInspection) -> Vec<String> {
    let mut lines = Vec::new();

    let scope = inspection.operation.as_ref().map_or_else(
        || inspection.connector.clone(),
        |op| format!("{}.{}", inspection.connector, op),
    );
    lines.push(format!("Access Inspection: {scope}"));

    // Grants section.
    if inspection.grants.is_empty() {
        lines.push("  Grants: (none)".into());
    } else {
        lines.push(format!("  Grants: {}", inspection.grants.len()));
        for g in &inspection.grants {
            let status = if g.is_expired() { "expired" } else { "active" };
            lines.push(format!(
                "    {} [{}] scope={} expires={}",
                g.handle,
                status,
                g.scope.label(),
                g.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
    }

    // Sessions section.
    if inspection.active_sessions.is_empty() {
        lines.push("  Sessions: (none)".into());
    } else {
        lines.push(format!("  Sessions: {}", inspection.active_sessions.len()));
        for s in &inspection.active_sessions {
            lines.push(format!(
                "    {} bundle={} started={}",
                s.session_id,
                s.bundle_handle,
                s.started_at.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
    }

    // Audit trail section.
    if inspection.audit_trail.is_empty() {
        lines.push("  Audit trail: (none)".into());
    } else {
        lines.push(format!(
            "  Audit trail: {} entries",
            inspection.audit_trail.len()
        ));
        for e in &inspection.audit_trail {
            let detail = e.details.as_deref().unwrap_or("");
            let detail_suffix = if detail.is_empty() {
                String::new()
            } else {
                format!(" — {detail}")
            };
            lines.push(format!(
                "    {} {} by {} on {}{}",
                e.timestamp.format("%H:%M:%S"),
                e.action.label(),
                e.actor,
                e.target,
                detail_suffix
            ));
        }
    }

    lines
}

/// Format an audit entry as TOON lines.
#[must_use]
pub fn format_audit_entry_toon(entry: &AuditEntry) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!(
        "{} {} by {} on {}",
        entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        entry.action.label(),
        entry.actor,
        entry.target,
    ));
    if let Some(d) = &entry.details {
        lines.push(format!("  Details: {d}"));
    }

    lines
}

// ── Blocker Diagnosis ────────────────────────────────────────────────

/// The specific remedy family for a blocker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemedyFamily {
    /// Caller should refresh stale data (e.g., re-fetch revocation list).
    Refresh,
    /// Caller needs to re-request approval.
    ReApprove,
    /// Caller should shrink the request scope.
    ShrinkRequest,
    /// Caller needs a policy change from an administrator.
    PolicyChange,
    /// Caller should switch to the correct zone.
    ZoneSwitch,
    /// Caller needs to wait for a time-based gate to expire.
    WaitForExpiry,
}

impl RemedyFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Refresh => "refresh",
            Self::ReApprove => "re-approve",
            Self::ShrinkRequest => "shrink-request",
            Self::PolicyChange => "policy-change",
            Self::ZoneSwitch => "zone-switch",
            Self::WaitForExpiry => "wait",
        }
    }

    /// Classify a `BlockerType` into its remedy family.
    #[must_use]
    pub const fn from_blocker(bt: BlockerType) -> Self {
        match bt {
            BlockerType::MissingCapability | BlockerType::ApprovalGated => Self::ReApprove,
            BlockerType::CeilingViolation | BlockerType::PolicyDenied => Self::PolicyChange,
            BlockerType::ZoneMismatch => Self::ZoneSwitch,
            BlockerType::OverBroadRequest => Self::ShrinkRequest,
            BlockerType::ExpiredCredential => Self::Refresh,
        }
    }
}

impl fmt::Display for RemedyFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A full blocker diagnosis — structured explanation of why access failed
/// and exactly what to do about it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockerDiagnosis {
    /// The blocker being diagnosed.
    pub blocker_type: BlockerType,
    /// `FCP_ERR` code.
    pub fcp_err_code: String,
    /// Human-readable summary.
    pub summary: String,
    /// Which remedy family this falls into.
    pub remedy: RemedyFamily,
    /// Specific next commands to run.
    pub next_commands: Vec<String>,
    /// Whether the blocker is from stale/outdated data.
    pub is_freshness_issue: bool,
    /// The exact object or boundary that caused the failure.
    pub failed_object: Option<String>,
}

impl BlockerDiagnosis {
    pub fn new(blocker_type: BlockerType, summary: impl Into<String>) -> Self {
        Self {
            fcp_err_code: blocker_type.label().into(),
            remedy: RemedyFamily::from_blocker(blocker_type),
            blocker_type,
            summary: summary.into(),
            next_commands: Vec::new(),
            is_freshness_issue: false,
            failed_object: None,
        }
    }

    #[must_use]
    pub fn with_next_command(mut self, cmd: impl Into<String>) -> Self {
        self.next_commands.push(cmd.into());
        self
    }

    #[must_use]
    pub const fn with_freshness_issue(mut self) -> Self {
        self.is_freshness_issue = true;
        self
    }

    #[must_use]
    pub fn with_failed_object(mut self, obj: impl Into<String>) -> Self {
        self.failed_object = Some(obj.into());
        self
    }
}

/// Diagnose a typed blocker into a full structured explanation.
#[must_use]
pub fn diagnose_blocker(
    blocker: &TypedBlocker,
    connector: &str,
    operation: &str,
    zone: &str,
) -> BlockerDiagnosis {
    let mut diag = BlockerDiagnosis::new(blocker.blocker_type, &blocker.message);

    match blocker.blocker_type {
        BlockerType::MissingCapability => {
            diag = diag
                .with_next_command(format!(
                    "fwc access plan {connector} {operation} --zone {zone}"
                ))
                .with_next_command(format!(
                    "fwc access request {connector} {operation} --zone {zone}"
                ));
        }
        BlockerType::CeilingViolation => {
            diag = diag
                .with_failed_object(format!("zone ceiling for {zone}"))
                .with_next_command(format!("fwc zones {zone} --policy"))
                .with_next_command("Contact zone administrator to raise ceiling");
        }
        BlockerType::ApprovalGated => {
            diag = diag
                .with_next_command(format!(
                    "fwc access request {connector} {operation} --zone {zone}"
                ))
                .with_next_command("fwc history --pending-approvals");
        }
        BlockerType::ZoneMismatch => {
            diag = diag
                .with_failed_object(format!("zone {zone}"))
                .with_next_command("fwc zones")
                .with_next_command(format!(
                    "fwc access check {connector} {operation} --zone z:work"
                ));
        }
        BlockerType::OverBroadRequest => {
            diag = diag
                .with_next_command(format!(
                    "fwc access plan {connector} {operation} --zone {zone}"
                ))
                .with_next_command("Review required capabilities and request only what is needed");
        }
        BlockerType::ExpiredCredential => {
            diag = diag
                .with_freshness_issue()
                .with_failed_object(format!("credential for {connector}"))
                .with_next_command(format!("fwc auth verify {connector}"))
                .with_next_command(format!("fwc auth refresh {connector}"));
        }
        BlockerType::PolicyDenied => {
            diag = diag
                .with_failed_object(format!("policy for {zone}"))
                .with_next_command(format!("fwc zones {zone} --policy"))
                .with_next_command("Contact policy administrator");
        }
    }

    diag
}

/// Format a blocker diagnosis as TOON lines.
#[must_use]
pub fn format_diagnosis_toon(diag: &BlockerDiagnosis) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("[{}] {}", diag.fcp_err_code, diag.summary));
    lines.push(format!("  Remedy: {}", diag.remedy));

    if let Some(obj) = &diag.failed_object {
        lines.push(format!("  Failed object: {obj}"));
    }
    if diag.is_freshness_issue {
        lines.push("  Note: This may be a freshness issue — try refreshing first.".into());
    }
    if !diag.next_commands.is_empty() {
        lines.push("  Next steps:".into());
        for cmd in &diag.next_commands {
            lines.push(format!("    $ {cmd}"));
        }
    }

    lines
}

// ── Capability Gap Analysis ──────────────────────────────────────────

/// Classification of an access check's authorization verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationVerdict {
    /// Already allowed — no changes needed.
    Allowed,
    /// Conditionally allowed — pending approval or time-gated.
    ConditionallyAllowed,
    /// Blocked — requires remediation before access is possible.
    Blocked,
}

impl AuthorizationVerdict {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::ConditionallyAllowed => "conditionally_allowed",
            Self::Blocked => "blocked",
        }
    }
}

impl fmt::Display for AuthorizationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Machine-readable blocker type codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerType {
    /// Capability not present in the zone/profile.
    MissingCapability,
    /// Operation exceeds capability ceiling (scope too broad).
    CeilingViolation,
    /// Access requires human approval before proceeding.
    ApprovalGated,
    /// Source and target zones do not match or are incompatible.
    ZoneMismatch,
    /// Request is broader than needed — smaller alternatives exist.
    OverBroadRequest,
    /// Token or credential has expired.
    ExpiredCredential,
    /// Policy explicitly forbids this operation.
    PolicyDenied,
}

impl BlockerType {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MissingCapability => "FCP_ERR_MISSING_CAPABILITY",
            Self::CeilingViolation => "FCP_ERR_CEILING_VIOLATION",
            Self::ApprovalGated => "FCP_ERR_APPROVAL_GATED",
            Self::ZoneMismatch => "FCP_ERR_ZONE_MISMATCH",
            Self::OverBroadRequest => "FCP_ERR_OVER_BROAD",
            Self::ExpiredCredential => "FCP_ERR_EXPIRED_CREDENTIAL",
            Self::PolicyDenied => "FCP_ERR_POLICY_DENIED",
        }
    }
}

impl fmt::Display for BlockerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A single grant in a least-privilege diff.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantDiffEntry {
    /// The capability to add or modify.
    pub capability: String,
    /// The scope (operation, connector, zone).
    pub scope: GrantScope,
    /// Whether this is an addition or modification.
    pub action: GrantDiffAction,
    /// The target resource (connector or zone).
    pub target: String,
    /// Reason this grant is needed.
    pub rationale: String,
}

impl GrantDiffEntry {
    #[must_use]
    pub fn new(
        capability: impl Into<String>,
        scope: GrantScope,
        action: GrantDiffAction,
        target: impl Into<String>,
    ) -> Self {
        Self {
            capability: capability.into(),
            scope,
            action,
            target: target.into(),
            rationale: String::new(),
        }
    }

    #[must_use]
    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Self {
        self.rationale = rationale.into();
        self
    }
}

/// Action type for a grant diff entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantDiffAction {
    /// New grant needed.
    Add,
    /// Existing grant needs scope change.
    Modify,
    /// Grant should be narrowed (for over-broad corrections).
    Narrow,
}

impl fmt::Display for GrantDiffAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add => f.write_str("add"),
            Self::Modify => f.write_str("modify"),
            Self::Narrow => f.write_str("narrow"),
        }
    }
}

/// Structured least-privilege grant diff.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantDiff {
    /// Individual grant entries that need to change.
    pub entries: Vec<GrantDiffEntry>,
    /// Whether this diff is the minimal set needed.
    pub is_minimal: bool,
    /// Safer alternatives if the request is over-broad.
    pub alternatives: Vec<GrantDiffAlternative>,
}

impl GrantDiff {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            is_minimal: true,
            alternatives: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_entry(mut self, entry: GrantDiffEntry) -> Self {
        self.entries.push(entry);
        self
    }

    #[must_use]
    pub fn with_alternative(mut self, alt: GrantDiffAlternative) -> Self {
        self.alternatives.push(alt);
        self.is_minimal = false;
        self
    }

    /// Total number of grants to add or modify.
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.entries.len()
    }

    /// Whether alternatives exist (over-broad request).
    #[must_use]
    pub fn has_alternatives(&self) -> bool {
        !self.alternatives.is_empty()
    }
}

impl Default for GrantDiff {
    fn default() -> Self {
        Self::new()
    }
}

/// A safer alternative to an over-broad request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantDiffAlternative {
    /// Description of the alternative.
    pub description: String,
    /// The narrower scope suggested.
    pub scope: GrantScope,
    /// Capability this alternative grants.
    pub capability: String,
    /// Why this is safer.
    pub reason: String,
}

impl GrantDiffAlternative {
    #[must_use]
    pub fn new(
        description: impl Into<String>,
        scope: GrantScope,
        capability: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            description: description.into(),
            scope,
            capability: capability.into(),
            reason: reason.into(),
        }
    }
}

/// Full capability gap analysis result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGapAnalysis {
    /// Authorization verdict.
    pub verdict: AuthorizationVerdict,
    /// Typed blockers with `FCP_ERR` codes.
    pub blockers: Vec<TypedBlocker>,
    /// Least-privilege grant diff (empty if already allowed).
    pub grant_diff: GrantDiff,
    /// Connector being analyzed.
    pub connector: String,
    /// Operation being analyzed.
    pub operation: String,
    /// Zone context.
    pub zone: String,
    /// Follow-up commands.
    pub follow_up_commands: Vec<String>,
}

impl CapabilityGapAnalysis {
    #[must_use]
    pub fn allowed(
        connector: impl Into<String>,
        operation: impl Into<String>,
        zone: impl Into<String>,
    ) -> Self {
        Self {
            verdict: AuthorizationVerdict::Allowed,
            blockers: Vec::new(),
            grant_diff: GrantDiff::new(),
            connector: connector.into(),
            operation: operation.into(),
            zone: zone.into(),
            follow_up_commands: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_blocker(mut self, blocker: TypedBlocker) -> Self {
        if blocker.blocker_type == BlockerType::ApprovalGated {
            self.verdict = AuthorizationVerdict::ConditionallyAllowed;
        } else {
            self.verdict = AuthorizationVerdict::Blocked;
        }
        self.blockers.push(blocker);
        self
    }

    #[must_use]
    pub fn with_diff(mut self, diff: GrantDiff) -> Self {
        self.grant_diff = diff;
        self
    }

    #[must_use]
    pub fn with_follow_up(mut self, cmd: impl Into<String>) -> Self {
        self.follow_up_commands.push(cmd.into());
        self
    }

    /// Whether any blocker is of the given type.
    #[must_use]
    pub fn has_blocker_type(&self, bt: BlockerType) -> bool {
        self.blockers.iter().any(|b| b.blocker_type == bt)
    }

    /// Count of blockers by type.
    #[must_use]
    pub fn blocker_count_by_type(&self, bt: BlockerType) -> usize {
        self.blockers
            .iter()
            .filter(|b| b.blocker_type == bt)
            .count()
    }
}

/// A blocker with a typed `FCP_ERR` code.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypedBlocker {
    /// Machine-readable blocker type.
    pub blocker_type: BlockerType,
    /// Human-readable message.
    pub message: String,
    /// Severity.
    pub severity: BlockerSeverity,
    /// Concrete remediation steps.
    pub remediation: Vec<String>,
}

impl TypedBlocker {
    #[must_use]
    pub fn new(
        blocker_type: BlockerType,
        message: impl Into<String>,
        severity: BlockerSeverity,
    ) -> Self {
        Self {
            blocker_type,
            message: message.into(),
            severity,
            remediation: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_remediation(mut self, step: impl Into<String>) -> Self {
        self.remediation.push(step.into());
        self
    }
}

/// Analyze capability gaps for a connector operation in a zone.
///
/// Returns a structured analysis with verdict, typed blockers,
/// and least-privilege grant diff.
#[must_use]
pub fn analyze_capability_gap(
    connector: &str,
    operation: &str,
    zone: &str,
    existing_capabilities: &[String],
    required_capabilities: &[String],
    ceiling: Option<&[String]>,
) -> CapabilityGapAnalysis {
    let mut analysis = CapabilityGapAnalysis::allowed(connector, operation, zone);
    let mut diff = GrantDiff::new();

    // Check for missing capabilities.
    for req in required_capabilities {
        if !existing_capabilities.contains(req) {
            analysis = analysis.with_blocker(
                TypedBlocker::new(
                    BlockerType::MissingCapability,
                    format!("capability '{req}' required for {connector}.{operation} in {zone}"),
                    BlockerSeverity::Error,
                )
                .with_remediation(format!(
                    "fwc access request {connector} {operation} --zone {zone}"
                )),
            );

            diff = diff.with_entry(
                GrantDiffEntry::new(req, GrantScope::Operation, GrantDiffAction::Add, connector)
                    .with_rationale(format!("Required for {operation}")),
            );
        }
    }

    // Check ceiling violations — over-broad if requesting more than ceiling allows.
    if let Some(ceiling_caps) = ceiling {
        for req in required_capabilities {
            if !ceiling_caps.contains(req) {
                analysis = analysis.with_blocker(
                    TypedBlocker::new(
                        BlockerType::CeilingViolation,
                        format!("capability '{req}' exceeds zone ceiling for {zone}"),
                        BlockerSeverity::Critical,
                    )
                    .with_remediation(format!(
                        "Request a zone policy exception or move to a zone that supports '{req}'"
                    )),
                );
            }
        }
    }

    // Check for over-broad requests: if requesting Zone-wide scope when Operation scope suffices.
    if required_capabilities.len() > 3 {
        let narrower: Vec<String> = required_capabilities.iter().take(2).cloned().collect();
        let alt = GrantDiffAlternative::new(
            format!(
                "Request only essential capabilities: {}",
                narrower.join(", ")
            ),
            GrantScope::Operation,
            narrower.join(", "),
            "Smaller grant set reduces risk and is easier to approve",
        );
        diff = diff.with_alternative(alt);
        analysis = analysis.with_blocker(
            TypedBlocker::new(
                BlockerType::OverBroadRequest,
                format!(
                    "requesting {} capabilities when fewer may suffice",
                    required_capabilities.len()
                ),
                BlockerSeverity::Warning,
            )
            .with_remediation(
                "Consider requesting only the capabilities needed for the specific operation",
            ),
        );
    }

    // Zone mismatch — check if zone is the expected format.
    if !zone.starts_with("z:") {
        analysis = analysis.with_blocker(TypedBlocker::new(
            BlockerType::ZoneMismatch,
            format!("'{zone}' is not a recognized zone identifier"),
            BlockerSeverity::Error,
        ).with_remediation("Use a zone identifier starting with 'z:' (e.g., z:work). Run `fwc zones` to see available zones"));
    }

    analysis = analysis.with_diff(diff);

    // Add follow-up commands.
    if analysis.verdict != AuthorizationVerdict::Allowed {
        analysis = analysis.with_follow_up(format!(
            "fwc access check {connector} {operation} --zone {zone}"
        ));
        analysis = analysis.with_follow_up(format!(
            "fwc access plan {connector} {operation} --zone {zone}"
        ));
    }

    analysis
}

/// Format a capability gap analysis as TOON.
#[must_use]
pub fn format_gap_analysis_toon(analysis: &CapabilityGapAnalysis) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "Access: {} ({}.{} in {})",
        analysis.verdict, analysis.connector, analysis.operation, analysis.zone
    ));

    if analysis.blockers.is_empty() {
        lines.push("  No blockers — access is allowed.".into());
    } else {
        lines.push(format!("  Blockers: {}", analysis.blockers.len()));
        for b in &analysis.blockers {
            lines.push(format!(
                "    [{}] {} — {}",
                b.blocker_type, b.severity, b.message
            ));
            for r in &b.remediation {
                lines.push(format!("      Remediation: {r}"));
            }
        }
    }

    if analysis.grant_diff.change_count() > 0 {
        lines.push(format!(
            "  Grant diff ({} change{}):",
            analysis.grant_diff.change_count(),
            if analysis.grant_diff.change_count() == 1 {
                ""
            } else {
                "s"
            }
        ));
        for entry in &analysis.grant_diff.entries {
            lines.push(format!(
                "    {} {} [{}] -> {}",
                entry.action, entry.capability, entry.scope, entry.target
            ));
            if !entry.rationale.is_empty() {
                lines.push(format!("      Reason: {}", entry.rationale));
            }
        }
    }

    if analysis.grant_diff.has_alternatives() {
        lines.push("  Safer alternatives:".into());
        for alt in &analysis.grant_diff.alternatives {
            lines.push(format!("    - {}", alt.description));
            lines.push(format!("      Why: {}", alt.reason));
        }
    }

    if !analysis.follow_up_commands.is_empty() {
        lines.push("  Next steps:".into());
        for cmd in &analysis.follow_up_commands {
            lines.push(format!("    $ {cmd}"));
        }
    }

    lines
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // ── BlockerSeverity ──────────────────────────────────────────

    #[test]
    fn severity_labels() {
        assert_eq!(BlockerSeverity::Info.label(), "info");
        assert_eq!(BlockerSeverity::Warning.label(), "warning");
        assert_eq!(BlockerSeverity::Error.label(), "error");
        assert_eq!(BlockerSeverity::Critical.label(), "critical");
    }

    #[test]
    fn severity_icons() {
        assert_eq!(BlockerSeverity::Info.icon(), "i");
        assert_eq!(BlockerSeverity::Warning.icon(), "!");
        assert_eq!(BlockerSeverity::Error.icon(), "X");
        assert_eq!(BlockerSeverity::Critical.icon(), "!!");
    }

    #[test]
    fn severity_blocking() {
        assert!(!BlockerSeverity::Info.is_blocking());
        assert!(!BlockerSeverity::Warning.is_blocking());
        assert!(BlockerSeverity::Error.is_blocking());
        assert!(BlockerSeverity::Critical.is_blocking());
    }

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", BlockerSeverity::Error), "error");
    }

    #[test]
    fn severity_ordering() {
        assert!(BlockerSeverity::Info < BlockerSeverity::Warning);
        assert!(BlockerSeverity::Warning < BlockerSeverity::Error);
        assert!(BlockerSeverity::Error < BlockerSeverity::Critical);
    }

    // ── BundleStatus ─────────────────────────────────────────────

    #[test]
    fn bundle_status_labels() {
        assert_eq!(BundleStatus::Pending.label(), "pending");
        assert_eq!(BundleStatus::Active.label(), "active");
        assert_eq!(BundleStatus::Revoked.label(), "revoked");
        assert_eq!(BundleStatus::Expired.label(), "expired");
        assert_eq!(BundleStatus::Denied.label(), "denied");
        assert_eq!(BundleStatus::Partial.label(), "partial");
    }

    #[test]
    fn bundle_status_usable() {
        assert!(!BundleStatus::Pending.is_usable());
        assert!(BundleStatus::Active.is_usable());
        assert!(!BundleStatus::Revoked.is_usable());
        assert!(!BundleStatus::Expired.is_usable());
        assert!(!BundleStatus::Denied.is_usable());
        assert!(BundleStatus::Partial.is_usable());
    }

    #[test]
    fn bundle_status_terminal() {
        assert!(!BundleStatus::Pending.is_terminal());
        assert!(!BundleStatus::Active.is_terminal());
        assert!(BundleStatus::Revoked.is_terminal());
        assert!(BundleStatus::Expired.is_terminal());
        assert!(BundleStatus::Denied.is_terminal());
        assert!(!BundleStatus::Partial.is_terminal());
    }

    #[test]
    fn bundle_status_display() {
        assert_eq!(format!("{}", BundleStatus::Active), "active");
    }

    // ── GrantScope ───────────────────────────────────────────────

    #[test]
    fn grant_scope_labels() {
        assert_eq!(GrantScope::Operation.label(), "operation");
        assert_eq!(GrantScope::Connector.label(), "connector");
        assert_eq!(GrantScope::Zone.label(), "zone");
        assert_eq!(GrantScope::Global.label(), "global");
    }

    #[test]
    fn grant_scope_display() {
        assert_eq!(format!("{}", GrantScope::Global), "global");
    }

    // ── AuditAction ──────────────────────────────────────────────

    #[test]
    fn audit_action_labels() {
        assert_eq!(AuditAction::Check.label(), "check");
        assert_eq!(AuditAction::Request.label(), "request");
        assert_eq!(AuditAction::Grant.label(), "grant");
        assert_eq!(AuditAction::Deny.label(), "deny");
        assert_eq!(AuditAction::Revoke.label(), "revoke");
        assert_eq!(AuditAction::Attach.label(), "attach");
        assert_eq!(AuditAction::Resume.label(), "resume");
        assert_eq!(AuditAction::Expire.label(), "expire");
    }

    #[test]
    fn audit_action_display() {
        assert_eq!(format!("{}", AuditAction::Revoke), "revoke");
    }

    // ── AccessCheckArgs ──────────────────────────────────────────

    #[test]
    fn check_args_new() {
        let a = AccessCheckArgs::new("github", "list_repos");
        assert_eq!(a.connector, "github");
        assert_eq!(a.operation, "list_repos");
        assert!(a.zone.is_none());
        assert!(a.context.is_empty());
    }

    #[test]
    fn check_args_with_zone() {
        let a = AccessCheckArgs::new("github", "list_repos").with_zone("us-east-1");
        assert_eq!(a.zone.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn check_args_with_context() {
        let a = AccessCheckArgs::new("github", "list_repos").with_context("env", "staging");
        assert_eq!(a.context.get("env").unwrap(), "staging");
    }

    #[test]
    fn check_args_validate_ok() {
        let a = AccessCheckArgs::new("github", "list_repos");
        assert!(a.validate().is_empty());
    }

    #[test]
    fn check_args_validate_empty_connector() {
        let a = AccessCheckArgs::new("", "list_repos");
        let errs = a.validate();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("connector"));
    }

    #[test]
    fn check_args_validate_empty_operation() {
        let a = AccessCheckArgs::new("github", "");
        let errs = a.validate();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("operation"));
    }

    #[test]
    fn check_args_validate_both_empty() {
        let a = AccessCheckArgs::new("", "");
        assert_eq!(a.validate().len(), 2);
    }

    #[test]
    fn check_args_validate_empty_zone() {
        let mut a = AccessCheckArgs::new("github", "list_repos");
        a.zone = Some(String::new());
        let errs = a.validate();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("zone"));
    }

    // ── AccessPlanArgs ───────────────────────────────────────────

    #[test]
    fn plan_args_new() {
        let a = AccessPlanArgs::new("slack", "post_message");
        assert_eq!(a.connector, "slack");
        assert_eq!(a.operation, "post_message");
        assert!(!a.dry_run);
    }

    #[test]
    fn plan_args_dry_run() {
        let a = AccessPlanArgs::new("slack", "post_message").with_dry_run();
        assert!(a.dry_run);
    }

    #[test]
    fn plan_args_context() {
        let a = AccessPlanArgs::new("slack", "post_message").with_context("team", "engineering");
        assert_eq!(a.context.get("team").unwrap(), "engineering");
    }

    #[test]
    fn plan_args_validate_ok() {
        let a = AccessPlanArgs::new("slack", "post_message");
        assert!(a.validate().is_empty());
    }

    #[test]
    fn plan_args_validate_empty() {
        let a = AccessPlanArgs::new("", "");
        assert_eq!(a.validate().len(), 2);
    }

    // ── AccessRequestArgs ────────────────────────────────────────

    #[test]
    fn request_args_new() {
        let a = AccessRequestArgs::new("jira", "create_issue", "sprint planning");
        assert_eq!(a.connector, "jira");
        assert_eq!(a.operation, "create_issue");
        assert_eq!(a.justification, "sprint planning");
    }

    #[test]
    fn request_args_validate_ok() {
        let a = AccessRequestArgs::new("jira", "create_issue", "needed for sprint");
        assert!(a.validate().is_empty());
    }

    #[test]
    fn request_args_validate_empty_justification() {
        let a = AccessRequestArgs::new("jira", "create_issue", "   ");
        let errs = a.validate();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("justification"));
    }

    #[test]
    fn request_args_validate_all_empty() {
        let a = AccessRequestArgs::new("", "", "");
        assert_eq!(a.validate().len(), 3);
    }

    // ── AccessAttachArgs ─────────────────────────────────────────

    #[test]
    fn attach_args_new() {
        let a = AccessAttachArgs::new("bnd-abc123");
        assert_eq!(a.handle, "bnd-abc123");
    }

    #[test]
    fn attach_args_validate_ok() {
        let a = AccessAttachArgs::new("bnd-abc123");
        assert!(a.validate().is_empty());
    }

    #[test]
    fn attach_args_validate_empty() {
        let a = AccessAttachArgs::new("");
        let errs = a.validate();
        assert!(!errs.is_empty());
    }

    #[test]
    fn attach_args_validate_invalid_chars() {
        let a = AccessAttachArgs::new("bnd abc!@#");
        let errs = a.validate();
        assert!(!errs.is_empty());
        assert!(errs.iter().any(|e| e.contains("invalid handle")));
    }

    // ── AccessResumeArgs ─────────────────────────────────────────

    #[test]
    fn resume_args_new() {
        let a = AccessResumeArgs::new("ses-xyz789");
        assert_eq!(a.handle, "ses-xyz789");
    }

    #[test]
    fn resume_args_validate_ok() {
        let a = AccessResumeArgs::new("ses-xyz789");
        assert!(a.validate().is_empty());
    }

    #[test]
    fn resume_args_validate_empty() {
        let a = AccessResumeArgs::new("");
        assert!(!a.validate().is_empty());
    }

    #[test]
    fn resume_args_validate_invalid() {
        let a = AccessResumeArgs::new("has spaces");
        let errs = a.validate();
        assert!(errs.iter().any(|e| e.contains("invalid handle")));
    }

    // ── AccessInspectArgs ────────────────────────────────────────

    #[test]
    fn inspect_args_new() {
        let a = AccessInspectArgs::new("github");
        assert_eq!(a.connector, "github");
        assert!(a.operation.is_none());
        assert!(!a.verbose);
    }

    #[test]
    fn inspect_args_with_operation() {
        let a = AccessInspectArgs::new("github").with_operation("list_repos");
        assert_eq!(a.operation.as_deref(), Some("list_repos"));
    }

    #[test]
    fn inspect_args_verbose() {
        let a = AccessInspectArgs::new("github").with_verbose();
        assert!(a.verbose);
    }

    #[test]
    fn inspect_args_validate_ok() {
        let a = AccessInspectArgs::new("github");
        assert!(a.validate().is_empty());
    }

    #[test]
    fn inspect_args_validate_empty_connector() {
        let a = AccessInspectArgs::new("");
        assert_eq!(a.validate().len(), 1);
    }

    #[test]
    fn inspect_args_validate_empty_operation() {
        let mut a = AccessInspectArgs::new("github");
        a.operation = Some(String::new());
        let errs = a.validate();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("operation"));
    }

    // ── Handle validation ────────────────────────────────────────

    #[test]
    fn valid_handles() {
        assert!(is_valid_handle("bnd-abc123"));
        assert!(is_valid_handle("grt_xyz.789"));
        assert!(is_valid_handle("a"));
        assert!(is_valid_handle("A-Z_0.9"));
    }

    #[test]
    fn invalid_handles() {
        assert!(!is_valid_handle(""));
        assert!(!is_valid_handle("has space"));
        assert!(!is_valid_handle("has!bang"));
        assert!(!is_valid_handle("has@at"));
        assert!(!is_valid_handle("has/slash"));
    }

    #[test]
    fn generate_handle_prefix() {
        let h = generate_handle("bnd", "github", "list_repos");
        assert!(h.starts_with("bnd-"));
        assert!(h.len() > 4);
    }

    #[test]
    fn generate_handle_valid_format() {
        let h = generate_handle("grt", "slack", "post");
        assert!(is_valid_handle(&h));
    }

    // ── AccessBlocker ────────────────────────────────────────────

    #[test]
    fn blocker_new() {
        let b = AccessBlocker::new("code1", "msg1", BlockerSeverity::Error);
        assert_eq!(b.code, "code1");
        assert_eq!(b.message, "msg1");
        assert_eq!(b.severity, BlockerSeverity::Error);
        assert!(b.remediation.is_none());
    }

    #[test]
    fn blocker_with_remediation() {
        let b = AccessBlocker::new("code1", "msg1", BlockerSeverity::Warning)
            .with_remediation("fix it");
        assert_eq!(b.remediation.as_deref(), Some("fix it"));
    }

    #[test]
    fn blocker_is_blocking() {
        assert!(AccessBlocker::new("c", "m", BlockerSeverity::Error).is_blocking());
        assert!(AccessBlocker::new("c", "m", BlockerSeverity::Critical).is_blocking());
        assert!(!AccessBlocker::new("c", "m", BlockerSeverity::Warning).is_blocking());
        assert!(!AccessBlocker::new("c", "m", BlockerSeverity::Info).is_blocking());
    }

    // ── AccessCheckResult ────────────────────────────────────────

    #[test]
    fn check_result_allowed() {
        let r = AccessCheckResult::allowed("gh", "list");
        assert!(r.allowed);
        assert!(r.blockers.is_empty());
        assert_eq!(r.blocking_count(), 0);
        assert_eq!(r.warning_count(), 0);
        assert!(!r.has_blockers());
    }

    #[test]
    fn check_result_blocked() {
        let blockers = vec![
            AccessBlocker::new("a", "m", BlockerSeverity::Error),
            AccessBlocker::new("b", "m", BlockerSeverity::Warning),
        ];
        let r = AccessCheckResult::blocked("gh", "list", blockers);
        assert!(!r.allowed);
        assert_eq!(r.blocking_count(), 1);
        assert_eq!(r.warning_count(), 1);
        assert!(r.has_blockers());
    }

    #[test]
    fn check_result_fields() {
        let r = AccessCheckResult::allowed("github", "repos");
        assert_eq!(r.connector, "github");
        assert_eq!(r.operation, "repos");
        assert!(r.grant_diff.is_none());
    }

    // ── AccessPlanStep ───────────────────────────────────────────

    #[test]
    fn plan_step_new() {
        let s = AccessPlanStep::new("do thing", "target", 0);
        assert_eq!(s.action, "do thing");
        assert_eq!(s.target, "target");
        assert_eq!(s.index, 0);
        assert!(!s.requires_approval);
        assert!(!s.has_side_effects());
    }

    #[test]
    fn plan_step_with_approval() {
        let s = AccessPlanStep::new("approve", "mgr", 1).with_approval();
        assert!(s.requires_approval);
    }

    #[test]
    fn plan_step_with_side_effect() {
        let s = AccessPlanStep::new("create", "db", 2).with_side_effect("writes record");
        assert!(s.has_side_effects());
        assert_eq!(s.side_effects.len(), 1);
    }

    #[test]
    fn plan_step_multiple_effects() {
        let s = AccessPlanStep::new("x", "y", 0)
            .with_side_effect("a")
            .with_side_effect("b");
        assert_eq!(s.side_effects.len(), 2);
    }

    // ── AccessPlan ───────────────────────────────────────────────

    #[test]
    fn plan_new() {
        let p = AccessPlan::new("gh", "list");
        assert!(p.steps.is_empty());
        assert!(p.estimated_duration.is_none());
        assert!(!p.dry_run);
        assert!(!p.has_prerequisites());
        assert!(!p.has_side_effects());
    }

    #[test]
    fn plan_with_step() {
        let p = AccessPlan::new("gh", "list").with_step(AccessPlanStep::new("a", "b", 0));
        assert_eq!(p.step_count(), 1);
    }

    #[test]
    fn plan_approval_steps() {
        let p = AccessPlan::new("gh", "list")
            .with_step(AccessPlanStep::new("a", "b", 0))
            .with_step(AccessPlanStep::new("c", "d", 1).with_approval());
        assert_eq!(p.approval_steps(), 1);
    }

    #[test]
    fn plan_estimated_duration() {
        let p = AccessPlan::new("gh", "list")
            .with_estimated_duration(std::time::Duration::from_secs(45));
        assert_eq!(p.estimated_duration.unwrap().as_secs(), 45);
    }

    #[test]
    fn plan_prerequisites() {
        let p = AccessPlan::new("gh", "list").with_prerequisite("creds configured");
        assert!(p.has_prerequisites());
        assert_eq!(p.prerequisites.len(), 1);
    }

    #[test]
    fn plan_dry_run() {
        let p = AccessPlan::new("gh", "list").with_dry_run();
        assert!(p.dry_run);
    }

    #[test]
    fn plan_has_side_effects() {
        let p = AccessPlan::new("gh", "list")
            .with_step(AccessPlanStep::new("a", "b", 0).with_side_effect("x"));
        assert!(p.has_side_effects());
    }

    #[test]
    fn plan_validate_step_order_ok() {
        let p = AccessPlan::new("gh", "list")
            .with_step(AccessPlanStep::new("a", "b", 0))
            .with_step(AccessPlanStep::new("c", "d", 1));
        assert!(p.validate_step_order().is_empty());
    }

    #[test]
    fn plan_validate_step_order_bad() {
        let p = AccessPlan::new("gh", "list").with_step(AccessPlanStep::new("a", "b", 5));
        let errs = p.validate_step_order();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("index 5"));
    }

    // ── AccessGrant ──────────────────────────────────────────────

    #[test]
    fn grant_new() {
        let exp = Utc::now() + Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        assert_eq!(g.handle, "grt-1");
        assert_eq!(g.connector, "gh");
        assert!(g.revocable);
        assert!(g.is_active());
        assert!(!g.is_expired());
    }

    #[test]
    fn grant_non_revocable() {
        let exp = Utc::now() + Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp).non_revocable();
        assert!(!g.revocable);
    }

    #[test]
    fn grant_expired() {
        let exp = Utc::now() - Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        assert!(g.is_expired());
        assert!(!g.is_active());
    }

    #[test]
    fn grant_remaining_active() {
        let exp = Utc::now() + Duration::hours(2);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        assert!(g.remaining().num_seconds() > 0);
        let display = g.remaining_display();
        assert!(display.contains('h') || display.contains('m'));
    }

    #[test]
    fn grant_remaining_expired() {
        let exp = Utc::now() - Duration::seconds(10);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        assert_eq!(g.remaining_display(), "expired");
    }

    #[test]
    fn grant_remaining_seconds() {
        let exp = Utc::now() + Duration::seconds(30);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        let d = g.remaining_display();
        assert!(d.contains('s'));
    }

    #[test]
    fn grant_remaining_minutes() {
        let exp = Utc::now() + Duration::minutes(5);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        let d = g.remaining_display();
        assert!(d.contains('m'));
    }

    // ── AccessBundle ─────────────────────────────────────────────

    #[test]
    fn bundle_new() {
        let b = AccessBundle::new("bnd-1");
        assert_eq!(b.handle, "bnd-1");
        assert_eq!(b.status, BundleStatus::Pending);
        assert!(b.grants.is_empty());
        assert!(b.receipt.is_none());
        assert!(b.justification.is_none());
    }

    #[test]
    fn bundle_with_grant() {
        let exp = Utc::now() + Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        let b = AccessBundle::new("bnd-1").with_grant(g);
        assert_eq!(b.grant_count(), 1);
    }

    #[test]
    fn bundle_active_count() {
        let future = Utc::now() + Duration::hours(1);
        let past = Utc::now() - Duration::hours(1);
        let b = AccessBundle::new("bnd-1")
            .with_grant(AccessGrant::new(
                "g1",
                "c",
                "o",
                GrantScope::Operation,
                future,
            ))
            .with_grant(AccessGrant::new(
                "g2",
                "c",
                "o",
                GrantScope::Operation,
                past,
            ));
        assert_eq!(b.active_grant_count(), 1);
    }

    #[test]
    fn bundle_with_status() {
        let b = AccessBundle::new("bnd-1").with_status(BundleStatus::Active);
        assert_eq!(b.status, BundleStatus::Active);
        assert!(b.is_usable());
    }

    #[test]
    fn bundle_with_receipt() {
        let b = AccessBundle::new("bnd-1").with_receipt("rcpt-abc");
        assert_eq!(b.receipt.as_deref(), Some("rcpt-abc"));
    }

    #[test]
    fn bundle_with_justification() {
        let b = AccessBundle::new("bnd-1").with_justification("needed for sprint");
        assert_eq!(b.justification.as_deref(), Some("needed for sprint"));
    }

    #[test]
    fn bundle_lifecycle_activate() {
        let mut b = AccessBundle::new("bnd-1");
        b.activate();
        assert_eq!(b.status, BundleStatus::Active);
    }

    #[test]
    fn bundle_lifecycle_revoke() {
        let mut b = AccessBundle::new("bnd-1");
        b.activate();
        b.revoke();
        assert_eq!(b.status, BundleStatus::Revoked);
        assert!(b.is_terminal());
    }

    #[test]
    fn bundle_lifecycle_expire() {
        let mut b = AccessBundle::new("bnd-1");
        b.expire();
        assert_eq!(b.status, BundleStatus::Expired);
        assert!(b.is_terminal());
    }

    #[test]
    fn bundle_lifecycle_deny() {
        let mut b = AccessBundle::new("bnd-1");
        b.deny();
        assert_eq!(b.status, BundleStatus::Denied);
        assert!(b.is_terminal());
    }

    // ── AuditEntry ───────────────────────────────────────────────

    #[test]
    fn audit_entry_new() {
        let e = AuditEntry::new(AuditAction::Check, "agent-1", "github.list_repos");
        assert_eq!(e.action.label(), "check");
        assert_eq!(e.actor, "agent-1");
        assert_eq!(e.target, "github.list_repos");
        assert!(e.details.is_none());
    }

    #[test]
    fn audit_entry_with_details() {
        let e = AuditEntry::new(AuditAction::Grant, "admin", "slack.post")
            .with_details("approved by policy");
        assert_eq!(e.details.as_deref(), Some("approved by policy"));
    }

    // ── ActiveSession ────────────────────────────────────────────

    #[test]
    fn active_session_new() {
        let s = ActiveSession::new("ses-1", "bnd-1");
        assert_eq!(s.session_id, "ses-1");
        assert_eq!(s.bundle_handle, "bnd-1");
    }

    #[test]
    fn active_session_touch() {
        let mut s = ActiveSession::new("ses-1", "bnd-1");
        let before = s.last_activity;
        // touch updates last_activity
        s.touch();
        assert!(s.last_activity >= before);
    }

    // ── AccessInspection ─────────────────────────────────────────

    #[test]
    fn inspection_new() {
        let i = AccessInspection::new("github");
        assert_eq!(i.connector, "github");
        assert!(i.operation.is_none());
        assert!(!i.has_grants());
        assert!(!i.has_active_sessions());
        assert_eq!(i.audit_count(), 0);
    }

    #[test]
    fn inspection_with_operation() {
        let i = AccessInspection::new("github").with_operation("list_repos");
        assert_eq!(i.operation.as_deref(), Some("list_repos"));
    }

    #[test]
    fn inspection_with_grant() {
        let exp = Utc::now() + Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        let i = AccessInspection::new("github").with_grant(g);
        assert!(i.has_grants());
        assert_eq!(i.active_grant_count(), 1);
    }

    #[test]
    fn inspection_with_session() {
        let s = ActiveSession::new("ses-1", "bnd-1");
        let i = AccessInspection::new("github").with_session(s);
        assert!(i.has_active_sessions());
    }

    #[test]
    fn inspection_with_audit() {
        let e = AuditEntry::new(AuditAction::Check, "a", "t");
        let i = AccessInspection::new("github").with_audit_entry(e);
        assert_eq!(i.audit_count(), 1);
    }

    // ── check_access ─────────────────────────────────────────────

    #[test]
    fn check_access_allowed() {
        let args = AccessCheckArgs::new("github", "list_repos");
        let result = check_access(&args).unwrap();
        assert!(result.allowed);
        assert!(result.blockers.is_empty());
    }

    #[test]
    fn check_access_restricted_zone_blocked() {
        let args = AccessCheckArgs::new("github", "list_repos").with_zone("restricted-prod");
        let result = check_access(&args).unwrap();
        assert!(!result.allowed);
        assert_eq!(result.blocking_count(), 1);
        assert_eq!(result.blockers[0].code, "invalid_zone");
    }

    #[test]
    fn check_access_production_warning() {
        let args =
            AccessCheckArgs::new("github", "list_repos").with_context("environment", "production");
        let result = check_access(&args).unwrap();
        assert!(result.allowed); // warning does not block
        assert_eq!(result.warning_count(), 1);
    }

    #[test]
    fn check_access_validation_error() {
        let args = AccessCheckArgs::new("", "");
        let err = check_access(&args).unwrap_err();
        assert!(err.contains("connector"));
        assert!(err.contains("operation"));
    }

    #[test]
    fn check_access_normal_zone_ok() {
        let args = AccessCheckArgs::new("github", "list_repos").with_zone("z:work");
        let result = check_access(&args).unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn check_access_missing_required_capability_blocked() {
        let args = AccessCheckArgs::new("github", "create_issue")
            .with_zone("z:work")
            .with_context("required_capabilities", "github.issues.write")
            .with_context("granted_capabilities", "github.issues.read");
        let result = check_access(&args).unwrap();
        assert!(!result.allowed);
        assert_eq!(result.blocking_count(), 1);
        assert_eq!(result.blockers[0].code, "FCP_ERR_MISSING_CAPABILITY");
        assert!(result.grant_diff.is_some());
    }

    #[test]
    fn check_access_required_capability_allowed_when_granted() {
        let args = AccessCheckArgs::new("github", "list_repos")
            .with_zone("z:work")
            .with_context("required_capabilities", "github.repos.read")
            .with_context("granted_capabilities", "github.repos.read");
        let result = check_access(&args).unwrap();
        assert!(result.allowed);
        assert_eq!(result.blocking_count(), 0);
        assert!(result.grant_diff.is_none());
    }

    #[test]
    fn check_access_staging_env_ok() {
        let args =
            AccessCheckArgs::new("github", "list_repos").with_context("environment", "staging");
        let result = check_access(&args).unwrap();
        assert!(result.allowed);
        assert_eq!(result.warning_count(), 0);
    }

    // ── plan_access ──────────────────────────────────────────────

    #[test]
    fn plan_access_basic() {
        let args = AccessPlanArgs::new("github", "list_repos");
        let plan = plan_access(&args).unwrap();
        assert_eq!(plan.connector, "github");
        assert_eq!(plan.operation, "list_repos");
        assert!(!plan.dry_run);
        assert!(plan.step_count() >= 2);
    }

    #[test]
    fn plan_access_dry_run() {
        let args = AccessPlanArgs::new("github", "list_repos").with_dry_run();
        let plan = plan_access(&args).unwrap();
        assert!(plan.dry_run);
    }

    #[test]
    fn plan_access_step_order() {
        let args = AccessPlanArgs::new("github", "list_repos");
        let plan = plan_access(&args).unwrap();
        assert!(plan.validate_step_order().is_empty());
    }

    #[test]
    fn plan_access_has_approval_step() {
        let args = AccessPlanArgs::new("github", "list_repos");
        let plan = plan_access(&args).unwrap();
        assert!(plan.approval_steps() >= 1);
    }

    #[test]
    fn plan_access_production_prereq() {
        let args =
            AccessPlanArgs::new("github", "list_repos").with_context("environment", "production");
        let plan = plan_access(&args).unwrap();
        assert!(plan.has_prerequisites());
    }

    #[test]
    fn plan_access_validation_error() {
        let args = AccessPlanArgs::new("", "");
        let err = plan_access(&args).unwrap_err();
        assert!(err.contains("connector"));
    }

    #[test]
    fn plan_access_estimated_duration() {
        let args = AccessPlanArgs::new("github", "list_repos");
        let plan = plan_access(&args).unwrap();
        assert!(plan.estimated_duration.is_some());
    }

    #[test]
    fn plan_access_side_effects() {
        let args = AccessPlanArgs::new("github", "list_repos");
        let plan = plan_access(&args).unwrap();
        assert!(plan.has_side_effects());
    }

    // ── request_access ───────────────────────────────────────────

    #[test]
    fn request_access_basic() {
        let args = AccessRequestArgs::new("jira", "create_issue", "sprint planning");
        let store = AccessBundleStore::new(
            std::env::temp_dir().join(format!("fwc-access-test-{}", uuid::Uuid::new_v4().simple())),
        );
        let bundle = request_access_with_store(&args, &store).unwrap();
        assert!(bundle.handle.starts_with("bnd-"));
        assert_eq!(bundle.status, BundleStatus::Pending);
        assert_eq!(bundle.grant_count(), 1);
        assert_eq!(bundle.justification.as_deref(), Some("sprint planning"));
    }

    #[test]
    fn request_access_grant_handle() {
        let args = AccessRequestArgs::new("jira", "create_issue", "reason");
        let store = AccessBundleStore::new(
            std::env::temp_dir().join(format!("fwc-access-test-{}", uuid::Uuid::new_v4().simple())),
        );
        let bundle = request_access_with_store(&args, &store).unwrap();
        let grant = &bundle.grants[0];
        assert!(grant.handle.starts_with("grt-"));
        assert_eq!(grant.connector, "jira");
        assert_eq!(grant.operation, "create_issue");
    }

    #[test]
    fn request_access_validation_error() {
        let args = AccessRequestArgs::new("", "", "");
        let store = AccessBundleStore::new(
            std::env::temp_dir().join(format!("fwc-access-test-{}", uuid::Uuid::new_v4().simple())),
        );
        let err = request_access_with_store(&args, &store).unwrap_err();
        assert!(err.contains("connector"));
    }

    #[test]
    fn request_access_grant_scope() {
        let args = AccessRequestArgs::new("jira", "create_issue", "reason");
        let store = AccessBundleStore::new(
            std::env::temp_dir().join(format!("fwc-access-test-{}", uuid::Uuid::new_v4().simple())),
        );
        let bundle = request_access_with_store(&args, &store).unwrap();
        assert_eq!(bundle.grants[0].scope, GrantScope::Operation);
    }

    #[test]
    fn request_access_grant_expiry() {
        let args = AccessRequestArgs::new("jira", "create_issue", "reason");
        let store = AccessBundleStore::new(
            std::env::temp_dir().join(format!("fwc-access-test-{}", uuid::Uuid::new_v4().simple())),
        );
        let bundle = request_access_with_store(&args, &store).unwrap();
        assert!(bundle.grants[0].is_active());
    }

    // ── attach_bundle ────────────────────────────────────────────

    #[test]
    fn attach_bundle_loads_persisted_bundle() {
        let store = AccessBundleStore::new(
            std::env::temp_dir().join(format!("fwc-access-test-{}", uuid::Uuid::new_v4().simple())),
        );
        let persisted = AccessBundle::new("bnd-abc123")
            .with_status(BundleStatus::Partial)
            .with_receipt("stored-receipt")
            .with_justification("saved on disk");
        store.save(&persisted).unwrap();
        let args = AccessAttachArgs::new("bnd-abc123");
        let bundle = attach_bundle_with_store(&args, &store).unwrap();
        assert_eq!(bundle.handle, "bnd-abc123");
        assert_eq!(bundle.status, BundleStatus::Partial);
        assert_eq!(bundle.receipt.as_deref(), Some("stored-receipt"));
        assert_eq!(bundle.justification.as_deref(), Some("saved on disk"));
    }

    #[test]
    fn attach_bundle_errors_for_unknown_handle() {
        let store = AccessBundleStore::new(
            std::env::temp_dir().join(format!("fwc-access-test-{}", uuid::Uuid::new_v4().simple())),
        );
        let args = AccessAttachArgs::new("bnd-abc123");
        let err = attach_bundle_with_store(&args, &store).unwrap_err();
        assert!(err.contains("unknown bundle handle: bnd-abc123"));
    }

    #[test]
    fn attach_bundle_validation_error() {
        let args = AccessAttachArgs::new("");
        let err = attach_bundle(&args).unwrap_err();
        assert!(err.contains("handle"));
    }

    #[test]
    fn attach_bundle_invalid_handle() {
        let args = AccessAttachArgs::new("has spaces!!");
        let err = attach_bundle(&args).unwrap_err();
        assert!(err.contains("invalid handle"));
    }

    // ── resume_access ────────────────────────────────────────────

    #[test]
    fn resume_access_basic() {
        let args = AccessResumeArgs::new("ses-xyz789");
        let bundle = resume_access(&args).unwrap();
        assert_eq!(bundle.handle, "ses-xyz789");
        assert_eq!(bundle.status, BundleStatus::Active);
    }

    #[test]
    fn resume_access_receipt() {
        let args = AccessResumeArgs::new("ses-xyz789");
        let bundle = resume_access(&args).unwrap();
        assert!(bundle.receipt.unwrap().starts_with("resumed-"));
    }

    #[test]
    fn resume_access_expired_handle() {
        let args = AccessResumeArgs::new("exp-old-session");
        let err = resume_access(&args).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn resume_access_validation_error() {
        let args = AccessResumeArgs::new("");
        let err = resume_access(&args).unwrap_err();
        assert!(err.contains("handle"));
    }

    // ── inspect_access ───────────────────────────────────────────

    #[test]
    fn inspect_access_basic() {
        let args = AccessInspectArgs::new("github");
        let inspection = inspect_access(&args).unwrap();
        assert_eq!(inspection.connector, "github");
        assert!(inspection.operation.is_none());
    }

    #[test]
    fn inspect_access_with_operation() {
        let args = AccessInspectArgs::new("github").with_operation("list_repos");
        let inspection = inspect_access(&args).unwrap();
        assert_eq!(inspection.operation.as_deref(), Some("list_repos"));
    }

    #[test]
    fn inspect_access_validation_error() {
        let args = AccessInspectArgs::new("");
        let err = inspect_access(&args).unwrap_err();
        assert!(err.contains("connector"));
    }

    // ── format_check_toon ────────────────────────────────────────

    #[test]
    fn format_check_toon_allowed() {
        let r = AccessCheckResult::allowed("github", "list_repos");
        let lines = format_check_toon(&r);
        assert!(lines[0].contains("ALLOWED"));
        assert!(lines.iter().any(|l| l.contains("github")));
        assert!(lines.iter().any(|l| l.contains("list_repos")));
        assert!(lines.iter().any(|l| l.contains("(none)")));
    }

    #[test]
    fn format_check_toon_denied() {
        let blockers = vec![
            AccessBlocker::new("missing_creds", "no creds", BlockerSeverity::Error)
                .with_remediation("run fwc auth add"),
        ];
        let r = AccessCheckResult::blocked("github", "list_repos", blockers);
        let lines = format_check_toon(&r);
        assert!(lines[0].contains("DENIED"));
        assert!(lines.iter().any(|l| l.contains("missing_creds")));
        assert!(lines.iter().any(|l| l.contains("Remedy")));
    }

    #[test]
    fn format_check_toon_multiple_blockers() {
        let blockers = vec![
            AccessBlocker::new("a", "first", BlockerSeverity::Error),
            AccessBlocker::new("b", "second", BlockerSeverity::Warning),
        ];
        let r = AccessCheckResult::blocked("gh", "op", blockers);
        let lines = format_check_toon(&r);
        assert!(lines.iter().any(|l| l.contains("[X]")));
        assert!(lines.iter().any(|l| l.contains("[!]")));
    }

    #[test]
    fn format_check_toon_with_grant_diff() {
        let mut r = AccessCheckResult::allowed("gh", "op");
        r.grant_diff = Some(serde_json::json!({"added": ["read"]}));
        let lines = format_check_toon(&r);
        assert!(lines.iter().any(|l| l.contains("Grant diff")));
    }

    // ── format_plan_toon ─────────────────────────────────────────

    #[test]
    fn format_plan_toon_basic() {
        let plan = AccessPlan::new("github", "list_repos")
            .with_step(AccessPlanStep::new("verify", "creds", 0))
            .with_step(AccessPlanStep::new("request", "grant", 1).with_approval());
        let lines = format_plan_toon(&plan);
        assert!(lines[0].contains("Access Plan"));
        assert!(lines.iter().any(|l| l.contains("verify")));
        assert!(lines.iter().any(|l| l.contains("approval required")));
    }

    #[test]
    fn format_plan_toon_dry_run() {
        let plan = AccessPlan::new("gh", "op").with_dry_run();
        let lines = format_plan_toon(&plan);
        assert!(lines[0].contains("DRY-RUN"));
    }

    #[test]
    fn format_plan_toon_prerequisites() {
        let plan = AccessPlan::new("gh", "op").with_prerequisite("manager approval");
        let lines = format_plan_toon(&plan);
        assert!(lines.iter().any(|l| l.contains("Prerequisites")));
        assert!(lines.iter().any(|l| l.contains("manager approval")));
    }

    #[test]
    fn format_plan_toon_duration() {
        let plan =
            AccessPlan::new("gh", "op").with_estimated_duration(std::time::Duration::from_secs(30));
        let lines = format_plan_toon(&plan);
        assert!(lines.iter().any(|l| l.contains("30")));
    }

    #[test]
    fn format_plan_toon_side_effects() {
        let plan = AccessPlan::new("gh", "op")
            .with_step(AccessPlanStep::new("do", "thing", 0).with_side_effect("writes log"));
        let lines = format_plan_toon(&plan);
        assert!(lines.iter().any(|l| l.contains("Side-effect")));
    }

    // ── format_bundle_toon ───────────────────────────────────────

    #[test]
    fn format_bundle_toon_basic() {
        let b = AccessBundle::new("bnd-1").with_status(BundleStatus::Active);
        let lines = format_bundle_toon(&b);
        assert!(lines[0].contains("Access Bundle"));
        assert!(lines.iter().any(|l| l.contains("active")));
    }

    #[test]
    fn format_bundle_toon_with_grants() {
        let exp = Utc::now() + Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        let b = AccessBundle::new("bnd-1").with_grant(g);
        let lines = format_bundle_toon(&b);
        assert!(lines.iter().any(|l| l.contains("grt-1")));
        assert!(lines.iter().any(|l| l.contains("operation")));
    }

    #[test]
    fn format_bundle_toon_justification() {
        let b = AccessBundle::new("bnd-1").with_justification("need access");
        let lines = format_bundle_toon(&b);
        assert!(lines.iter().any(|l| l.contains("Justification")));
    }

    #[test]
    fn format_bundle_toon_receipt() {
        let b = AccessBundle::new("bnd-1").with_receipt("rcpt-xyz");
        let lines = format_bundle_toon(&b);
        assert!(lines.iter().any(|l| l.contains("rcpt-xyz")));
    }

    // ── format_grant_toon ────────────────────────────────────────

    #[test]
    fn format_grant_toon_active() {
        let exp = Utc::now() + Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        let lines = format_grant_toon(&g);
        assert!(lines[0].contains("ACTIVE"));
        assert!(lines.iter().any(|l| l.contains("operation")));
    }

    #[test]
    fn format_grant_toon_expired() {
        let exp = Utc::now() - Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        let lines = format_grant_toon(&g);
        assert!(lines[0].contains("EXPIRED"));
        assert!(lines.iter().any(|l| l.contains("expired")));
    }

    #[test]
    fn format_grant_toon_non_revocable() {
        let exp = Utc::now() + Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp).non_revocable();
        let lines = format_grant_toon(&g);
        assert!(lines.iter().any(|l| l.contains("false")));
    }

    // ── format_blocker_toon ──────────────────────────────────────

    #[test]
    fn format_blocker_toon_basic() {
        let b = AccessBlocker::new("no_creds", "missing credentials", BlockerSeverity::Error);
        let lines = format_blocker_toon(&b);
        assert!(lines[0].contains("[X]"));
        assert!(lines[0].contains("no_creds"));
    }

    #[test]
    fn format_blocker_toon_with_remedy() {
        let b = AccessBlocker::new("no_creds", "missing", BlockerSeverity::Error)
            .with_remediation("add creds");
        let lines = format_blocker_toon(&b);
        assert!(lines.len() >= 2);
        assert!(lines[1].contains("Remedy"));
    }

    #[test]
    fn format_blocker_toon_info() {
        let b = AccessBlocker::new("info1", "fyi", BlockerSeverity::Info);
        let lines = format_blocker_toon(&b);
        assert!(lines[0].contains("[i]"));
    }

    #[test]
    fn format_blocker_toon_critical() {
        let b = AccessBlocker::new("crit", "bad", BlockerSeverity::Critical);
        let lines = format_blocker_toon(&b);
        assert!(lines[0].contains("[!!]"));
    }

    // ── format_inspection_toon ───────────────────────────────────

    #[test]
    fn format_inspection_toon_empty() {
        let i = AccessInspection::new("github");
        let lines = format_inspection_toon(&i);
        assert!(lines[0].contains("Access Inspection"));
        assert!(lines.iter().any(|l| l.contains("(none)")));
    }

    #[test]
    fn format_inspection_toon_with_operation() {
        let i = AccessInspection::new("github").with_operation("list_repos");
        let lines = format_inspection_toon(&i);
        assert!(lines[0].contains("github.list_repos"));
    }

    #[test]
    fn format_inspection_toon_with_grants() {
        let exp = Utc::now() + Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        let i = AccessInspection::new("github").with_grant(g);
        let lines = format_inspection_toon(&i);
        assert!(lines.iter().any(|l| l.contains("grt-1")));
        assert!(lines.iter().any(|l| l.contains("active")));
    }

    #[test]
    fn format_inspection_toon_with_sessions() {
        let s = ActiveSession::new("ses-1", "bnd-1");
        let i = AccessInspection::new("github").with_session(s);
        let lines = format_inspection_toon(&i);
        assert!(lines.iter().any(|l| l.contains("ses-1")));
        assert!(lines.iter().any(|l| l.contains("bnd-1")));
    }

    #[test]
    fn format_inspection_toon_with_audit() {
        let e =
            AuditEntry::new(AuditAction::Grant, "admin", "github.list").with_details("approved");
        let i = AccessInspection::new("github").with_audit_entry(e);
        let lines = format_inspection_toon(&i);
        assert!(lines.iter().any(|l| l.contains("grant")));
        assert!(lines.iter().any(|l| l.contains("admin")));
        assert!(lines.iter().any(|l| l.contains("approved")));
    }

    #[test]
    fn format_inspection_toon_audit_no_details() {
        let e = AuditEntry::new(AuditAction::Check, "bot", "gh.list");
        let i = AccessInspection::new("github").with_audit_entry(e);
        let lines = format_inspection_toon(&i);
        // Should not have a trailing " — " when details is None.
        let audit_line = lines.iter().find(|l| l.contains("check")).unwrap();
        assert!(!audit_line.ends_with(" — "));
    }

    // ── format_audit_entry_toon ──────────────────────────────────

    #[test]
    fn format_audit_entry_toon_basic() {
        let e = AuditEntry::new(AuditAction::Revoke, "admin", "github.list");
        let lines = format_audit_entry_toon(&e);
        assert!(lines[0].contains("revoke"));
        assert!(lines[0].contains("admin"));
    }

    #[test]
    fn format_audit_entry_toon_with_details() {
        let e = AuditEntry::new(AuditAction::Grant, "sys", "target").with_details("auto approved");
        let lines = format_audit_entry_toon(&e);
        assert!(lines.len() >= 2);
        assert!(lines[1].contains("auto approved"));
    }

    // ── Serialization round-trips ────────────────────────────────

    #[test]
    fn blocker_severity_serde_roundtrip() {
        let s = BlockerSeverity::Critical;
        let json = serde_json::to_string(&s).unwrap();
        let back: BlockerSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn bundle_status_serde_roundtrip() {
        let s = BundleStatus::Active;
        let json = serde_json::to_string(&s).unwrap();
        let back: BundleStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn grant_scope_serde_roundtrip() {
        let s = GrantScope::Zone;
        let json = serde_json::to_string(&s).unwrap();
        let back: GrantScope = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn check_args_serde_roundtrip() {
        let a = AccessCheckArgs::new("gh", "list")
            .with_zone("us-east-1")
            .with_context("env", "prod");
        let json = serde_json::to_string(&a).unwrap();
        let back: AccessCheckArgs = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector, "gh");
        assert_eq!(back.zone.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn plan_args_serde_roundtrip() {
        let a = AccessPlanArgs::new("gh", "list").with_dry_run();
        let json = serde_json::to_string(&a).unwrap();
        let back: AccessPlanArgs = serde_json::from_str(&json).unwrap();
        assert!(back.dry_run);
    }

    #[test]
    fn request_args_serde_roundtrip() {
        let a = AccessRequestArgs::new("gh", "list", "reason");
        let json = serde_json::to_string(&a).unwrap();
        let back: AccessRequestArgs = serde_json::from_str(&json).unwrap();
        assert_eq!(back.justification, "reason");
    }

    #[test]
    fn access_check_result_serde() {
        let r = AccessCheckResult::allowed("gh", "list");
        let json = serde_json::to_string(&r).unwrap();
        let back: AccessCheckResult = serde_json::from_str(&json).unwrap();
        assert!(back.allowed);
    }

    #[test]
    fn access_grant_serde() {
        let exp = Utc::now() + Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, exp);
        let json = serde_json::to_string(&g).unwrap();
        let back: AccessGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(back.handle, "grt-1");
    }

    #[test]
    fn access_bundle_serde() {
        let b = AccessBundle::new("bnd-1")
            .with_status(BundleStatus::Active)
            .with_justification("reason");
        let json = serde_json::to_string(&b).unwrap();
        let back: AccessBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, BundleStatus::Active);
    }

    #[test]
    fn audit_entry_serde() {
        let e = AuditEntry::new(AuditAction::Grant, "admin", "gh").with_details("ok");
        let json = serde_json::to_string(&e).unwrap();
        let back: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.details.as_deref(), Some("ok"));
    }

    // ── Edge cases ───────────────────────────────────────────────

    #[test]
    fn check_access_multiple_contexts() {
        let args = AccessCheckArgs::new("gh", "list")
            .with_context("environment", "production")
            .with_context("team", "security");
        let result = check_access(&args).unwrap();
        // production adds warning but does not block
        assert!(result.allowed);
        assert_eq!(result.warning_count(), 1);
    }

    #[test]
    fn check_access_restricted_zone_with_production() {
        let args = AccessCheckArgs::new("gh", "list")
            .with_zone("restricted-prod")
            .with_context("environment", "production");
        let result = check_access(&args).unwrap();
        assert!(!result.allowed);
        assert_eq!(result.blockers.len(), 2);
    }

    #[test]
    fn plan_access_no_production_prereqs() {
        let args = AccessPlanArgs::new("gh", "list").with_context("environment", "staging");
        let plan = plan_access(&args).unwrap();
        assert!(!plan.has_prerequisites());
    }

    #[test]
    fn bundle_all_grants_expired() {
        let past = Utc::now() - Duration::hours(1);
        let b = AccessBundle::new("bnd-1")
            .with_grant(AccessGrant::new(
                "g1",
                "c",
                "o",
                GrantScope::Operation,
                past,
            ))
            .with_grant(AccessGrant::new(
                "g2",
                "c",
                "o",
                GrantScope::Operation,
                past,
            ));
        assert_eq!(b.active_grant_count(), 0);
        assert_eq!(b.grant_count(), 2);
    }

    #[test]
    fn inspection_expired_grant_counted() {
        let past = Utc::now() - Duration::hours(1);
        let g = AccessGrant::new("grt-1", "gh", "list", GrantScope::Operation, past);
        let i = AccessInspection::new("gh").with_grant(g);
        assert!(i.has_grants());
        assert_eq!(i.active_grant_count(), 0);
    }

    #[test]
    fn format_check_toon_lines_count_allowed() {
        let r = AccessCheckResult::allowed("gh", "op");
        let lines = format_check_toon(&r);
        assert!(lines.len() >= 5); // header + connector + operation + checked + blockers
    }

    #[test]
    fn format_check_toon_lines_count_blocked() {
        let blockers =
            vec![AccessBlocker::new("a", "msg", BlockerSeverity::Error).with_remediation("fix")];
        let r = AccessCheckResult::blocked("gh", "op", blockers);
        let lines = format_check_toon(&r);
        assert!(lines.len() >= 6);
    }

    #[test]
    fn format_plan_toon_empty_steps() {
        let plan = AccessPlan::new("gh", "op");
        let lines = format_plan_toon(&plan);
        assert!(lines.iter().any(|l| l.contains("Steps: 0")));
    }

    #[test]
    fn format_bundle_toon_empty_grants() {
        let b = AccessBundle::new("bnd-1");
        let lines = format_bundle_toon(&b);
        assert!(lines.iter().any(|l| l.contains("Grants:  0")));
    }

    #[test]
    fn format_inspection_toon_all_sections_empty() {
        let i = AccessInspection::new("gh");
        let lines = format_inspection_toon(&i);
        let none_count = lines.iter().filter(|l| l.contains("(none)")).count();
        assert_eq!(none_count, 3); // grants, sessions, audit
    }

    #[test]
    fn handle_with_dots_valid() {
        assert!(is_valid_handle("bnd.abc.123"));
    }

    #[test]
    fn handle_with_underscores_valid() {
        assert!(is_valid_handle("bnd_abc_123"));
    }

    #[test]
    fn handle_with_mixed_valid() {
        assert!(is_valid_handle("bnd-abc_123.xyz"));
    }

    #[test]
    fn check_result_no_blockers_counts() {
        let r = AccessCheckResult::allowed("c", "o");
        assert_eq!(r.blocking_count(), 0);
        assert_eq!(r.warning_count(), 0);
    }

    #[test]
    fn blocker_all_severities() {
        for sev in [
            BlockerSeverity::Info,
            BlockerSeverity::Warning,
            BlockerSeverity::Error,
            BlockerSeverity::Critical,
        ] {
            let b = AccessBlocker::new("code", "msg", sev);
            assert_eq!(b.severity, sev);
            assert!(!b.code.is_empty());
        }
    }

    #[test]
    fn plan_step_zero_index() {
        let s = AccessPlanStep::new("a", "b", 0);
        assert_eq!(s.index, 0);
    }

    #[test]
    fn plan_step_large_index() {
        let s = AccessPlanStep::new("a", "b", 999);
        assert_eq!(s.index, 999);
    }

    #[test]
    fn grant_scope_all_variants_label() {
        let scopes = [
            GrantScope::Operation,
            GrantScope::Connector,
            GrantScope::Zone,
            GrantScope::Global,
        ];
        for s in scopes {
            assert!(!s.label().is_empty());
        }
    }

    #[test]
    fn bundle_status_all_variants_label() {
        let statuses = [
            BundleStatus::Pending,
            BundleStatus::Active,
            BundleStatus::Revoked,
            BundleStatus::Expired,
            BundleStatus::Denied,
            BundleStatus::Partial,
        ];
        for s in statuses {
            assert!(!s.label().is_empty());
        }
    }

    #[test]
    fn audit_action_all_variants_label() {
        let actions = [
            AuditAction::Check,
            AuditAction::Request,
            AuditAction::Grant,
            AuditAction::Deny,
            AuditAction::Revoke,
            AuditAction::Attach,
            AuditAction::Resume,
            AuditAction::Expire,
        ];
        for a in actions {
            assert!(!a.label().is_empty());
        }
    }

    // ── AuthorizationVerdict ────────────────────────────────────────

    #[test]
    fn verdict_labels() {
        assert_eq!(AuthorizationVerdict::Allowed.label(), "allowed");
        assert_eq!(
            AuthorizationVerdict::ConditionallyAllowed.label(),
            "conditionally_allowed"
        );
        assert_eq!(AuthorizationVerdict::Blocked.label(), "blocked");
    }

    #[test]
    fn verdict_display() {
        assert_eq!(format!("{}", AuthorizationVerdict::Allowed), "allowed");
        assert_eq!(format!("{}", AuthorizationVerdict::Blocked), "blocked");
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let v = AuthorizationVerdict::ConditionallyAllowed;
        let json = serde_json::to_string(&v).unwrap();
        let back: AuthorizationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // ── BlockerType ─────────────────────────────────────────────────

    #[test]
    fn blocker_type_fcp_err_codes() {
        assert_eq!(
            BlockerType::MissingCapability.label(),
            "FCP_ERR_MISSING_CAPABILITY"
        );
        assert_eq!(
            BlockerType::CeilingViolation.label(),
            "FCP_ERR_CEILING_VIOLATION"
        );
        assert_eq!(BlockerType::ApprovalGated.label(), "FCP_ERR_APPROVAL_GATED");
        assert_eq!(BlockerType::ZoneMismatch.label(), "FCP_ERR_ZONE_MISMATCH");
        assert_eq!(BlockerType::OverBroadRequest.label(), "FCP_ERR_OVER_BROAD");
        assert_eq!(
            BlockerType::ExpiredCredential.label(),
            "FCP_ERR_EXPIRED_CREDENTIAL"
        );
        assert_eq!(BlockerType::PolicyDenied.label(), "FCP_ERR_POLICY_DENIED");
    }

    #[test]
    fn blocker_type_display() {
        assert_eq!(
            format!("{}", BlockerType::MissingCapability),
            "FCP_ERR_MISSING_CAPABILITY"
        );
    }

    #[test]
    fn blocker_type_serde_roundtrip() {
        let bt = BlockerType::CeilingViolation;
        let json = serde_json::to_string(&bt).unwrap();
        let back: BlockerType = serde_json::from_str(&json).unwrap();
        assert_eq!(bt, back);
    }

    // ── GrantDiffEntry ──────────────────────────────────────────────

    #[test]
    fn grant_diff_entry_new() {
        let e = GrantDiffEntry::new(
            "read",
            GrantScope::Operation,
            GrantDiffAction::Add,
            "github",
        );
        assert_eq!(e.capability, "read");
        assert_eq!(e.target, "github");
        assert!(e.rationale.is_empty());
    }

    #[test]
    fn grant_diff_entry_with_rationale() {
        let e = GrantDiffEntry::new(
            "write",
            GrantScope::Connector,
            GrantDiffAction::Modify,
            "slack",
        )
        .with_rationale("Need write for messages");
        assert_eq!(e.rationale, "Need write for messages");
    }

    #[test]
    fn grant_diff_action_display() {
        assert_eq!(format!("{}", GrantDiffAction::Add), "add");
        assert_eq!(format!("{}", GrantDiffAction::Modify), "modify");
        assert_eq!(format!("{}", GrantDiffAction::Narrow), "narrow");
    }

    // ── GrantDiff ───────────────────────────────────────────────────

    #[test]
    fn grant_diff_empty() {
        let d = GrantDiff::new();
        assert_eq!(d.change_count(), 0);
        assert!(d.is_minimal);
        assert!(!d.has_alternatives());
    }

    #[test]
    fn grant_diff_with_entries() {
        let d = GrantDiff::new()
            .with_entry(GrantDiffEntry::new(
                "a",
                GrantScope::Operation,
                GrantDiffAction::Add,
                "t",
            ))
            .with_entry(GrantDiffEntry::new(
                "b",
                GrantScope::Operation,
                GrantDiffAction::Add,
                "t",
            ));
        assert_eq!(d.change_count(), 2);
        assert!(d.is_minimal);
    }

    #[test]
    fn grant_diff_with_alternative() {
        let d = GrantDiff::new().with_alternative(GrantDiffAlternative::new(
            "Smaller",
            GrantScope::Operation,
            "read",
            "Less risky",
        ));
        assert!(!d.is_minimal);
        assert!(d.has_alternatives());
    }

    #[test]
    fn grant_diff_default() {
        let d = GrantDiff::default();
        assert_eq!(d.change_count(), 0);
    }

    #[test]
    fn grant_diff_serde_roundtrip() {
        let d = GrantDiff::new().with_entry(GrantDiffEntry::new(
            "cap",
            GrantScope::Zone,
            GrantDiffAction::Add,
            "gh",
        ));
        let json = serde_json::to_string(&d).unwrap();
        let back: GrantDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].capability, "cap");
    }

    // ── GrantDiffAlternative ────────────────────────────────────────

    #[test]
    fn alternative_new() {
        let a = GrantDiffAlternative::new("desc", GrantScope::Operation, "read", "safer");
        assert_eq!(a.description, "desc");
        assert_eq!(a.capability, "read");
        assert_eq!(a.reason, "safer");
    }

    // ── TypedBlocker ────────────────────────────────────────────────

    #[test]
    fn typed_blocker_new() {
        let b = TypedBlocker::new(
            BlockerType::MissingCapability,
            "missing",
            BlockerSeverity::Error,
        );
        assert_eq!(b.blocker_type, BlockerType::MissingCapability);
        assert_eq!(b.message, "missing");
        assert!(b.remediation.is_empty());
    }

    #[test]
    fn typed_blocker_with_remediation() {
        let b = TypedBlocker::new(
            BlockerType::ZoneMismatch,
            "bad zone",
            BlockerSeverity::Error,
        )
        .with_remediation("Use z:work");
        assert_eq!(b.remediation.len(), 1);
        assert_eq!(b.remediation[0], "Use z:work");
    }

    #[test]
    fn typed_blocker_serde_roundtrip() {
        let b = TypedBlocker::new(
            BlockerType::ApprovalGated,
            "needs approval",
            BlockerSeverity::Warning,
        );
        let json = serde_json::to_string(&b).unwrap();
        let back: TypedBlocker = serde_json::from_str(&json).unwrap();
        assert_eq!(back.blocker_type, BlockerType::ApprovalGated);
    }

    // ── CapabilityGapAnalysis ───────────────────────────────────────

    #[test]
    fn gap_analysis_allowed() {
        let a = CapabilityGapAnalysis::allowed("gh", "read", "z:work");
        assert_eq!(a.verdict, AuthorizationVerdict::Allowed);
        assert!(a.blockers.is_empty());
        assert_eq!(a.grant_diff.change_count(), 0);
    }

    #[test]
    fn gap_analysis_with_blocker_becomes_blocked() {
        let a = CapabilityGapAnalysis::allowed("gh", "write", "z:work").with_blocker(
            TypedBlocker::new(
                BlockerType::MissingCapability,
                "missing",
                BlockerSeverity::Error,
            ),
        );
        assert_eq!(a.verdict, AuthorizationVerdict::Blocked);
        assert_eq!(a.blockers.len(), 1);
    }

    #[test]
    fn gap_analysis_approval_gated_is_conditional() {
        let a = CapabilityGapAnalysis::allowed("gh", "admin", "z:work").with_blocker(
            TypedBlocker::new(
                BlockerType::ApprovalGated,
                "needs approval",
                BlockerSeverity::Warning,
            ),
        );
        assert_eq!(a.verdict, AuthorizationVerdict::ConditionallyAllowed);
    }

    #[test]
    fn gap_analysis_has_blocker_type() {
        let a = CapabilityGapAnalysis::allowed("gh", "op", "z:work").with_blocker(
            TypedBlocker::new(BlockerType::ZoneMismatch, "msg", BlockerSeverity::Error),
        );
        assert!(a.has_blocker_type(BlockerType::ZoneMismatch));
        assert!(!a.has_blocker_type(BlockerType::MissingCapability));
    }

    #[test]
    fn gap_analysis_blocker_count_by_type() {
        let a = CapabilityGapAnalysis::allowed("gh", "op", "z:work")
            .with_blocker(TypedBlocker::new(
                BlockerType::MissingCapability,
                "a",
                BlockerSeverity::Error,
            ))
            .with_blocker(TypedBlocker::new(
                BlockerType::MissingCapability,
                "b",
                BlockerSeverity::Error,
            ))
            .with_blocker(TypedBlocker::new(
                BlockerType::CeilingViolation,
                "c",
                BlockerSeverity::Critical,
            ));
        assert_eq!(a.blocker_count_by_type(BlockerType::MissingCapability), 2);
        assert_eq!(a.blocker_count_by_type(BlockerType::CeilingViolation), 1);
    }

    #[test]
    fn gap_analysis_with_follow_up() {
        let a = CapabilityGapAnalysis::allowed("gh", "op", "z:work")
            .with_follow_up("fwc access check gh op");
        assert_eq!(a.follow_up_commands.len(), 1);
    }

    #[test]
    fn gap_analysis_serde_roundtrip() {
        let a =
            CapabilityGapAnalysis::allowed("gh", "read", "z:work").with_blocker(TypedBlocker::new(
                BlockerType::MissingCapability,
                "msg",
                BlockerSeverity::Error,
            ));
        let json = serde_json::to_string(&a).unwrap();
        let back: CapabilityGapAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdict, AuthorizationVerdict::Blocked);
        assert_eq!(back.blockers.len(), 1);
    }

    // ── analyze_capability_gap ──────────────────────────────────────

    #[test]
    fn analyze_gap_all_caps_present() {
        let existing = vec!["read".into(), "write".into()];
        let required = vec!["read".into()];
        let a = analyze_capability_gap("gh", "issues", "z:work", &existing, &required, None);
        assert_eq!(a.verdict, AuthorizationVerdict::Allowed);
        assert!(a.blockers.is_empty());
    }

    #[test]
    fn analyze_gap_missing_capability() {
        let existing = vec!["read".into()];
        let required = vec!["read".into(), "write".into()];
        let a = analyze_capability_gap("gh", "issues", "z:work", &existing, &required, None);
        assert_eq!(a.verdict, AuthorizationVerdict::Blocked);
        assert!(a.has_blocker_type(BlockerType::MissingCapability));
        assert_eq!(a.grant_diff.change_count(), 1);
        assert_eq!(a.grant_diff.entries[0].capability, "write");
    }

    #[test]
    fn analyze_gap_ceiling_violation() {
        let existing: Vec<String> = vec![];
        let required = vec!["admin".into()];
        let ceiling = vec!["read".into(), "write".into()];
        let a = analyze_capability_gap(
            "gh",
            "admin_op",
            "z:work",
            &existing,
            &required,
            Some(&ceiling),
        );
        assert!(a.has_blocker_type(BlockerType::CeilingViolation));
        assert!(a.has_blocker_type(BlockerType::MissingCapability));
    }

    #[test]
    fn analyze_gap_zone_mismatch() {
        let existing = vec!["read".into()];
        let required = vec!["read".into()];
        let a = analyze_capability_gap("gh", "issues", "invalid_zone", &existing, &required, None);
        assert!(a.has_blocker_type(BlockerType::ZoneMismatch));
    }

    #[test]
    fn analyze_gap_over_broad_request() {
        let existing: Vec<String> = vec![];
        let required: Vec<String> = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let a = analyze_capability_gap("gh", "op", "z:work", &existing, &required, None);
        assert!(a.has_blocker_type(BlockerType::OverBroadRequest));
        assert!(a.grant_diff.has_alternatives());
    }

    #[test]
    fn analyze_gap_over_broad_suggests_narrower() {
        let existing: Vec<String> = vec![];
        let required: Vec<String> = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let a = analyze_capability_gap("gh", "op", "z:work", &existing, &required, None);
        let alt = &a.grant_diff.alternatives[0];
        assert!(alt.description.contains("essential"));
        assert_eq!(alt.scope, GrantScope::Operation);
    }

    #[test]
    fn analyze_gap_follow_up_commands_when_blocked() {
        let existing: Vec<String> = vec![];
        let required = vec!["write".into()];
        let a = analyze_capability_gap("gh", "create", "z:work", &existing, &required, None);
        assert!(!a.follow_up_commands.is_empty());
        assert!(
            a.follow_up_commands
                .iter()
                .any(|c| c.contains("fwc access"))
        );
    }

    #[test]
    fn analyze_gap_no_follow_up_when_allowed() {
        let existing = vec!["read".into()];
        let required = vec!["read".into()];
        let a = analyze_capability_gap("gh", "list", "z:work", &existing, &required, None);
        assert!(a.follow_up_commands.is_empty());
    }

    #[test]
    fn analyze_gap_grant_diff_has_rationale() {
        let existing: Vec<String> = vec![];
        let required = vec!["write".into()];
        let a = analyze_capability_gap("gh", "create", "z:work", &existing, &required, None);
        assert!(!a.grant_diff.entries[0].rationale.is_empty());
    }

    #[test]
    fn analyze_gap_multiple_missing_caps() {
        let existing: Vec<String> = vec![];
        let required = vec!["read".into(), "write".into(), "admin".into()];
        let a = analyze_capability_gap("gh", "manage", "z:work", &existing, &required, None);
        assert_eq!(a.blocker_count_by_type(BlockerType::MissingCapability), 3);
        assert_eq!(a.grant_diff.change_count(), 3);
    }

    #[test]
    fn analyze_gap_ceiling_no_extra_for_present_caps() {
        let existing = vec!["read".into()];
        let required = vec!["read".into()];
        let ceiling = vec!["read".into(), "write".into()];
        let a =
            analyze_capability_gap("gh", "list", "z:work", &existing, &required, Some(&ceiling));
        assert_eq!(a.verdict, AuthorizationVerdict::Allowed);
        assert!(!a.has_blocker_type(BlockerType::CeilingViolation));
    }

    // ── format_gap_analysis_toon ────────────────────────────────────

    #[test]
    fn format_gap_toon_allowed() {
        let a = CapabilityGapAnalysis::allowed("gh", "read", "z:work");
        let lines = format_gap_analysis_toon(&a);
        assert!(lines[0].contains("allowed"));
        assert!(lines.iter().any(|l| l.contains("No blockers")));
    }

    #[test]
    fn format_gap_toon_blocked_shows_blocker() {
        let a = CapabilityGapAnalysis::allowed("gh", "write", "z:work").with_blocker(
            TypedBlocker::new(
                BlockerType::MissingCapability,
                "need write",
                BlockerSeverity::Error,
            )
            .with_remediation("fwc access request gh write"),
        );
        let lines = format_gap_analysis_toon(&a);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("FCP_ERR_MISSING_CAPABILITY"))
        );
        assert!(lines.iter().any(|l| l.contains("Remediation")));
    }

    #[test]
    fn format_gap_toon_shows_grant_diff() {
        let a = CapabilityGapAnalysis::allowed("gh", "write", "z:work").with_diff(
            GrantDiff::new().with_entry(GrantDiffEntry::new(
                "write",
                GrantScope::Operation,
                GrantDiffAction::Add,
                "gh",
            )),
        );
        let lines = format_gap_analysis_toon(&a);
        assert!(lines.iter().any(|l| l.contains("Grant diff")));
        assert!(lines.iter().any(|l| l.contains("write")));
    }

    #[test]
    fn format_gap_toon_shows_alternatives() {
        let a = CapabilityGapAnalysis::allowed("gh", "op", "z:work").with_diff(
            GrantDiff::new().with_alternative(GrantDiffAlternative::new(
                "Use read only",
                GrantScope::Operation,
                "read",
                "Safer",
            )),
        );
        let lines = format_gap_analysis_toon(&a);
        assert!(lines.iter().any(|l| l.contains("Safer alternatives")));
    }

    #[test]
    fn format_gap_toon_shows_follow_up() {
        let a = CapabilityGapAnalysis::allowed("gh", "op", "z:work")
            .with_follow_up("fwc access check gh op");
        let lines = format_gap_analysis_toon(&a);
        assert!(lines.iter().any(|l| l.contains("fwc access check")));
    }

    // ── Bundle lifecycle: abandon, stale-context, validate_resume ────

    #[test]
    fn bundle_abandon_pending_ok() {
        let mut b = AccessBundle::new("bnd-test");
        assert!(b.abandon().is_ok());
        assert_eq!(b.status, BundleStatus::Denied);
    }

    #[test]
    fn bundle_abandon_active_fails() {
        let mut b = AccessBundle::new("bnd-test").with_status(BundleStatus::Active);
        assert!(b.abandon().is_err());
        assert_eq!(b.status, BundleStatus::Active);
    }

    #[test]
    fn bundle_abandon_revoked_fails() {
        let mut b = AccessBundle::new("bnd-test").with_status(BundleStatus::Revoked);
        assert!(b.abandon().is_err());
    }

    #[test]
    fn bundle_stale_context_fresh() {
        let b = AccessBundle::new("bnd-test");
        assert!(!b.is_stale_context(Duration::hours(1)));
    }

    #[test]
    fn bundle_stale_context_old() {
        let mut b = AccessBundle::new("bnd-test");
        b.created_at = Utc::now() - Duration::hours(2);
        assert!(b.is_stale_context(Duration::hours(1)));
    }

    #[test]
    fn bundle_stale_context_not_pending() {
        let mut b = AccessBundle::new("bnd-test").with_status(BundleStatus::Active);
        b.created_at = Utc::now() - Duration::hours(2);
        assert!(!b.is_stale_context(Duration::hours(1)));
    }

    #[test]
    fn validate_resume_active_ok() {
        let b = AccessBundle::new("bnd-test").with_status(BundleStatus::Active);
        assert!(b.validate_resume().is_ok());
    }

    #[test]
    fn validate_resume_partial_ok() {
        let b = AccessBundle::new("bnd-test").with_status(BundleStatus::Partial);
        assert!(b.validate_resume().is_ok());
    }

    #[test]
    fn validate_resume_pending_err() {
        let b = AccessBundle::new("bnd-test");
        let err = b.validate_resume().unwrap_err();
        assert!(err.contains("pending"));
    }

    #[test]
    fn validate_resume_revoked_err() {
        let b = AccessBundle::new("bnd-test").with_status(BundleStatus::Revoked);
        let err = b.validate_resume().unwrap_err();
        assert!(err.contains("revoked"));
    }

    #[test]
    fn validate_resume_expired_err() {
        let b = AccessBundle::new("bnd-test").with_status(BundleStatus::Expired);
        let err = b.validate_resume().unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn validate_resume_denied_err() {
        let b = AccessBundle::new("bnd-test").with_status(BundleStatus::Denied);
        let err = b.validate_resume().unwrap_err();
        assert!(err.contains("denied"));
    }

    #[test]
    fn validate_resume_denied_has_guidance() {
        let b = AccessBundle::new("bnd-test").with_status(BundleStatus::Denied);
        let err = b.validate_resume().unwrap_err();
        assert!(err.contains("request a new one"));
    }

    // ── RemedyFamily ────────────────────────────────────────────────

    #[test]
    fn remedy_family_labels() {
        assert_eq!(RemedyFamily::Refresh.label(), "refresh");
        assert_eq!(RemedyFamily::ReApprove.label(), "re-approve");
        assert_eq!(RemedyFamily::ShrinkRequest.label(), "shrink-request");
        assert_eq!(RemedyFamily::PolicyChange.label(), "policy-change");
        assert_eq!(RemedyFamily::ZoneSwitch.label(), "zone-switch");
        assert_eq!(RemedyFamily::WaitForExpiry.label(), "wait");
    }

    #[test]
    fn remedy_family_display() {
        assert_eq!(format!("{}", RemedyFamily::Refresh), "refresh");
    }

    #[test]
    fn remedy_from_missing_capability() {
        assert_eq!(
            RemedyFamily::from_blocker(BlockerType::MissingCapability),
            RemedyFamily::ReApprove
        );
    }

    #[test]
    fn remedy_from_ceiling_violation() {
        assert_eq!(
            RemedyFamily::from_blocker(BlockerType::CeilingViolation),
            RemedyFamily::PolicyChange
        );
    }

    #[test]
    fn remedy_from_zone_mismatch() {
        assert_eq!(
            RemedyFamily::from_blocker(BlockerType::ZoneMismatch),
            RemedyFamily::ZoneSwitch
        );
    }

    #[test]
    fn remedy_from_over_broad() {
        assert_eq!(
            RemedyFamily::from_blocker(BlockerType::OverBroadRequest),
            RemedyFamily::ShrinkRequest
        );
    }

    #[test]
    fn remedy_from_expired_credential() {
        assert_eq!(
            RemedyFamily::from_blocker(BlockerType::ExpiredCredential),
            RemedyFamily::Refresh
        );
    }

    #[test]
    fn remedy_serde_roundtrip() {
        let r = RemedyFamily::PolicyChange;
        let json = serde_json::to_string(&r).unwrap();
        let back: RemedyFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // ── BlockerDiagnosis ────────────────────────────────────────────

    #[test]
    fn diagnosis_new() {
        let d = BlockerDiagnosis::new(BlockerType::MissingCapability, "missing write");
        assert_eq!(d.blocker_type, BlockerType::MissingCapability);
        assert_eq!(d.fcp_err_code, "FCP_ERR_MISSING_CAPABILITY");
        assert_eq!(d.remedy, RemedyFamily::ReApprove);
        assert!(!d.is_freshness_issue);
        assert!(d.failed_object.is_none());
    }

    #[test]
    fn diagnosis_with_next_command() {
        let d = BlockerDiagnosis::new(BlockerType::ZoneMismatch, "bad zone")
            .with_next_command("fwc zones");
        assert_eq!(d.next_commands.len(), 1);
    }

    #[test]
    fn diagnosis_with_freshness() {
        let d =
            BlockerDiagnosis::new(BlockerType::ExpiredCredential, "expired").with_freshness_issue();
        assert!(d.is_freshness_issue);
    }

    #[test]
    fn diagnosis_with_failed_object() {
        let d = BlockerDiagnosis::new(BlockerType::CeilingViolation, "ceiling")
            .with_failed_object("zone ceiling for z:work");
        assert_eq!(d.failed_object.as_deref(), Some("zone ceiling for z:work"));
    }

    #[test]
    fn diagnosis_serde_roundtrip() {
        let d = BlockerDiagnosis::new(BlockerType::PolicyDenied, "denied");
        let json = serde_json::to_string(&d).unwrap();
        let back: BlockerDiagnosis = serde_json::from_str(&json).unwrap();
        assert_eq!(back.blocker_type, BlockerType::PolicyDenied);
        assert_eq!(back.remedy, RemedyFamily::PolicyChange);
    }

    // ── diagnose_blocker ────────────────────────────────────────────

    #[test]
    fn diagnose_missing_capability() {
        let b = TypedBlocker::new(
            BlockerType::MissingCapability,
            "missing write",
            BlockerSeverity::Error,
        );
        let d = diagnose_blocker(&b, "github", "issues.create", "z:work");
        assert_eq!(d.remedy, RemedyFamily::ReApprove);
        assert!(
            d.next_commands
                .iter()
                .any(|c| c.contains("fwc access plan"))
        );
        assert!(
            d.next_commands
                .iter()
                .any(|c| c.contains("fwc access request"))
        );
    }

    #[test]
    fn diagnose_ceiling_violation() {
        let b = TypedBlocker::new(
            BlockerType::CeilingViolation,
            "exceeds ceiling",
            BlockerSeverity::Critical,
        );
        let d = diagnose_blocker(&b, "github", "admin", "z:work");
        assert_eq!(d.remedy, RemedyFamily::PolicyChange);
        assert!(d.failed_object.is_some());
        assert!(d.next_commands.iter().any(|c| c.contains("fwc zones")));
    }

    #[test]
    fn diagnose_approval_gated() {
        let b = TypedBlocker::new(
            BlockerType::ApprovalGated,
            "needs approval",
            BlockerSeverity::Warning,
        );
        let d = diagnose_blocker(&b, "github", "delete", "z:work");
        assert_eq!(d.remedy, RemedyFamily::ReApprove);
        assert!(
            d.next_commands
                .iter()
                .any(|c| c.contains("fwc access request"))
        );
        assert!(
            d.next_commands
                .iter()
                .any(|c| c.contains("pending-approvals"))
        );
    }

    #[test]
    fn diagnose_zone_mismatch() {
        let b = TypedBlocker::new(
            BlockerType::ZoneMismatch,
            "wrong zone",
            BlockerSeverity::Error,
        );
        let d = diagnose_blocker(&b, "github", "read", "invalid");
        assert_eq!(d.remedy, RemedyFamily::ZoneSwitch);
        assert!(d.next_commands.iter().any(|c| c.contains("fwc zones")));
    }

    #[test]
    fn diagnose_over_broad() {
        let b = TypedBlocker::new(
            BlockerType::OverBroadRequest,
            "too many caps",
            BlockerSeverity::Warning,
        );
        let d = diagnose_blocker(&b, "github", "manage", "z:work");
        assert_eq!(d.remedy, RemedyFamily::ShrinkRequest);
        assert!(
            d.next_commands
                .iter()
                .any(|c| c.contains("fwc access plan"))
        );
    }

    #[test]
    fn diagnose_expired_credential() {
        let b = TypedBlocker::new(
            BlockerType::ExpiredCredential,
            "token expired",
            BlockerSeverity::Error,
        );
        let d = diagnose_blocker(&b, "github", "read", "z:work");
        assert_eq!(d.remedy, RemedyFamily::Refresh);
        assert!(d.is_freshness_issue);
        assert!(d.failed_object.is_some());
        assert!(d.next_commands.iter().any(|c| c.contains("fwc auth")));
    }

    #[test]
    fn diagnose_policy_denied() {
        let b = TypedBlocker::new(
            BlockerType::PolicyDenied,
            "policy forbids",
            BlockerSeverity::Critical,
        );
        let d = diagnose_blocker(&b, "github", "admin", "z:private");
        assert_eq!(d.remedy, RemedyFamily::PolicyChange);
        assert!(d.failed_object.is_some());
        assert!(d.next_commands.iter().any(|c| c.contains("fwc zones")));
    }

    // ── format_diagnosis_toon ───────────────────────────────────────

    #[test]
    fn format_diagnosis_toon_shows_code() {
        let d = BlockerDiagnosis::new(BlockerType::MissingCapability, "missing");
        let lines = format_diagnosis_toon(&d);
        assert!(lines[0].contains("FCP_ERR_MISSING_CAPABILITY"));
    }

    #[test]
    fn format_diagnosis_toon_shows_remedy() {
        let d = BlockerDiagnosis::new(BlockerType::ZoneMismatch, "bad zone");
        let lines = format_diagnosis_toon(&d);
        assert!(lines.iter().any(|l| l.contains("zone-switch")));
    }

    #[test]
    fn format_diagnosis_toon_shows_failed_object() {
        let d = BlockerDiagnosis::new(BlockerType::CeilingViolation, "ceiling")
            .with_failed_object("zone ceiling for z:work");
        let lines = format_diagnosis_toon(&d);
        assert!(lines.iter().any(|l| l.contains("zone ceiling for z:work")));
    }

    #[test]
    fn format_diagnosis_toon_shows_freshness_note() {
        let d =
            BlockerDiagnosis::new(BlockerType::ExpiredCredential, "expired").with_freshness_issue();
        let lines = format_diagnosis_toon(&d);
        assert!(lines.iter().any(|l| l.contains("freshness")));
    }

    #[test]
    fn format_diagnosis_toon_shows_next_steps() {
        let d = BlockerDiagnosis::new(BlockerType::MissingCapability, "missing")
            .with_next_command("fwc access plan gh op");
        let lines = format_diagnosis_toon(&d);
        assert!(lines.iter().any(|l| l.contains("fwc access plan")));
    }

    // ── Verification matrix: full path coverage ─────────────────────

    #[test]
    fn matrix_allowed_path() {
        let existing = vec!["read".into(), "write".into()];
        let required = vec!["read".into()];
        let gap = analyze_capability_gap("gh", "list", "z:work", &existing, &required, None);
        assert_eq!(gap.verdict, AuthorizationVerdict::Allowed);
        assert!(gap.blockers.is_empty());
        assert_eq!(gap.grant_diff.change_count(), 0);
        // TOON output verifiable
        let toon = format_gap_analysis_toon(&gap);
        assert!(toon[0].contains("allowed"));
    }

    #[test]
    fn matrix_approval_gated_path() {
        let gap = CapabilityGapAnalysis::allowed("gh", "delete", "z:work").with_blocker(
            TypedBlocker::new(
                BlockerType::ApprovalGated,
                "delete requires manager approval",
                BlockerSeverity::Warning,
            ),
        );
        assert_eq!(gap.verdict, AuthorizationVerdict::ConditionallyAllowed);
        let diag = diagnose_blocker(&gap.blockers[0], "gh", "delete", "z:work");
        assert_eq!(diag.remedy, RemedyFamily::ReApprove);
        // JSON round-trips
        let json = serde_json::to_string(&gap).unwrap();
        let back: CapabilityGapAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdict, AuthorizationVerdict::ConditionallyAllowed);
    }

    #[test]
    fn matrix_denied_path() {
        let gap = analyze_capability_gap("gh", "admin", "z:work", &[], &["admin".into()], None);
        assert_eq!(gap.verdict, AuthorizationVerdict::Blocked);
        let diag = diagnose_blocker(&gap.blockers[0], "gh", "admin", "z:work");
        assert_eq!(diag.remedy, RemedyFamily::ReApprove);
        let toon = format_gap_analysis_toon(&gap);
        assert!(toon.iter().any(|l| l.contains("FCP_ERR")));
    }

    #[test]
    fn matrix_stale_context_path() {
        let mut bundle = AccessBundle::new("bnd-stale");
        bundle.created_at = Utc::now() - Duration::hours(25);
        assert!(bundle.is_stale_context(Duration::hours(24)));
        assert!(bundle.validate_resume().is_err());
    }

    #[test]
    fn matrix_superseded_path() {
        let mut bundle = AccessBundle::new("bnd-old").with_status(BundleStatus::Active);
        bundle.revoke();
        assert_eq!(bundle.status, BundleStatus::Revoked);
        let err = bundle.validate_resume().unwrap_err();
        assert!(err.contains("revoked"));
    }

    #[test]
    fn matrix_changed_context_expired() {
        let mut bundle = AccessBundle::new("bnd-expired").with_status(BundleStatus::Active);
        bundle.expire();
        assert_eq!(bundle.status, BundleStatus::Expired);
        let err = bundle.validate_resume().unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn matrix_cross_zone_path() {
        let gap = analyze_capability_gap(
            "gh",
            "read",
            "not-a-zone",
            &["read".into()],
            &["read".into()],
            None,
        );
        assert!(gap.has_blocker_type(BlockerType::ZoneMismatch));
        let diag = diagnose_blocker(&gap.blockers[0], "gh", "read", "not-a-zone");
        assert_eq!(diag.remedy, RemedyFamily::ZoneSwitch);
    }

    #[test]
    fn matrix_policy_conflict_path() {
        let gap = CapabilityGapAnalysis::allowed("gh", "admin", "z:private").with_blocker(
            TypedBlocker::new(
                BlockerType::PolicyDenied,
                "z:private policy forbids admin operations",
                BlockerSeverity::Critical,
            ),
        );
        assert_eq!(gap.verdict, AuthorizationVerdict::Blocked);
        let diag = diagnose_blocker(&gap.blockers[0], "gh", "admin", "z:private");
        assert_eq!(diag.remedy, RemedyFamily::PolicyChange);
        let toon = format_diagnosis_toon(&diag);
        assert!(toon.iter().any(|l| l.contains("FCP_ERR_POLICY_DENIED")));
    }

    #[test]
    fn matrix_toon_json_parity() {
        let gap = analyze_capability_gap("gh", "write", "z:work", &[], &["write".into()], None);
        // TOON has the verdict
        let toon = format_gap_analysis_toon(&gap);
        assert!(toon[0].contains("blocked"));
        // JSON has the same verdict
        let json: serde_json::Value = serde_json::to_value(&gap).unwrap();
        assert_eq!(json["verdict"], "blocked");
        // Both have the blocker
        assert!(
            toon.iter()
                .any(|l| l.contains("FCP_ERR_MISSING_CAPABILITY"))
        );
        assert!(
            json["blockers"][0]["blocker_type"]
                .as_str()
                .unwrap()
                .contains("missing_capability")
        );
    }

    #[test]
    fn matrix_all_blocker_types_have_diagnoses() {
        let types = [
            BlockerType::MissingCapability,
            BlockerType::CeilingViolation,
            BlockerType::ApprovalGated,
            BlockerType::ZoneMismatch,
            BlockerType::OverBroadRequest,
            BlockerType::ExpiredCredential,
            BlockerType::PolicyDenied,
        ];
        for bt in types {
            let blocker = TypedBlocker::new(bt, "test", BlockerSeverity::Error);
            let diag = diagnose_blocker(&blocker, "gh", "op", "z:work");
            assert!(!diag.fcp_err_code.is_empty());
            assert!(
                !diag.next_commands.is_empty(),
                "blocker type {bt} should have next commands"
            );
        }
    }

    #[test]
    fn matrix_all_remedy_families_from_blockers() {
        let remedies: Vec<RemedyFamily> = [
            BlockerType::MissingCapability,
            BlockerType::CeilingViolation,
            BlockerType::ApprovalGated,
            BlockerType::ZoneMismatch,
            BlockerType::OverBroadRequest,
            BlockerType::ExpiredCredential,
            BlockerType::PolicyDenied,
        ]
        .iter()
        .map(|bt| RemedyFamily::from_blocker(*bt))
        .collect();
        // We should have at least 4 distinct remedies.
        let unique: std::collections::BTreeSet<String> =
            remedies.iter().map(|r| r.label().to_owned()).collect();
        assert!(
            unique.len() >= 4,
            "Expected at least 4 distinct remedies, got {}",
            unique.len()
        );
    }
}
