//! Lifecycle mutation contract for FWC connector lifecycle management.
//!
//! Implements the state machine for enable/disable/start/stop/restart actions
//! on connectors.  Every transition is validated against the state machine,
//! pre-flight checked for safety, and produces a tamper-evident receipt.
//!
//! # State machine
//!
//! ```text
//! Disabled ──Enable──▶ Enabled ──Start──▶ Starting ──▶ Running
//! Running  ──Stop───▶ Stopping ──▶ Stopped
//! Running  ──ForceStop──▶ Stopped
//! Running  ──Disable──▶ Draining ──▶ Disabled
//! Stopped  ──Start──▶ Starting ──▶ Running
//! Stopped  ──Disable──▶ Disabled
//! Failed   ──Restart──▶ Starting ──▶ Running
//! Any      ──Restart──▶ (Stop→Start)
//! ```

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Enums ─────────────────────────────────────────────────────────────

/// Actions that can be performed on a connector's lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Enable,
    Disable,
    Start,
    Stop,
    Restart,
    ForceStop,
}

impl LifecycleAction {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::ForceStop => "force-stop",
        }
    }

    /// Whether this action is potentially destructive.
    pub const fn is_destructive(self) -> bool {
        matches!(self, Self::ForceStop | Self::Disable)
    }

    /// Whether this action requires the connector to be running.
    pub const fn requires_running(self) -> bool {
        matches!(self, Self::Stop | Self::ForceStop)
    }

    /// All variants in declaration order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Enable,
            Self::Disable,
            Self::Start,
            Self::Stop,
            Self::Restart,
            Self::ForceStop,
        ]
    }
}

impl fmt::Display for LifecycleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Possible states of a connector's lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Unknown,
    Disabled,
    Enabled,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
    Draining,
}

impl LifecycleState {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Draining => "draining",
        }
    }

    /// Whether this state is considered healthy.
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Enabled | Self::Running)
    }

    /// Whether this state is a terminal failure.
    pub const fn is_terminal_failure(self) -> bool {
        matches!(self, Self::Failed)
    }

    /// Whether the connector is in a transient state.
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::Starting | Self::Stopping | Self::Draining)
    }

    /// All variants in declaration order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Unknown,
            Self::Disabled,
            Self::Enabled,
            Self::Starting,
            Self::Running,
            Self::Stopping,
            Self::Stopped,
            Self::Failed,
            Self::Draining,
        ]
    }
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Error ─────────────────────────────────────────────────────────────

/// Error returned when a lifecycle transition is invalid.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransitionError {
    pub from: LifecycleState,
    pub action: LifecycleAction,
    pub reason: String,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot {} from {}: {}",
            self.action.label(),
            self.from.label(),
            self.reason
        )
    }
}

impl std::error::Error for TransitionError {}

// ── Risk level ────────────────────────────────────────────────────────

/// Risk level for a lifecycle mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationRisk {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl MutationRisk {
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Whether confirmation is required at this risk level.
    pub const fn requires_confirmation(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

impl fmt::Display for MutationRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Request / Result ──────────────────────────────────────────────────

/// A request to mutate a connector's lifecycle state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutationRequest {
    /// Target connector identifier.
    pub target: String,
    /// The lifecycle action to perform.
    pub action: LifecycleAction,
    /// Force the action even if unsafe.
    pub force: bool,
    /// Timeout for the operation.
    pub timeout: Option<Duration>,
    /// Dry-run mode: validate without executing.
    pub dry_run: bool,
    /// Optional operator name for audit.
    pub operator: Option<String>,
}

impl MutationRequest {
    /// Create a new mutation request.
    pub fn new(target: impl Into<String>, action: LifecycleAction) -> Self {
        Self {
            target: target.into(),
            action,
            force: false,
            timeout: None,
            dry_run: false,
            operator: None,
        }
    }

    /// Builder: set force.
    #[must_use]
    pub const fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Builder: set timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Builder: set `dry_run`.
    #[must_use]
    pub const fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Builder: set operator.
    #[must_use]
    pub fn with_operator(mut self, operator: impl Into<String>) -> Self {
        self.operator = Some(operator.into());
        self
    }
}

/// Result of a lifecycle mutation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutationResult {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Previous state.
    pub old_state: LifecycleState,
    /// New state after the mutation.
    pub new_state: LifecycleState,
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Duration the mutation took.
    pub duration: Duration,
    /// Warnings generated during the mutation.
    pub warnings: Vec<String>,
    /// Error message if the mutation failed.
    pub error: Option<String>,
}

impl MutationResult {
    /// Create a success result.
    pub fn success(
        old_state: LifecycleState,
        new_state: LifecycleState,
        receipt_id: impl Into<String>,
        duration: Duration,
    ) -> Self {
        Self {
            success: true,
            old_state,
            new_state,
            receipt_id: receipt_id.into(),
            duration,
            warnings: Vec::new(),
            error: None,
        }
    }

    /// Create a failure result.
    pub fn failure(
        old_state: LifecycleState,
        receipt_id: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            success: false,
            old_state,
            new_state: old_state,
            receipt_id: receipt_id.into(),
            duration: Duration::ZERO,
            warnings: Vec::new(),
            error: Some(error.into()),
        }
    }

    /// Add a warning.
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }
}

// ── PreflightCheck ────────────────────────────────────────────────────

/// Pre-action safety check before performing a lifecycle mutation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreflightCheck {
    /// The action being checked.
    pub action: LifecycleAction,
    /// Risk level of this mutation.
    pub risk_level: MutationRisk,
    /// Whether the user must confirm.
    pub requires_confirmation: bool,
    /// Warnings that should be shown.
    pub warnings: Vec<String>,
    /// Blockers that must be resolved before the action can proceed.
    pub blockers: Vec<String>,
    /// Whether the action is a safe no-op.
    pub is_noop: bool,
    /// Estimated duration.
    pub estimated_duration: Duration,
}

impl PreflightCheck {
    /// Whether the action can proceed (no blockers).
    pub fn can_proceed(&self) -> bool {
        self.blockers.is_empty()
    }

    /// Whether the action has any warnings or blockers.
    pub fn has_issues(&self) -> bool {
        !self.warnings.is_empty() || !self.blockers.is_empty()
    }
}

// ── TransitionRule ────────────────────────────────────────────────────

/// A rule in the lifecycle state machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransitionRule {
    /// Current state.
    pub from_state: LifecycleState,
    /// Action being taken.
    pub action: LifecycleAction,
    /// Target state.
    pub to_state: LifecycleState,
    /// Whether the transition requires operator approval.
    pub requires_approval: bool,
}

/// Return the full set of transition rules.
pub fn transition_rules() -> Vec<TransitionRule> {
    vec![
        TransitionRule {
            from_state: LifecycleState::Disabled,
            action: LifecycleAction::Enable,
            to_state: LifecycleState::Enabled,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Enabled,
            action: LifecycleAction::Start,
            to_state: LifecycleState::Starting,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Running,
            action: LifecycleAction::Stop,
            to_state: LifecycleState::Stopping,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Running,
            action: LifecycleAction::ForceStop,
            to_state: LifecycleState::Stopped,
            requires_approval: true,
        },
        TransitionRule {
            from_state: LifecycleState::Running,
            action: LifecycleAction::Disable,
            to_state: LifecycleState::Draining,
            requires_approval: true,
        },
        TransitionRule {
            from_state: LifecycleState::Running,
            action: LifecycleAction::Restart,
            to_state: LifecycleState::Starting,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Stopped,
            action: LifecycleAction::Start,
            to_state: LifecycleState::Starting,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Stopped,
            action: LifecycleAction::Disable,
            to_state: LifecycleState::Disabled,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Stopped,
            action: LifecycleAction::Restart,
            to_state: LifecycleState::Starting,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Failed,
            action: LifecycleAction::Restart,
            to_state: LifecycleState::Starting,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Failed,
            action: LifecycleAction::Stop,
            to_state: LifecycleState::Stopped,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Failed,
            action: LifecycleAction::Disable,
            to_state: LifecycleState::Disabled,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Enabled,
            action: LifecycleAction::Disable,
            to_state: LifecycleState::Disabled,
            requires_approval: false,
        },
        TransitionRule {
            from_state: LifecycleState::Enabled,
            action: LifecycleAction::Restart,
            to_state: LifecycleState::Starting,
            requires_approval: false,
        },
    ]
}

// ── MutationReceipt ───────────────────────────────────────────────────

/// Post-action receipt for audit trail.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutationReceipt {
    /// Unique receipt identifier.
    pub id: String,
    /// When the mutation was performed.
    pub timestamp: DateTime<Utc>,
    /// The action that was performed.
    pub action: LifecycleAction,
    /// Target connector identifier.
    pub target: String,
    /// Previous state.
    pub old_state: LifecycleState,
    /// New state after the mutation.
    pub new_state: LifecycleState,
    /// Operator who performed the action.
    pub operator: String,
    /// Duration of the mutation.
    pub duration: Duration,
    /// Whether this was a dry run.
    pub dry_run: bool,
    /// Whether force was used.
    pub forced: bool,
}

impl MutationReceipt {
    /// Create a receipt from a request and result.
    pub fn from_request_and_result(
        request: &MutationRequest,
        result: &MutationResult,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            id: result.receipt_id.clone(),
            timestamp,
            action: request.action,
            target: request.target.clone(),
            old_state: result.old_state,
            new_state: result.new_state,
            operator: request.operator.clone().unwrap_or_else(|| "system".into()),
            duration: result.duration,
            dry_run: request.dry_run,
            forced: request.force,
        }
    }
}

// ── Core functions ────────────────────────────────────────────────────

/// Validate a state transition and return the target state.
pub fn validate_transition(
    state: LifecycleState,
    action: LifecycleAction,
) -> Result<LifecycleState, TransitionError> {
    // Check for no-ops first.
    if is_safe_noop(state, action) {
        return Ok(state);
    }

    for rule in &transition_rules() {
        if rule.from_state == state && rule.action == action {
            return Ok(rule.to_state);
        }
    }

    Err(TransitionError {
        from: state,
        action,
        reason: format!(
            "no valid transition from '{}' via '{}'",
            state.label(),
            action.label()
        ),
    })
}

/// Whether performing the action in the current state is a safe no-op.
pub const fn is_safe_noop(state: LifecycleState, action: LifecycleAction) -> bool {
    matches!(
        (state, action),
        (LifecycleState::Enabled, LifecycleAction::Enable)
            | (LifecycleState::Disabled, LifecycleAction::Disable)
            | (LifecycleState::Stopped, LifecycleAction::Stop)
            | (LifecycleState::Running, LifecycleAction::Start)
    )
}

/// Whether the state can accept the given action.
pub fn state_can_accept(state: LifecycleState, action: LifecycleAction) -> bool {
    if is_safe_noop(state, action) {
        return true;
    }
    transition_rules()
        .iter()
        .any(|r| r.from_state == state && r.action == action)
}

/// Estimate the duration for an action.
pub const fn estimate_duration(action: LifecycleAction) -> Duration {
    match action {
        LifecycleAction::Enable => Duration::from_millis(100),
        LifecycleAction::Disable | LifecycleAction::Stop => Duration::from_secs(5),
        LifecycleAction::Start => Duration::from_secs(3),
        LifecycleAction::Restart => Duration::from_secs(8),
        LifecycleAction::ForceStop => Duration::from_millis(500),
    }
}

/// Compute the risk level for a (state, action) pair.
pub const fn compute_risk(state: LifecycleState, action: LifecycleAction) -> MutationRisk {
    match (state, action) {
        (_, LifecycleAction::ForceStop) => MutationRisk::Critical,
        (LifecycleState::Running, LifecycleAction::Disable) => MutationRisk::High,
        (LifecycleState::Running, LifecycleAction::Stop | LifecycleAction::Restart) => {
            MutationRisk::Medium
        }
        (_, LifecycleAction::Enable) => MutationRisk::None,
        _ => MutationRisk::Low,
    }
}

/// Pre-action safety check.
pub fn preflight(request: &MutationRequest, current_state: LifecycleState) -> PreflightCheck {
    let mut warnings = Vec::new();
    let mut blockers = Vec::new();
    let is_noop = is_safe_noop(current_state, request.action);

    // Validate the transition.
    if !is_noop {
        if let Err(e) = validate_transition(current_state, request.action) {
            blockers.push(e.reason);
        }
    }

    // Warn about transient states.
    if current_state.is_transient() && !request.force {
        warnings.push(format!(
            "connector is in transient state '{}'; action may be premature",
            current_state.label()
        ));
    }

    // Warn about force on destructive actions.
    if request.force && request.action.is_destructive() {
        warnings.push(format!(
            "forcing destructive action '{}' — data loss is possible",
            request.action.label()
        ));
    }

    // Dry-run notice.
    if request.dry_run {
        warnings.push("dry-run mode: no changes will be made".into());
    }

    let risk_level = compute_risk(current_state, request.action);
    let requires_confirmation = risk_level.requires_confirmation() && !request.force;

    PreflightCheck {
        action: request.action,
        risk_level,
        requires_confirmation,
        warnings,
        blockers,
        is_noop,
        estimated_duration: estimate_duration(request.action),
    }
}

/// Format a preflight check as TOON output.
pub fn format_preflight_toon(check: &PreflightCheck) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Preflight: {}", check.action.label()));
    lines.push(format!("  Risk:     {}", check.risk_level.label()));
    lines.push(format!("  Confirm:  {}", check.requires_confirmation));
    lines.push(format!("  No-op:    {}", check.is_noop));
    lines.push(format!(
        "  Duration: {:?}",
        check.estimated_duration
    ));

    if !check.warnings.is_empty() {
        lines.push("  Warnings:".into());
        for w in &check.warnings {
            lines.push(format!("    - {w}"));
        }
    }
    if !check.blockers.is_empty() {
        lines.push("  Blockers:".into());
        for b in &check.blockers {
            lines.push(format!("    ! {b}"));
        }
    }

    let verdict = if check.can_proceed() {
        "PASS"
    } else {
        "BLOCKED"
    };
    lines.push(format!("  Verdict:  {verdict}"));

    lines.join("\n")
}

/// Format a mutation receipt as TOON output.
pub fn format_receipt_toon(receipt: &MutationReceipt) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Receipt: {}", receipt.id));
    lines.push(format!("  Action:    {}", receipt.action.label()));
    lines.push(format!("  Target:    {}", receipt.target));
    lines.push(format!(
        "  Transition: {} -> {}",
        receipt.old_state.label(),
        receipt.new_state.label()
    ));
    lines.push(format!("  Operator:  {}", receipt.operator));
    lines.push(format!("  Duration:  {:?}", receipt.duration));
    lines.push(format!("  Timestamp: {}", receipt.timestamp));

    if receipt.dry_run {
        lines.push("  Mode:      DRY-RUN".into());
    }
    if receipt.forced {
        lines.push("  Forced:    yes".into());
    }

    lines.join("\n")
}

/// Format a denied transition as TOON output.
pub fn format_denied_toon(state: LifecycleState, action: LifecycleAction) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "DENIED: cannot {} from {}",
        action.label(),
        state.label()
    ));

    // Suggest valid actions for the current state.
    let valid: Vec<&str> = LifecycleAction::all()
        .iter()
        .filter(|a| state_can_accept(state, **a))
        .map(|a| a.label())
        .collect();

    if valid.is_empty() {
        lines.push("  No actions available in this state.".into());
    } else {
        lines.push(format!("  Available actions: {}", valid.join(", ")));
    }

    lines.join("\n")
}

/// Find all valid actions for a given state.
pub fn valid_actions(state: LifecycleState) -> Vec<LifecycleAction> {
    LifecycleAction::all()
        .iter()
        .copied()
        .filter(|a| state_can_accept(state, *a))
        .collect()
}

/// Find the transition rule for a (state, action) pair if one exists.
pub fn find_rule(
    state: LifecycleState,
    action: LifecycleAction,
) -> Option<TransitionRule> {
    transition_rules()
        .into_iter()
        .find(|r| r.from_state == state && r.action == action)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Valid transitions ────────────────────────────────────────────

    #[test]
    fn transition_disabled_enable() {
        let s = validate_transition(LifecycleState::Disabled, LifecycleAction::Enable);
        assert_eq!(s.unwrap(), LifecycleState::Enabled);
    }

    #[test]
    fn transition_enabled_start() {
        let s = validate_transition(LifecycleState::Enabled, LifecycleAction::Start);
        assert_eq!(s.unwrap(), LifecycleState::Starting);
    }

    #[test]
    fn transition_running_stop() {
        let s = validate_transition(LifecycleState::Running, LifecycleAction::Stop);
        assert_eq!(s.unwrap(), LifecycleState::Stopping);
    }

    #[test]
    fn transition_running_force_stop() {
        let s = validate_transition(LifecycleState::Running, LifecycleAction::ForceStop);
        assert_eq!(s.unwrap(), LifecycleState::Stopped);
    }

    #[test]
    fn transition_running_disable() {
        let s = validate_transition(LifecycleState::Running, LifecycleAction::Disable);
        assert_eq!(s.unwrap(), LifecycleState::Draining);
    }

    #[test]
    fn transition_running_restart() {
        let s = validate_transition(LifecycleState::Running, LifecycleAction::Restart);
        assert_eq!(s.unwrap(), LifecycleState::Starting);
    }

    #[test]
    fn transition_stopped_start() {
        let s = validate_transition(LifecycleState::Stopped, LifecycleAction::Start);
        assert_eq!(s.unwrap(), LifecycleState::Starting);
    }

    #[test]
    fn transition_stopped_disable() {
        let s = validate_transition(LifecycleState::Stopped, LifecycleAction::Disable);
        assert_eq!(s.unwrap(), LifecycleState::Disabled);
    }

    #[test]
    fn transition_stopped_restart() {
        let s = validate_transition(LifecycleState::Stopped, LifecycleAction::Restart);
        assert_eq!(s.unwrap(), LifecycleState::Starting);
    }

    #[test]
    fn transition_failed_restart() {
        let s = validate_transition(LifecycleState::Failed, LifecycleAction::Restart);
        assert_eq!(s.unwrap(), LifecycleState::Starting);
    }

    #[test]
    fn transition_failed_stop() {
        let s = validate_transition(LifecycleState::Failed, LifecycleAction::Stop);
        assert_eq!(s.unwrap(), LifecycleState::Stopped);
    }

    #[test]
    fn transition_failed_disable() {
        let s = validate_transition(LifecycleState::Failed, LifecycleAction::Disable);
        assert_eq!(s.unwrap(), LifecycleState::Disabled);
    }

    #[test]
    fn transition_enabled_disable() {
        let s = validate_transition(LifecycleState::Enabled, LifecycleAction::Disable);
        assert_eq!(s.unwrap(), LifecycleState::Disabled);
    }

    #[test]
    fn transition_enabled_restart() {
        let s = validate_transition(LifecycleState::Enabled, LifecycleAction::Restart);
        assert_eq!(s.unwrap(), LifecycleState::Starting);
    }

    // ── No-op transitions ───────────────────────────────────────────

    #[test]
    fn noop_enable_when_enabled() {
        assert!(is_safe_noop(LifecycleState::Enabled, LifecycleAction::Enable));
        let s = validate_transition(LifecycleState::Enabled, LifecycleAction::Enable);
        assert_eq!(s.unwrap(), LifecycleState::Enabled);
    }

    #[test]
    fn noop_disable_when_disabled() {
        assert!(is_safe_noop(LifecycleState::Disabled, LifecycleAction::Disable));
        let s = validate_transition(LifecycleState::Disabled, LifecycleAction::Disable);
        assert_eq!(s.unwrap(), LifecycleState::Disabled);
    }

    #[test]
    fn noop_stop_when_stopped() {
        assert!(is_safe_noop(LifecycleState::Stopped, LifecycleAction::Stop));
        let s = validate_transition(LifecycleState::Stopped, LifecycleAction::Stop);
        assert_eq!(s.unwrap(), LifecycleState::Stopped);
    }

    #[test]
    fn noop_start_when_running() {
        assert!(is_safe_noop(LifecycleState::Running, LifecycleAction::Start));
        let s = validate_transition(LifecycleState::Running, LifecycleAction::Start);
        assert_eq!(s.unwrap(), LifecycleState::Running);
    }

    #[test]
    fn not_noop_enable_when_disabled() {
        assert!(!is_safe_noop(LifecycleState::Disabled, LifecycleAction::Enable));
    }

    #[test]
    fn not_noop_start_when_stopped() {
        assert!(!is_safe_noop(LifecycleState::Stopped, LifecycleAction::Start));
    }

    #[test]
    fn not_noop_restart_when_running() {
        assert!(!is_safe_noop(LifecycleState::Running, LifecycleAction::Restart));
    }

    // ── Denied transitions ──────────────────────────────────────────

    #[test]
    fn denied_start_when_disabled() {
        let err = validate_transition(LifecycleState::Disabled, LifecycleAction::Start);
        assert!(err.is_err());
        let e = err.unwrap_err();
        assert_eq!(e.from, LifecycleState::Disabled);
        assert_eq!(e.action, LifecycleAction::Start);
    }

    #[test]
    fn denied_stop_when_disabled() {
        let err = validate_transition(LifecycleState::Disabled, LifecycleAction::Stop);
        assert!(err.is_err());
    }

    #[test]
    fn denied_force_stop_when_disabled() {
        let err = validate_transition(LifecycleState::Disabled, LifecycleAction::ForceStop);
        assert!(err.is_err());
    }

    #[test]
    fn denied_enable_when_running() {
        let err = validate_transition(LifecycleState::Running, LifecycleAction::Enable);
        assert!(err.is_err());
    }

    #[test]
    fn denied_start_when_starting() {
        let err = validate_transition(LifecycleState::Starting, LifecycleAction::Start);
        assert!(err.is_err());
    }

    #[test]
    fn denied_enable_when_starting() {
        let err = validate_transition(LifecycleState::Starting, LifecycleAction::Enable);
        assert!(err.is_err());
    }

    #[test]
    fn denied_stop_when_stopping() {
        let err = validate_transition(LifecycleState::Stopping, LifecycleAction::Stop);
        assert!(err.is_err());
    }

    #[test]
    fn denied_start_when_draining() {
        let err = validate_transition(LifecycleState::Draining, LifecycleAction::Start);
        assert!(err.is_err());
    }

    #[test]
    fn denied_enable_when_draining() {
        let err = validate_transition(LifecycleState::Draining, LifecycleAction::Enable);
        assert!(err.is_err());
    }

    #[test]
    fn denied_stop_when_enabled() {
        let err = validate_transition(LifecycleState::Enabled, LifecycleAction::Stop);
        assert!(err.is_err());
    }

    #[test]
    fn denied_force_stop_when_stopped() {
        let err = validate_transition(LifecycleState::Stopped, LifecycleAction::ForceStop);
        assert!(err.is_err());
    }

    #[test]
    fn denied_enable_when_stopped() {
        let err = validate_transition(LifecycleState::Stopped, LifecycleAction::Enable);
        assert!(err.is_err());
    }

    #[test]
    fn denied_enable_when_failed() {
        let err = validate_transition(LifecycleState::Failed, LifecycleAction::Enable);
        assert!(err.is_err());
    }

    #[test]
    fn denied_start_when_failed() {
        let err = validate_transition(LifecycleState::Failed, LifecycleAction::Start);
        assert!(err.is_err());
    }

    #[test]
    fn denied_force_stop_when_enabled() {
        let err = validate_transition(LifecycleState::Enabled, LifecycleAction::ForceStop);
        assert!(err.is_err());
    }

    #[test]
    fn denied_restart_when_disabled() {
        let err = validate_transition(LifecycleState::Disabled, LifecycleAction::Restart);
        assert!(err.is_err());
    }

    // ── state_can_accept ────────────────────────────────────────────

    #[test]
    fn can_accept_disabled_enable() {
        assert!(state_can_accept(LifecycleState::Disabled, LifecycleAction::Enable));
    }

    #[test]
    fn can_accept_disabled_disable_noop() {
        assert!(state_can_accept(LifecycleState::Disabled, LifecycleAction::Disable));
    }

    #[test]
    fn cannot_accept_disabled_start() {
        assert!(!state_can_accept(LifecycleState::Disabled, LifecycleAction::Start));
    }

    #[test]
    fn can_accept_running_all_expected() {
        assert!(state_can_accept(LifecycleState::Running, LifecycleAction::Stop));
        assert!(state_can_accept(LifecycleState::Running, LifecycleAction::ForceStop));
        assert!(state_can_accept(LifecycleState::Running, LifecycleAction::Disable));
        assert!(state_can_accept(LifecycleState::Running, LifecycleAction::Restart));
        assert!(state_can_accept(LifecycleState::Running, LifecycleAction::Start)); // noop
    }

    #[test]
    fn cannot_accept_running_enable() {
        assert!(!state_can_accept(LifecycleState::Running, LifecycleAction::Enable));
    }

    #[test]
    fn can_accept_failed_restart() {
        assert!(state_can_accept(LifecycleState::Failed, LifecycleAction::Restart));
    }

    #[test]
    fn can_accept_failed_stop() {
        assert!(state_can_accept(LifecycleState::Failed, LifecycleAction::Stop));
    }

    #[test]
    fn can_accept_failed_disable() {
        assert!(state_can_accept(LifecycleState::Failed, LifecycleAction::Disable));
    }

    #[test]
    fn cannot_accept_unknown_most_actions() {
        for action in LifecycleAction::all() {
            assert!(
                !state_can_accept(LifecycleState::Unknown, *action),
                "Unknown should not accept {:?}",
                action
            );
        }
    }

    // ── valid_actions ───────────────────────────────────────────────

    #[test]
    fn valid_actions_for_disabled() {
        let actions = valid_actions(LifecycleState::Disabled);
        assert!(actions.contains(&LifecycleAction::Enable));
        assert!(actions.contains(&LifecycleAction::Disable)); // noop
        assert!(!actions.contains(&LifecycleAction::Start));
    }

    #[test]
    fn valid_actions_for_running() {
        let actions = valid_actions(LifecycleState::Running);
        assert!(actions.contains(&LifecycleAction::Stop));
        assert!(actions.contains(&LifecycleAction::ForceStop));
        assert!(actions.contains(&LifecycleAction::Disable));
        assert!(actions.contains(&LifecycleAction::Restart));
        assert!(actions.contains(&LifecycleAction::Start)); // noop
        assert!(!actions.contains(&LifecycleAction::Enable));
    }

    #[test]
    fn valid_actions_for_stopped() {
        let actions = valid_actions(LifecycleState::Stopped);
        assert!(actions.contains(&LifecycleAction::Start));
        assert!(actions.contains(&LifecycleAction::Disable));
        assert!(actions.contains(&LifecycleAction::Restart));
        assert!(actions.contains(&LifecycleAction::Stop)); // noop
    }

    #[test]
    fn valid_actions_for_failed() {
        let actions = valid_actions(LifecycleState::Failed);
        assert!(actions.contains(&LifecycleAction::Restart));
        assert!(actions.contains(&LifecycleAction::Stop));
        assert!(actions.contains(&LifecycleAction::Disable));
    }

    #[test]
    fn valid_actions_for_unknown_is_empty() {
        let actions = valid_actions(LifecycleState::Unknown);
        assert!(actions.is_empty());
    }

    #[test]
    fn valid_actions_for_starting_is_empty() {
        let actions = valid_actions(LifecycleState::Starting);
        assert!(actions.is_empty());
    }

    #[test]
    fn valid_actions_for_stopping_is_empty() {
        let actions = valid_actions(LifecycleState::Stopping);
        assert!(actions.is_empty());
    }

    #[test]
    fn valid_actions_for_draining_is_empty() {
        let actions = valid_actions(LifecycleState::Draining);
        assert!(actions.is_empty());
    }

    // ── estimate_duration ───────────────────────────────────────────

    #[test]
    fn estimate_enable_fast() {
        let d = estimate_duration(LifecycleAction::Enable);
        assert!(d < Duration::from_secs(1));
    }

    #[test]
    fn estimate_restart_longest() {
        let d = estimate_duration(LifecycleAction::Restart);
        assert!(d >= estimate_duration(LifecycleAction::Start));
    }

    #[test]
    fn estimate_force_stop_fast() {
        let d = estimate_duration(LifecycleAction::ForceStop);
        assert!(d < Duration::from_secs(1));
    }

    #[test]
    fn estimate_stop_moderate() {
        let d = estimate_duration(LifecycleAction::Stop);
        assert!(d >= Duration::from_secs(1));
    }

    #[test]
    fn estimate_all_nonzero() {
        for action in LifecycleAction::all() {
            assert!(estimate_duration(*action) > Duration::ZERO);
        }
    }

    // ── compute_risk ────────────────────────────────────────────────

    #[test]
    fn risk_force_stop_critical() {
        assert_eq!(
            compute_risk(LifecycleState::Running, LifecycleAction::ForceStop),
            MutationRisk::Critical
        );
    }

    #[test]
    fn risk_running_disable_high() {
        assert_eq!(
            compute_risk(LifecycleState::Running, LifecycleAction::Disable),
            MutationRisk::High
        );
    }

    #[test]
    fn risk_running_stop_medium() {
        assert_eq!(
            compute_risk(LifecycleState::Running, LifecycleAction::Stop),
            MutationRisk::Medium
        );
    }

    #[test]
    fn risk_enable_none() {
        assert_eq!(
            compute_risk(LifecycleState::Disabled, LifecycleAction::Enable),
            MutationRisk::None
        );
    }

    #[test]
    fn risk_failed_restart_low() {
        assert_eq!(
            compute_risk(LifecycleState::Failed, LifecycleAction::Restart),
            MutationRisk::Low
        );
    }

    #[test]
    fn risk_force_stop_always_critical() {
        for state in LifecycleState::all() {
            assert_eq!(
                compute_risk(*state, LifecycleAction::ForceStop),
                MutationRisk::Critical
            );
        }
    }

    // ── preflight ───────────────────────────────────────────────────

    #[test]
    fn preflight_valid_enable() {
        let req = MutationRequest::new("test-connector", LifecycleAction::Enable);
        let check = preflight(&req, LifecycleState::Disabled);
        assert!(check.can_proceed());
        assert!(!check.is_noop);
        assert!(!check.requires_confirmation);
    }

    #[test]
    fn preflight_noop_enable() {
        let req = MutationRequest::new("test-connector", LifecycleAction::Enable);
        let check = preflight(&req, LifecycleState::Enabled);
        assert!(check.can_proceed());
        assert!(check.is_noop);
    }

    #[test]
    fn preflight_blocked_start_from_disabled() {
        let req = MutationRequest::new("test-connector", LifecycleAction::Start);
        let check = preflight(&req, LifecycleState::Disabled);
        assert!(!check.can_proceed());
        assert!(!check.blockers.is_empty());
    }

    #[test]
    fn preflight_force_stop_requires_confirmation() {
        let req = MutationRequest::new("test-connector", LifecycleAction::ForceStop);
        let check = preflight(&req, LifecycleState::Running);
        assert!(check.can_proceed());
        assert!(check.requires_confirmation);
        assert_eq!(check.risk_level, MutationRisk::Critical);
    }

    #[test]
    fn preflight_force_stop_forced_no_confirmation() {
        let req = MutationRequest::new("test-connector", LifecycleAction::ForceStop)
            .with_force(true);
        let check = preflight(&req, LifecycleState::Running);
        assert!(!check.requires_confirmation);
    }

    #[test]
    fn preflight_dry_run_warning() {
        let req = MutationRequest::new("test-connector", LifecycleAction::Enable)
            .with_dry_run(true);
        let check = preflight(&req, LifecycleState::Disabled);
        assert!(check.warnings.iter().any(|w| w.contains("dry-run")));
    }

    #[test]
    fn preflight_transient_state_warning() {
        let req = MutationRequest::new("test-connector", LifecycleAction::Start);
        let check = preflight(&req, LifecycleState::Starting);
        assert!(check.warnings.iter().any(|w| w.contains("transient")));
    }

    #[test]
    fn preflight_force_destructive_warning() {
        let req = MutationRequest::new("test-connector", LifecycleAction::Disable)
            .with_force(true);
        let check = preflight(&req, LifecycleState::Running);
        assert!(check.warnings.iter().any(|w| w.contains("destructive")));
    }

    #[test]
    fn preflight_has_issues_with_warnings() {
        let req = MutationRequest::new("test-connector", LifecycleAction::Enable)
            .with_dry_run(true);
        let check = preflight(&req, LifecycleState::Disabled);
        assert!(check.has_issues());
    }

    #[test]
    fn preflight_has_issues_with_blockers() {
        let req = MutationRequest::new("test-connector", LifecycleAction::Start);
        let check = preflight(&req, LifecycleState::Disabled);
        assert!(check.has_issues());
    }

    #[test]
    fn preflight_no_issues_clean() {
        let req = MutationRequest::new("test-connector", LifecycleAction::Enable);
        let check = preflight(&req, LifecycleState::Disabled);
        assert!(!check.has_issues());
    }

    // ── MutationRequest builder ─────────────────────────────────────

    #[test]
    fn request_builder_defaults() {
        let req = MutationRequest::new("my-conn", LifecycleAction::Start);
        assert_eq!(req.target, "my-conn");
        assert_eq!(req.action, LifecycleAction::Start);
        assert!(!req.force);
        assert!(req.timeout.is_none());
        assert!(!req.dry_run);
        assert!(req.operator.is_none());
    }

    #[test]
    fn request_builder_with_all() {
        let req = MutationRequest::new("c", LifecycleAction::Restart)
            .with_force(true)
            .with_timeout(Duration::from_secs(30))
            .with_dry_run(true)
            .with_operator("admin");
        assert!(req.force);
        assert_eq!(req.timeout, Some(Duration::from_secs(30)));
        assert!(req.dry_run);
        assert_eq!(req.operator.as_deref(), Some("admin"));
    }

    // ── MutationResult ──────────────────────────────────────────────

    #[test]
    fn result_success() {
        let r = MutationResult::success(
            LifecycleState::Disabled,
            LifecycleState::Enabled,
            "rcpt-001",
            Duration::from_millis(42),
        );
        assert!(r.success);
        assert_eq!(r.old_state, LifecycleState::Disabled);
        assert_eq!(r.new_state, LifecycleState::Enabled);
        assert_eq!(r.receipt_id, "rcpt-001");
        assert!(r.error.is_none());
    }

    #[test]
    fn result_failure() {
        let r = MutationResult::failure(
            LifecycleState::Running,
            "rcpt-002",
            "timeout exceeded",
        );
        assert!(!r.success);
        assert_eq!(r.old_state, LifecycleState::Running);
        assert_eq!(r.new_state, LifecycleState::Running); // unchanged
        assert_eq!(r.error.as_deref(), Some("timeout exceeded"));
    }

    #[test]
    fn result_with_warning() {
        let r = MutationResult::success(
            LifecycleState::Running,
            LifecycleState::Stopping,
            "rcpt-003",
            Duration::from_secs(1),
        )
        .with_warning("slow shutdown");
        assert_eq!(r.warnings.len(), 1);
        assert_eq!(r.warnings[0], "slow shutdown");
    }

    #[test]
    fn result_failure_state_unchanged() {
        let r = MutationResult::failure(LifecycleState::Failed, "rcpt", "err");
        assert_eq!(r.old_state, r.new_state);
        assert_eq!(r.duration, Duration::ZERO);
    }

    // ── MutationReceipt ─────────────────────────────────────────────

    #[test]
    fn receipt_from_request_result() {
        let req = MutationRequest::new("conn-a", LifecycleAction::Enable)
            .with_operator("alice");
        let res = MutationResult::success(
            LifecycleState::Disabled,
            LifecycleState::Enabled,
            "rcpt-100",
            Duration::from_millis(50),
        );
        let ts = Utc::now();
        let receipt = MutationReceipt::from_request_and_result(&req, &res, ts);
        assert_eq!(receipt.id, "rcpt-100");
        assert_eq!(receipt.action, LifecycleAction::Enable);
        assert_eq!(receipt.target, "conn-a");
        assert_eq!(receipt.operator, "alice");
        assert!(!receipt.dry_run);
        assert!(!receipt.forced);
    }

    #[test]
    fn receipt_default_operator() {
        let req = MutationRequest::new("conn-b", LifecycleAction::Stop);
        let res = MutationResult::success(
            LifecycleState::Running,
            LifecycleState::Stopping,
            "rcpt-101",
            Duration::from_secs(2),
        );
        let receipt = MutationReceipt::from_request_and_result(&req, &res, Utc::now());
        assert_eq!(receipt.operator, "system");
    }

    #[test]
    fn receipt_dry_run_flag() {
        let req = MutationRequest::new("conn-c", LifecycleAction::Enable)
            .with_dry_run(true);
        let res = MutationResult::success(
            LifecycleState::Disabled,
            LifecycleState::Enabled,
            "rcpt-102",
            Duration::ZERO,
        );
        let receipt = MutationReceipt::from_request_and_result(&req, &res, Utc::now());
        assert!(receipt.dry_run);
    }

    #[test]
    fn receipt_forced_flag() {
        let req = MutationRequest::new("conn-d", LifecycleAction::ForceStop)
            .with_force(true);
        let res = MutationResult::success(
            LifecycleState::Running,
            LifecycleState::Stopped,
            "rcpt-103",
            Duration::from_millis(100),
        );
        let receipt = MutationReceipt::from_request_and_result(&req, &res, Utc::now());
        assert!(receipt.forced);
    }

    // ── format_preflight_toon ───────────────────────────────────────

    #[test]
    fn format_preflight_clean() {
        let req = MutationRequest::new("c", LifecycleAction::Enable);
        let check = preflight(&req, LifecycleState::Disabled);
        let toon = format_preflight_toon(&check);
        assert!(toon.contains("Preflight: enable"));
        assert!(toon.contains("Risk:     none"));
        assert!(toon.contains("Verdict:  PASS"));
    }

    #[test]
    fn format_preflight_blocked() {
        let req = MutationRequest::new("c", LifecycleAction::Start);
        let check = preflight(&req, LifecycleState::Disabled);
        let toon = format_preflight_toon(&check);
        assert!(toon.contains("Verdict:  BLOCKED"));
        assert!(toon.contains("Blockers:"));
    }

    #[test]
    fn format_preflight_with_warnings() {
        let req = MutationRequest::new("c", LifecycleAction::Disable)
            .with_force(true);
        let check = preflight(&req, LifecycleState::Running);
        let toon = format_preflight_toon(&check);
        assert!(toon.contains("Warnings:"));
        assert!(toon.contains("destructive"));
    }

    #[test]
    fn format_preflight_noop_shown() {
        let req = MutationRequest::new("c", LifecycleAction::Enable);
        let check = preflight(&req, LifecycleState::Enabled);
        let toon = format_preflight_toon(&check);
        assert!(toon.contains("No-op:    true"));
    }

    // ── format_receipt_toon ─────────────────────────────────────────

    #[test]
    fn format_receipt_basic() {
        let receipt = MutationReceipt {
            id: "rcpt-200".into(),
            timestamp: Utc::now(),
            action: LifecycleAction::Enable,
            target: "my-conn".into(),
            old_state: LifecycleState::Disabled,
            new_state: LifecycleState::Enabled,
            operator: "admin".into(),
            duration: Duration::from_millis(75),
            dry_run: false,
            forced: false,
        };
        let toon = format_receipt_toon(&receipt);
        assert!(toon.contains("Receipt: rcpt-200"));
        assert!(toon.contains("Action:    enable"));
        assert!(toon.contains("Target:    my-conn"));
        assert!(toon.contains("Transition: disabled -> enabled"));
        assert!(toon.contains("Operator:  admin"));
    }

    #[test]
    fn format_receipt_dry_run() {
        let receipt = MutationReceipt {
            id: "rcpt-201".into(),
            timestamp: Utc::now(),
            action: LifecycleAction::Start,
            target: "x".into(),
            old_state: LifecycleState::Enabled,
            new_state: LifecycleState::Starting,
            operator: "sys".into(),
            duration: Duration::ZERO,
            dry_run: true,
            forced: false,
        };
        let toon = format_receipt_toon(&receipt);
        assert!(toon.contains("DRY-RUN"));
    }

    #[test]
    fn format_receipt_forced() {
        let receipt = MutationReceipt {
            id: "rcpt-202".into(),
            timestamp: Utc::now(),
            action: LifecycleAction::ForceStop,
            target: "y".into(),
            old_state: LifecycleState::Running,
            new_state: LifecycleState::Stopped,
            operator: "root".into(),
            duration: Duration::from_millis(200),
            dry_run: false,
            forced: true,
        };
        let toon = format_receipt_toon(&receipt);
        assert!(toon.contains("Forced:    yes"));
    }

    // ── format_denied_toon ──────────────────────────────────────────

    #[test]
    fn format_denied_disabled_start() {
        let toon = format_denied_toon(LifecycleState::Disabled, LifecycleAction::Start);
        assert!(toon.contains("DENIED"));
        assert!(toon.contains("Available actions:"));
        assert!(toon.contains("enable"));
    }

    #[test]
    fn format_denied_unknown_no_actions() {
        let toon = format_denied_toon(LifecycleState::Unknown, LifecycleAction::Start);
        assert!(toon.contains("No actions available"));
    }

    #[test]
    fn format_denied_starting_no_actions() {
        let toon = format_denied_toon(LifecycleState::Starting, LifecycleAction::Stop);
        assert!(toon.contains("No actions available"));
    }

    // ── TransitionRule ──────────────────────────────────────────────

    #[test]
    fn transition_rules_nonempty() {
        assert!(!transition_rules().is_empty());
    }

    #[test]
    fn find_rule_exists() {
        let rule = find_rule(LifecycleState::Disabled, LifecycleAction::Enable);
        assert!(rule.is_some());
        let r = rule.unwrap();
        assert_eq!(r.to_state, LifecycleState::Enabled);
        assert!(!r.requires_approval);
    }

    #[test]
    fn find_rule_force_stop_requires_approval() {
        let rule = find_rule(LifecycleState::Running, LifecycleAction::ForceStop);
        assert!(rule.is_some());
        assert!(rule.unwrap().requires_approval);
    }

    #[test]
    fn find_rule_running_disable_requires_approval() {
        let rule = find_rule(LifecycleState::Running, LifecycleAction::Disable);
        assert!(rule.is_some());
        assert!(rule.unwrap().requires_approval);
    }

    #[test]
    fn find_rule_nonexistent() {
        let rule = find_rule(LifecycleState::Disabled, LifecycleAction::Stop);
        assert!(rule.is_none());
    }

    // ── LifecycleAction properties ──────────────────────────────────

    #[test]
    fn action_labels() {
        assert_eq!(LifecycleAction::Enable.label(), "enable");
        assert_eq!(LifecycleAction::Disable.label(), "disable");
        assert_eq!(LifecycleAction::Start.label(), "start");
        assert_eq!(LifecycleAction::Stop.label(), "stop");
        assert_eq!(LifecycleAction::Restart.label(), "restart");
        assert_eq!(LifecycleAction::ForceStop.label(), "force-stop");
    }

    #[test]
    fn action_display() {
        assert_eq!(format!("{}", LifecycleAction::Enable), "enable");
        assert_eq!(format!("{}", LifecycleAction::ForceStop), "force-stop");
    }

    #[test]
    fn action_is_destructive() {
        assert!(LifecycleAction::ForceStop.is_destructive());
        assert!(LifecycleAction::Disable.is_destructive());
        assert!(!LifecycleAction::Enable.is_destructive());
        assert!(!LifecycleAction::Start.is_destructive());
        assert!(!LifecycleAction::Stop.is_destructive());
        assert!(!LifecycleAction::Restart.is_destructive());
    }

    #[test]
    fn action_requires_running() {
        assert!(LifecycleAction::Stop.requires_running());
        assert!(LifecycleAction::ForceStop.requires_running());
        assert!(!LifecycleAction::Enable.requires_running());
        assert!(!LifecycleAction::Start.requires_running());
        assert!(!LifecycleAction::Restart.requires_running());
    }

    #[test]
    fn action_all_len() {
        assert_eq!(LifecycleAction::all().len(), 6);
    }

    // ── LifecycleState properties ───────────────────────────────────

    #[test]
    fn state_labels() {
        assert_eq!(LifecycleState::Unknown.label(), "unknown");
        assert_eq!(LifecycleState::Disabled.label(), "disabled");
        assert_eq!(LifecycleState::Enabled.label(), "enabled");
        assert_eq!(LifecycleState::Starting.label(), "starting");
        assert_eq!(LifecycleState::Running.label(), "running");
        assert_eq!(LifecycleState::Stopping.label(), "stopping");
        assert_eq!(LifecycleState::Stopped.label(), "stopped");
        assert_eq!(LifecycleState::Failed.label(), "failed");
        assert_eq!(LifecycleState::Draining.label(), "draining");
    }

    #[test]
    fn state_display() {
        assert_eq!(format!("{}", LifecycleState::Running), "running");
        assert_eq!(format!("{}", LifecycleState::Draining), "draining");
    }

    #[test]
    fn state_is_healthy() {
        assert!(LifecycleState::Enabled.is_healthy());
        assert!(LifecycleState::Running.is_healthy());
        assert!(!LifecycleState::Disabled.is_healthy());
        assert!(!LifecycleState::Failed.is_healthy());
        assert!(!LifecycleState::Stopped.is_healthy());
    }

    #[test]
    fn state_is_terminal_failure() {
        assert!(LifecycleState::Failed.is_terminal_failure());
        assert!(!LifecycleState::Running.is_terminal_failure());
        assert!(!LifecycleState::Stopped.is_terminal_failure());
    }

    #[test]
    fn state_is_transient() {
        assert!(LifecycleState::Starting.is_transient());
        assert!(LifecycleState::Stopping.is_transient());
        assert!(LifecycleState::Draining.is_transient());
        assert!(!LifecycleState::Running.is_transient());
        assert!(!LifecycleState::Stopped.is_transient());
    }

    #[test]
    fn state_all_len() {
        assert_eq!(LifecycleState::all().len(), 9);
    }

    // ── MutationRisk ────────────────────────────────────────────────

    #[test]
    fn risk_labels() {
        assert_eq!(MutationRisk::None.label(), "none");
        assert_eq!(MutationRisk::Low.label(), "low");
        assert_eq!(MutationRisk::Medium.label(), "medium");
        assert_eq!(MutationRisk::High.label(), "high");
        assert_eq!(MutationRisk::Critical.label(), "critical");
    }

    #[test]
    fn risk_requires_confirmation() {
        assert!(!MutationRisk::None.requires_confirmation());
        assert!(!MutationRisk::Low.requires_confirmation());
        assert!(!MutationRisk::Medium.requires_confirmation());
        assert!(MutationRisk::High.requires_confirmation());
        assert!(MutationRisk::Critical.requires_confirmation());
    }

    #[test]
    fn risk_ordering() {
        assert!(MutationRisk::None < MutationRisk::Low);
        assert!(MutationRisk::Low < MutationRisk::Medium);
        assert!(MutationRisk::Medium < MutationRisk::High);
        assert!(MutationRisk::High < MutationRisk::Critical);
    }

    #[test]
    fn risk_display() {
        assert_eq!(format!("{}", MutationRisk::Critical), "critical");
    }

    // ── TransitionError ─────────────────────────────────────────────

    #[test]
    fn transition_error_display() {
        let e = TransitionError {
            from: LifecycleState::Disabled,
            action: LifecycleAction::Start,
            reason: "not enabled".into(),
        };
        let msg = format!("{e}");
        assert!(msg.contains("cannot start from disabled"));
        assert!(msg.contains("not enabled"));
    }

    #[test]
    fn transition_error_is_error_trait() {
        let e = TransitionError {
            from: LifecycleState::Unknown,
            action: LifecycleAction::Stop,
            reason: "unknown state".into(),
        };
        let _: &dyn std::error::Error = &e;
    }

    // ── Serialization round-trip ────────────────────────────────────

    #[test]
    fn serde_lifecycle_action_roundtrip() {
        for action in LifecycleAction::all() {
            let json = serde_json::to_string(action).unwrap();
            let back: LifecycleAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, back);
        }
    }

    #[test]
    fn serde_lifecycle_state_roundtrip() {
        for state in LifecycleState::all() {
            let json = serde_json::to_string(state).unwrap();
            let back: LifecycleState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, back);
        }
    }

    #[test]
    fn serde_mutation_request_roundtrip() {
        let req = MutationRequest::new("test", LifecycleAction::Restart)
            .with_force(true)
            .with_dry_run(true)
            .with_operator("op");
        let json = serde_json::to_string(&req).unwrap();
        let back: MutationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "test");
        assert_eq!(back.action, LifecycleAction::Restart);
        assert!(back.force);
        assert!(back.dry_run);
    }

    #[test]
    fn serde_mutation_result_roundtrip() {
        let r = MutationResult::success(
            LifecycleState::Disabled,
            LifecycleState::Enabled,
            "r1",
            Duration::from_millis(100),
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: MutationResult = serde_json::from_str(&json).unwrap();
        assert!(back.success);
        assert_eq!(back.receipt_id, "r1");
    }

    #[test]
    fn serde_transition_error_roundtrip() {
        let e = TransitionError {
            from: LifecycleState::Disabled,
            action: LifecycleAction::Start,
            reason: "test".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: TransitionError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}
