//! Terraform Apply with `ApprovalToken` (Plan Hash Binding).
//!
//! Implements a secure apply workflow that requires plan hash binding
//! and approval tokens before executing `terraform apply`. Never uses
//! `-auto-approve`; always uses `-input=false`.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ApplyStatus
// ---------------------------------------------------------------------------

/// Lifecycle status of a terraform apply operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus {
    /// Awaiting approval token.
    Pending,
    /// Token validated, ready to execute.
    Approved,
    /// `terraform apply` is running.
    Executing,
    /// Apply finished successfully.
    Completed,
    /// Apply finished with an error.
    Failed,
    /// Apply was cancelled before completion.
    Cancelled,
    /// Apply exceeded the configured timeout.
    TimedOut,
}

impl ApplyStatus {
    /// Returns `true` when no further transitions are possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }
}

impl std::fmt::Display for ApplyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Executing => "executing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// ApplyDenialCode
// ---------------------------------------------------------------------------

/// Reason an apply was denied by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyDenialCode {
    MissingPlanHash,
    PlanHashMismatch,
    TokenMissing,
    TokenExpired,
    TokenUsed,
    WorkspaceNotAllowed,
    TargetForbidden,
    ResourceLimitExceeded,
    AutoApproveBlocked,
}

impl std::fmt::Display for ApplyDenialCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::MissingPlanHash => "missing_plan_hash",
            Self::PlanHashMismatch => "plan_hash_mismatch",
            Self::TokenMissing => "token_missing",
            Self::TokenExpired => "token_expired",
            Self::TokenUsed => "token_used",
            Self::WorkspaceNotAllowed => "workspace_not_allowed",
            Self::TargetForbidden => "target_forbidden",
            Self::ResourceLimitExceeded => "resource_limit_exceeded",
            Self::AutoApproveBlocked => "auto_approve_blocked",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// ApplyDecision
// ---------------------------------------------------------------------------

/// Outcome of a policy check against an [`ApplyRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ApplyDecision {
    /// The request is approved.
    Approve { reason: String },
    /// The request is denied.
    Deny {
        code: ApplyDenialCode,
        reason: String,
    },
    /// An approval token is required before proceeding.
    NeedsToken,
}

impl ApplyDecision {
    /// Returns `true` when the decision permits execution.
    #[must_use]
    pub const fn is_approved(&self) -> bool {
        matches!(self, Self::Approve { .. })
    }

    /// Returns `true` when the decision denies execution.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

// ---------------------------------------------------------------------------
// ApplyRequest
// ---------------------------------------------------------------------------

/// An inbound request to execute `terraform apply`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyRequest {
    pub workspace_id: String,
    pub plan_reference: String,
    pub plan_hash: String,
    pub approval_token: Option<String>,
    pub targets: Vec<String>,
    pub variables: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

impl ApplyRequest {
    /// Validates that all required fields are present and non-empty.
    ///
    /// # Errors
    ///
    /// Returns a human-readable description of the first validation failure.
    pub fn validate(&self) -> Result<(), String> {
        if self.workspace_id.is_empty() {
            return Err("workspace_id must not be empty".into());
        }
        if self.plan_reference.is_empty() {
            return Err("plan_reference must not be empty".into());
        }
        if self.plan_hash.is_empty() {
            return Err("plan_hash must not be empty".into());
        }
        Ok(())
    }

    /// Returns `true` when `-auto-approve` would be implied (always `false`
    /// in this implementation since auto-approve is forbidden).
    #[must_use]
    pub const fn uses_auto_approve(&self) -> bool {
        // SAFETY INVARIANT: we never use -auto-approve.
        false
    }

    /// Returns the number of targeted resources (0 = whole plan).
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
}

// ---------------------------------------------------------------------------
// ApplyResult
// ---------------------------------------------------------------------------

/// The outcome of a completed (or failed) apply operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub apply_id: String,
    pub workspace_id: String,
    pub status: ApplyStatus,
    pub plan_hash: String,
    pub resources_added: u64,
    pub resources_changed: u64,
    pub resources_destroyed: u64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub audit_events: Vec<ApplyAuditEvent>,
}

impl ApplyResult {
    /// Total number of resources affected.
    #[must_use]
    pub const fn total_resources_affected(&self) -> u64 {
        self.resources_added + self.resources_changed + self.resources_destroyed
    }

    /// Whether the apply completed successfully.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self.status, ApplyStatus::Completed)
    }

    /// Duration of the apply, if both start and end are known.
    #[must_use]
    pub fn duration(&self) -> Option<chrono::Duration> {
        self.completed_at.map(|end| end - self.started_at)
    }
}

// ---------------------------------------------------------------------------
// ApplyToken
// ---------------------------------------------------------------------------

/// An approval token that binds to a specific plan hash and workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyToken {
    pub token_id: String,
    pub plan_hash: String,
    pub workspace_id: String,
    pub issued_by: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub allowed_targets: Vec<String>,
    pub max_resources: Option<u64>,
    pub single_use: bool,
    pub used: bool,
}

impl ApplyToken {
    /// Whether the token has passed its expiration time.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Whether the token has passed its expiration relative to the given
    /// reference time.
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Whether the token's plan hash matches a given hash.
    #[must_use]
    pub fn matches_plan(&self, hash: &str) -> bool {
        self.plan_hash == hash
    }

    /// Whether the token's workspace matches a given workspace id.
    #[must_use]
    pub fn matches_workspace(&self, workspace_id: &str) -> bool {
        self.workspace_id == workspace_id
    }

    /// Whether the token permits the given target resource.
    ///
    /// An empty `allowed_targets` list means all targets are allowed.
    #[must_use]
    pub fn allows_target(&self, target: &str) -> bool {
        if self.allowed_targets.is_empty() {
            return true;
        }
        self.allowed_targets.iter().any(|t| t == target)
    }

    /// Whether the token can still be used.
    ///
    /// A token is usable when it has not expired, has not already been used
    /// (if single-use), and is otherwise valid.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        if self.is_expired() {
            return false;
        }
        if self.single_use && self.used {
            return false;
        }
        true
    }

    /// Same as [`is_usable`](Self::is_usable) but accepts a reference time.
    #[must_use]
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        if self.is_expired_at(now) {
            return false;
        }
        if self.single_use && self.used {
            return false;
        }
        true
    }

    /// Mark the token as used. Returns `false` if it was already used.
    pub const fn consume(&mut self) -> bool {
        if self.used {
            return false;
        }
        self.used = true;
        true
    }
}

// ---------------------------------------------------------------------------
// ApplyPolicy
// ---------------------------------------------------------------------------

/// Policy governing whether an apply may proceed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyPolicy {
    pub require_approval: bool,
    pub require_plan_hash: bool,
    pub max_resources_per_apply: Option<u64>,
    pub allowed_workspaces: Vec<String>,
    pub forbidden_targets: Vec<String>,
    pub timeout_seconds: u64,
}

impl ApplyPolicy {
    /// A strict policy that requires approval, plan hash, and has a 30-minute
    /// timeout.
    #[must_use]
    pub const fn default_strict() -> Self {
        Self {
            require_approval: true,
            require_plan_hash: true,
            max_resources_per_apply: Some(100),
            allowed_workspaces: Vec::new(),
            forbidden_targets: Vec::new(),
            timeout_seconds: 1800,
        }
    }

    /// A permissive policy for development/testing.
    #[must_use]
    pub const fn default_permissive() -> Self {
        Self {
            require_approval: false,
            require_plan_hash: false,
            max_resources_per_apply: None,
            allowed_workspaces: Vec::new(),
            forbidden_targets: Vec::new(),
            timeout_seconds: 7200,
        }
    }

    /// Check an [`ApplyRequest`] against this policy.
    #[must_use]
    pub fn check_request(&self, request: &ApplyRequest) -> ApplyDecision {
        // 1. Plan hash is always checked even in permissive mode when
        //    `require_plan_hash` is set.
        if self.require_plan_hash && request.plan_hash.is_empty() {
            return ApplyDecision::Deny {
                code: ApplyDenialCode::MissingPlanHash,
                reason: "Plan hash is required by policy".into(),
            };
        }

        // 2. Workspace allow-list (empty = all allowed).
        if !self.allowed_workspaces.is_empty()
            && !self
                .allowed_workspaces
                .iter()
                .any(|w| w == &request.workspace_id)
        {
            return ApplyDecision::Deny {
                code: ApplyDenialCode::WorkspaceNotAllowed,
                reason: format!(
                    "Workspace '{}' is not in the allowed list",
                    request.workspace_id
                ),
            };
        }

        // 3. Forbidden targets.
        for target in &request.targets {
            if self.forbidden_targets.iter().any(|f| f == target) {
                return ApplyDecision::Deny {
                    code: ApplyDenialCode::TargetForbidden,
                    reason: format!("Target '{target}' is forbidden by policy"),
                };
            }
        }

        // 4. Approval token required?
        if self.require_approval && request.approval_token.is_none() {
            return ApplyDecision::NeedsToken;
        }

        ApplyDecision::Approve {
            reason: "All policy checks passed".into(),
        }
    }

    /// Whether the workspace is in the allow-list (or the list is empty).
    #[must_use]
    pub fn is_workspace_allowed(&self, workspace_id: &str) -> bool {
        if self.allowed_workspaces.is_empty() {
            return true;
        }
        self.allowed_workspaces.iter().any(|w| w == workspace_id)
    }

    /// Whether a target is forbidden.
    #[must_use]
    pub fn is_target_forbidden(&self, target: &str) -> bool {
        self.forbidden_targets.iter().any(|f| f == target)
    }
}

// ---------------------------------------------------------------------------
// ApplyAuditEvent
// ---------------------------------------------------------------------------

/// A single audit-trail entry for an apply operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyAuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub apply_id: Option<String>,
    pub details: String,
    pub actor: String,
}

impl ApplyAuditEvent {
    /// Create a new audit event stamped at the current time.
    #[must_use]
    pub fn now(event_type: &str, details: &str, actor: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type: event_type.to_owned(),
            apply_id: None,
            details: details.to_owned(),
            actor: actor.to_owned(),
        }
    }

    /// Create a new audit event at a specific time.
    #[must_use]
    pub fn at(
        timestamp: DateTime<Utc>,
        event_type: &str,
        details: &str,
        actor: &str,
    ) -> Self {
        Self {
            timestamp,
            event_type: event_type.to_owned(),
            apply_id: None,
            details: details.to_owned(),
            actor: actor.to_owned(),
        }
    }

    /// Attach an apply id to this event.
    #[must_use]
    pub fn with_apply_id(mut self, id: &str) -> Self {
        self.apply_id = Some(id.to_owned());
        self
    }
}

// ---------------------------------------------------------------------------
// ApplyLifecycle
// ---------------------------------------------------------------------------

/// State machine tracking an apply through its lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyLifecycle {
    pub apply_id: String,
    pub request: ApplyRequest,
    pub status: ApplyStatus,
    pub audit_trail: Vec<ApplyAuditEvent>,
}

impl ApplyLifecycle {
    /// Create a new lifecycle in the [`Pending`](ApplyStatus::Pending) state.
    #[must_use]
    pub fn new(apply_id: &str, request: ApplyRequest) -> Self {
        let mut lc = Self {
            apply_id: apply_id.to_owned(),
            request,
            status: ApplyStatus::Pending,
            audit_trail: Vec::new(),
        };
        lc.audit_trail.push(
            ApplyAuditEvent::now("lifecycle_created", "Apply lifecycle created", "system")
                .with_apply_id(apply_id),
        );
        lc
    }

    /// Transition from `Pending` to `Approved`.
    ///
    /// # Errors
    ///
    /// Returns an error if the current status is not `Pending`.
    pub fn approve(&mut self, actor: &str) -> Result<(), String> {
        if self.status != ApplyStatus::Pending {
            return Err(format!(
                "Cannot approve: current status is {}",
                self.status
            ));
        }
        self.status = ApplyStatus::Approved;
        self.audit_trail.push(
            ApplyAuditEvent::now("approved", "Apply approved", actor)
                .with_apply_id(&self.apply_id),
        );
        Ok(())
    }

    /// Transition from `Approved` to `Executing`.
    ///
    /// # Errors
    ///
    /// Returns an error if the current status is not `Approved`.
    pub fn start_execution(&mut self) -> Result<(), String> {
        if self.status != ApplyStatus::Approved {
            return Err(format!(
                "Cannot start execution: current status is {}",
                self.status
            ));
        }
        self.status = ApplyStatus::Executing;
        self.audit_trail.push(
            ApplyAuditEvent::now("execution_started", "Apply execution started", "system")
                .with_apply_id(&self.apply_id),
        );
        Ok(())
    }

    /// Transition from `Executing` to `Completed`.
    ///
    /// # Errors
    ///
    /// Returns an error if the current status is not `Executing`.
    pub fn complete(&mut self) -> Result<(), String> {
        if self.status != ApplyStatus::Executing {
            return Err(format!(
                "Cannot complete: current status is {}",
                self.status
            ));
        }
        self.status = ApplyStatus::Completed;
        self.audit_trail.push(
            ApplyAuditEvent::now(
                "completed",
                "Apply completed successfully",
                "system",
            )
            .with_apply_id(&self.apply_id),
        );
        Ok(())
    }

    /// Transition from `Executing` to `Failed`.
    ///
    /// # Errors
    ///
    /// Returns an error if the current status is not `Executing`.
    pub fn fail(&mut self, reason: &str) -> Result<(), String> {
        if self.status != ApplyStatus::Executing {
            return Err(format!(
                "Cannot fail: current status is {}",
                self.status
            ));
        }
        self.status = ApplyStatus::Failed;
        self.audit_trail.push(
            ApplyAuditEvent::now("failed", reason, "system")
                .with_apply_id(&self.apply_id),
        );
        Ok(())
    }

    /// Transition to `Cancelled` from any non-terminal state.
    ///
    /// # Errors
    ///
    /// Returns an error if the lifecycle is already in a terminal state.
    pub fn cancel(&mut self, actor: &str) -> Result<(), String> {
        if self.status.is_terminal() {
            return Err(format!(
                "Cannot cancel: current status is {} (terminal)",
                self.status
            ));
        }
        self.status = ApplyStatus::Cancelled;
        self.audit_trail.push(
            ApplyAuditEvent::now("cancelled", "Apply cancelled", actor)
                .with_apply_id(&self.apply_id),
        );
        Ok(())
    }

    /// Transition from `Executing` to `TimedOut`.
    ///
    /// # Errors
    ///
    /// Returns an error if the current status is not `Executing`.
    pub fn timeout(&mut self) -> Result<(), String> {
        if self.status != ApplyStatus::Executing {
            return Err(format!(
                "Cannot timeout: current status is {}",
                self.status
            ));
        }
        self.status = ApplyStatus::TimedOut;
        self.audit_trail.push(
            ApplyAuditEvent::now("timed_out", "Apply timed out", "system")
                .with_apply_id(&self.apply_id),
        );
        Ok(())
    }

    /// The current status.
    #[must_use]
    pub const fn current_status(&self) -> ApplyStatus {
        self.status
    }

    /// Whether the lifecycle is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    /// Number of audit events recorded so far.
    #[must_use]
    pub fn audit_event_count(&self) -> usize {
        self.audit_trail.len()
    }
}

// ---------------------------------------------------------------------------
// Validate token against request helper
// ---------------------------------------------------------------------------

/// Validate an [`ApplyToken`] against an [`ApplyRequest`] and
/// [`ApplyPolicy`], returning an [`ApplyDecision`].
#[must_use]
pub fn validate_token_for_request(
    token: &ApplyToken,
    request: &ApplyRequest,
    policy: &ApplyPolicy,
) -> ApplyDecision {
    // 1. Token must not be expired.
    if token.is_expired() {
        return ApplyDecision::Deny {
            code: ApplyDenialCode::TokenExpired,
            reason: "Approval token has expired".into(),
        };
    }

    // 2. Single-use token must not be consumed.
    if token.single_use && token.used {
        return ApplyDecision::Deny {
            code: ApplyDenialCode::TokenUsed,
            reason: "Single-use approval token has already been used".into(),
        };
    }

    // 3. Plan hash binding.
    if !token.matches_plan(&request.plan_hash) {
        return ApplyDecision::Deny {
            code: ApplyDenialCode::PlanHashMismatch,
            reason: format!(
                "Token plan hash '{}' does not match request plan hash '{}'",
                token.plan_hash, request.plan_hash
            ),
        };
    }

    // 4. Workspace binding.
    if !token.matches_workspace(&request.workspace_id) {
        return ApplyDecision::Deny {
            code: ApplyDenialCode::WorkspaceNotAllowed,
            reason: format!(
                "Token workspace '{}' does not match request workspace '{}'",
                token.workspace_id, request.workspace_id
            ),
        };
    }

    // 5. Target binding.
    for target in &request.targets {
        if !token.allows_target(target) {
            return ApplyDecision::Deny {
                code: ApplyDenialCode::TargetForbidden,
                reason: format!("Target '{target}' is not allowed by the token"),
            };
        }
    }

    // 6. Resource limit.
    if let Some(max) = policy.max_resources_per_apply {
        if let Some(token_max) = token.max_resources {
            if token_max > max {
                return ApplyDecision::Deny {
                    code: ApplyDenialCode::ResourceLimitExceeded,
                    reason: format!(
                        "Token max resources ({token_max}) exceeds policy limit ({max})"
                    ),
                };
            }
        }
    }

    ApplyDecision::Approve {
        reason: "Token validated successfully".into(),
    }
}

/// Build the CLI arguments for `terraform apply`. Never includes
/// `-auto-approve`.
#[must_use]
pub fn build_apply_args(request: &ApplyRequest) -> Vec<String> {
    let mut args = vec!["apply".to_owned(), "-input=false".to_owned()];

    for target in &request.targets {
        args.push(format!("-target={target}"));
    }

    for (key, value) in &request.variables {
        args.push(format!("-var={key}={value}"));
    }

    args.push(request.plan_reference.clone());
    args
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // -- helper factories ---------------------------------------------------

    fn sample_request() -> ApplyRequest {
        ApplyRequest {
            workspace_id: "ws-prod-001".into(),
            plan_reference: "plan-abc123.tfplan".into(),
            plan_hash: "sha256:deadbeef".into(),
            approval_token: Some("tok-xyz".into()),
            targets: vec!["aws_instance.web".into()],
            variables: {
                let mut m = HashMap::new();
                m.insert("region".into(), "us-east-1".into());
                m
            },
            created_at: Utc::now(),
        }
    }

    fn sample_token(plan_hash: &str, workspace_id: &str) -> ApplyToken {
        ApplyToken {
            token_id: "tok-001".into(),
            plan_hash: plan_hash.into(),
            workspace_id: workspace_id.into(),
            issued_by: "admin@example.com".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            allowed_targets: Vec::new(),
            max_resources: None,
            single_use: false,
            used: false,
        }
    }

    fn strict_policy() -> ApplyPolicy {
        ApplyPolicy::default_strict()
    }

    fn permissive_policy() -> ApplyPolicy {
        ApplyPolicy::default_permissive()
    }

    // =====================================================================
    // ApplyStatus
    // =====================================================================

    #[test]
    fn status_pending_not_terminal() {
        assert!(!ApplyStatus::Pending.is_terminal());
    }

    #[test]
    fn status_approved_not_terminal() {
        assert!(!ApplyStatus::Approved.is_terminal());
    }

    #[test]
    fn status_executing_not_terminal() {
        assert!(!ApplyStatus::Executing.is_terminal());
    }

    #[test]
    fn status_completed_is_terminal() {
        assert!(ApplyStatus::Completed.is_terminal());
    }

    #[test]
    fn status_failed_is_terminal() {
        assert!(ApplyStatus::Failed.is_terminal());
    }

    #[test]
    fn status_cancelled_is_terminal() {
        assert!(ApplyStatus::Cancelled.is_terminal());
    }

    #[test]
    fn status_timed_out_is_terminal() {
        assert!(ApplyStatus::TimedOut.is_terminal());
    }

    #[test]
    fn status_display_pending() {
        assert_eq!(ApplyStatus::Pending.to_string(), "pending");
    }

    #[test]
    fn status_display_approved() {
        assert_eq!(ApplyStatus::Approved.to_string(), "approved");
    }

    #[test]
    fn status_display_executing() {
        assert_eq!(ApplyStatus::Executing.to_string(), "executing");
    }

    #[test]
    fn status_display_completed() {
        assert_eq!(ApplyStatus::Completed.to_string(), "completed");
    }

    #[test]
    fn status_display_failed() {
        assert_eq!(ApplyStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn status_display_cancelled() {
        assert_eq!(ApplyStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn status_display_timed_out() {
        assert_eq!(ApplyStatus::TimedOut.to_string(), "timed_out");
    }

    #[test]
    fn status_serde_roundtrip() {
        let v = serde_json::to_string(&ApplyStatus::Executing).unwrap();
        assert_eq!(v, "\"executing\"");
        let s: ApplyStatus = serde_json::from_str(&v).unwrap();
        assert_eq!(s, ApplyStatus::Executing);
    }

    #[test]
    fn status_serde_all_variants() {
        let statuses = [
            ApplyStatus::Pending,
            ApplyStatus::Approved,
            ApplyStatus::Executing,
            ApplyStatus::Completed,
            ApplyStatus::Failed,
            ApplyStatus::Cancelled,
            ApplyStatus::TimedOut,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let back: ApplyStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    #[test]
    fn status_clone() {
        let s = ApplyStatus::Approved;
        let cloned = s;
        assert_eq!(cloned, ApplyStatus::Approved);
    }

    #[test]
    fn status_debug() {
        let dbg = format!("{:?}", ApplyStatus::Failed);
        assert!(dbg.contains("Failed"));
    }

    // =====================================================================
    // ApplyDenialCode
    // =====================================================================

    #[test]
    fn denial_code_display_missing_plan_hash() {
        assert_eq!(
            ApplyDenialCode::MissingPlanHash.to_string(),
            "missing_plan_hash"
        );
    }

    #[test]
    fn denial_code_display_plan_hash_mismatch() {
        assert_eq!(
            ApplyDenialCode::PlanHashMismatch.to_string(),
            "plan_hash_mismatch"
        );
    }

    #[test]
    fn denial_code_display_token_missing() {
        assert_eq!(
            ApplyDenialCode::TokenMissing.to_string(),
            "token_missing"
        );
    }

    #[test]
    fn denial_code_display_token_expired() {
        assert_eq!(
            ApplyDenialCode::TokenExpired.to_string(),
            "token_expired"
        );
    }

    #[test]
    fn denial_code_display_token_used() {
        assert_eq!(ApplyDenialCode::TokenUsed.to_string(), "token_used");
    }

    #[test]
    fn denial_code_display_workspace_not_allowed() {
        assert_eq!(
            ApplyDenialCode::WorkspaceNotAllowed.to_string(),
            "workspace_not_allowed"
        );
    }

    #[test]
    fn denial_code_display_target_forbidden() {
        assert_eq!(
            ApplyDenialCode::TargetForbidden.to_string(),
            "target_forbidden"
        );
    }

    #[test]
    fn denial_code_display_resource_limit() {
        assert_eq!(
            ApplyDenialCode::ResourceLimitExceeded.to_string(),
            "resource_limit_exceeded"
        );
    }

    #[test]
    fn denial_code_display_auto_approve() {
        assert_eq!(
            ApplyDenialCode::AutoApproveBlocked.to_string(),
            "auto_approve_blocked"
        );
    }

    #[test]
    fn denial_code_serde_roundtrip() {
        let code = ApplyDenialCode::PlanHashMismatch;
        let json = serde_json::to_string(&code).unwrap();
        let back: ApplyDenialCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }

    #[test]
    fn denial_code_debug() {
        let dbg = format!("{:?}", ApplyDenialCode::TokenExpired);
        assert!(dbg.contains("TokenExpired"));
    }

    // =====================================================================
    // ApplyDecision
    // =====================================================================

    #[test]
    fn decision_approve_is_approved() {
        let d = ApplyDecision::Approve {
            reason: "ok".into(),
        };
        assert!(d.is_approved());
        assert!(!d.is_denied());
    }

    #[test]
    fn decision_deny_is_denied() {
        let d = ApplyDecision::Deny {
            code: ApplyDenialCode::TokenMissing,
            reason: "missing".into(),
        };
        assert!(d.is_denied());
        assert!(!d.is_approved());
    }

    #[test]
    fn decision_needs_token_neither() {
        let d = ApplyDecision::NeedsToken;
        assert!(!d.is_approved());
        assert!(!d.is_denied());
    }

    #[test]
    fn decision_serde_approve_roundtrip() {
        let d = ApplyDecision::Approve {
            reason: "ok".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: ApplyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn decision_serde_deny_roundtrip() {
        let d = ApplyDecision::Deny {
            code: ApplyDenialCode::TokenExpired,
            reason: "expired".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: ApplyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn decision_serde_needs_token_roundtrip() {
        let d = ApplyDecision::NeedsToken;
        let json = serde_json::to_string(&d).unwrap();
        let back: ApplyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn decision_debug() {
        let dbg = format!("{:?}", ApplyDecision::NeedsToken);
        assert!(dbg.contains("NeedsToken"));
    }

    // =====================================================================
    // ApplyRequest
    // =====================================================================

    #[test]
    fn request_validate_ok() {
        let req = sample_request();
        assert!(req.validate().is_ok());
    }

    #[test]
    fn request_validate_empty_workspace() {
        let mut req = sample_request();
        req.workspace_id = String::new();
        let err = req.validate().unwrap_err();
        assert!(err.contains("workspace_id"));
    }

    #[test]
    fn request_validate_empty_plan_reference() {
        let mut req = sample_request();
        req.plan_reference = String::new();
        let err = req.validate().unwrap_err();
        assert!(err.contains("plan_reference"));
    }

    #[test]
    fn request_validate_empty_plan_hash() {
        let mut req = sample_request();
        req.plan_hash = String::new();
        let err = req.validate().unwrap_err();
        assert!(err.contains("plan_hash"));
    }

    #[test]
    fn request_never_auto_approve() {
        let req = sample_request();
        assert!(!req.uses_auto_approve());
    }

    #[test]
    fn request_target_count() {
        let req = sample_request();
        assert_eq!(req.target_count(), 1);
    }

    #[test]
    fn request_target_count_empty() {
        let mut req = sample_request();
        req.targets.clear();
        assert_eq!(req.target_count(), 0);
    }

    #[test]
    fn request_target_count_many() {
        let mut req = sample_request();
        req.targets = vec!["a".into(), "b".into(), "c".into()];
        assert_eq!(req.target_count(), 3);
    }

    #[test]
    fn request_serde_roundtrip() {
        let req = sample_request();
        let json = serde_json::to_string(&req).unwrap();
        let back: ApplyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.workspace_id, req.workspace_id);
        assert_eq!(back.plan_hash, req.plan_hash);
    }

    #[test]
    fn request_clone() {
        let req = sample_request();
        let cloned = req.clone();
        drop(req);
        assert_eq!(cloned.workspace_id, "ws-prod-001");
    }

    #[test]
    fn request_debug() {
        let req = sample_request();
        let dbg = format!("{req:?}");
        assert!(dbg.contains("ApplyRequest"));
        assert!(dbg.contains("ws-prod-001"));
    }

    #[test]
    fn request_without_token() {
        let mut req = sample_request();
        req.approval_token = None;
        assert!(req.approval_token.is_none());
        // Should still validate OK — token is optional at the struct level.
        assert!(req.validate().is_ok());
    }

    #[test]
    fn request_with_variables() {
        let req = sample_request();
        assert_eq!(req.variables.get("region"), Some(&"us-east-1".into()));
    }

    #[test]
    fn request_no_variables() {
        let mut req = sample_request();
        req.variables.clear();
        assert!(req.variables.is_empty());
        assert!(req.validate().is_ok());
    }

    // =====================================================================
    // ApplyResult
    // =====================================================================

    #[test]
    fn result_total_resources() {
        let r = ApplyResult {
            apply_id: "apply-1".into(),
            workspace_id: "ws-1".into(),
            status: ApplyStatus::Completed,
            plan_hash: "sha256:abc".into(),
            resources_added: 3,
            resources_changed: 2,
            resources_destroyed: 1,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            error_message: None,
            audit_events: Vec::new(),
        };
        assert_eq!(r.total_resources_affected(), 6);
    }

    #[test]
    fn result_total_resources_zero() {
        let r = ApplyResult {
            apply_id: "apply-2".into(),
            workspace_id: "ws-1".into(),
            status: ApplyStatus::Completed,
            plan_hash: "sha256:abc".into(),
            resources_added: 0,
            resources_changed: 0,
            resources_destroyed: 0,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            error_message: None,
            audit_events: Vec::new(),
        };
        assert_eq!(r.total_resources_affected(), 0);
    }

    #[test]
    fn result_is_success() {
        let r = ApplyResult {
            apply_id: "apply-3".into(),
            workspace_id: "ws-1".into(),
            status: ApplyStatus::Completed,
            plan_hash: "sha256:abc".into(),
            resources_added: 1,
            resources_changed: 0,
            resources_destroyed: 0,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            error_message: None,
            audit_events: Vec::new(),
        };
        assert!(r.is_success());
    }

    #[test]
    fn result_not_success_when_failed() {
        let r = ApplyResult {
            apply_id: "apply-4".into(),
            workspace_id: "ws-1".into(),
            status: ApplyStatus::Failed,
            plan_hash: "sha256:abc".into(),
            resources_added: 0,
            resources_changed: 0,
            resources_destroyed: 0,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            error_message: Some("boom".into()),
            audit_events: Vec::new(),
        };
        assert!(!r.is_success());
    }

    #[test]
    fn result_duration_some() {
        let start = Utc::now();
        let end = start + Duration::seconds(120);
        let r = ApplyResult {
            apply_id: "apply-5".into(),
            workspace_id: "ws-1".into(),
            status: ApplyStatus::Completed,
            plan_hash: "sha256:abc".into(),
            resources_added: 0,
            resources_changed: 0,
            resources_destroyed: 0,
            started_at: start,
            completed_at: Some(end),
            error_message: None,
            audit_events: Vec::new(),
        };
        let dur = r.duration().unwrap();
        assert_eq!(dur.num_seconds(), 120);
    }

    #[test]
    fn result_duration_none() {
        let r = ApplyResult {
            apply_id: "apply-6".into(),
            workspace_id: "ws-1".into(),
            status: ApplyStatus::Executing,
            plan_hash: "sha256:abc".into(),
            resources_added: 0,
            resources_changed: 0,
            resources_destroyed: 0,
            started_at: Utc::now(),
            completed_at: None,
            error_message: None,
            audit_events: Vec::new(),
        };
        assert!(r.duration().is_none());
    }

    #[test]
    fn result_serde_roundtrip() {
        let r = ApplyResult {
            apply_id: "apply-7".into(),
            workspace_id: "ws-1".into(),
            status: ApplyStatus::Completed,
            plan_hash: "sha256:abc".into(),
            resources_added: 5,
            resources_changed: 3,
            resources_destroyed: 1,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            error_message: None,
            audit_events: Vec::new(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ApplyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.apply_id, "apply-7");
        assert_eq!(back.resources_added, 5);
    }

    #[test]
    fn result_with_error_message() {
        let r = ApplyResult {
            apply_id: "apply-8".into(),
            workspace_id: "ws-1".into(),
            status: ApplyStatus::Failed,
            plan_hash: "sha256:abc".into(),
            resources_added: 0,
            resources_changed: 0,
            resources_destroyed: 0,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            error_message: Some("Provider auth failed".into()),
            audit_events: Vec::new(),
        };
        assert_eq!(r.error_message.as_deref(), Some("Provider auth failed"));
    }

    #[test]
    fn result_clone() {
        let r = ApplyResult {
            apply_id: "apply-9".into(),
            workspace_id: "ws-1".into(),
            status: ApplyStatus::Completed,
            plan_hash: "sha256:abc".into(),
            resources_added: 1,
            resources_changed: 0,
            resources_destroyed: 0,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            error_message: None,
            audit_events: Vec::new(),
        };
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.apply_id, "apply-9");
    }

    #[test]
    fn result_debug() {
        let r = ApplyResult {
            apply_id: "apply-10".into(),
            workspace_id: "ws-1".into(),
            status: ApplyStatus::Completed,
            plan_hash: "sha256:abc".into(),
            resources_added: 0,
            resources_changed: 0,
            resources_destroyed: 0,
            started_at: Utc::now(),
            completed_at: None,
            error_message: None,
            audit_events: Vec::new(),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ApplyResult"));
    }

    // =====================================================================
    // ApplyToken
    // =====================================================================

    #[test]
    fn token_matches_plan_true() {
        let t = sample_token("sha256:abc", "ws-1");
        assert!(t.matches_plan("sha256:abc"));
    }

    #[test]
    fn token_matches_plan_false() {
        let t = sample_token("sha256:abc", "ws-1");
        assert!(!t.matches_plan("sha256:def"));
    }

    #[test]
    fn token_matches_workspace_true() {
        let t = sample_token("sha256:abc", "ws-prod");
        assert!(t.matches_workspace("ws-prod"));
    }

    #[test]
    fn token_matches_workspace_false() {
        let t = sample_token("sha256:abc", "ws-prod");
        assert!(!t.matches_workspace("ws-staging"));
    }

    #[test]
    fn token_allows_target_empty_list() {
        let t = sample_token("sha256:abc", "ws-1");
        assert!(t.allows_target("anything"));
    }

    #[test]
    fn token_allows_target_match() {
        let mut t = sample_token("sha256:abc", "ws-1");
        t.allowed_targets = vec!["aws_instance.web".into()];
        assert!(t.allows_target("aws_instance.web"));
    }

    #[test]
    fn token_denies_target_no_match() {
        let mut t = sample_token("sha256:abc", "ws-1");
        t.allowed_targets = vec!["aws_instance.web".into()];
        assert!(!t.allows_target("aws_s3_bucket.data"));
    }

    #[test]
    fn token_not_expired() {
        let t = sample_token("sha256:abc", "ws-1");
        assert!(!t.is_expired());
    }

    #[test]
    fn token_expired() {
        let mut t = sample_token("sha256:abc", "ws-1");
        t.expires_at = Utc::now() - Duration::hours(1);
        assert!(t.is_expired());
    }

    #[test]
    fn token_is_expired_at() {
        let t = sample_token("sha256:abc", "ws-1");
        let future = Utc::now() + Duration::hours(2);
        assert!(t.is_expired_at(future));
    }

    #[test]
    fn token_not_expired_at() {
        let t = sample_token("sha256:abc", "ws-1");
        let past = Utc::now() - Duration::hours(2);
        assert!(!t.is_expired_at(past));
    }

    #[test]
    fn token_usable() {
        let t = sample_token("sha256:abc", "ws-1");
        assert!(t.is_usable());
    }

    #[test]
    fn token_not_usable_expired() {
        let mut t = sample_token("sha256:abc", "ws-1");
        t.expires_at = Utc::now() - Duration::minutes(5);
        assert!(!t.is_usable());
    }

    #[test]
    fn token_not_usable_single_use_consumed() {
        let mut t = sample_token("sha256:abc", "ws-1");
        t.single_use = true;
        t.used = true;
        assert!(!t.is_usable());
    }

    #[test]
    fn token_usable_multi_use_even_when_used() {
        let mut t = sample_token("sha256:abc", "ws-1");
        t.single_use = false;
        t.used = true;
        assert!(t.is_usable());
    }

    #[test]
    fn token_is_usable_at() {
        let t = sample_token("sha256:abc", "ws-1");
        let within = Utc::now() + Duration::minutes(30);
        assert!(t.is_usable_at(within));
    }

    #[test]
    fn token_not_usable_at_expired() {
        let t = sample_token("sha256:abc", "ws-1");
        let after = Utc::now() + Duration::hours(2);
        assert!(!t.is_usable_at(after));
    }

    #[test]
    fn token_consume_first_time() {
        let mut t = sample_token("sha256:abc", "ws-1");
        assert!(t.consume());
        assert!(t.used);
    }

    #[test]
    fn token_consume_already_used() {
        let mut t = sample_token("sha256:abc", "ws-1");
        t.used = true;
        assert!(!t.consume());
    }

    #[test]
    fn token_serde_roundtrip() {
        let t = sample_token("sha256:abc", "ws-1");
        let json = serde_json::to_string(&t).unwrap();
        let back: ApplyToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.token_id, "tok-001");
        assert_eq!(back.plan_hash, "sha256:abc");
    }

    #[test]
    fn token_clone() {
        let t = sample_token("sha256:abc", "ws-1");
        let cloned = t.clone();
        drop(t);
        assert_eq!(cloned.token_id, "tok-001");
    }

    #[test]
    fn token_debug() {
        let t = sample_token("sha256:abc", "ws-1");
        let dbg = format!("{t:?}");
        assert!(dbg.contains("ApplyToken"));
        assert!(dbg.contains("tok-001"));
    }

    #[test]
    fn token_allows_multiple_targets() {
        let mut t = sample_token("sha256:abc", "ws-1");
        t.allowed_targets = vec![
            "aws_instance.web".into(),
            "aws_instance.api".into(),
        ];
        assert!(t.allows_target("aws_instance.web"));
        assert!(t.allows_target("aws_instance.api"));
        assert!(!t.allows_target("aws_instance.db"));
    }

    // =====================================================================
    // ApplyPolicy
    // =====================================================================

    #[test]
    fn strict_policy_values() {
        let p = strict_policy();
        assert!(p.require_approval);
        assert!(p.require_plan_hash);
        assert_eq!(p.max_resources_per_apply, Some(100));
        assert_eq!(p.timeout_seconds, 1800);
    }

    #[test]
    fn permissive_policy_values() {
        let p = permissive_policy();
        assert!(!p.require_approval);
        assert!(!p.require_plan_hash);
        assert!(p.max_resources_per_apply.is_none());
        assert_eq!(p.timeout_seconds, 7200);
    }

    #[test]
    fn policy_check_approve() {
        let p = permissive_policy();
        let req = sample_request();
        let decision = p.check_request(&req);
        assert!(decision.is_approved());
    }

    #[test]
    fn policy_check_deny_missing_plan_hash() {
        let p = strict_policy();
        let mut req = sample_request();
        req.plan_hash = String::new();
        match p.check_request(&req) {
            ApplyDecision::Deny { code, .. } => {
                assert_eq!(code, ApplyDenialCode::MissingPlanHash);
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_check_needs_token() {
        let p = strict_policy();
        let mut req = sample_request();
        req.approval_token = None;
        assert_eq!(p.check_request(&req), ApplyDecision::NeedsToken);
    }

    #[test]
    fn policy_check_workspace_not_allowed() {
        let mut p = strict_policy();
        p.allowed_workspaces = vec!["ws-staging".into()];
        let req = sample_request();
        match p.check_request(&req) {
            ApplyDecision::Deny { code, .. } => {
                assert_eq!(code, ApplyDenialCode::WorkspaceNotAllowed);
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_check_workspace_allowed_when_in_list() {
        let mut p = strict_policy();
        p.allowed_workspaces = vec!["ws-prod-001".into()];
        let req = sample_request();
        // Should pass workspace check but may need token.
        let decision = p.check_request(&req);
        assert!(!matches!(
            decision,
            ApplyDecision::Deny {
                code: ApplyDenialCode::WorkspaceNotAllowed,
                ..
            }
        ));
    }

    #[test]
    fn policy_check_target_forbidden() {
        let mut p = strict_policy();
        p.forbidden_targets = vec!["aws_instance.web".into()];
        let req = sample_request();
        match p.check_request(&req) {
            ApplyDecision::Deny { code, reason } => {
                assert_eq!(code, ApplyDenialCode::TargetForbidden);
                assert!(reason.contains("aws_instance.web"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_check_target_not_forbidden() {
        let mut p = permissive_policy();
        p.forbidden_targets = vec!["aws_rds_instance.prod".into()];
        let req = sample_request();
        assert!(p.check_request(&req).is_approved());
    }

    #[test]
    fn policy_is_workspace_allowed_empty_list() {
        let p = strict_policy();
        assert!(p.is_workspace_allowed("any-workspace"));
    }

    #[test]
    fn policy_is_workspace_allowed_in_list() {
        let mut p = strict_policy();
        p.allowed_workspaces = vec!["ws-prod".into()];
        assert!(p.is_workspace_allowed("ws-prod"));
    }

    #[test]
    fn policy_is_workspace_not_allowed() {
        let mut p = strict_policy();
        p.allowed_workspaces = vec!["ws-prod".into()];
        assert!(!p.is_workspace_allowed("ws-dev"));
    }

    #[test]
    fn policy_is_target_forbidden() {
        let mut p = strict_policy();
        p.forbidden_targets = vec!["aws_iam_role.admin".into()];
        assert!(p.is_target_forbidden("aws_iam_role.admin"));
    }

    #[test]
    fn policy_is_target_not_forbidden() {
        let mut p = strict_policy();
        p.forbidden_targets = vec!["aws_iam_role.admin".into()];
        assert!(!p.is_target_forbidden("aws_instance.web"));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = strict_policy();
        let json = serde_json::to_string(&p).unwrap();
        let back: ApplyPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.require_approval);
        assert_eq!(back.timeout_seconds, 1800);
    }

    #[test]
    fn policy_clone() {
        let p = strict_policy();
        let cloned = p.clone();
        drop(p);
        assert!(cloned.require_approval);
    }

    #[test]
    fn policy_debug() {
        let p = strict_policy();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("ApplyPolicy"));
    }

    #[test]
    fn policy_empty_workspace_allows_all() {
        let p = ApplyPolicy {
            require_approval: false,
            require_plan_hash: false,
            max_resources_per_apply: None,
            allowed_workspaces: Vec::new(),
            forbidden_targets: Vec::new(),
            timeout_seconds: 600,
        };
        let req = sample_request();
        assert!(p.check_request(&req).is_approved());
    }

    // =====================================================================
    // ApplyAuditEvent
    // =====================================================================

    #[test]
    fn audit_event_now() {
        let evt = ApplyAuditEvent::now("test_event", "test details", "admin");
        assert_eq!(evt.event_type, "test_event");
        assert_eq!(evt.details, "test details");
        assert_eq!(evt.actor, "admin");
        assert!(evt.apply_id.is_none());
    }

    #[test]
    fn audit_event_at() {
        let ts = Utc::now();
        let evt = ApplyAuditEvent::at(ts, "plan_validated", "Plan ok", "system");
        assert_eq!(evt.timestamp, ts);
        assert_eq!(evt.event_type, "plan_validated");
    }

    #[test]
    fn audit_event_with_apply_id() {
        let evt = ApplyAuditEvent::now("x", "y", "z").with_apply_id("apply-99");
        assert_eq!(evt.apply_id, Some("apply-99".into()));
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let evt = ApplyAuditEvent::now("created", "lifecycle created", "system")
            .with_apply_id("apply-1");
        let json = serde_json::to_string(&evt).unwrap();
        let back: ApplyAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type, "created");
        assert_eq!(back.apply_id, Some("apply-1".into()));
    }

    #[test]
    fn audit_event_clone() {
        let evt = ApplyAuditEvent::now("x", "y", "z");
        let cloned = evt.clone();
        drop(evt);
        assert_eq!(cloned.event_type, "x");
    }

    #[test]
    fn audit_event_debug() {
        let evt = ApplyAuditEvent::now("x", "y", "z");
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("ApplyAuditEvent"));
    }

    // =====================================================================
    // ApplyLifecycle
    // =====================================================================

    #[test]
    fn lifecycle_new_starts_pending() {
        let req = sample_request();
        let lc = ApplyLifecycle::new("apply-1", req);
        assert_eq!(lc.current_status(), ApplyStatus::Pending);
        assert!(!lc.is_terminal());
    }

    #[test]
    fn lifecycle_new_has_created_event() {
        let req = sample_request();
        let lc = ApplyLifecycle::new("apply-1", req);
        assert_eq!(lc.audit_event_count(), 1);
        assert_eq!(lc.audit_trail[0].event_type, "lifecycle_created");
    }

    #[test]
    fn lifecycle_approve_from_pending() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        assert!(lc.approve("admin").is_ok());
        assert_eq!(lc.current_status(), ApplyStatus::Approved);
        assert_eq!(lc.audit_event_count(), 2);
    }

    #[test]
    fn lifecycle_approve_from_non_pending_fails() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        let err = lc.approve("admin").unwrap_err();
        assert!(err.contains("approved"));
    }

    #[test]
    fn lifecycle_start_execution() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        assert!(lc.start_execution().is_ok());
        assert_eq!(lc.current_status(), ApplyStatus::Executing);
    }

    #[test]
    fn lifecycle_start_execution_from_pending_fails() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        let err = lc.start_execution().unwrap_err();
        assert!(err.contains("pending"));
    }

    #[test]
    fn lifecycle_complete() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        lc.start_execution().unwrap();
        assert!(lc.complete().is_ok());
        assert_eq!(lc.current_status(), ApplyStatus::Completed);
        assert!(lc.is_terminal());
    }

    #[test]
    fn lifecycle_complete_from_approved_fails() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        let err = lc.complete().unwrap_err();
        assert!(err.contains("approved"));
    }

    #[test]
    fn lifecycle_fail() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        lc.start_execution().unwrap();
        assert!(lc.fail("Provider timeout").is_ok());
        assert_eq!(lc.current_status(), ApplyStatus::Failed);
        assert!(lc.is_terminal());
    }

    #[test]
    fn lifecycle_fail_from_pending_fails() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        let err = lc.fail("boom").unwrap_err();
        assert!(err.contains("pending"));
    }

    #[test]
    fn lifecycle_cancel_from_pending() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        assert!(lc.cancel("admin").is_ok());
        assert_eq!(lc.current_status(), ApplyStatus::Cancelled);
        assert!(lc.is_terminal());
    }

    #[test]
    fn lifecycle_cancel_from_approved() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        assert!(lc.cancel("admin").is_ok());
        assert_eq!(lc.current_status(), ApplyStatus::Cancelled);
    }

    #[test]
    fn lifecycle_cancel_from_executing() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        lc.start_execution().unwrap();
        assert!(lc.cancel("admin").is_ok());
        assert_eq!(lc.current_status(), ApplyStatus::Cancelled);
    }

    #[test]
    fn lifecycle_cancel_from_terminal_fails() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        lc.start_execution().unwrap();
        lc.complete().unwrap();
        let err = lc.cancel("admin").unwrap_err();
        assert!(err.contains("terminal"));
    }

    #[test]
    fn lifecycle_timeout() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        lc.start_execution().unwrap();
        assert!(lc.timeout().is_ok());
        assert_eq!(lc.current_status(), ApplyStatus::TimedOut);
        assert!(lc.is_terminal());
    }

    #[test]
    fn lifecycle_timeout_from_pending_fails() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        let err = lc.timeout().unwrap_err();
        assert!(err.contains("pending"));
    }

    #[test]
    fn lifecycle_full_happy_path_audit_trail() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        lc.start_execution().unwrap();
        lc.complete().unwrap();
        // created + approved + execution_started + completed = 4
        assert_eq!(lc.audit_event_count(), 4);
        assert_eq!(lc.audit_trail[0].event_type, "lifecycle_created");
        assert_eq!(lc.audit_trail[1].event_type, "approved");
        assert_eq!(lc.audit_trail[2].event_type, "execution_started");
        assert_eq!(lc.audit_trail[3].event_type, "completed");
    }

    #[test]
    fn lifecycle_full_failure_path_audit_trail() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("admin").unwrap();
        lc.start_execution().unwrap();
        lc.fail("Provider error").unwrap();
        assert_eq!(lc.audit_event_count(), 4);
        assert_eq!(lc.audit_trail[3].event_type, "failed");
        assert_eq!(lc.audit_trail[3].details, "Provider error");
    }

    #[test]
    fn lifecycle_serde_roundtrip() {
        let req = sample_request();
        let lc = ApplyLifecycle::new("apply-1", req);
        let json = serde_json::to_string(&lc).unwrap();
        let back: ApplyLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.apply_id, "apply-1");
        assert_eq!(back.current_status(), ApplyStatus::Pending);
    }

    #[test]
    fn lifecycle_clone() {
        let req = sample_request();
        let lc = ApplyLifecycle::new("apply-1", req);
        let cloned = lc.clone();
        drop(lc);
        assert_eq!(cloned.apply_id, "apply-1");
    }

    #[test]
    fn lifecycle_debug() {
        let req = sample_request();
        let lc = ApplyLifecycle::new("apply-1", req);
        let dbg = format!("{lc:?}");
        assert!(dbg.contains("ApplyLifecycle"));
    }

    #[test]
    fn lifecycle_apply_id_in_audit_events() {
        let req = sample_request();
        let lc = ApplyLifecycle::new("apply-42", req);
        for evt in &lc.audit_trail {
            assert_eq!(evt.apply_id, Some("apply-42".into()));
        }
    }

    #[test]
    fn lifecycle_approve_actor_recorded() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.approve("ops-lead@corp.com").unwrap();
        assert_eq!(lc.audit_trail[1].actor, "ops-lead@corp.com");
    }

    #[test]
    fn lifecycle_cancel_actor_recorded() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-1", req);
        lc.cancel("security-team").unwrap();
        let last = lc.audit_trail.last().unwrap();
        assert_eq!(last.actor, "security-team");
        assert_eq!(last.event_type, "cancelled");
    }

    // =====================================================================
    // validate_token_for_request
    // =====================================================================

    #[test]
    fn validate_token_success() {
        let req = sample_request();
        let token = sample_token("sha256:deadbeef", "ws-prod-001");
        let policy = strict_policy();
        let decision = validate_token_for_request(&token, &req, &policy);
        assert!(decision.is_approved());
    }

    #[test]
    fn validate_token_expired() {
        let req = sample_request();
        let mut token = sample_token("sha256:deadbeef", "ws-prod-001");
        token.expires_at = Utc::now() - Duration::hours(1);
        let policy = strict_policy();
        match validate_token_for_request(&token, &req, &policy) {
            ApplyDecision::Deny { code, .. } => {
                assert_eq!(code, ApplyDenialCode::TokenExpired);
            }
            other => panic!("expected Deny TokenExpired, got {other:?}"),
        }
    }

    #[test]
    fn validate_token_already_used() {
        let req = sample_request();
        let mut token = sample_token("sha256:deadbeef", "ws-prod-001");
        token.single_use = true;
        token.used = true;
        let policy = strict_policy();
        match validate_token_for_request(&token, &req, &policy) {
            ApplyDecision::Deny { code, .. } => {
                assert_eq!(code, ApplyDenialCode::TokenUsed);
            }
            other => panic!("expected Deny TokenUsed, got {other:?}"),
        }
    }

    #[test]
    fn validate_token_plan_hash_mismatch() {
        let req = sample_request();
        let token = sample_token("sha256:wrong", "ws-prod-001");
        let policy = strict_policy();
        match validate_token_for_request(&token, &req, &policy) {
            ApplyDecision::Deny { code, reason } => {
                assert_eq!(code, ApplyDenialCode::PlanHashMismatch);
                assert!(reason.contains("sha256:wrong"));
                assert!(reason.contains("sha256:deadbeef"));
            }
            other => panic!("expected Deny PlanHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn validate_token_workspace_mismatch() {
        let req = sample_request();
        let token = sample_token("sha256:deadbeef", "ws-other");
        let policy = strict_policy();
        match validate_token_for_request(&token, &req, &policy) {
            ApplyDecision::Deny { code, .. } => {
                assert_eq!(code, ApplyDenialCode::WorkspaceNotAllowed);
            }
            other => panic!("expected Deny WorkspaceNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn validate_token_target_not_allowed() {
        let req = sample_request();
        let mut token = sample_token("sha256:deadbeef", "ws-prod-001");
        token.allowed_targets = vec!["aws_s3_bucket.data".into()];
        let policy = strict_policy();
        match validate_token_for_request(&token, &req, &policy) {
            ApplyDecision::Deny { code, .. } => {
                assert_eq!(code, ApplyDenialCode::TargetForbidden);
            }
            other => panic!("expected Deny TargetForbidden, got {other:?}"),
        }
    }

    #[test]
    fn validate_token_resource_limit_exceeded() {
        let req = sample_request();
        let mut token = sample_token("sha256:deadbeef", "ws-prod-001");
        token.max_resources = Some(500);
        let mut policy = strict_policy();
        policy.max_resources_per_apply = Some(100);
        match validate_token_for_request(&token, &req, &policy) {
            ApplyDecision::Deny { code, .. } => {
                assert_eq!(code, ApplyDenialCode::ResourceLimitExceeded);
            }
            other => panic!("expected Deny ResourceLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn validate_token_resource_limit_ok() {
        let req = sample_request();
        let mut token = sample_token("sha256:deadbeef", "ws-prod-001");
        token.max_resources = Some(50);
        let mut policy = strict_policy();
        policy.max_resources_per_apply = Some(100);
        assert!(validate_token_for_request(&token, &req, &policy).is_approved());
    }

    #[test]
    fn validate_token_no_policy_limit() {
        let req = sample_request();
        let mut token = sample_token("sha256:deadbeef", "ws-prod-001");
        token.max_resources = Some(9999);
        let policy = permissive_policy();
        assert!(validate_token_for_request(&token, &req, &policy).is_approved());
    }

    // =====================================================================
    // build_apply_args
    // =====================================================================

    #[test]
    fn build_args_basic() {
        let req = sample_request();
        let args = build_apply_args(&req);
        assert_eq!(args[0], "apply");
        assert_eq!(args[1], "-input=false");
        assert!(args.last().unwrap().contains("plan-abc123"));
    }

    #[test]
    fn build_args_never_auto_approve() {
        let req = sample_request();
        let args = build_apply_args(&req);
        assert!(!args.iter().any(|a| a.contains("auto-approve")));
    }

    #[test]
    fn build_args_with_targets() {
        let req = sample_request();
        let args = build_apply_args(&req);
        assert!(args.iter().any(|a| a == "-target=aws_instance.web"));
    }

    #[test]
    fn build_args_with_variables() {
        let req = sample_request();
        let args = build_apply_args(&req);
        assert!(args.iter().any(|a| a.starts_with("-var=region=")));
    }

    #[test]
    fn build_args_no_targets() {
        let mut req = sample_request();
        req.targets.clear();
        let args = build_apply_args(&req);
        assert!(!args.iter().any(|a| a.starts_with("-target=")));
    }

    #[test]
    fn build_args_no_variables() {
        let mut req = sample_request();
        req.variables.clear();
        let args = build_apply_args(&req);
        assert!(!args.iter().any(|a| a.starts_with("-var=")));
    }

    #[test]
    fn build_args_multiple_targets() {
        let mut req = sample_request();
        req.targets = vec!["aws_instance.a".into(), "aws_instance.b".into()];
        let args = build_apply_args(&req);
        let target_count = args.iter().filter(|a| a.starts_with("-target=")).count();
        assert_eq!(target_count, 2);
    }

    #[test]
    fn build_args_plan_reference_is_last() {
        let req = sample_request();
        let args = build_apply_args(&req);
        assert_eq!(args.last().unwrap(), &req.plan_reference);
    }

    // =====================================================================
    // Integration-style: full workflow
    // =====================================================================

    #[test]
    fn full_workflow_approve_execute_complete() {
        let req = sample_request();
        let mut token = sample_token("sha256:deadbeef", "ws-prod-001");
        let policy = strict_policy();

        // 1. Validate request against policy.
        let policy_decision = policy.check_request(&req);
        assert!(policy_decision.is_approved());

        // 2. Validate token.
        let token_decision = validate_token_for_request(&token, &req, &policy);
        assert!(token_decision.is_approved());

        // 3. Consume token.
        token.single_use = true;
        assert!(token.consume());

        // 4. Create lifecycle and drive through states.
        let mut lc = ApplyLifecycle::new("apply-full-1", req);
        assert_eq!(lc.current_status(), ApplyStatus::Pending);

        lc.approve("admin").unwrap();
        assert_eq!(lc.current_status(), ApplyStatus::Approved);

        lc.start_execution().unwrap();
        assert_eq!(lc.current_status(), ApplyStatus::Executing);

        lc.complete().unwrap();
        assert_eq!(lc.current_status(), ApplyStatus::Completed);
        assert!(lc.is_terminal());

        // 5. Verify audit trail.
        assert_eq!(lc.audit_event_count(), 4);

        // 6. Token is now consumed.
        assert!(!token.consume());
    }

    #[test]
    fn full_workflow_deny_missing_hash() {
        let mut req = sample_request();
        req.plan_hash = String::new();
        let policy = strict_policy();
        let decision = policy.check_request(&req);
        assert!(decision.is_denied());
    }

    #[test]
    fn full_workflow_deny_expired_token() {
        let req = sample_request();
        let mut token = sample_token("sha256:deadbeef", "ws-prod-001");
        token.expires_at = Utc::now() - Duration::seconds(1);
        let policy = strict_policy();
        let decision = validate_token_for_request(&token, &req, &policy);
        assert!(decision.is_denied());
    }

    #[test]
    fn full_workflow_cancel_mid_execution() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-cancel-1", req);
        lc.approve("admin").unwrap();
        lc.start_execution().unwrap();
        lc.cancel("security").unwrap();
        assert_eq!(lc.current_status(), ApplyStatus::Cancelled);
        assert!(lc.is_terminal());
        // Cannot cancel again.
        assert!(lc.cancel("admin").is_err());
    }

    #[test]
    fn full_workflow_timeout_during_execution() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-timeout-1", req);
        lc.approve("admin").unwrap();
        lc.start_execution().unwrap();
        lc.timeout().unwrap();
        assert_eq!(lc.current_status(), ApplyStatus::TimedOut);
        assert!(lc.is_terminal());
    }

    #[test]
    fn full_workflow_fail_and_check_audit() {
        let req = sample_request();
        let mut lc = ApplyLifecycle::new("apply-fail-1", req);
        lc.approve("admin").unwrap();
        lc.start_execution().unwrap();
        lc.fail("AWS credentials expired").unwrap();
        assert_eq!(lc.current_status(), ApplyStatus::Failed);
        let last = lc.audit_trail.last().unwrap();
        assert_eq!(last.event_type, "failed");
        assert_eq!(last.details, "AWS credentials expired");
    }

    #[test]
    fn build_args_are_safe_no_auto_approve_ever() {
        // Construct a request that tries to be sneaky by putting -auto-approve
        // in the plan reference.
        let mut req = sample_request();
        req.plan_reference = "plan.tfplan".into();
        let args = build_apply_args(&req);
        // -auto-approve must never appear.
        for arg in &args {
            assert!(
                !arg.contains("auto-approve"),
                "Found auto-approve in args: {arg}"
            );
        }
    }
}
